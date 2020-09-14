package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/bigquery"
	bigquerytools "github.com/Leapforce-nl/go_bigquerytools"
	errortools "github.com/Leapforce-nl/go_errortools"
	types "github.com/Leapforce-nl/go_types"
	"github.com/getsentry/sentry-go"
	"google.golang.org/api/iterator"
)

const (
	tableRefreshToken string = "leapforce.oauth2"
)

// OAuth2 stores OAuth2 configuration
//
type OAuth2 struct {
	// config
	apiName         string
	clientID        string
	clientSecret    string
	scope           string
	redirectURL     string
	authURL         string
	tokenURL        string
	tokenHTTPMethod string
	token           *Token
	bigQuery        *bigquerytools.BigQuery
	isLive          bool
}

type ApiError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func NewOAuth(apiName string, clientID string, clienSecret string, scope string, redirectURL string, authURL string, tokenURL string, tokenHTTPMethod string, bigquery *bigquerytools.BigQuery, isLive bool) *OAuth2 {
	_oAuth2 := new(OAuth2)
	_oAuth2.apiName = apiName
	_oAuth2.clientID = clientID
	_oAuth2.clientSecret = clienSecret
	_oAuth2.scope = scope
	_oAuth2.redirectURL = redirectURL
	_oAuth2.authURL = authURL
	_oAuth2.tokenURL = tokenURL
	_oAuth2.tokenHTTPMethod = tokenHTTPMethod
	_oAuth2.bigQuery = bigquery
	_oAuth2.isLive = isLive

	return _oAuth2
}

func (oa *OAuth2) lockToken() {
	tokenMutex.Lock()
}

func (oa *OAuth2) GetToken(params *url.Values) error {
	request := new(http.Request)

	if oa.tokenHTTPMethod == http.MethodGet {
		url := oa.tokenURL

		index := 0
		for key, value := range *params {
			if index == 0 {
				url = fmt.Sprintf("%s?%s=%s", url, key, value)
			} else {
				url = fmt.Sprintf("%s&%s=%s", url, key, value)
			}
			index++
		}

		req, err := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		if err != nil {
			return err
		}

		request = req
	} else if oa.tokenHTTPMethod == http.MethodPost {

		encoded := ""
		body := new(strings.Reader)
		if params != nil {
			encoded = params.Encode()
			body = strings.NewReader(encoded)
		}

		req, err := http.NewRequest(http.MethodPost, oa.tokenURL, body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Content-Length", strconv.Itoa(len(encoded)))
		req.Header.Set("Accept", "application/json")
		if err != nil {
			return err
		}

		request = req
	} else {
		return &types.ErrorString{fmt.Sprintf("Invalid TokenHTTPMethod: %s", oa.tokenHTTPMethod)}
	}

	httpClient := http.Client{}

	// Send out the HTTP request
	res, err := httpClient.Do(request)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	b, err := ioutil.ReadAll(res.Body)

	if res.StatusCode < 200 || res.StatusCode > 299 {
		eoError := ApiError{}

		err = json.Unmarshal(b, &eoError)
		if err != nil {
			return err
		}

		message := fmt.Sprintln("Error:", res.StatusCode, eoError.Error, ", ", eoError.Description)
		fmt.Println(message)

		oa.token.Print()

		if res.StatusCode == 401 {
			if oa.isLive {
				sentry.CaptureMessage(fmt.Sprintf("%s refreshtoken not valid, login needed to retrieve a new one. Error: %s", oa.apiName, message))
			}
			oa.initTokenNeeded()
		}

		return &types.ErrorString{fmt.Sprintf("Server returned statuscode %v, url: %s", res.StatusCode, request.URL)}
	}

	token := Token{}

	err = json.Unmarshal(b, &token)
	if err != nil {
		log.Println(err)
		return err
	}

	if token.ExpiresIn != nil {
		expiresIn, err := strconv.ParseInt(*token.ExpiresIn, 10, 64)
		if err != nil {
			token.Expiry = nil
		} else {
			expiry := time.Now().Add(time.Duration(expiresIn) * time.Second)
			token.Expiry = &expiry
		}
	} else {
		token.Expiry = nil
	}

	token.Print()

	oa.token = &token

	err = oa.saveTokenToBigQuery()
	if err != nil {
		return err
	}

	return nil
}

func (oa *OAuth2) getTokenFromCode(code string) error {
	data := url.Values{}
	data.Set("client_id", oa.clientID)
	data.Set("client_secret", oa.clientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", oa.redirectURL)

	return oa.GetToken(&data)
}

func (oa *OAuth2) getTokenFromRefreshToken() error {
	fmt.Println("***getTokenFromRefreshToken***")

	//always get refresh token from BQ prior to using it
	oa.getTokenFromBigQuery()

	if !oa.token.hasRefreshToken() {
		oa.initTokenNeeded()
	}

	data := url.Values{}
	data.Set("client_id", oa.clientID)
	data.Set("client_secret", oa.clientSecret)
	data.Set("refresh_token", *((*oa.token).RefreshToken))
	data.Set("grant_type", "refresh_token")

	return oa.GetToken(&data)
}

// ValidateToken validates current token and retrieves a new one if necessary
//
func (oa *OAuth2) ValidateToken() error {
	oa.lockToken()
	defer oa.unlockToken()

	if !oa.token.hasAccessToken() {
		// retrieve AccessCode from BigQuery
		err := oa.getTokenFromBigQuery()
		if err != nil {
			return err
		}
	}

	if oa.token.hasValidAccessToken() {
		return nil
	}

	if oa.token.hasRefreshToken() {
		err := oa.getTokenFromRefreshToken()
		if err != nil {
			return err
		}

		if oa.token.hasValidAccessToken() {
			return nil
		}
	}

	oa.initTokenNeeded()

	return nil
}

func (oa *OAuth2) initTokenNeeded() {
	message := "No valid accesscode or refreshcode found. Manual login needed, lease run 'token' mode."
	fmt.Println(message)

	err := &types.ErrorString{message}

	errortools.FatalSentry(err, oa.isLive)
}

func (oa *OAuth2) InitToken() error {

	if oa == nil {
		return &types.ErrorString{fmt.Sprintf("%s variable not initialized", oa.apiName)}
	}

	url2 := fmt.Sprintf("%s?client_id=%s&response_type=code&redirect_uri=%s&scope=%s&access_type=offline&prompt=consent", oa.authURL, oa.clientID, url.PathEscape(oa.redirectURL), url.PathEscape(oa.scope))

	fmt.Println("Go to this url to get new access token:\n")
	fmt.Println(url2 + "\n")

	// Create a new redirect route
	http.HandleFunc("/oauth/redirect", func(w http.ResponseWriter, r *http.Request) {
		//
		// get authorization code
		//
		err := r.ParseForm()
		if err != nil {
			fmt.Fprintf(os.Stdout, "could not parse query: %v", err)
			w.WriteHeader(http.StatusBadRequest)
		}
		code := r.FormValue("code")

		fmt.Println(code)

		err = oa.getTokenFromCode(code)
		if err != nil {
			fmt.Println(err)
		}

		w.WriteHeader(http.StatusFound)

		return
	})

	http.ListenAndServe(":8080", nil)

	return nil
}

func (oa *OAuth2) getTokenFromBigQuery() error {
	fmt.Println("***getTokenFromBigQuery***")
	// create client
	bqClient, err := oa.bigQuery.CreateClient()
	if err != nil {
		fmt.Println("\nerror in BigQueryCreateClient")
		return err
	}

	ctx := context.Background()

	sql := fmt.Sprintf("SELECT TokenType, AccessToken, RefreshToken, Expiry, Scope FROM `%s` WHERE Api = '%s' AND ClientID = '%s'", tableRefreshToken, oa.apiName, oa.clientID)
	//fmt.Println(sql)

	q := bqClient.Query(sql)
	it, err := q.Read(ctx)
	if err != nil {
		return err
	}

	type TokenBQ struct {
		AccessToken  bigquery.NullString
		Scope        bigquery.NullString
		TokenType    bigquery.NullString
		RefreshToken bigquery.NullString
		Expiry       bigquery.NullTimestamp
	}

	tokenBQ := new(TokenBQ)

	for {
		err := it.Next(tokenBQ)
		if err == iterator.Done {
			break
		}
		if err != nil {
			fmt.Println(err)
			return err
		}

		break
	}

	oa.token = &Token{
		bigquerytools.NullStringToString(tokenBQ.AccessToken),
		bigquerytools.NullStringToString(tokenBQ.Scope),
		bigquerytools.NullStringToString(tokenBQ.TokenType),
		nil,
		bigquerytools.NullStringToString(tokenBQ.RefreshToken),
		bigquerytools.NullTimestampToTime(tokenBQ.Expiry),
	}

	oa.token.Print()

	return nil
}

func (oa *OAuth2) saveTokenToBigQuery() error {
	// create client
	bqClient, err := oa.bigQuery.CreateClient()
	if err != nil {
		fmt.Println("\nerror in BigQueryCreateClient")
		return err
	}

	ctx := context.Background()

	tokenType := "NULLIF('','')"
	if oa.token.TokenType != nil {
		if *oa.token.TokenType != "" {
			tokenType = fmt.Sprintf("'%s'", *oa.token.TokenType)
		}
	}

	accessToken := "NULLIF('','')"
	if oa.token.AccessToken != nil {
		if *oa.token.AccessToken != "" {
			accessToken = fmt.Sprintf("'%s'", *oa.token.AccessToken)
		}
	}

	refreshToken := "NULLIF('','')"
	if oa.token.RefreshToken != nil {
		if *oa.token.RefreshToken != "" {
			refreshToken = fmt.Sprintf("'%s'", *oa.token.RefreshToken)
		}
	}

	expiry := "TIMESTAMP(NULL)"
	if oa.token.Expiry != nil {
		expiry = fmt.Sprintf("TIMESTAMP('%s')", (*oa.token.Expiry).Format("2006-01-02T15:04:05"))
	}

	scope := "NULLIF('','')"
	if oa.token.Scope != nil {
		if *oa.token.Scope != "" {
			scope = fmt.Sprintf("'%s'", *oa.token.Scope)
		}
	}

	sql := "MERGE `" + tableRefreshToken + "` AS TARGET " +
		"USING  (SELECT '" +
		oa.apiName + "' AS Api,'" +
		oa.clientID + "' AS ClientID," +
		tokenType + " AS TokenType," +
		accessToken + " AS AccessToken," +
		refreshToken + " AS RefreshToken," +
		expiry + " AS Expiry," +
		scope + " AS Scope) AS SOURCE " +
		" ON TARGET.Api = SOURCE.Api " +
		" AND TARGET.ClientID = SOURCE.ClientID " +
		"WHEN MATCHED THEN " +
		"	UPDATE " +
		"	SET TokenType = SOURCE.TokenType " +
		"	, AccessToken = SOURCE.AccessToken " +
		"	, RefreshToken = SOURCE.RefreshToken " +
		"	, Expiry = SOURCE.Expiry " +
		"	, Scope = SOURCE.Scope	 " +
		"WHEN NOT MATCHED BY TARGET THEN " +
		"	INSERT (Api, ClientID, TokenType, AccessToken, RefreshToken, Expiry, Scope) " +
		"	VALUES (SOURCE.Api, SOURCE.ClientID, SOURCE.TokenType, SOURCE.AccessToken, SOURCE.RefreshToken, SOURCE.Expiry, SOURCE.Scope)"

	q := bqClient.Query(sql)
	//fmt.Println(sql)

	job, err := q.Run(ctx)
	if err != nil {
		return err
	}

	for {
		status, err := job.Status(ctx)
		if err != nil {
			return err
		}
		if status.Done() {
			if status.Err() != nil {
				return status.Err()
			}
			break
		}
		time.Sleep(1 * time.Second)
	}

	return nil
}
