package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/bigquery"
	bigquerytools "github.com/leapforce-libraries/go_bigquerytools"
	errortools "github.com/leapforce-libraries/go_errortools"
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
	tokenFunction   *func() (*Token, error)
	token           *Token
	bigQuery        *bigquerytools.BigQuery
	isLive          bool
	locationUTC     *time.Location
}

type OAuth2Config struct {
	ApiName         string
	ClientID        string
	ClientSecret    string
	Scope           string
	RedirectURL     string
	AuthURL         string
	TokenURL        string
	TokenHTTPMethod string
	TokenFunction   *func() (*Token, error)
}

type ApiError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func NewOAuth(config OAuth2Config, bigquery *bigquerytools.BigQuery, isLive bool) *OAuth2 {
	_oAuth2 := new(OAuth2)
	_oAuth2.apiName = config.ApiName
	_oAuth2.clientID = config.ClientID
	_oAuth2.clientSecret = config.ClientSecret
	_oAuth2.scope = config.Scope
	_oAuth2.redirectURL = config.RedirectURL
	_oAuth2.authURL = config.AuthURL
	_oAuth2.tokenURL = config.TokenURL
	_oAuth2.tokenHTTPMethod = config.TokenHTTPMethod
	_oAuth2.tokenFunction = config.TokenFunction
	_oAuth2.bigQuery = bigquery
	_oAuth2.isLive = isLive

	locUTC, _ := time.LoadLocation("UTC")
	_oAuth2.locationUTC = locUTC

	return _oAuth2
}

func (oa *OAuth2) lockToken() {
	tokenMutex.Lock()
}

func (oa *OAuth2) GetToken(params *url.Values) *errortools.Error {
	request := new(http.Request)

	fmt.Println(oa.tokenHTTPMethod)

	e := new(errortools.Error)

	if oa.tokenHTTPMethod == http.MethodGet {
		url := oa.tokenURL

		/*index := 0
		for key, value := range *params {
			valueString := ""
			if len(value) > 0 {
				valueString = value[0]
			}

			if index == 0 {
				url = fmt.Sprintf("%s?%s=%s", url, key, valueString)
			} else {
				url = fmt.Sprintf("%s&%s=%s", url, key, valueString)
			}
			index++
		}*/

		if params != nil {
			if len(*params) > 0 {
				url = fmt.Sprintf("%s?%s", url, (*params).Encode())
			}
		}

		req, err := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		e.SetRequest(req)
		if err != nil {
			e.SetMessage(err)
			return e
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
		e.SetRequest(req)
		if err != nil {
			e.SetMessage(err)
			return e
		}

		request = req
	} else {
		e.SetMessage(fmt.Sprintf("Invalid TokenHTTPMethod: %s", oa.tokenHTTPMethod))
		return e
	}

	httpClient := http.Client{}

	// Send out the HTTP request
	res, err := httpClient.Do(request)
	e.SetResponse(res)
	if err != nil {
		e.SetMessage(err)
		return e
	}

	defer res.Body.Close()

	b, err := ioutil.ReadAll(res.Body)

	if res.StatusCode < 200 || res.StatusCode > 299 {
		eoError := ApiError{}

		err = json.Unmarshal(b, &eoError)
		if err != nil {
			e.SetMessage(err)
			return e
		}

		//message := fmt.Sprintln("Error:", res.StatusCode, eoError.Error, ", ", eoError.Description)
		//fmt.Println(message)

		oa.token.Print()

		if res.StatusCode == 401 {
			/*if oa.isLive {
				message := fmt.Sprintln("Error:", res.StatusCode, eoError.Error, ", ", eoError.Description)
				sentry.CaptureMessage(fmt.Sprintf("%s refreshtoken not valid, login needed to retrieve a new one. Error: %s", oa.apiName, message))
			}*/
			return oa.initTokenNeeded()
		}

		e.SetMessage(fmt.Sprintf("Server returned statuscode %v, url: %s", res.StatusCode, request.URL))
		return e
	}

	token := Token{}

	err = json.Unmarshal(b, &token)
	if err != nil {
		e.SetMessage(err)
		return e
	}

	ee := oa.setToken(&token)
	if ee != nil {
		return ee
	}

	ee = oa.saveTokenToBigQuery()
	if ee != nil {
		return ee
	}

	return nil
}

func (oa *OAuth2) setToken(token *Token) *errortools.Error {
	fmt.Println("setToken")
	if token != nil {
		if token.ExpiresIn != nil {
			var expiresInInt int64
			var expiresInString string
			err := json.Unmarshal(*token.ExpiresIn, &expiresInInt)
			if err != nil {
				err = json.Unmarshal(*token.ExpiresIn, &expiresInString)

				if err == nil {
					expiresInInt, err = strconv.ParseInt(expiresInString, 10, 64)
				}
			}

			if err != nil {
				return errortools.ErrorMessage(fmt.Sprintf("Cannot convert ExpiresIn %s to Int64.", fmt.Sprintf("%v", *token.ExpiresIn)))
			}

			//convert to UTC
			expiry := time.Now().Add(time.Duration(expiresInInt) * time.Second).In(oa.locationUTC)
			token.Expiry = &expiry
		} else {
			token.Expiry = nil
		}
	}

	token.Print()

	oa.token = token

	return nil
}

func (oa *OAuth2) getTokenFromCode(code string) *errortools.Error {
	data := url.Values{}
	data.Set("client_id", oa.clientID)
	data.Set("client_secret", oa.clientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", oa.redirectURL)

	return oa.GetToken(&data)
}

func (oa *OAuth2) getTokenFromRefreshToken() *errortools.Error {
	fmt.Println("***getTokenFromRefreshToken***")

	//always get refresh token from BQ prior to using it
	oa.getTokenFromBigQuery()

	if !oa.token.hasRefreshToken() {
		return oa.initTokenNeeded()
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
func (oa *OAuth2) ValidateToken() (*Token, *errortools.Error) {
	oa.lockToken()
	defer oa.unlockToken()

	if !oa.token.hasAccessToken() {
		// retrieve AccessCode from BigQuery
		err := oa.getTokenFromBigQuery()
		if err != nil {
			return nil, errortools.ErrorMessage(err)
		}
	}

	// token should be valid at least one minute from now (te be sure)
	atTimeUTC := time.Now().In(oa.locationUTC).Add(60 * time.Second)

	if oa.token.hasValidAccessToken(atTimeUTC) {
		return oa.token, nil
	}

	if oa.token.hasRefreshToken() {
		err := oa.getTokenFromRefreshToken()
		if err != nil {
			return nil, errortools.ErrorMessage(err)
		}

		if oa.token.hasValidAccessToken(atTimeUTC) {
			return oa.token, nil
		}
	}

	if oa.tokenFunction != nil {
		err := oa.getTokenFromFunction()
		if err != nil {
			return nil, errortools.ErrorMessage(err)
		} else {
			return oa.token, nil
		}
	}

	return nil, oa.initTokenNeeded()
}

func (oa *OAuth2) initTokenNeeded() *errortools.Error {
	message := fmt.Sprintf("No valid accesscode or refreshcode found. Please generate new token by running command:\noauth2_token.exe %s %s", oa.apiName, oa.clientID)
	fmt.Println(message)

	return errortools.ErrorMessage(message)
}

func (oa *OAuth2) InitToken() *errortools.Error {

	if oa == nil {
		return errortools.ErrorMessage(fmt.Sprintf("%s variable not initialized", oa.apiName))
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

		ee := oa.getTokenFromCode(code)
		if ee != nil {
			fmt.Println(ee.Message)
		}

		w.WriteHeader(http.StatusFound)

		return
	})

	http.ListenAndServe(":8080", nil)

	return nil
}

func (oa *OAuth2) getTokenFromFunction() *errortools.Error {
	fmt.Println("***getTokenFromFunction***")

	if oa.tokenFunction == nil {
		return errortools.ErrorMessage("No TokenFunction defined.")
	}

	token, err := (*oa.tokenFunction)()
	if err != nil {
		return errortools.ErrorMessage(err)
	}

	ee := oa.setToken(token)
	if ee != nil {
		return ee
	}

	ee = oa.saveTokenToBigQuery()
	if ee != nil {
		return ee
	}

	return nil
}

func (oa *OAuth2) getTokenFromBigQuery() *errortools.Error {
	fmt.Println("***getTokenFromBigQuery***")
	// create client
	bqClient, e := oa.bigQuery.CreateClient()
	if e != nil {
		fmt.Println("\nerror in BigQueryCreateClient")
		return errortools.ErrorMessage(e)
	}

	ctx := context.Background()

	sql := fmt.Sprintf("SELECT TokenType, AccessToken, RefreshToken, Expiry, Scope FROM `%s` WHERE Api = '%s' AND ClientID = '%s'", tableRefreshToken, oa.apiName, oa.clientID)
	//fmt.Println(sql)

	q := bqClient.Query(sql)
	it, err := q.Read(ctx)
	if err != nil {
		return errortools.ErrorMessage(err)
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
			return errortools.ErrorMessage(err)
		}

		break
	}

	expiry := bigquerytools.NullTimestampToTime(tokenBQ.Expiry)

	if expiry != nil {
		//convert to UTC
		expiryUTC := (*expiry).In(oa.locationUTC)
		expiry = &expiryUTC
	}

	oa.token = &Token{
		bigquerytools.NullStringToString(tokenBQ.AccessToken),
		bigquerytools.NullStringToString(tokenBQ.Scope),
		bigquerytools.NullStringToString(tokenBQ.TokenType),
		nil,
		bigquerytools.NullStringToString(tokenBQ.RefreshToken),
		expiry,
	}

	oa.token.Print()

	return nil
}

func (oa *OAuth2) saveTokenToBigQuery() *errortools.Error {
	// create client
	bqClient, e := oa.bigQuery.CreateClient()
	if e != nil {
		return e
	}

	ctx := context.Background()

	sqlUpdate := "SET AccessToken = SOURCE.AccessToken, Expiry = SOURCE.Expiry"

	tokenType := "NULLIF('','')"
	if oa.token.TokenType != nil {
		if *oa.token.TokenType != "" {
			tokenType = fmt.Sprintf("'%s'", *oa.token.TokenType)
			sqlUpdate = fmt.Sprintf("%s, TokenType = SOURCE.TokenType", sqlUpdate)
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
			sqlUpdate = fmt.Sprintf("%s, RefreshToken = SOURCE.RefreshToken", sqlUpdate)
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
			sqlUpdate = fmt.Sprintf("%s, Scope = SOURCE.Scope", sqlUpdate)
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
		"	UPDATE " + sqlUpdate +
		" WHEN NOT MATCHED BY TARGET THEN " +
		"	INSERT (Api, ClientID, TokenType, AccessToken, RefreshToken, Expiry, Scope) " +
		"	VALUES (SOURCE.Api, SOURCE.ClientID, SOURCE.TokenType, SOURCE.AccessToken, SOURCE.RefreshToken, SOURCE.Expiry, SOURCE.Scope)"

	q := bqClient.Query(sql)
	//fmt.Println(sql)

	job, err := q.Run(ctx)
	if err != nil {
		return errortools.ErrorMessage(err)
	}

	for {
		status, err := job.Status(ctx)
		if err != nil {
			return errortools.ErrorMessage(err)
		}
		if status.Done() {
			if status.Err() != nil {
				return errortools.ErrorMessage(status.Err())
			}
			break
		}
		time.Sleep(1 * time.Second)
	}

	return nil
}
