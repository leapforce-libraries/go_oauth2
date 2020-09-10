package googleoauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	bigquerytools "github.com/Leapforce-nl/go_bigquerytools"
	types "github.com/Leapforce-nl/go_types"
	"github.com/getsentry/sentry-go"
	"google.golang.org/api/iterator"
)

const (
	tableRefreshToken string = "leapforce.refreshtokens"
)

// OAuth2 stores OAuth2 configuration
//
type OAuth2 struct {
	// config
	apiName      string
	clientID     string
	clientSecret string
	scopes       []string
	redirectURL  string
	authURL      string
	tokenURL     string
	Token        *Token
	bigQuery     *bigquerytools.BigQuery
	isLive       bool
}

var tokenMutex sync.Mutex

type Token struct {
	AccessToken  string `json:"access_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Expiry       time.Time
}

type ApiError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func NewOAuth(apiName string, clientID string, clienSecret string, scopes []string, redirectURL string, authURL string, tokenURL string, bigquery *bigquerytools.BigQuery, isLive bool) *OAuth2 {
	_oAuth2 := new(OAuth2)
	_oAuth2.apiName = apiName
	_oAuth2.clientID = clientID
	_oAuth2.clientSecret = clienSecret
	_oAuth2.scopes = scopes
	_oAuth2.redirectURL = redirectURL
	_oAuth2.authURL = authURL
	_oAuth2.tokenURL = tokenURL
	//_oAuth2.Token        *Token
	_oAuth2.bigQuery = bigquery
	_oAuth2.isLive = isLive

	return _oAuth2
}

func (oa *OAuth2) LockToken() {
	tokenMutex.Lock()
}

func (oa *OAuth2) UnlockToken() {
	tokenMutex.Unlock()
}

func (t *Token) Useable() bool {
	if t == nil {
		return false
	}
	if t.AccessToken == "" || t.RefreshToken == "" {
		return false
	}
	return true
}

func (t *Token) Refreshable() bool {
	if t == nil {
		return false
	}
	if t.RefreshToken == "" {
		return false
	}
	return true
}

func (t *Token) IsExpired() (bool, error) {
	if !t.Useable() {
		return true, &types.ErrorString{"Token is not valid."}
	}
	if t.Expiry.Add(-60 * time.Second).Before(time.Now()) {
		return true, nil
	}
	return false, nil
}

func (oa *OAuth2) GetToken(url string, hasRefreshToken bool) error {
	guid := types.NewGUID()
	fmt.Println("GetTokenGUID:", guid)
	fmt.Println(url)

	httpClient := http.Client{}
	req, err := http.NewRequest(http.MethodPost, url, nil)
	req.Header.Add("Content-Type", "application/json")
	//req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	if err != nil {
		return err
	}

	// We set this header since we want the response
	// as JSON
	req.Header.Set("accept", "application/json")

	// Send out the HTTP request
	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	b, err := ioutil.ReadAll(res.Body)

	if res.StatusCode < 200 || res.StatusCode > 299 {
		fmt.Println("GetTokenGUID:", guid)
		fmt.Println("AccessToken:", oa.Token.AccessToken)
		fmt.Println("Refresh:", oa.Token.RefreshToken)
		fmt.Println("Expiry:", oa.Token.Expiry)
		fmt.Println("Now:", time.Now())

		eoError := ApiError{}

		err = json.Unmarshal(b, &eoError)
		if err != nil {
			return err
		}

		message := fmt.Sprintln("Error:", eoError.Error, ", ", eoError.Description)
		fmt.Println(message)

		if res.StatusCode == 401 {
			if oa.isLive {
				sentry.CaptureMessage(fmt.Sprintf("%s refreshtoken not valid, login needed to retrieve a new one. Error: %s", oa.apiName, message))
			}
			oa.initToken()
		}

		return &types.ErrorString{fmt.Sprintf("Server returned statuscode %v, url: %s", res.StatusCode, req.URL)}
	}

	token := Token{}

	err = json.Unmarshal(b, &token)
	if err != nil {
		log.Println(err)
		return err
	}

	fmt.Println(token)

	token.Expiry = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)

	if oa.Token == nil {
		oa.Token = &Token{}
	}

	oa.Token.Expiry = token.Expiry
	oa.Token.AccessToken = token.AccessToken

	if hasRefreshToken {
		oa.Token.RefreshToken = token.RefreshToken

		err = oa.saveTokenToBigQuery()
		if err != nil {
			return err
		}
	}

	fmt.Println("new token:")
	fmt.Println(oa.Token.AccessToken)
	fmt.Println("new refresh token:")
	fmt.Println(oa.Token.RefreshToken)
	fmt.Println("new expiry:")
	fmt.Println(oa.Token.Expiry)
	fmt.Println("GetTokenGUID:", guid)

	return nil
}

func (oa *OAuth2) getTokenFromCode(code string) error {
	//fmt.Println("getTokenFromCode")
	url2 := fmt.Sprintf("%s?code=%s&redirect_uri=%s&client_id=%s&client_secret=%s&scope=&grant_type=authorization_code", oa.tokenURL, code, url.QueryEscape(oa.redirectURL), oa.clientID, oa.clientSecret)
	//fmt.Println("getTokenFromCode", url)
	return oa.GetToken(url2, true)
}

func (oa *OAuth2) getTokenFromRefreshToken() error {
	fmt.Println("***getTokenFromRefreshToken***")

	//always get refresh token from BQ prior to using it
	oa.getTokenFromBigQuery()

	if !oa.Token.Refreshable() {
		return oa.initToken()
	}

	url2 := fmt.Sprintf("%s?client_id=%s&client_secret=%s&refresh_token=%s&grant_type=refresh_token&access_type=offline&prompt=consent", oa.tokenURL, oa.clientID, oa.clientSecret, oa.Token.RefreshToken)
	//fmt.Println("getTokenFromRefreshToken", url)
	return oa.GetToken(url2, false)
}

// ValidateToken validates current token and retrieves a new one if necessary
//
func (oa *OAuth2) ValidateToken() error {
	oa.LockToken()
	defer oa.UnlockToken()

	if !oa.Token.Useable() {

		err := oa.getTokenFromRefreshToken()
		if err != nil {
			return err
		}

		if !oa.Token.Useable() {
			if oa.isLive {
				sentry.CaptureMessage("Refreshtoken not found or empty, login needed to retrieve a new one.")
			}
			err := oa.initToken()
			if err != nil {
				return err
			}
			//return &types.ErrorString{""}
		}
	}

	isExpired, err := oa.Token.IsExpired()
	if err != nil {
		return err
	}
	if isExpired {
		//fmt.Println(time.Now(), "[token expired]")
		err = oa.getTokenFromRefreshToken()
		if err != nil {
			return err
		}
	}

	return nil
}

func (oa *OAuth2) initToken() error {

	if oa == nil {
		return &types.ErrorString{fmt.Sprintf("%s variable not initialized", oa.apiName)}
	}

	scope := strings.Join(oa.scopes, ",")

	url2 := fmt.Sprintf("%s?client_id=%s&response_type=code&redirect_uri=%s&scope=%s&access_type=offline&prompt=consent", url.QueryEscape(oa.authURL), oa.clientID, url.QueryEscape(oa.redirectURL), url.QueryEscape(scope))

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

	//sql := "SELECT refreshtoken AS RefreshToken FROM `" + tableRefreshToken + "` WHERE client_id = '" + oa.ClientID + "'"
	sql := fmt.Sprintf("SELECT refreshtoken AS RefreshToken FROM `%s` WHERE api = '%s' AND client_id = '%s'", tableRefreshToken, oa.apiName, oa.clientID)

	//fmt.Println(sql)

	q := bqClient.Query(sql)
	it, err := q.Read(ctx)
	if err != nil {
		return err
	}

	token := new(Token)

	for {
		err := it.Next(token)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}

		break
	}

	if oa.Token == nil {
		oa.Token = new(Token)
	}

	oa.Token.TokenType = "bearer"
	oa.Token.Expiry = time.Now().Add(-10 * time.Second)
	oa.Token.RefreshToken = token.RefreshToken
	oa.Token.AccessToken = ""

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

	sql := "MERGE `" + tableRefreshToken + "` AS TARGET " +
		"USING  (SELECT '" + oa.apiName + "' AS api,'" + oa.clientID + "' AS client_id,'" + oa.Token.RefreshToken + "' AS refreshtoken) AS SOURCE " +
		" ON TARGET.api = SOURCE.api " +
		" AND TARGET.client_id = SOURCE.client_id " +
		"WHEN MATCHED THEN " +
		"	UPDATE " +
		"	SET refreshtoken = SOURCE.refreshtoken " +
		"WHEN NOT MATCHED BY TARGET THEN " +
		"	INSERT (api, client_id, refreshtoken) " +
		"	VALUES (SOURCE.api, SOURCE.client_id, SOURCE.refreshtoken)"

	q := bqClient.Query(sql)

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
