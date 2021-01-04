package oauth2

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	errortools "github.com/leapforce-libraries/go_errortools"
)

// OAuth2 stores OAuth2 configuration
//
type OAuth2 struct {
	// config
	//apiName               string
	clientID              string
	clientSecret          string
	scope                 string
	redirectURL           string
	authURL               string
	tokenURL              string
	tokenHTTPMethod       string
	getTokenFunction      *func() (*Token, *errortools.Error)
	newTokenFunction      *func() (*Token, *errortools.Error)
	saveTokenFunction     *func(token *Token) *errortools.Error
	token                 *Token
	locationUTC           *time.Location
	maxRetries            uint
	secondsBetweenRetries uint32
}

type OAuth2Config struct {
	//APIName               string
	ClientID              string
	ClientSecret          string
	Scope                 string
	RedirectURL           string
	AuthURL               string
	TokenURL              string
	TokenHTTPMethod       string
	GetTokenFunction      *func() (*Token, *errortools.Error)
	NewTokenFunction      *func() (*Token, *errortools.Error)
	SaveTokenFunction     *func(token *Token) *errortools.Error
	MaxRetries            *uint
	SecondsBetweenRetries *uint32
}

type ApiError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func NewOAuth(config OAuth2Config) *OAuth2 {
	oa := new(OAuth2)
	//oa.apiName = config.APIName
	oa.clientID = config.ClientID
	oa.clientSecret = config.ClientSecret
	oa.scope = config.Scope
	oa.redirectURL = config.RedirectURL
	oa.authURL = config.AuthURL
	oa.tokenURL = config.TokenURL
	oa.tokenHTTPMethod = config.TokenHTTPMethod
	oa.getTokenFunction = config.GetTokenFunction
	oa.newTokenFunction = config.NewTokenFunction
	oa.saveTokenFunction = config.SaveTokenFunction
	locUTC, _ := time.LoadLocation("UTC")
	oa.locationUTC = locUTC

	if config.MaxRetries != nil {
		oa.maxRetries = *config.MaxRetries
	} else {
		oa.maxRetries = 0
	}

	if config.SecondsBetweenRetries != nil {
		oa.secondsBetweenRetries = *config.SecondsBetweenRetries
	} else {
		oa.secondsBetweenRetries = 3
	}

	return oa
}

func (oa *OAuth2) lockToken() {
	tokenMutex.Lock()
}

func (oa *OAuth2) getToken(params *url.Values) *errortools.Error {
	request := new(http.Request)

	fmt.Println(oa.tokenHTTPMethod)

	e := new(errortools.Error)

	if oa.tokenHTTPMethod == http.MethodGet {
		url := oa.tokenURL

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

	e = oa.setToken(&token)
	if e != nil {
		return e
	}

	if oa.saveTokenFunction != nil {
		e = (*oa.saveTokenFunction)(&token)
		if e != nil {
			return e
		}
	}

	/*
		ee = oa.saveTokenToBigQuery()
		if ee != nil {
			return ee
		}*/

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

	return oa.getToken(&data)
}

func (oa *OAuth2) getTokenFromRefreshToken() *errortools.Error {
	fmt.Println("***getTokenFromRefreshToken***")

	//always get refresh token from BQ prior to using it
	if oa.getTokenFunction != nil {
		// retrieve AccessCode from BigQuery
		token, e := (*oa.getTokenFunction)()
		if e != nil {
			return e
		}

		oa.token = token
	}

	if !oa.token.hasRefreshToken() {
		return oa.initTokenNeeded()
	}

	data := url.Values{}
	data.Set("client_id", oa.clientID)
	data.Set("client_secret", oa.clientSecret)
	data.Set("refresh_token", *((*oa.token).RefreshToken))
	data.Set("grant_type", "refresh_token")

	return oa.getToken(&data)
}

// ValidateToken validates current token and retrieves a new one if necessary
//
func (oa *OAuth2) ValidateToken() (*Token, *errortools.Error) {
	oa.lockToken()
	defer oa.unlockToken()

	if !oa.token.hasAccessToken() {
		if oa.getTokenFunction != nil {
			// retrieve AccessCode from BigQuery
			token, e := (*oa.getTokenFunction)()
			if e != nil {
				return nil, e
			}

			oa.token = token
		}

		/*e := oa.getTokenFromBigQuery()
		if e != nil {
			return nil, e
		}*/
	}

	// token should be valid at least one minute from now (te be sure)
	atTimeUTC := time.Now().In(oa.locationUTC).Add(60 * time.Second)

	if oa.token.hasValidAccessToken(atTimeUTC) {
		return oa.token, nil
	}

	if oa.token.hasRefreshToken() {
		e := oa.getTokenFromRefreshToken()
		if e != nil {
			return nil, e
		}

		if oa.token.hasValidAccessToken(atTimeUTC) {
			return oa.token, nil
		}
	}

	if oa.newTokenFunction != nil {
		e := oa.getNewTokenFromFunction()
		if e != nil {
			return nil, e
		} else {
			return oa.token, nil
		}
	}

	return nil, oa.initTokenNeeded()
}

func (oa *OAuth2) initTokenNeeded() *errortools.Error {
	message := fmt.Sprintf("No valid accesscode or refreshcode found. Please generate new token by running command:\noauth2_token.exe %s", oa.clientID)
	fmt.Println(message)

	return errortools.ErrorMessage(message)
}

func (oa *OAuth2) InitToken() *errortools.Error {
	if oa == nil {
		return errortools.ErrorMessage("OAuth2 variable is nil pointer")
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

func (oa *OAuth2) getNewTokenFromFunction() *errortools.Error {
	fmt.Println("***getNewTokenFromFunction***")

	if oa.newTokenFunction == nil {
		return errortools.ErrorMessage("No NewTokenFunction defined.")
	}

	token, e := (*oa.newTokenFunction)()
	if e != nil {
		return e
	}

	e = oa.setToken(token)
	if e != nil {
		return e
	}

	if oa.saveTokenFunction != nil {
		e = (*oa.saveTokenFunction)(token)
		if e != nil {
			return e
		}
	}
	/*
		ee = oa.saveTokenToBigQuery()
		if ee != nil {
			return ee
		}*/

	return nil
}
