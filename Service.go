package oauth2

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	errortools "github.com/leapforce-libraries/go_errortools"
	go_http "github.com/leapforce-libraries/go_http"
)

const defaultRefreshMargin time.Duration = time.Minute

type Service struct {
	clientID        string
	clientSecret    string
	redirectURL     string
	authURL         string
	tokenURL        string
	tokenHTTPMethod string
	refreshMargin   time.Duration // refresh at earliest {RefreshMargin} before expiry
	tokenSource     TokenSource
	//getTokenFunction  *func() (*Token, *errortools.Error)
	//newTokenFunction  *func() (*Token, *errortools.Error)
	//saveTokenFunction *func(token *Token) *errortools.Error
	//token       *Token
	locationUTC *time.Location
	httpService *go_http.Service
}

type ServiceConfig struct {
	ClientID        string
	ClientSecret    string
	RedirectURL     string
	AuthURL         string
	TokenURL        string
	TokenHTTPMethod string
	RefreshMargin   *time.Duration
	TokenSource     TokenSource
	//GetTokenFunction  *func() (*Token, *errortools.Error)
	//NewTokenFunction  *func() (*Token, *errortools.Error)
	//SaveTokenFunction *func(token *Token) *errortools.Error
}

type ApiError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func NewService(serviceConfig *ServiceConfig) (*Service, *errortools.Error) {
	if serviceConfig == nil {
		return nil, errortools.ErrorMessage("ServiceConfig must not be a nil pointer")
	}

	locUTC, _ := time.LoadLocation("UTC")

	httpService, e := go_http.NewService(&go_http.ServiceConfig{})
	if e != nil {
		return nil, e
	}

	refreshMargin := defaultRefreshMargin
	if serviceConfig.RefreshMargin != nil {
		refreshMargin = *serviceConfig.RefreshMargin
	}

	return &Service{
		clientID:        serviceConfig.ClientID,
		clientSecret:    serviceConfig.ClientSecret,
		redirectURL:     serviceConfig.RedirectURL,
		authURL:         serviceConfig.AuthURL,
		tokenURL:        serviceConfig.TokenURL,
		refreshMargin:   refreshMargin,
		tokenHTTPMethod: serviceConfig.TokenHTTPMethod,
		tokenSource:     serviceConfig.TokenSource,
		//getTokenFunction:  serviceConfig.GetTokenFunction,
		//newTokenFunction:  serviceConfig.NewTokenFunction,
		//saveTokenFunction: serviceConfig.SaveTokenFunction,
		locationUTC: locUTC,
		httpService: httpService,
	}, nil
}

func (*Service) lockToken() {
	tokenMutex.Lock()
}

func (*Service) unlockToken() {
	tokenMutex.Unlock()
}

func (service *Service) getToken(params *url.Values) *errortools.Error {
	var request *http.Request = nil

	e := new(errortools.Error)

	if service.tokenHTTPMethod == http.MethodGet {
		url := service.tokenURL

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
	} else if service.tokenHTTPMethod == http.MethodPost {

		encoded := ""
		body := new(strings.Reader)
		if params != nil {
			encoded = params.Encode()
			body = strings.NewReader(encoded)
		}

		req, err := http.NewRequest(http.MethodPost, service.tokenURL, body)
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
		e.SetMessage(fmt.Sprintf("Invalid TokenHTTPMethod: %s", service.tokenHTTPMethod))
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
	if err != nil {
		e.SetMessage(err)
		return e
	}

	if res.StatusCode < 200 || res.StatusCode > 299 {
		eoError := ApiError{}

		err = json.Unmarshal(b, &eoError)
		if err != nil {
			e.SetMessage(err)
			return e
		}

		if res.StatusCode == 401 {
			return service.initTokenNeeded()
		}

		fmt.Printf("ResponseBody: %s\n", string(b))
		e.SetMessage(fmt.Sprintf("Server returned statuscode %v, url: %s", res.StatusCode, request.URL))
		return e
	}

	token := Token{}

	err = json.Unmarshal(b, &token)
	if err != nil {
		e.SetMessage(err)
		return e
	}

	e = service.tokenSource.SetToken(&token, true)
	if e != nil {
		return e
	}

	return nil
}

/*
func (service *Service) setToken(token *Token) *errortools.Error {
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
			expiry := time.Now().Add(time.Duration(expiresInInt) * time.Second).In(service.locationUTC)
			token.Expiry = &expiry
		} else {
			token.Expiry = nil
		}
	}

	token.Print()

	service.token = token

	return nil
}*/

func (service *Service) GetTokenFromCode(r *http.Request) *errortools.Error {
	err := r.ParseForm()
	if err != nil {
		return errortools.ErrorMessage(err)
	}
	code := r.FormValue("code")

	data := url.Values{}
	data.Set("client_id", service.clientID)
	data.Set("client_secret", service.clientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", service.redirectURL)

	return service.getToken(&data)
}

func (service *Service) getTokenFromRefreshToken() *errortools.Error {
	e := service.tokenSource.RetrieveToken()
	if e != nil {
		return e
	}

	service.tokenSource.Token().Print()

	if !service.tokenSource.Token().hasRefreshToken() {
		return service.initTokenNeeded()
	}

	data := url.Values{}
	data.Set("client_id", service.clientID)
	data.Set("client_secret", service.clientSecret)
	data.Set("refresh_token", *(*service.tokenSource.Token()).RefreshToken)
	data.Set("grant_type", "refresh_token")

	return service.getToken(&data)
}

// ValidateToken validates current token and retrieves a new one if necessary
//
func (service *Service) ValidateToken() (*Token, *errortools.Error) {
	service.lockToken()
	defer service.unlockToken()

	if service.tokenSource.Token() == nil {
		e := service.tokenSource.RetrieveToken()
		if e != nil {
			return nil, e
		}

		if service.tokenSource.Token() == nil {
			return nil, errortools.ErrorMessage("Unable to retrieve token")
		}
	}

	if !service.tokenSource.Token().hasAccessToken() {
		e := service.tokenSource.RetrieveToken()
		if e != nil {
			return nil, e
		}

		if !service.tokenSource.Token().hasAccessToken() {
			return nil, errortools.ErrorMessage("Token has no accesscode")
		}
	}

	// token should be valid at least one minute from now (te be sure)
	atTimeUTC := time.Now().In(service.locationUTC).Add(service.refreshMargin)

	if service.tokenSource.Token().hasValidAccessToken(atTimeUTC) {
		return service.tokenSource.Token(), nil
	}

	if service.tokenSource.Token().hasRefreshToken() {
		e := service.getTokenFromRefreshToken()
		if e != nil {
			return nil, e
		}

		if service.tokenSource.Token().hasValidAccessToken(atTimeUTC) {
			return service.tokenSource.Token(), nil
		}
	}

	token, e := service.tokenSource.NewToken()
	if e != nil {
		return nil, e
	}
	if token == nil {
		return nil, service.initTokenNeeded()
	}

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
			return nil, errortools.ErrorMessage(fmt.Sprintf("Cannot convert ExpiresIn %s to Int64.", fmt.Sprintf("%v", *token.ExpiresIn)))
		}

		//convert to UTC
		expiry := time.Now().Add(time.Duration(expiresInInt) * time.Second).In(service.locationUTC)
		token.Expiry = &expiry
	} else {
		token.Expiry = nil
	}

	token.Print()

	e = service.tokenSource.SetToken(token, true)
	if e != nil {
		return nil, e
	}

	e = service.tokenSource.SaveToken()
	if e != nil {
		return nil, e
	}

	return service.tokenSource.Token(), nil
}

func (service *Service) initTokenNeeded() *errortools.Error {
	return errortools.ErrorMessage("No valid accesscode or refreshcode found. Please reconnect.")
}

/*
func (service *Service) GetToken() *Token {
	return service.token
}

func (service *Service) SetToken(token *Token) {
	service.token = token
}*/

func (service *Service) authorizeURL(scope string, accessType *string, prompt *string, state *string) string {
	params := url.Values{}
	params.Set("redirect_uri", service.redirectURL)
	params.Set("client_id", service.clientID)
	params.Set("response_type", "code")
	params.Set("scope", scope)

	if accessType != nil {
		params.Set("access_type", *accessType)
	}

	if prompt != nil {
		params.Set("prompt", *prompt)
	}

	if state != nil {
		params.Set("state", *state)
	}

	return fmt.Sprintf("%s?%s", service.authURL, params.Encode())
}

func (service *Service) InitToken(scope string, accessType *string, prompt *string, state *string) *errortools.Error {
	if service == nil {
		return errortools.ErrorMessage("Service variable is nil pointer")
	}

	fmt.Println("Go to this url to get new access token:")
	fmt.Println()
	fmt.Println(service.authorizeURL(scope, accessType, prompt, state))
	fmt.Println()

	// Create a new redirect route
	http.HandleFunc("/oauth/redirect", func(w http.ResponseWriter, r *http.Request) {
		//
		// get authorization code
		//
		e := service.GetTokenFromCode(r)
		if e != nil {
			errortools.CaptureError(e)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusFound)
	})

	http.ListenAndServe(":8080", nil)

	return nil
}

/*
func (service *Service) getNewTokenFromFunction() *errortools.Error {
	token, e := service.tokenSource.NewToken()
	if e != nil {
		return e
	}

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
			expiry := time.Now().Add(time.Duration(expiresInInt) * time.Second).In(service.locationUTC)
			token.Expiry = &expiry
		} else {
			token.Expiry = nil
		}
	}

	token.Print()

	e = service.tokenSource.SetToken(token)
	if e != nil {
		return e
	}

	e = service.tokenSource.SaveToken()
	if e != nil {
		return e
	}

	return nil
}*/

// HTTPRequest returns http.Response for generic oAuth2 http call
//
func (service *Service) HTTPRequest(requestConfig *go_http.RequestConfig) (*http.Request, *http.Response, *errortools.Error) {
	return service.httpRequest(requestConfig, false)
}

func (service *Service) HTTPRequestWithoutAccessToken(requestConfig *go_http.RequestConfig) (*http.Request, *http.Response, *errortools.Error) {
	return service.httpRequest(requestConfig, true)
}

// httpRequest returns http.Response for generic oAuth2 http call
//
func (service *Service) httpRequest(requestConfig *go_http.RequestConfig, skipAccessToken bool) (*http.Request, *http.Response, *errortools.Error) {
	// Authorization header
	if !skipAccessToken {

		_, e := service.ValidateToken()
		if e != nil {
			return nil, nil, e
		}
		/*
			if service.tokenSource.Token() == nil {
				e.SetMessage("No Token.")
				return nil, nil, e
			}

			if (*service.tokenSource.Token()).AccessToken == nil {
				e.SetMessage("No AccessToken.")
				return nil, nil, e
			}*/

		header := http.Header{}
		if requestConfig.NonDefaultHeaders != nil {
			header = *requestConfig.NonDefaultHeaders
		}
		header.Set("Authorization", fmt.Sprintf("Bearer %s", *(service.tokenSource.Token().AccessToken)))
		requestConfig.NonDefaultHeaders = &header
	}

	return service.httpService.HTTPRequest(requestConfig)
}

func (service *Service) APICallCount() int64 {
	return service.httpService.RequestCount()
}

func (service Service) APIReset() {
	service.httpService.ResetRequestCount()
}
