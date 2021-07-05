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
	go_http "github.com/leapforce-libraries/go_http"
)

type Service struct {
	clientID          string
	clientSecret      string
	redirectURL       string
	authURL           string
	tokenURL          string
	tokenHTTPMethod   string
	getTokenFunction  *func() (*Token, *errortools.Error)
	newTokenFunction  *func() (*Token, *errortools.Error)
	saveTokenFunction *func(token *Token) *errortools.Error
	token             *Token
	locationUTC       *time.Location
	httpService       *go_http.Service
}

type ServiceConfig struct {
	ClientID          string
	ClientSecret      string
	RedirectURL       string
	AuthURL           string
	TokenURL          string
	TokenHTTPMethod   string
	GetTokenFunction  *func() (*Token, *errortools.Error)
	NewTokenFunction  *func() (*Token, *errortools.Error)
	SaveTokenFunction *func(token *Token) *errortools.Error
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

	return &Service{
		clientID:          serviceConfig.ClientID,
		clientSecret:      serviceConfig.ClientSecret,
		redirectURL:       serviceConfig.RedirectURL,
		authURL:           serviceConfig.AuthURL,
		tokenURL:          serviceConfig.TokenURL,
		tokenHTTPMethod:   serviceConfig.TokenHTTPMethod,
		getTokenFunction:  serviceConfig.GetTokenFunction,
		newTokenFunction:  serviceConfig.NewTokenFunction,
		saveTokenFunction: serviceConfig.SaveTokenFunction,
		locationUTC:       locUTC,
		httpService:       httpService,
	}, nil
}

func (*Service) lockToken() {
	tokenMutex.Lock()
}

func (*Service) unlockToken() {
	tokenMutex.Unlock()
}

func (service *Service) getToken(params *url.Values) *errortools.Error {
	request := new(http.Request)

	fmt.Println(service.tokenHTTPMethod)

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

	if res.StatusCode < 200 || res.StatusCode > 299 {
		eoError := ApiError{}

		err = json.Unmarshal(b, &eoError)
		if err != nil {
			e.SetMessage(err)
			return e
		}

		//message := fmt.Sprintln("Error:", res.StatusCode, eoError.Error, ", ", eoError.Description)
		//fmt.Println(message)

		service.token.Print()

		if res.StatusCode == 401 {
			return service.initTokenNeeded()
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

	e = service.setToken(&token)
	if e != nil {
		return e
	}

	if service.saveTokenFunction != nil {
		e = (*service.saveTokenFunction)(&token)
		if e != nil {
			return e
		}
	}

	/*
		ee = service.saveTokenToBigQuery()
		if ee != nil {
			return ee
		}*/

	return nil
}

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
}

func (service *Service) getTokenFromCode(code string) *errortools.Error {
	data := url.Values{}
	data.Set("client_id", service.clientID)
	data.Set("client_secret", service.clientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", service.redirectURL)

	return service.getToken(&data)
}

func (service *Service) getTokenFromRefreshToken() *errortools.Error {
	fmt.Println("***getTokenFromRefreshToken***")

	//always get refresh token from BQ prior to using it
	if service.getTokenFunction != nil {
		// retrieve AccessCode from BigQuery
		token, e := (*service.getTokenFunction)()
		if e != nil {
			return e
		}

		service.token = token

		service.token.Print()
	}

	if !service.token.hasRefreshToken() {
		return service.initTokenNeeded()
	}

	data := url.Values{}
	data.Set("client_id", service.clientID)
	data.Set("client_secret", service.clientSecret)
	data.Set("refresh_token", *((*service.token).RefreshToken))
	data.Set("grant_type", "refresh_token")

	return service.getToken(&data)
}

// ValidateToken validates current token and retrieves a new one if necessary
//
func (service *Service) ValidateToken() (*Token, *errortools.Error) {
	service.lockToken()
	defer service.unlockToken()

	if !service.token.hasAccessToken() {
		if service.getTokenFunction != nil {
			// retrieve AccessCode from BigQuery
			token, e := (*service.getTokenFunction)()
			if e != nil {
				return nil, e
			}

			service.token = token
		}

		/*e := service.getTokenFromBigQuery()
		if e != nil {
			return nil, e
		}*/
	}

	// token should be valid at least one minute from now (te be sure)
	atTimeUTC := time.Now().In(service.locationUTC).Add(60 * time.Second)

	if service.token.hasValidAccessToken(atTimeUTC) {
		return service.token, nil
	}

	if service.token.hasRefreshToken() {
		e := service.getTokenFromRefreshToken()
		if e != nil {
			return nil, e
		}

		if service.token.hasValidAccessToken(atTimeUTC) {
			return service.token, nil
		}
	}

	if service.newTokenFunction != nil {
		e := service.getNewTokenFromFunction()
		if e != nil {
			return nil, e
		} else {
			return service.token, nil
		}
	}

	return nil, service.initTokenNeeded()
}

func (service *Service) initTokenNeeded() *errortools.Error {
	return errortools.ErrorMessage("No valid accesscode or refreshcode found. Please reconnect.")
}

func (service *Service) GetToken() *Token {
	return service.token
}

func (service *Service) SetToken(token *Token) {
	service.token = token
}

func (service *Service) InitToken(scope string, accessType *string, prompt *string, state *string) *errortools.Error {
	if service == nil {
		return errortools.ErrorMessage("Service variable is nil pointer")
	}

	fmt.Println("Go to this url to get new access token:")
	fmt.Println()
	fmt.Println(service.AuthorizeURL(scope, accessType, prompt, state))
	fmt.Println()

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

		e := service.getTokenFromCode(code)
		if e != nil {
			fmt.Println(e)
		}

		w.WriteHeader(http.StatusFound)
	})

	http.ListenAndServe(":8080", nil)

	return nil
}

func (service *Service) getNewTokenFromFunction() *errortools.Error {
	fmt.Println("***getNewTokenFromFunction***")

	if service.newTokenFunction == nil {
		return errortools.ErrorMessage("No NewTokenFunction defined.")
	}

	token, e := (*service.newTokenFunction)()
	if e != nil {
		return e
	}

	e = service.setToken(token)
	if e != nil {
		return e
	}

	if service.saveTokenFunction != nil {
		e = (*service.saveTokenFunction)(token)
		if e != nil {
			return e
		}
	}
	/*
		ee = service.saveTokenToBigQuery()
		if ee != nil {
			return ee
		}*/

	return nil
}

// Get returns http.Response for generic oAuth2 Get http call
//
func (service *Service) Get(requestConfig *go_http.RequestConfig) (*http.Request, *http.Response, *errortools.Error) {
	return service.httpRequest(http.MethodGet, requestConfig, false)
}

// Post returns http.Response for generic oAuth2 Post http call
//
func (service *Service) Post(requestConfig *go_http.RequestConfig) (*http.Request, *http.Response, *errortools.Error) {
	return service.httpRequest(http.MethodPost, requestConfig, false)
}

// Put returns http.Response for generic oAuth2 Put http call
//
func (service *Service) Put(requestConfig *go_http.RequestConfig) (*http.Request, *http.Response, *errortools.Error) {
	return service.httpRequest(http.MethodPut, requestConfig, false)
}

// Patch returns http.Response for generic oAuth2 Patch http call
//
func (service *Service) Patch(requestConfig *go_http.RequestConfig) (*http.Request, *http.Response, *errortools.Error) {
	return service.httpRequest(http.MethodPatch, requestConfig, false)
}

// Delete returns http.Response for generic oAuth2 Delete http call
//
func (service *Service) Delete(requestConfig *go_http.RequestConfig) (*http.Request, *http.Response, *errortools.Error) {
	return service.httpRequest(http.MethodDelete, requestConfig, false)
}

// HTTPRequest returns http.Response for generic oAuth2 http call
//
func (service *Service) HTTPRequest(httpMethod string, requestConfig *go_http.RequestConfig, skipAccessToken bool) (*http.Request, *http.Response, *errortools.Error) {
	return service.httpRequest(httpMethod, requestConfig, skipAccessToken)
}

// httpRequest returns http.Response for generic oAuth2 http call
//
func (service *Service) httpRequest(httpMethod string, requestConfig *go_http.RequestConfig, skipAccessToken bool) (*http.Request, *http.Response, *errortools.Error) {
	// Authorization header
	if !skipAccessToken {

		_, e := service.ValidateToken()
		if e != nil {
			return nil, nil, e
		}

		if service.token == nil {
			e.SetMessage("No Token.")
			return nil, nil, e
		}

		if (*service.token).AccessToken == nil {
			e.SetMessage("No AccessToken.")
			return nil, nil, e
		}

		header := http.Header{}
		if requestConfig.NonDefaultHeaders != nil {
			header = *requestConfig.NonDefaultHeaders
		}
		header.Set("Authorization", fmt.Sprintf("Bearer %s", *((*service.token).AccessToken)))
		requestConfig.NonDefaultHeaders = &header
	}

	return service.httpService.HTTPRequest(httpMethod, requestConfig)
}

func (service *Service) APICallCount() int64 {
	return service.httpService.RequestCount()
}

func (service Service) APIReset() {
	service.httpService.ResetRequestCount()
}
