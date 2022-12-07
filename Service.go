package oauth2

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	errortools "github.com/leapforce-libraries/go_errortools"
	go_http "github.com/leapforce-libraries/go_http"
	go_token "github.com/leapforce-libraries/go_oauth2/token"
	tokensource "github.com/leapforce-libraries/go_oauth2/tokensource"
)

const defaultRefreshMargin time.Duration = time.Minute
const defaultClientIdName string = "client_id"

var tokenMutex sync.Mutex

type Service struct {
	clientId        string
	clientSecret    string
	redirectUrl     string
	authUrl         string
	tokenUrl        string
	tokenHttpMethod string
	refreshMargin   time.Duration // refresh at earliest {RefreshMargin} before expiry
	tokenSource     tokensource.TokenSource
	locationUTC     *time.Location
	httpService     *go_http.Service
	clientIdName    string
}

type ServiceConfig struct {
	ClientId        string
	ClientSecret    string
	RedirectUrl     string
	AuthUrl         string
	TokenUrl        string
	TokenHttpMethod string
	RefreshMargin   *time.Duration
	TokenSource     tokensource.TokenSource
	ClientIdName    *string
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

	cn := defaultClientIdName
	if serviceConfig.ClientIdName != nil {
		cn = *serviceConfig.ClientIdName
	}
	return &Service{
		clientId:        serviceConfig.ClientId,
		clientSecret:    serviceConfig.ClientSecret,
		redirectUrl:     serviceConfig.RedirectUrl,
		authUrl:         serviceConfig.AuthUrl,
		tokenUrl:        serviceConfig.TokenUrl,
		refreshMargin:   refreshMargin,
		tokenHttpMethod: serviceConfig.TokenHttpMethod,
		tokenSource:     serviceConfig.TokenSource,
		locationUTC:     locUTC,
		httpService:     httpService,
		clientIdName:    cn,
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

	if service.tokenHttpMethod == http.MethodGet {
		url := service.tokenUrl

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
	} else if service.tokenHttpMethod == http.MethodPost {

		encoded := ""
		body := new(strings.Reader)
		if params != nil {
			encoded = params.Encode()
			body = strings.NewReader(encoded)
		}

		req, err := http.NewRequest(http.MethodPost, service.tokenUrl, body)
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
		e.SetMessage(fmt.Sprintf("Invalid TokenHttpMethod: %s", service.tokenHttpMethod))
		return e
	}

	httpClient := http.Client{}

	// Send out the Http request
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

	token, e := service.tokenSource.UnmarshalToken(b)
	if e != nil {
		return e
	}

	e = service.parseExpireIn(token)
	if e != nil {
		return e
	}

	e = service.tokenSource.SetToken(token, true)
	if e != nil {
		return e
	}

	return nil
}

func (service *Service) GetTokenFromCode(r *http.Request, checkState *func(state string) *errortools.Error) *errortools.Error {
	err := r.ParseForm()
	if err != nil {
		return errortools.ErrorMessage(err)
	}
	code := r.FormValue("code")

	if checkState != nil {
		state := r.FormValue("state")
		if state == "" {
			return errortools.ErrorMessage("No state returned")
		}

		e := (*checkState)(state)
		if e != nil {
			return e
		}
	}

	data := url.Values{}
	data.Set(service.clientIdName, service.clientId)
	data.Set("client_secret", service.clientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", service.redirectUrl)

	return service.getToken(&data)
}

// ValidateToken validates current token and retrieves a new one if necessary
//
func (service *Service) ValidateToken() (*go_token.Token, *errortools.Error) {
	service.lockToken()
	defer service.unlockToken()

	if service.tokenSource.Token() == nil {
		// retrieve used token
		e := service.tokenSource.RetrieveToken()
		if e != nil {
			return nil, e
		}
	}

	if service.tokenSource.Token() == nil {
		// retrieve new token from source
		e := service.newToken()
		if e != nil {
			return nil, e
		}
	}

	if service.tokenSource.Token() == nil {
		return nil, errortools.ErrorMessage("Unable to retrieve token")
	}

	// check existence of accesstoken
	if !service.tokenSource.Token().HasAccessToken() {
		// re-retrieve used token
		e := service.tokenSource.RetrieveToken()
		if e != nil {
			return nil, e
		}

		if !service.tokenSource.Token().HasAccessToken() {
			// stop if no access token found
			return nil, errortools.ErrorMessage("Token has no accesscode")
		}
	}

	// token should be valid at least one minute from now (te be sure)
	atTimeUTC := time.Now().In(service.locationUTC).Add(service.refreshMargin)

	if service.tokenSource.Token().HasValidAccessToken(atTimeUTC) {
		return service.tokenSource.Token(), nil
	}

	if service.tokenSource.Token().HasRefreshToken() {
		// refresh access token
		data := url.Values{}
		data.Set(service.clientIdName, service.clientId)
		data.Set("client_secret", service.clientSecret)
		data.Set("refresh_token", *(*service.tokenSource.Token()).RefreshToken)
		data.Set("grant_type", "refresh_token")

		e := service.getToken(&data)
		if e != nil {
			return nil, e
		}
	} else {
		// retrieve new token from source
		e := service.newToken()
		if e != nil {
			return nil, e
		}
	}

	if service.tokenSource.Token().HasValidAccessToken(atTimeUTC) {
		return service.tokenSource.Token(), nil
	}

	return nil, service.initTokenNeeded()
}

func (service *Service) newToken() *errortools.Error {
	// retrieve new token from source
	token, e := service.tokenSource.NewToken()
	if e != nil {
		return e
	}

	e = service.parseExpireIn(token)
	if e != nil {
		return e
	}

	token.Print()

	e = service.tokenSource.SetToken(token, true)
	if e != nil {
		return e
	}

	return nil
}

func (service *Service) parseExpireIn(t *go_token.Token) *errortools.Error {
	if t == nil {
		return nil
	}

	if t.ExpiresIn != nil {
		var expiresInInt int64
		var expiresInString string
		err := json.Unmarshal(*t.ExpiresIn, &expiresInInt)
		if err != nil {
			err = json.Unmarshal(*t.ExpiresIn, &expiresInString)

			if err == nil {
				expiresInInt, err = strconv.ParseInt(expiresInString, 10, 64)
			}
		}

		if err != nil {
			return errortools.ErrorMessage(fmt.Sprintf("Cannot convert ExpiresIn %s to Int64.", fmt.Sprintf("%v", *t.ExpiresIn)))
		}

		//convert to UTC
		expiry := time.Now().Add(time.Duration(expiresInInt) * time.Second).In(service.locationUTC)
		(*t).Expiry = &expiry
	} else {
		(*t).Expiry = nil
	}

	return nil
}

func (service *Service) initTokenNeeded() *errortools.Error {
	return errortools.ErrorMessage("No valid accesscode or refreshcode found. Please reconnect.")
}

func (service *Service) AuthorizeUrl(scope string, accessType *string, prompt *string, state *string) string {
	params := url.Values{}
	params.Set("redirect_uri", service.redirectUrl)
	params.Set(service.clientIdName, service.clientId)
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

	return fmt.Sprintf("%s?%s", service.authUrl, params.Encode())
}

/*
func (service *Service) InitToken(scope string, accessType *string, prompt *string, state *string) *errortools.Error {
	if service == nil {
		return errortools.ErrorMessage("Service variable is nil pointer")
	}

	fmt.Println("Go to this url to get new access token:")
	fmt.Println()
	fmt.Println(service.AuthorizeUrl(scope, accessType, prompt, state))
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
}*/

// HttpRequest returns http.Response for generic oAuth2 http call
//
func (service *Service) HttpRequest(requestConfig *go_http.RequestConfig) (*http.Request, *http.Response, *errortools.Error) {
	return service.httpRequest(requestConfig, false)
}

func (service *Service) HttpRequestWithoutAccessToken(requestConfig *go_http.RequestConfig) (*http.Request, *http.Response, *errortools.Error) {
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

		header := http.Header{}
		if requestConfig.NonDefaultHeaders != nil {
			header = *requestConfig.NonDefaultHeaders
		}
		header.Set("Authorization", fmt.Sprintf("Bearer %s", *(service.tokenSource.Token().AccessToken)))
		requestConfig.NonDefaultHeaders = &header
	}

	return service.httpService.HttpRequest(requestConfig)
}

func (service *Service) ApiCallCount() int64 {
	return service.httpService.RequestCount()
}

func (service Service) ApiReset() {
	service.httpService.ResetRequestCount()
}
