package oauth2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"reflect"

	errortools "github.com/leapforce-libraries/go_errortools"
	utilities "github.com/leapforce-libraries/go_utilities"
)

type RequestConfig struct {
	URL             string
	BodyModel       interface{}
	ResponseModel   interface{}
	ErrorModel      interface{}
	SkipAccessToken *bool
}

// Get returns http.Response for generic oAuth2 Get http call
//
func (oa *OAuth2) Get(config *RequestConfig) (*http.Request, *http.Response, *errortools.Error) {
	return oa.httpRequest(http.MethodGet, config)
}

// Post returns http.Response for generic oAuth2 Post http call
//
func (oa *OAuth2) Post(config *RequestConfig) (*http.Request, *http.Response, *errortools.Error) {
	return oa.httpRequest(http.MethodPost, config)
}

// Put returns http.Response for generic oAuth2 Put http call
//
func (oa *OAuth2) Put(config *RequestConfig) (*http.Request, *http.Response, *errortools.Error) {
	return oa.httpRequest(http.MethodPut, config)
}

// Patch returns http.Response for generic oAuth2 Patch http call
//
func (oa *OAuth2) Patch(config *RequestConfig) (*http.Request, *http.Response, *errortools.Error) {
	return oa.httpRequest(http.MethodPatch, config)
}

// Delete returns http.Response for generic oAuth2 Delete http call
//
func (oa *OAuth2) Delete(config *RequestConfig) (*http.Request, *http.Response, *errortools.Error) {
	return oa.httpRequest(http.MethodDelete, config)
}

// HTTP returns http.Response for generic oAuth2 http call
//
func (oa *OAuth2) HTTP(httpMethod string, config *RequestConfig) (*http.Request, *http.Response, *errortools.Error) {
	return oa.httpRequest(httpMethod, config)
}

func (oa *OAuth2) getHTTPClient() (*http.Client, *errortools.Error) {
	_, e := oa.ValidateToken()
	if e != nil {
		return nil, e
	}

	return new(http.Client), nil
}

func (oa *OAuth2) httpRequest(httpMethod string, config *RequestConfig) (*http.Request, *http.Response, *errortools.Error) {
	if config == nil {
		return nil, nil, errortools.ErrorMessage("Request config may not be a nil pointer.")
	}

	if utilities.IsNil(config.BodyModel) {
		return oa.httpRequestWithBuffer(httpMethod, config, nil)
	}

	b, err := json.Marshal(config.BodyModel)
	if err != nil {
		return nil, nil, errortools.ErrorMessage(err)
	}

	return oa.httpRequestWithBuffer(httpMethod, config, bytes.NewBuffer(b))
}

func (oa *OAuth2) httpRequestWithBuffer(httpMethod string, config *RequestConfig, body io.Reader) (*http.Request, *http.Response, *errortools.Error) {
	client, e := oa.getHTTPClient()
	if e != nil {
		return nil, nil, e
	}

	e = new(errortools.Error)

	request, err := http.NewRequest(httpMethod, config.URL, body)
	e.SetRequest(request)
	if err != nil {
		e.SetMessage(err)
		return request, nil, e
	}

	// default headers
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	// Authorization header
	accessToken := ""
	if config.SkipAccessToken != nil {
		if *config.SkipAccessToken == false {
			oa.lockToken()

			if oa.token == nil {
				e.SetMessage("No Token.")
				return request, nil, e
			}

			if (*oa.token).AccessToken == nil {
				e.SetMessage("No AccessToken.")
				return request, nil, e
			}

			accessToken = *((*oa.token).AccessToken)
			bearer := fmt.Sprintf("Bearer %s", accessToken)
			request.Header.Set("Authorization", bearer)
		}
	}

	// overrule with input headers
	if oa.nonDefaultHeaders != nil {
		for key, values := range *oa.nonDefaultHeaders {
			request.Header.Del(key) //delete old header
			for _, value := range values {
				request.Header.Add(key, value) //add new header(s)
			}
		}
	}

	// Send out the HTTP request
	response, e := utilities.DoWithRetry(client, request, oa.maxRetries, oa.secondsBetweenRetries)

	oa.unlockToken()

	if response != nil {
		// Check HTTP StatusCode
		if response.StatusCode < 200 || response.StatusCode > 299 {
			fmt.Println(fmt.Sprintf("ERROR in %s", httpMethod))
			fmt.Println("url", config.URL)
			fmt.Println("StatusCode", response.StatusCode)
			fmt.Println(accessToken)

			if e == nil {
				e = new(errortools.Error)
				e.SetRequest(request)
				e.SetResponse(response)
			}

			e.SetMessage(fmt.Sprintf("Server returned statuscode %v", response.StatusCode))
		}
	}

	if response.Body == nil {
		return request, response, e
	}

	if e != nil {
		if !utilities.IsNil(config.ErrorModel) {
			err := oa.unmarshalError(response, config.ErrorModel)
			errortools.CaptureInfo(err)
		}

		return request, response, e
	}

	if !utilities.IsNil(config.ResponseModel) {
		defer response.Body.Close()

		b, err := ioutil.ReadAll(response.Body)
		if err != nil {
			e.SetMessage(err)
			return request, response, e
		}

		err = json.Unmarshal(b, &config.ResponseModel)
		if err != nil {
			e.SetMessage(err)
			return request, response, e
		}
	}

	return request, response, nil
}

func (oa *OAuth2) unmarshalError(response *http.Response, errorModel interface{}) *errortools.Error {
	if response == nil {
		return nil
	}
	if reflect.TypeOf(errorModel).Kind() != reflect.Ptr {
		return errortools.ErrorMessage("Type of errorModel must be a pointer.")
	}
	if reflect.ValueOf(errorModel).IsNil() {
		return nil
	}

	defer response.Body.Close()

	b, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return errortools.ErrorMessage(err)
	}

	err = json.Unmarshal(b, &errorModel)
	if err != nil {
		return errortools.ErrorMessage(err)
	}

	return nil
}
