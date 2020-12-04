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

// Get returns http.Response for generic oAuth2 Get http call
//
func (oa *OAuth2) Get(url string, model interface{}, modelError interface{}) (*http.Request, *http.Response, *errortools.Error) {
	return oa.httpRequest(http.MethodGet, url, nil, model, modelError)
}

// Post returns http.Response for generic oAuth2 Post http call
//
func (oa *OAuth2) Post(url string, buf *bytes.Buffer, model interface{}, modelError interface{}) (*http.Request, *http.Response, *errortools.Error) {
	if buf == nil {
		return oa.httpRequest(http.MethodPost, url, nil, model, modelError)
	}
	return oa.httpRequest(http.MethodPost, url, buf, model, modelError)
}

// Put returns http.Response for generic oAuth2 Put http call
//
func (oa *OAuth2) Put(url string, buf *bytes.Buffer, model interface{}, modelError interface{}) (*http.Request, *http.Response, *errortools.Error) {
	if buf == nil {
		return oa.httpRequest(http.MethodPut, url, nil, model, modelError)
	}
	return oa.httpRequest(http.MethodPut, url, buf, model, modelError)
}

// Patch returns http.Response for generic oAuth2 Patch http call
//
func (oa *OAuth2) Patch(url string, buf *bytes.Buffer, model interface{}, modelError interface{}) (*http.Request, *http.Response, *errortools.Error) {
	if buf == nil {
		return oa.httpRequest(http.MethodPatch, url, nil, model, modelError)
	}
	return oa.httpRequest(http.MethodPatch, url, buf, model, modelError)
}

// Delete returns http.Response for generic oAuth2 Delete http call
//
func (oa *OAuth2) Delete(url string, buf *bytes.Buffer, model interface{}, modelError interface{}) (*http.Request, *http.Response, *errortools.Error) {
	if buf == nil {
		return oa.httpRequest(http.MethodDelete, url, nil, model, modelError)
	}
	return oa.httpRequest(http.MethodDelete, url, buf, model, modelError)
}

func (oa *OAuth2) getHTTPClient() (*http.Client, *errortools.Error) {
	_, err := oa.ValidateToken()
	if err != nil {
		return nil, errortools.ErrorMessage(err)
	}

	return new(http.Client), nil
}

func (oa *OAuth2) httpRequest(httpMethod string, url string, body io.Reader, model interface{}, modelError interface{}) (*http.Request, *http.Response, *errortools.Error) {
	client, e := oa.getHTTPClient()
	if e != nil {
		return nil, nil, e
	}

	e = new(errortools.Error)

	request, err := http.NewRequest(httpMethod, url, body)
	e.SetRequest(request)
	if err != nil {
		e.SetMessage(err)
		return request, nil, e
	}

	oa.lockToken()

	if oa.token == nil {
		e.SetMessage("No Token.")
		return request, nil, e
	}

	if (*oa.token).AccessToken == nil {
		e.SetMessage("No AccessToken.")
		return request, nil, e
	}

	accessToken := *((*oa.token).AccessToken)

	// Add authorization token to header
	bearer := fmt.Sprintf("Bearer %s", accessToken)
	request.Header.Add("Authorization", bearer)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	// Send out the HTTP request
	response, e := utilities.DoWithRetry(client, request, oa.maxRetries, oa.secondsBetweenRetries)

	oa.unlockToken()

	if response != nil {
		// Check HTTP StatusCode
		if response.StatusCode < 200 || response.StatusCode > 299 {
			fmt.Println(fmt.Sprintf("ERROR in %s", httpMethod))
			fmt.Println("url", url)
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

	if e != nil {
		err2 := unmarshalError(response, modelError)
		errortools.CaptureInfo(err2)

		return request, response, e
	}

	if model != nil {
		defer response.Body.Close()

		b, err := ioutil.ReadAll(response.Body)
		if err != nil {
			e.SetMessage(err)
			return request, response, e
		}

		err = json.Unmarshal(b, &model)
		if err != nil {
			e.SetMessage(err)
			return request, response, e
		}
	}

	return request, response, nil
}

func unmarshalError(response *http.Response, modelError interface{}) *errortools.Error {
	if response == nil {
		return nil
	}
	if reflect.TypeOf(modelError).Kind() != reflect.Ptr {
		return errortools.ErrorMessage("Type of modelError must be a pointer.")
	}
	if reflect.ValueOf(modelError).IsNil() {
		return nil
	}

	defer response.Body.Close()

	b, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return errortools.ErrorMessage(err)
	}

	err = json.Unmarshal(b, &modelError)
	if err != nil {
		return errortools.ErrorMessage(err)
	}

	return nil
}
