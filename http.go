package oauth2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	errortools "github.com/leapforce-libraries/go_errortools"
)

// Get returns http.Response for generic oAuth2 Get http call
//
func (oa *OAuth2) Get(url string, model interface{}) (*http.Request, *http.Response, *errortools.Error) {
	//fmt.Println("GET ", url)
	return oa.httpRequest(http.MethodGet, url, nil, model)
}

// Post returns http.Response for generic oAuth2 Post http call
//
func (oa *OAuth2) Post(url string, buf *bytes.Buffer, model interface{}) (*http.Request, *http.Response, *errortools.Error) {
	//fmt.Println("POST ", url)
	if buf == nil {
		return oa.httpRequest(http.MethodPost, url, nil, model)
	}
	return oa.httpRequest(http.MethodPost, url, buf, model)
}

// Put returns http.Response for generic oAuth2 Put http call
//
func (oa *OAuth2) Put(url string, buf *bytes.Buffer, model interface{}) (*http.Request, *http.Response, *errortools.Error) {
	//fmt.Println("PUT ", url)
	if buf == nil {
		return oa.httpRequest(http.MethodPut, url, nil, model)
	}
	return oa.httpRequest(http.MethodPut, url, buf, model)
}

// Patch returns http.Response for generic oAuth2 Patch http call
//
func (oa *OAuth2) Patch(url string, buf *bytes.Buffer, model interface{}) (*http.Request, *http.Response, *errortools.Error) {
	//fmt.Println("PATCH ", url)
	if buf == nil {
		return oa.httpRequest(http.MethodPatch, url, nil, model)
	}
	return oa.httpRequest(http.MethodPatch, url, buf, model)
}

// Delete returns http.Response for generic oAuth2 Delete http call
//
func (oa *OAuth2) Delete(url string, buf *bytes.Buffer, model interface{}) (*http.Request, *http.Response, *errortools.Error) {
	//fmt.Println("DELETE ", url)
	if buf == nil {
		return oa.httpRequest(http.MethodDelete, url, nil, model)
	}
	return oa.httpRequest(http.MethodDelete, url, buf, model)
}

func (oa *OAuth2) getHTTPClient() (*http.Client, *errortools.Error) {
	_, err := oa.ValidateToken()
	if err != nil {
		return nil, errortools.ErrorMessage(err)
	}

	return new(http.Client), nil
}

func (oa *OAuth2) httpRequest(httpMethod string, url string, body io.Reader, model interface{}) (*http.Request, *http.Response, *errortools.Error) {
	client, e := oa.getHTTPClient()
	if e != nil {
		return nil, nil, e
	}

	e = new(errortools.Error)

	request, err := http.NewRequest(httpMethod, url, body)
	e.SetRequest(request)
	if err != nil {
		return request, nil, errortools.ErrorMessage(err)
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
	response, err := client.Do(request)
	e.SetResponse(response)

	oa.unlockToken()

	// Check HTTP StatusCode
	if response.StatusCode < 200 || response.StatusCode > 299 {
		fmt.Println(fmt.Sprintf("ERROR in %s", httpMethod))
		fmt.Println("url", url)
		fmt.Println("StatusCode", response.StatusCode)
		fmt.Println(accessToken)
		//return nil, oa.printError(response)

		e.SetMessage(fmt.Sprintf("Server returned statuscode %v", response.StatusCode))
		return request, response, e
	}
	if err != nil {
		e.SetMessage(err)
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
