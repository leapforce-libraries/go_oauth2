package oauth2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	types "github.com/Leapforce-nl/go_types"
)

// Get returns http.Response for generic oAuth2 Get http call
//
func (oa *OAuth2) Get(url string, model interface{}) (*http.Response, error) {
	//fmt.Println("GET ", url)
	return oa.httpRequest(http.MethodGet, url, nil, model)
}

// Post returns http.Response for generic oAuth2 Post http call
//
func (oa *OAuth2) Post(url string, buf *bytes.Buffer, model interface{}) (*http.Response, error) {
	//fmt.Println("POST ", url)
	if buf == nil {
		return oa.httpRequest(http.MethodPost, url, nil, model)
	} else {
		return oa.httpRequest(http.MethodPost, url, buf, model)
	}
}

// Put returns http.Response for generic oAuth2 Put http call
//
func (oa *OAuth2) Put(url string, buf *bytes.Buffer, model interface{}) (*http.Response, error) {
	//fmt.Println("PUT ", url)
	if buf == nil {
		return oa.httpRequest(http.MethodPut, url, nil, model)
	} else {
		return oa.httpRequest(http.MethodPut, url, buf, model)
	}
}

// Patch returns http.Response for generic oAuth2 Patch http call
//
func (oa *OAuth2) Patch(url string, buf *bytes.Buffer, model interface{}) (*http.Response, error) {
	//fmt.Println("PATCH ", url)
	if buf == nil {
		return oa.httpRequest(http.MethodPatch, url, nil, model)
	} else {
		return oa.httpRequest(http.MethodPatch, url, buf, model)
	}
}

// Delete returns http.Response for generic oAuth2 Delete http call
//
func (oa *OAuth2) Delete(url string, buf *bytes.Buffer, model interface{}) (*http.Response, error) {
	//fmt.Println("DELETE ", url)
	if buf == nil {
		return oa.httpRequest(http.MethodDelete, url, nil, model)
	} else {
		return oa.httpRequest(http.MethodDelete, url, buf, model)
	}
}

func (oa *OAuth2) getHTTPClient() (*http.Client, error) {
	_, err := oa.ValidateToken()
	if err != nil {
		return nil, err
	}

	return new(http.Client), nil
}

func (oa *OAuth2) httpRequest(httpMethod string, url string, body io.Reader, model interface{}) (*http.Response, error) {
	client, err := oa.getHTTPClient()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(httpMethod, url, body)
	if err != nil {
		return nil, err
	}

	oa.lockToken()

	if oa.token == nil {
		return nil, &types.ErrorString{"No Token."}
	}

	if (*oa.token).AccessToken == nil {
		return nil, &types.ErrorString{"No AccessToken."}
	}

	accessToken := *((*oa.token).AccessToken)

	// Add authorization token to header
	bearer := fmt.Sprintf("Bearer %s", accessToken)
	req.Header.Add("Authorization", bearer)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Send out the HTTP request
	response, err := client.Do(req)

	oa.unlockToken()

	// Check HTTP StatusCode
	if response.StatusCode < 200 || response.StatusCode > 299 {
		fmt.Println(fmt.Sprintf("ERROR in %s", httpMethod))
		fmt.Println("url", url)
		fmt.Println("StatusCode", response.StatusCode)
		fmt.Println(accessToken)
		//return nil, oa.printError(response)

		message := fmt.Sprintf("Server returned statuscode %v", response.StatusCode)
		return response, &types.ErrorString{message}
	}
	if err != nil {
		return response, err
	}

	if model != nil {
		defer response.Body.Close()

		b, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(b, &model)
		if err != nil {
			return nil, err
		}
	}

	return response, nil
}
