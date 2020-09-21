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
	res, err := oa.httpRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	if model != nil {
		defer res.Body.Close()

		b, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(b, &model)
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

// Post returns http.Response for generic oAuth2 Post http call
//
func (oa *OAuth2) Post(url string, buf *bytes.Buffer, model interface{}) (*http.Response, error) {
	//fmt.Println("POST ", url)
	res, err := oa.httpRequest(http.MethodPost, url, buf)
	if err != nil {
		return nil, err
	}

	if model != nil {
		defer res.Body.Close()

		b, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(b, &model)
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

// Put returns http.Response for generic oAuth2 Put http call
//
func (oa *OAuth2) Put(url string, buf *bytes.Buffer, model interface{}) (*http.Response, error) {
	//fmt.Println("PUT ", url)
	res, err := oa.httpRequest(http.MethodPut, url, buf)
	if err != nil {
		return nil, err
	}

	if model != nil {
		defer res.Body.Close()

		b, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(b, &model)
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

// Delete returns http.Response for generic oAuth2 Delete http call
//
func (oa *OAuth2) Delete(url string) (*http.Response, error) {
	//fmt.Println("DELETE ", url)
	res, err := oa.httpRequest(http.MethodDelete, url, nil)
	if err != nil {
		return res, err
	}

	defer res.Body.Close()

	return res, nil
}

func (oa *OAuth2) getHTTPClient() (*http.Client, error) {
	err := oa.ValidateToken()
	if err != nil {
		return nil, err
	}

	return new(http.Client), nil
}

func (oa *OAuth2) httpRequest(httpMethod string, url string, body io.Reader) (*http.Response, error) {
	client, err := oa.getHTTPClient()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(httpMethod, url, nil)
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
	req.Header.Add("authorization", bearer)
	req.Header.Set("Accept", "application/json")

	// Send out the HTTP request
	response, err := client.Do(req)

	oa.unlockToken()

	// Check HTTP StatusCode
	if response.StatusCode < 200 || response.StatusCode > 299 {
		fmt.Println(fmt.Sprintf("ERROR in %s", httpMethod))
		fmt.Println(url)
		fmt.Println("StatusCode", response.StatusCode)
		fmt.Println(accessToken)
		//return nil, oa.printError(response)

		message := fmt.Sprintf("Server returned statuscode %v", response.StatusCode)
		return response, &types.ErrorString{message}
	}
	if err != nil {
		return response, err
	}

	return response, nil
}
