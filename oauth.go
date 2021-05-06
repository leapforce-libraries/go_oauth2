package oauth2

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	errortools "github.com/leapforce-libraries/go_errortools"
	go_http "github.com/leapforce-libraries/go_http"
)

func (service *OAuth2) AuthorizeURL() string {
	params := url.Values{}
	params.Set("redirect_uri", service.redirectURL)
	params.Set("client_id", service.clientID)
	params.Set("response_type", "code")
	params.Set("scope", service.scope)
	params.Set("access_type", "offline")
	//if state != nil {
	//	params.Set("state", *state)
	//}

	return fmt.Sprintf("%s?%s", service.authURL, params.Encode())
}

func (service *OAuth2) GetAccessTokenFromCode(r *http.Request) *errortools.Error {
	authorizationCode := r.URL.Query().Get("code")
	if authorizationCode == "" {
		return errortools.ErrorMessage("RedirectURL does not contain 'code' parameter")
	}

	// STEP 3: Convert the request token into a usable access token
	params := url.Values{}
	params.Set("client_id", service.clientID)
	params.Set("client_secret", service.clientSecret)
	params.Set("code", authorizationCode)
	params.Set("grant_type", "authorization_code")
	params.Set("redirect_uri", service.redirectURL)

	// create body
	encoded := params.Encode()
	body := strings.NewReader(encoded)

	// set extra headers
	header := http.Header{}
	header.Set("Content-Type", "application/x-www-form-urlencoded")
	header.Set("Content-Length", strconv.Itoa(len(encoded)))

	requestConfig := go_http.RequestConfig{
		URL:               service.tokenURL,
		NonDefaultHeaders: &header,
		BodyModel:         body,
	}

	_, response, e := service.httpService.HTTPRequest(service.tokenHTTPMethod, &requestConfig)
	if e != nil {
		return e
	}
	fmt.Println(response.StatusCode)

	if response == nil {
		return errortools.ErrorMessage("Response is nil")
	}
	if response.Body == nil {
		return errortools.ErrorMessage("Response body is nil")
	}

	defer response.Body.Close()
	b, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return errortools.ErrorMessage(err)
	}

	token := Token{}

	fmt.Println(string(b))

	err = json.Unmarshal(b, &token)
	if err != nil {
		return errortools.ErrorMessage(err)
	}

	return errortools.ErrorMessage(token.AccessToken)
}
