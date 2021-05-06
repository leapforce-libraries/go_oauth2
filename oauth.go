package oauth2

import (
	"fmt"
	"net/http"
	"net/url"

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
	body := struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Code         string `json:"code"`
		GrantType    string `json:"grant_type"`
		RedirectURI  string `json:"redirect_uri"`
	}{
		service.clientID,
		service.clientSecret,
		authorizationCode,
		"authorization_code",
		service.redirectURL,
	}

	// set extra headers
	header := http.Header{}
	header.Set("Content-Type", "application/x-www-form-urlencoded")

	// reponse model
	token := Token{}

	t := true
	requestConfig := go_http.RequestConfig{
		URL:                service.tokenURL,
		NonDefaultHeaders:  &header,
		BodyModel:          body,
		ResponseModel:      &token,
		XWWWFormURLEncoded: &t,
	}

	_, response, e := service.httpService.HTTPRequest(service.tokenHTTPMethod, &requestConfig)
	if e != nil {
		fmt.Println(122)
		return e
	}

	if response == nil {
		fmt.Println(123)
		return errortools.ErrorMessage("Response is nil")
	}
	if response.Body == nil {
		fmt.Println(124)
		return errortools.ErrorMessage("Response body is nil")
	}

	return errortools.ErrorMessage(token.AccessToken)
}
