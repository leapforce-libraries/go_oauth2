package oauth2

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	errortools "github.com/leapforce-libraries/go_errortools"
	gcs "github.com/leapforce-libraries/go_googlecloudstorage"
)

var tokenMutex sync.Mutex

// Token stures Token object
//
type Token struct {
	AccessToken  *string          `json:"access_token"`
	Scope        *string          `json:"scope"`
	TokenType    *string          `json:"token_type"`
	ExpiresIn    *json.RawMessage `json:"expires_in"`
	RefreshToken *string          `json:"refresh_token"`
	Expiry       *time.Time
}

func (t *Token) Print() {
	if t == nil {
		fmt.Println("Token: <nil>")
		return
	}

	if t.AccessToken == nil {
		fmt.Println("AccessToken: <nil>")
	} else {
		fmt.Println("AccessToken: ", *t.AccessToken)
	}

	if t.Scope == nil {
		fmt.Println("Scope: <nil>")
	} else {
		fmt.Println("Scope: ", *t.Scope)
	}

	if t.TokenType == nil {
		fmt.Println("TokenType: <nil>")
	} else {
		fmt.Println("TokenType: ", *t.TokenType)
	}

	if t.RefreshToken == nil {
		fmt.Println("RefreshToken: <nil>")
	} else {
		fmt.Println("RefreshToken: ", *t.RefreshToken)
	}

	if t.Expiry == nil {
		fmt.Println("Expiry: <nil>")
	} else {
		fmt.Println("Expiry: ", *t.Expiry)
	}
}

func (t *Token) hasAccessToken() bool {
	if t == nil {
		return false
	}
	if t.AccessToken == nil {
		return false
	}
	if *t.AccessToken == "" {
		return false
	}
	return true
}

func (t *Token) hasValidAccessToken(atTime time.Time) bool {
	if !t.hasAccessToken() {
		return false
	}
	if t.Expiry == nil {
		return true
	}

	if t.Expiry.Before(atTime) {
		return false
	}
	return true
}

func (t *Token) hasRefreshToken() bool {
	if t == nil {
		return false
	}
	if t.RefreshToken == nil {
		return false
	}
	if *t.RefreshToken == "" {
		return false
	}
	return true
}

func (t *Token) isExpired() (bool, *errortools.Error) {
	if t == nil {
		return true, errortools.ErrorMessage("Token is nil.")
	}
	if !t.hasAccessToken() {
		return true, errortools.ErrorMessage("Token is not valid.")
	}
	if t.Expiry.Add(-60 * time.Second).Before(time.Now()) {
		return true, nil
	}
	return false, nil
}

func GetTokenFromMap(m *gcs.Map) (*Token, *errortools.Error) {
	if m == nil {
		return nil, errortools.ErrorMessage("Map is nil pointer")
	}

	accessToken, _ := m.Get("access_token")
	refreshToken, _ := m.Get("refresh_token")
	tokenType, _ := m.Get("token_type")
	scope, _ := m.Get("scope")
	expiry, _ := m.GetTimestamp("expiry")

	return &Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    tokenType,
		Scope:        scope,
		Expiry:       expiry,
	}, nil
}

func SaveTokenToMap(m *gcs.Map, token *Token) *errortools.Error {
	if m == nil {
		return errortools.ErrorMessage("Map is nil pointer")
	}

	if token == nil {
		return errortools.ErrorMessage("Token is nil pointer")
	}

	if token.AccessToken != nil {
		m.Set("access_token", *token.AccessToken, false)
	}

	if token.RefreshToken != nil {
		m.Set("refresh_token", *token.RefreshToken, false)
	}

	if token.TokenType != nil {
		m.Set("token_type", *token.TokenType, false)
	}

	if token.Scope != nil {
		m.Set("scope", *token.Scope, false)
	}

	if token.Expiry != nil {
		m.SetTimestamp("expiry", *token.Expiry, false)
	}

	e := m.Save()
	if e != nil {
		return e
	}

	return nil
}
