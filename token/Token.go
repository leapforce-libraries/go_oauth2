package token

import (
	"encoding/json"
	"fmt"
	"time"
)

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

func (t *Token) HasAccessToken() bool {
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

func (t *Token) HasValidAccessToken(atTime time.Time) bool {
	if !t.HasAccessToken() {
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

func (t *Token) HasRefreshToken() bool {
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
