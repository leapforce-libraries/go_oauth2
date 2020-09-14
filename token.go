package oauth2

import (
	"fmt"
	"sync"
	"time"

	types "github.com/Leapforce-nl/go_types"
)

var tokenMutex sync.Mutex

// Token stures Token object
//
type Token struct {
	AccessToken  string `json:"access_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	ExpiresIn    string `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Expiry       *time.Time
}

func (t *Token) Print() {
	if t == nil {
		fmt.Println("Token: <nil>")
		return
	}

	if t.AccessToken == "" {
		fmt.Println("AccessToken: <nil>")
	} else {
		fmt.Println("AccessToken: ", t.AccessToken)
	}

	if t.Scope == "" {
		fmt.Println("Scope: <nil>")
	} else {
		fmt.Println("Scope: ", t.Scope)
	}

	if t.TokenType == "" {
		fmt.Println("TokenType: <nil>")
	} else {
		fmt.Println("TokenType: ", t.TokenType)
	}

	if t.ExpiresIn == "" {
		fmt.Println("ExpiresIn: <nil>")
	} else {
		fmt.Println("ExpiresIn: ", t.ExpiresIn)
	}

	if t.RefreshToken == "" {
		fmt.Println("RefreshToken: <nil>")
	} else {
		fmt.Println("RefreshToken: ", t.RefreshToken)
	}

	if t.Expiry == nil {
		fmt.Println("Expiry: <nil>")
	} else {
		fmt.Println("Expiry: ", *t.Expiry)
	}
}

func (oa *OAuth2) unlockToken() {
	tokenMutex.Unlock()
}

func (t *Token) useable() bool {
	if t == nil {
		return false
	}
	if t.AccessToken == "" {
		if t.RefreshToken == "" {
			return false
		}
	}
	return true
}

func (t *Token) refreshable() bool {
	if t == nil {
		return false
	}
	if t.RefreshToken == "" {
		return false
	}
	return true
}

func (t *Token) isExpired() (bool, error) {
	if !t.useable() {
		return true, &types.ErrorString{"Token is not valid."}
	}
	if t.Expiry.Add(-60 * time.Second).Before(time.Now()) {
		return true, nil
	}
	return false, nil
}
