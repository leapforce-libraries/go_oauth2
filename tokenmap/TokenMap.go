package tokenmap

import (
	"encoding/json"
	errortools "github.com/leapforce-libraries/go_errortools"
	gcs "github.com/leapforce-libraries/go_googlecloudstorage"
	token "github.com/leapforce-libraries/go_oauth2/token"
)

type TokenMap struct {
	token *token.Token
	map_  *gcs.Map
}

func NewTokenMap(map_ *gcs.Map) (*TokenMap, *errortools.Error) {
	if map_ == nil {
		return nil, errortools.ErrorMessage("Map is a nil pointer")
	}

	return &TokenMap{
		map_: map_,
	}, nil
}

func (m *TokenMap) Token() *token.Token {
	return m.token
}

func (m *TokenMap) NewToken() (*token.Token, *errortools.Error) {
	return nil, nil
}

func (m *TokenMap) SetToken(token *token.Token, save bool) *errortools.Error {
	if token.AccessToken == nil {
		return errortools.ErrorMessage("AccessToken of new token is nil")
	}

	if token.RefreshToken == nil {
		token.RefreshToken = m.token.RefreshToken
	}
	m.token = token

	if !save {
		return nil
	}

	return m.SaveToken()
}

func (m *TokenMap) RetrieveToken() *errortools.Error {
	accessToken, e := m.map_.Get("access_token")
	if e != nil {
		return e
	}
	refreshToken, e := m.map_.Get("refresh_token")
	if e != nil {
		return e
	}
	tokenType, e := m.map_.Get("token_type")
	if e != nil {
		return e
	}
	scope, e := m.map_.Get("scope")
	if e != nil {
		return e
	}
	expiry, e := m.map_.GetTimestamp("expiry")
	if e != nil {
		return e
	}

	m.token = &token.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    tokenType,
		Scope:        scope,
		Expiry:       expiry,
	}

	return nil
}

func (m *TokenMap) SaveToken() *errortools.Error {
	if m.token == nil {
		return errortools.ErrorMessage("Token is nil pointer")
	}

	if m.token.AccessToken != nil {
		m.map_.Set("access_token", *m.token.AccessToken, false)
	}

	if m.token.RefreshToken != nil {
		m.map_.Set("refresh_token", *m.token.RefreshToken, false)
	}

	if m.token.TokenType != nil {
		m.map_.Set("token_type", *m.token.TokenType, false)
	}

	if m.token.Scope != nil {
		m.map_.Set("scope", *m.token.Scope, false)
	}

	if m.token.Expiry != nil {
		m.map_.SetTimestamp("expiry", *m.token.Expiry, false)
	}

	e := m.map_.Save()
	if e != nil {
		return e
	}

	return nil
}

func (m *TokenMap) UnmarshalToken(b []byte) (*token.Token, *errortools.Error) {
	var token token.Token

	err := json.Unmarshal(b, &token)
	if err != nil {
		return nil, errortools.ErrorMessage(err)
	}
	return &token, nil
}
