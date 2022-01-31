package oauth2

import (
	errortools "github.com/leapforce-libraries/go_errortools"
	gcs "github.com/leapforce-libraries/go_googlecloudstorage"
)

type TokenMap struct {
	token *Token
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

func (m *TokenMap) Token() *Token {
	return m.token
}

func (m *TokenMap) NewToken() (*Token, *errortools.Error) {
	return nil, nil
}

func (m *TokenMap) SetToken(token *Token, save bool) *errortools.Error {
	m.token = token

	if !save {
		return nil
	}

	return m.SaveToken()
}

func (m *TokenMap) RetrieveToken() (*errortools.Error) {
	accessToken, _ := m.map_.Get("access_token")
	refreshToken, _ := m.map_.Get("refresh_token")
	tokenType, _ := m.map_.Get("token_type")
	scope, _ := m.map_.Get("scope")
	expiry, _ := m.map_.GetTimestamp("expiry")

	m.token = &Token{
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
