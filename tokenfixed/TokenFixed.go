package tokenfixed

import (
	errortools "github.com/leapforce-libraries/go_errortools"
	token "github.com/leapforce-libraries/go_oauth2/token"
)

type TokenFixed struct {
	accessToken string
}

func NewTokenFixed(accessToken string) (*TokenFixed, *errortools.Error) {
	return &TokenFixed{
		accessToken: accessToken,
	}, nil
}

func (m *TokenFixed) Token() *token.Token {
	return &token.Token{
		AccessToken: &m.accessToken,
	}
}

func (m *TokenFixed) NewToken() (*token.Token, *errortools.Error) {
	return nil, nil
}

func (m *TokenFixed) SetToken(token *token.Token, save bool) *errortools.Error {
	return nil
}

func (m *TokenFixed) RetrieveToken() *errortools.Error {
	return nil
}

func (m *TokenFixed) SaveToken() *errortools.Error {
	return nil
}

func (m *TokenFixed) UnmarshalToken(b []byte) (*token.Token, *errortools.Error) {
	return nil, nil
}
