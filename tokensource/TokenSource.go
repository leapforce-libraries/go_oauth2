package tokensource

import (
	errortools "github.com/leapforce-libraries/go_errortools"
	token "github.com/leapforce-libraries/go_oauth2/token"
)

type TokenSource interface {
	Token() *token.Token
	NewToken() (*token.Token, *errortools.Error)
	SetToken(*token.Token, bool) *errortools.Error
	RetrieveToken() *errortools.Error
	SaveToken() *errortools.Error
}
