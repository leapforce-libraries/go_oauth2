package oauth2

import (
	errortools "github.com/leapforce-libraries/go_errortools"
)

type TokenSource interface {
	Token() *Token
	NewToken() *errortools.Error
	SetToken(*Token, bool) *errortools.Error
	RetrieveToken() *errortools.Error
	SaveToken() *errortools.Error
}
