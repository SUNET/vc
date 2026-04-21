package oauth2

import "errors"

var (
	ErrInvalidClient = errors.New("invalid client") // 400 Bad Request
	ErrPKCERequired  = errors.New("code_verifier required for public client")
)
