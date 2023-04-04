package model

import "errors"

var (
	// ErrNotFound is about
	ErrNotFound = errors.New("NOT_FOUND")

	// ErrPrivateKeyNotRSA error for private key is not rsa type
	ErrPrivateKeyNotRSA = errors.New("ERR_PRIVATE_KEY_NOT_RSA")

	// ErrPrivateKeyEmpty error for empty private key
	ErrPrivateKeyEmpty = errors.New("ERR_PRIVATE_KEY_EMPTY")

	// ErrCRTEmpty error for empty crt
	ErrCRTEmpty = errors.New("ERR_CRT_EMPTY")

	// ErrCRTNotCertificate error for wrong format of crt
	ErrCRTNotCertificate = errors.New("ERR_CRT_NOT_CERTIFICATE")

	// ErrCertificateNotValid error for not valid certificate
	ErrCertificateNotValid = errors.New("ERR_CERTIFICATE_NOT_VALID")
)
