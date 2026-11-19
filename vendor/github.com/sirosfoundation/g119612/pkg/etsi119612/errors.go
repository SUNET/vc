package etsi119612

import (
	"errors"
)

var (
	ErrInvalidDate        = errors.New("not currently valid")
	ErrInvalidStatus      = errors.New("status is not recognized or granted")
	ErrInvalidConstraints = errors.New("service constraints not fulfilled")
)
