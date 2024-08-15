package errors

import (
	"errors"
	"fmt"
)

type ErrorCode int

const (
	ErrUnknown ErrorCode = iota
	ErrInvalidInput
	ErrCryptographicFailure
)

// Error represents a TwoPartyTSS error
type TssError struct {
	Code    ErrorCode
	Message string
	Err     error
}

func (e *TssError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("TwoPartyTSS error [%d]: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("TwoPartyTSS error [%d]: %s", e.Code, e.Message)
}

func (e *TssError) Unwrap() error {
	return e.Err
}

func NewTssError(code ErrorCode, message string, err error) *TssError {
	return &TssError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

func WrapError(err error, code ErrorCode, message string) *TssError {
	if err == nil {
		return nil
	}
	return NewTssError(code, message, err)
}

func IsError(err error) bool {
	var tptsErr *TssError
	return errors.As(err, &tptsErr)
}

func GetError(err error) (*TssError, bool) {
	var tptsErr *TssError
	if errors.As(err, &tptsErr) {
		return tptsErr, true
	}
	return nil, false
}

func GetOriginalError(err error) error {
	for err != nil {
		tptsErr, ok := err.(*TssError)
		if !ok {
			return err
		}
		err = tptsErr.Unwrap()
	}
	return nil
}
