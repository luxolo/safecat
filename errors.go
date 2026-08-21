package safecat

import "errors"

var (
	ErrLimitExceeded = errors.New("safecat: configured buffer limit exceeded")
	ErrInvalidMatch  = errors.New("safecat: detector returned an invalid match")
)
