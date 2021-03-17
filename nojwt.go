package nojwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

const nojwtparts = 2 // Dot-separated parts in the nojwt format

var (
	ErrInvalidFormat    = errors.New("invalid nojwt format")
	ErrInvalidSignature = errors.New("invalid nojwt signature")
)

// SignHS256 ...
func SignHS256(payload, secret []byte) string {
	signature := hmac.New(sha256.New, secret)
	signature.Write(payload)
	signed := base64.RawURLEncoding.EncodeToString(signature.Sum(nil))

	return base64.RawURLEncoding.EncodeToString(payload) + "." + signed
}

// Parse doesn't verify signature.
func Parse(token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != nojwtparts {
		return nil, ErrInvalidFormat
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidFormat
	}

	return payload, nil
}

// VerifyHS256 ...
func VerifyHS256(token string, secret []byte) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != nojwtparts {
		return nil, ErrInvalidFormat
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidFormat
	}

	signature := hmac.New(sha256.New, secret)
	signature.Write(payload)
	signed := base64.RawURLEncoding.EncodeToString(signature.Sum(nil))

	if signed != parts[1] {
		return payload, ErrInvalidSignature
	}

	return payload, nil
}
