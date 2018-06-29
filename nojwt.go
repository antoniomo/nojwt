package nojwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// SignHS256 ...
func SignHS256(payload, secret []byte) string {

	signature := hmac.New(sha256.New, secret)
	signature.Write(payload)
	signature.Write(secret)
	signed := base64.RawURLEncoding.EncodeToString(signature.Sum(nil))
	return base64.RawURLEncoding.EncodeToString(payload) + "." + signed
}

// Parse doesn't verify signature
func Parse(token string) ([]byte, bool) {

	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, false
	}

	return payload, true
}

// VerifyHS256 ...
func VerifyHS256(token string, secret []byte) ([]byte, bool) {

	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, false
	}

	signature := hmac.New(sha256.New, secret)
	signature.Write(payload)
	signature.Write(secret)
	signed := base64.RawURLEncoding.EncodeToString(signature.Sum(nil))

	if signed != parts[1] {
		return payload, false
	}

	return payload, true
}
