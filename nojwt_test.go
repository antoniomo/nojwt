package nojwt

import (
	"bytes"
	"testing"
)

var (
	payload = []byte(`{"hello": "world!"}`)
	secret  = []byte("my secret")
)

const (
	notAToken         = "asdfasdfasdfasdf"
	token             = "eyJoZWxsbyI6ICJ3b3JsZCEifQ.g8o_EQ3pOt9qBQ-Yz8vK_rSoqWO47ds5hUsbPf9eObU"
	tamperedSignature = "eyJoZWxsbyI6ICJ3b3JsZCEifQ.g8o_EQ3pOt9qBQ-xz8vK_rSoqWO47ds5hUsbPf9eObU"
	tamperedPayload   = "eyJoZWxxbyI6ICJ3b3JsZCEifQ.g8o_EQ3pOt9qBQ-xz8vK_rSoqWO47ds5hUsbPf9eObU"
)

func TestSign(t *testing.T) {
	tok := SignHS256(payload, secret)

	if token != tok {
		t.Error("tokens don't match")
	}
}

func TestParse(t *testing.T) {
	payload2, err := Parse(tamperedSignature)

	if !bytes.Equal(payload, payload2) {
		t.Error("payloads don't match")
	}

	if err != nil {
		t.Error("unable to parse token")
	}

	_, err = Parse(notAToken)
	if err != ErrInvalidFormat {
		t.Error("wrongly parsing wrong format")
	}
}

func TestVerify(t *testing.T) {
	payload2, err := VerifyHS256(token, secret)

	if !bytes.Equal(payload, payload2) {
		t.Error("payloads don't match")
	}

	if err == ErrInvalidFormat {
		t.Error("unable to parse token")
	}

	if err == ErrInvalidSignature {
		t.Error("unable to verify token")
	}

	payload2, err = VerifyHS256(tamperedSignature, secret)

	if !bytes.Equal(payload, payload2) {
		t.Error("payloads don't match")
	}

	if err != ErrInvalidSignature {
		t.Error("wrongly verifying tampered signature token")
	}

	payload2, err = VerifyHS256(tamperedPayload, secret)

	if bytes.Equal(payload, payload2) {
		t.Error("payloads match on tampered payload")
	}

	if err != ErrInvalidSignature {
		t.Error("wrongly verifying tampered signature token")
	}

	_, err = VerifyHS256(notAToken, secret)
	if err != ErrInvalidFormat {
		t.Error("wrongly parsing wrong format")
	}
}
