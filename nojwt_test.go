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
	token         = "eyJoZWxsbyI6ICJ3b3JsZCEifQ.EmzSBHDU2UaoGhmTWaOSWHW9X8bvpEs7PX4oyqu4ISk"
	tamperedToken = "eyJoZWxsbyI6ICJ3b3JsZCEifQ.EmzSBHDU2UaoGhmxWaOSWHW9X8bvpEs7PX4oyqu4ISk"
)

func testSign(t *testing.T) {

	tok := SignHS256(payload, secret)

	if token != tok {
		t.Error("tokens don't match")
	}
}

func TestParse(t *testing.T) {

	payload2, ok := Parse(tamperedToken)

	if !bytes.Equal(payload, payload2) {
		t.Error("payloads don't match")
	}

	if !ok {
		t.Error("unable to parse token")
	}
}

func TestVerify(t *testing.T) {

	payload2, ok := VerifyHS256(token, secret)

	if !bytes.Equal(payload, payload2) {
		t.Error("payloads don't match")
	}

	if !ok {
		t.Error("unable to verify token")
	}

	payload2, ok = VerifyHS256(tamperedToken, secret)

	if !bytes.Equal(payload, payload2) {
		t.Error("payloads don't match")
	}

	if ok {
		t.Error("wrongly verifying tampered token")
	}
}
