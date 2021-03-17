# NoJWT

This is for now a simple proof of concept not a full-blown library, although if
you are ok with using HS256 and parsing your own payloads, it's totally
functional.

The idea is that in JWT we can't ever trust the `alg` header, and the `typ` and
`cty` are very seldom needed when you control when and how you would be getting
JWTs. This makes the JWT header totally unnecessary, so we could do without it
making our tokens smaller.

Aside from being "headerless JWTs", the payload can be any []byte blob, not
necessarily JSON content, and we only base64-encode it once (to produce the
final token), not before at signature creation. This saves a bit of creation and
verification time, although it's probably negligible.

## Installation

`go get -u github.com/antoniomo/nojwt`

## Sample usage

```go
package main

import (
	"fmt"

	"github.com/antoniomo/nojwt"
)

func main() {
	payload := []byte(`{"hello": "world!"}`)
	secret := []byte("my secret")

	token := nojwt.SignHS256(payload, secret)
	fmt.Println(token)

	payload2, ok := nojwt.VerifyHS256(token, secret)
	fmt.Println(string(payload2), ok)

	// Lets tamper it!
	tamperedToken := []byte(token)
	tamperedToken[42] = 'x'
	fmt.Println(string(tamperedToken))

	payload3, ok := nojwt.VerifyHS256(string(tamperedToken), secret)
	fmt.Println(string(payload3), ok)

	// There's also unsafe nowjt.Parse for when we don't care about the
	// signature, but it test that it's valid nojwt format
	payload4, ok := nojwt.Parse(string(tamperedToken))
	fmt.Println(string(payload4), ok)
}

```

The output of that should be:

```
eyJoZWxsbyI6ICJ3b3JsZCEifQ.g8o_EQ3pOt9qBQ-Yz8vK_rSoqWO47ds5hUsbPf9eObU
{"hello": "world!"} <nil>
eyJoZWxsbyI6ICJ3b3JsZCEifQ.g8o_EQ3pOt9qBQ-xz8vK_rSoqWO47ds5hUsbPf9eObU
{"hello": "world!"} invalid nojwt signature
{"hello": "world!"} <nil>
```

## CLI

There's a very minimal CLI included. It doesn't check all use cases, but it's
good for experimentation purposes.

Check the help:

```bash
$ ./nojwt -h
nojwt command line tool.

Commands:
	sign	Signs a payload with a secret, prints token
	verify	Verifies a token with a secret, prints payload and possible error
	parse	Parses a token, prints payload

Usage:
	nojwt <command> [options]

Use "nojwt <command> --help" for more information about a given command.

$./nojwt sign -h
Usage of sign:
  -p string
    	Payload
  -s string
    	Signature

$./nojwt verify -h
Usage of verify:
  -s string
    	Signature
  -t string
    	Token

$./nojwt parse -h
Usage of parse:
  -t string
    	Token
```
