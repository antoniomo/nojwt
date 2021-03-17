package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/antoniomo/nojwt"
)

const usagestr = "Usage: %s sign|verify|parse\n"

func main() {
	var (
		signCmd = flag.NewFlagSet("sign", flag.ExitOnError)
		sp      = signCmd.String("p", "", "Payload")
		ss      = signCmd.String("s", "", "Signature")

		verifyCmd = flag.NewFlagSet("verify", flag.ExitOnError)
		vt        = verifyCmd.String("t", "", "Token")
		vs        = verifyCmd.String("s", "", "Signature")

		parseCmd = flag.NewFlagSet("parse", flag.ExitOnError)
		pt       = parseCmd.String("t", "", "Token")
	)

	flag.Usage = func() {
		usage()
	}
	flag.Parse()

	if len(os.Args) < 2 {
		usage()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "sign":
		signCmd.Parse(os.Args[2:])

		payload := []byte(*sp)
		secret := []byte(*ss)

		token := nojwt.SignHS256(payload, secret)
		fmt.Println(token)
	case "verify":
		verifyCmd.Parse(os.Args[2:])

		secret := []byte(*vs)

		payload, err := nojwt.VerifyHS256(*vt, secret)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(string(payload))
	case "parse":
		parseCmd.Parse(os.Args[2:])

		payload, err := nojwt.Parse(*pt)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(string(payload))
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`nojwt command line tool.

Commands:
	sign	Signs a payload with a secret, prints token
	verify	Verifies a token with a secret, prints payload and possible error
	parse	Parses a token, prints payload

Usage:
	nojwt <command> [options]

Use "nojwt <command> --help" for more information about a given command.`)
	flag.PrintDefaults()
}
