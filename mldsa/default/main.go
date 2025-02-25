package main

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"

	"github.com/cloudflare/circl/pki"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

const ()

var ()

func main() {
	flag.Parse()

	ppu, ppr, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	puPem, err := pki.MarshalPEMPublicKey(ppu)
	if err != nil {
		panic(err)
	}

	prPem, err := pki.MarshalPEMPrivateKey(ppr)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Public \n%s\n", puPem)
	fmt.Printf("Private \n%s\n", prPem)

	data := []byte("foo")

	sig, err := ppr.Sign(rand.Reader, data, crypto.Hash(0))
	if err != nil {
		panic(err)
	}
	log.Printf("Signature %s", base64.StdEncoding.EncodeToString(sig))

	ok := mldsa44.Verify(ppu, data, nil, sig)
	if !ok {
		log.Printf("Error verifying")
	}
	log.Println("Signature Verified")
}
