package main

import (
	"crypto/mlkem"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

var (
	mlkem758OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
)

type pkixPrivKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type pkixPubKey struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func main() {

	mk, err := mlkem.GenerateKey768()
	if err != nil {
		log.Fatal(err)
	}

	pubbin := mk.EncapsulationKey().Bytes()
	privbin := mk.Bytes()

	err = os.WriteFile("certs/bpub.dat", pubbin, 0644)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile("certs/bpriv.dat", privbin, 0644)
	if err != nil {
		log.Fatal(err)
	}

	pu, err := mlkem.NewEncapsulationKey768(pubbin)
	if err != nil {
		log.Fatal(err)
	}

	pux := &pkixPubKey{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: mlkem758OID},
		PublicKey: asn1.BitString{
			Bytes:     pubbin,
			BitLength: len(pubbin) * 8,
		},
	}
	b, err := asn1.Marshal(*pux)
	if err != nil {
		log.Fatal(err)
	}
	pstr := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})

	err = os.WriteFile("certs/public.pem", pstr, 0644)
	if err != nil {
		log.Fatal(err)
	}

	prkix := &pkixPrivKey{
		Version: 0,
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: mlkem758OID,
		},
		PrivateKey: privbin,
	}
	br, err := asn1.Marshal(*prkix)
	if err != nil {
		log.Fatal(err)
	}
	prstr := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: br,
	})

	err = os.WriteFile("certs/private.pem", prstr, 0644)
	if err != nil {
		log.Fatal(err)
	}

	shared, ciphertext := pu.Encapsulate()
	fmt.Fprintf(os.Stdout, "SharedSecret: kemShared (%s) \n", hex.EncodeToString(shared))

	// now read the bytes to decapsulate
	pr, err := mlkem.NewDecapsulationKey768(privbin)
	if err != nil {
		log.Fatal(err)
	}

	recovered, err := pr.Decapsulate(ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stdout, "SharedSecret: kemShared (%s) \n", hex.EncodeToString(recovered))

}
