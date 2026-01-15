package main

import (
	"crypto/mlkem"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

var (
	mlkem758OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
)

//	PrivateKeyInfo ::= SEQUENCE {
//	  version                   Version,
//	  privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
//	  privateKey                PrivateKey,
//	  attributes           [0]  IMPLICIT Attributes OPTIONAL }
//
// Version ::= INTEGER
// PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
// PrivateKey ::= OCTET STRING
// Attributes ::= SET OF Attribute
type PrivateKeyInfo struct {
	Version             int
	PrivateKeyAlgorithm pkix.AlgorithmIdentifier
	PrivateKey          []byte      `asn1:""`                            // The actual key data, an OCTET STRING
	Attributes          []Attribute `asn1:"optional,tag:0,implicit,set"` // Optional attributes
}

//	Attribute ::= SEQUENCE {
//	  attrType OBJECT IDENTIFIER,
//	  attrValues SET OF AttributeValue }
//
// AttributeValue ::= ANY
type Attribute struct {
	Type asn1.ObjectIdentifier
	// This should be a SET OF ANY, but Go's asn1 parser can't handle slices of
	// RawValues. Use value() to get an AnySet of the value.
	RawValue []asn1.RawValue `asn1:"set"`
}

//	SubjectPublicKeyInfo  ::=  SEQUENCE  {
//	     algorithm            AlgorithmIdentifier,
//	     subjectPublicKey     BIT STRING  }
type SubjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func main() {

	// generate a new keypair
	mk, err := mlkem.GenerateKey768()
	if err != nil {
		log.Fatal(err)
	}

	// get the public/private bytes
	pubbin := mk.EncapsulationKey().Bytes()
	privbin := mk.Bytes()

	// write the public private to PEM files

	pux := &SubjectPublicKeyInfo{
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

	prkix := &PrivateKeyInfo{
		Version: 0,
		PrivateKeyAlgorithm: pkix.AlgorithmIdentifier{
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

	err = os.WriteFile("certs/bare-seed.pem", prstr, 0644)
	if err != nil {
		log.Fatal(err)
	}

	/// ********************************* READ

	// now read the public key back from pem
	rpub_bytes, err := os.ReadFile("certs/public.pem")
	if err != nil {
		log.Fatal(err)
	}

	pubPEMblock, rest := pem.Decode(rpub_bytes)
	if len(rest) != 0 {
		fmt.Printf("trailing data found during pemDecode")
		return
	}
	var pkix SubjectPublicKeyInfo
	if rest, err := asn1.Unmarshal(pubPEMblock.Bytes, &pkix); err != nil {
		panic(err)
	} else if len(rest) != 0 {
		fmt.Printf("rest not nil")
		return
	}

	var cipherText []byte
	var kemSharedSecret []byte
	if pkix.Algorithm.Algorithm.Equal(mlkem758OID) {
		fmt.Println("Found MLKEM758 in public key")

		ek, err := mlkem.NewEncapsulationKey768(pkix.PublicKey.Bytes)
		if err != nil {
			panic(err)
		}
		kemSharedSecret, cipherText = ek.Encapsulate()
	}

	fmt.Printf("sharedSecret %s \n", base64.StdEncoding.EncodeToString(kemSharedSecret))
	fmt.Printf("cipherText %s \n", base64.StdEncoding.EncodeToString(cipherText))

	// now read the privarte key back from pem
	privBytes, err := os.ReadFile("certs/bare-seed.pem")
	if err != nil {
		panic(err)
	}
	privPEMblock, rest := pem.Decode(privBytes)
	if len(rest) != 0 {
		fmt.Printf("trailing data found during pemDecode")
		return
	}
	var rprkix PrivateKeyInfo
	if rest, err := asn1.Unmarshal(privPEMblock.Bytes, &rprkix); err != nil {
		panic(err)
	} else if len(rest) != 0 {
		fmt.Printf("rest not nil")
	}

	if rprkix.PrivateKeyAlgorithm.Algorithm.Equal(mlkem758OID) {
		fmt.Println("Found MLKEM758 in private key")

		dk, err := mlkem.NewDecapsulationKey768(rprkix.PrivateKey)
		if err != nil {
			panic(err)
		}

		sharedKey, err := dk.Decapsulate(cipherText)
		if err != nil {
			panic(err)
		}
		fmt.Printf("recovered shared secret: kemShared %s \n", base64.StdEncoding.EncodeToString(sharedKey))
	}

}
