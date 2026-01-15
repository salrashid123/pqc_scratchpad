package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/cloudflare/circl/sign/slhdsa"
)

const ()

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

var (
	OID_sl_dsa_128s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}
)

var ()

func main() {
	flag.Parse()

	/// ********************************* READ "bareseed"

	var pubs *slhdsa.PublicKey

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
	var rpkix SubjectPublicKeyInfo
	if rest, err := asn1.Unmarshal(pubPEMblock.Bytes, &rpkix); err != nil {
		panic(err)
	} else if len(rest) != 0 {
		fmt.Printf("rest not nil")
		return
	}

	if rpkix.Algorithm.Algorithm.Equal(OID_sl_dsa_128s) {
		fmt.Println("Found OID_sl_dsa_128s in public key")

		var pkix struct {
			Raw       asn1.RawContent
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
		if rest, err := asn1.Unmarshal(pubPEMblock.Bytes, &pkix); err != nil {
			panic(err)
		} else if len(rest) != 0 {
			fmt.Printf("trailing data")
			return
		}
		key := slhdsa.PublicKey{ID: slhdsa.SHA2_128s}
		err = key.UnmarshalBinary(pkix.PublicKey.Bytes)
		if err != nil {
			panic(err)
		}

		pubs = &key
	} else {
		fmt.Printf("unable to parse public key")
		return
	}

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

	//*******************

	key := slhdsa.PrivateKey{ID: slhdsa.SHA2_128s}
	err = key.UnmarshalBinary(rprkix.PrivateKey)
	if err != nil {
		panic(err)
	}

	data := []byte("foo")

	sig, err := key.Sign(rand.Reader, data, crypto.Hash(0))
	if err != nil {
		panic(err)
	}

	log.Printf("Signature %s", base64.StdEncoding.EncodeToString(sig))

	ok := slhdsa.Verify(pubs, slhdsa.NewMessage(data), sig, nil)
	if !ok {
		log.Printf("Error verifying")
		return
	}
	log.Println("Signature  1 Verified")

	/// *******************

	// m := slhdsa.NewMessage(data)

	// ss, err := slhdsa.SignDeterministic(&key, m, []byte("foo"))
	// if err != nil {
	// 	panic(err)
	// }

	// log.Printf("Signature  SignDeterministic %s\n", base64.StdEncoding.EncodeToString(ss))

	// ok = slhdsa.Verify(pubs, slhdsa.NewMessage(data), sig, nil)
	// if !ok {
	// 	log.Printf("Error verifying")
	// 	return
	// }
	// log.Println("Signature  1 Verified")

}
