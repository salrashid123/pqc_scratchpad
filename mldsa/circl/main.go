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

	"github.com/cloudflare/circl/pki"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
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
	mldsa44aoid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
)

var ()

func main() {
	flag.Parse()

	// the following generat3es a keypair and saves it as 'bare-seed format')

	// pk, sk, err := mldsa44.GenerateKey(rand.Reader)
	// if err != nil {
	// 	panic(err)
	// }

	// pubPEM, err := pki.MarshalPEMPublicKey(pk)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("Public PEM \n%s\n", pubPEM)
	// privPEM, err := pki.MarshalPEMPrivateKey(sk)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("privPEM PEM \n%s\n", privPEM)

	// // to save as `bare-seed`, extract the seed and save as private key

	// s := PrivateKeyInfo{
	// 	Version: 0,
	// 	PrivateKeyAlgorithm: pkix.AlgorithmIdentifier{
	// 		Algorithm: mldsa44aoid,
	// 	},
	// 	PrivateKey: sk.Seed(),
	// }

	// sb, err := asn1.Marshal(s)
	// if err != nil {
	// 	panic(err)
	// }
	// // 2. Create PEM block
	// block := &pem.Block{
	// 	Type:  "PRIVATE KEY",
	// 	Bytes: sb,
	// }
	// err = pem.Encode(os.Stdout, block)
	// if err != nil {
	// 	panic(err)
	// }

	/// ********************************* READ

	var pubs *mldsa44.PublicKey

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

	if pkix.Algorithm.Algorithm.Equal(mldsa44aoid) {
		fmt.Println("Found MLDSA-44 in public key")

		pub, err := pki.UnmarshalPKIXPublicKey(pubPEMblock.Bytes)
		if err != nil {
			panic(err)
		}
		pubs = pub.(*mldsa44.PublicKey)
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

	if rprkix.PrivateKeyAlgorithm.Algorithm.Equal(mldsa44aoid) {
		fmt.Println("Found  MLDSA-44  in private key")

		data := []byte("foo")
		_, pr := mldsa44.NewKeyFromSeed((*[32]byte)(rprkix.PrivateKey))
		sig, err := pr.Sign(rand.Reader, data, crypto.Hash(0))
		if err != nil {
			panic(err)
		}
		log.Printf("Signature %s", base64.StdEncoding.EncodeToString(sig))

		ok := mldsa44.Verify(pubs, data, nil, sig)
		if !ok {
			log.Printf("Error verifying")
		}
		log.Println("Signature Verified")
	} else {
		fmt.Printf("unable to parse priate key")
		return
	}
}
