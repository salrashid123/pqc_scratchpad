package main

import (
	"crypto"
	"crypto/mldsa"
	"crypto/sha3"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
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

	// id-ML-DSA-65 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2)
	//         country(16) us(840) organization(1) gov(101) csor(3)
	//         nistAlgorithm(4) sigAlgs(3) TBD }

	idmldsa65    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	data         = flag.String("data", "foo", "data to sign")
	publicOut    = flag.String("public", "public.pem", "public key")
	privateOut   = flag.String("private", "private.pem", "private key")
	signContext  = flag.String("signContext", "mycontext", "signcontext")
	signatureOut = flag.String("signature", "signature.dat", "signature file")
)

func main() {

	flag.Parse()

	pr, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		panic(err)
	}

	p := PrivateKeyInfo{
		Version: 0,
		PrivateKeyAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: idmldsa65,
		},
		PrivateKey: pr.Bytes(),
	}

	privateDER, err := asn1.Marshal(p)
	if err != nil {
		panic(err)
	}

	keyOut, err := os.Create(*privateOut)
	if err != nil {
		log.Fatalf("Failed writing to file %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}); err != nil {
		log.Fatalf("Failed to write data: %s", err)
	}
	fmt.Print("wrote private.pem\n")

	// get cypto.publickey
	// publicKey := pr.Public()
	// mp, ok := publicKey.(*mldsa.PublicKey)
	// if !ok {
	// 	fmt.Println("Error converting to mldsa.PublicKey")
	// 	return
	// }
	// fmt.Println(mp.Equal(pr.PublicKey()))

	pu := SubjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: idmldsa65,
		},
		PublicKey: asn1.BitString{
			Bytes: pr.PublicKey().Bytes(),
		},
	}

	publicDER, err := asn1.Marshal(pu)
	if err != nil {
		fmt.Printf("Error marshallling %v", err)
		return
	}
	pubout, err := os.Create(*publicOut)
	if err != nil {
		fmt.Printf("Failed writing to file %v", err)
		return
	}
	if err := pem.Encode(pubout, &pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}); err != nil {
		fmt.Printf("Failed to write data: %s", err)
		return
	}

	// sign and verify
	msg := []byte(*data)
	s, err := pr.Sign(nil, msg, &mldsa.Options{
		Context: *signContext,
	})
	if err != nil {
		fmt.Printf("error signing %v", err)
		return
	}

	err = os.WriteFile(*signatureOut, s, os.FileMode(0644))
	if err != nil {
		fmt.Printf("Error writing file: %v", err)
		return
	}

	pr2, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pr.PublicKey().Bytes())
	if err != nil {
		fmt.Printf("error signing %v", err)
		return
	}
	err = mldsa.Verify(pr2, msg, s, &mldsa.Options{
		Context: *signContext,
	})
	if err != nil {
		fmt.Printf("error verifying %v", err)
		return
	}
	fmt.Println("Verified signature")

	// *******************************************

	////   create mu

	mu := computeMu(pr.PublicKey(), msg, *signContext)

	fmt.Printf("external calculated mu %s\n", hex.EncodeToString(mu))

	sig, err := pr.Sign(nil, mu, crypto.MLDSAMu)
	if err != nil {
		fmt.Printf("error signing mu %v", err)
		return
	}
	// The signature produced via external mu should verify against
	// the original message via the standard Verify.
	if err := mldsa.Verify(pr.PublicKey(), msg, sig, &mldsa.Options{
		Context: *signContext,
	}); err != nil {
		fmt.Printf("error verifying mu %v", err)
		return
	}
	fmt.Println("Verified with external mu")

}

// computeMu computes the μ message representative as specified in FIPS 204.
// μ = SHAKE256(tr || 0x00 || len(ctx) || ctx || msg), where
// tr = SHAKE256(publicKeyBytes) is 64 bytes.
func computeMu(pk *mldsa.PublicKey, msg []byte, context string) []byte {
	H := sha3.NewSHAKE256()
	H.Write(pk.Bytes())
	var tr [64]byte
	H.Read(tr[:])

	H.Reset()
	H.Write(tr[:])
	H.Write([]byte{0x00}) // ML-DSA domain separator
	H.Write([]byte{byte(len(context))})
	H.Write([]byte(context))
	H.Write(msg)
	mu := make([]byte, 64)
	H.Read(mu)
	return mu
}
