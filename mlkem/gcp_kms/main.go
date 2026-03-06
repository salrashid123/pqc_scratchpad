package main

import (
	"context"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"

	cloudkms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"golang.org/x/crypto/hkdf"
)

var (
	publicKey = flag.String("publicKey", "certs/public.pem", "Public Key")
	kmsURI    = flag.String("kmsURI", "projects/core-eso/locations/global/keyRings/kem_kr/cryptoKeys/kem_key_1/cryptoKeyVersions/1", "PrivateKey Key on KMS")

	mlkem512_OID  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}
	mlkem768_OID  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	mlkem1024_OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
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

	flag.Parse()

	ctx := context.Background()

	// get the pubic key
	// you ofcourse dont' have to use the kmsclient to get the public key ...you can just use the PEM file
	kmsClient, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		panic(err)
	}
	defer kmsClient.Close()

	pk, err := kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name:            *kmsURI,
		PublicKeyFormat: kmspb.PublicKey_NIST_PQC})
	if err != nil {
		panic(err)
	}

	v, err := asn1.Marshal(struct {
		pkix.AlgorithmIdentifier
		asn1.BitString
	}{
		pkix.AlgorithmIdentifier{
			Algorithm: mlkem768_OID,
		},
		asn1.BitString{
			Bytes:     pk.PublicKey.Data,
			BitLength: len(pk.PublicKey.Data) * 8,
		},
	})
	if err != nil {
		panic(err)
	}

	str := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: v,
	})

	err = os.WriteFile(*publicKey, []byte(str), 0644)
	if err != nil {
		panic(err)
	}

	// now get a shared secret and run a kdf
	// if you are encrypting some data using mlkdem shared secret,
	//  the suggestion is to acquire a derivedKey from the sharedSecert via KDF

	var kemCipherText []byte
	var kemSharedSecret []byte

	ek, err := mlkem.NewEncapsulationKey768(pk.PublicKey.Data)
	if err != nil {
		panic(err)
	}

	kemSharedSecret, kemCipherText = ek.Encapsulate()

	// run a kdf on the sharedSecret
	salt := make([]byte, sha256.New().Size())
	_, err = rand.Read(salt)
	if err != nil {
		panic(err)
	}

	kdf := hkdf.New(sha256.New, kemSharedSecret, salt, nil)
	derivedKey := make([]byte, 32)
	_, err = io.ReadFull(kdf, derivedKey)
	if err != nil {
		panic(err)
	}

	fmt.Printf("DerivedKey: %s\n", hex.EncodeToString(derivedKey))

	/// now decapsulate and then run a another kdef to get the derivedKey

	resp, err := kmsClient.Decapsulate(ctx, &kmspb.DecapsulateRequest{
		Name:       *kmsURI,
		Ciphertext: kemCipherText,
	})

	sharedSecret2 := resp.SharedSecret

	// now run kdf on the sharedSecret again
	kdf2 := hkdf.New(sha256.New, sharedSecret2, salt, nil)
	derivedKey2 := make([]byte, 32)
	_, err = io.ReadFull(kdf2, derivedKey2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("DerivedKey: %s\n, ", hex.EncodeToString(derivedKey2))
}
