package main

import (
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"filippo.io/mldsa"
)

/*
export AWS_ACCESS_KEY_ID=redacted
export AWS_SECRET_ACCESS_KEY=redacted
export AWS_REGION="us-east-2"
*/

var (
	keyID      = flag.String("keyID", "37aca4ea-3915-441f-b03d-d90bad1eb45a", "kms key id")
	awsRegion  = flag.String("region", "us-east-2", "AWS Region")
	OidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	OidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	OidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
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

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	kmsClient := kms.NewFromConfig(cfg)

	pubOut, err := kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: keyID,
	})
	if err != nil {
		log.Fatalf("error getting publci key %v\n", err)
	}

	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubOut.PublicKey,
	}

	publicKeyPEM := pem.EncodeToMemory(&publicKeyBlock)

	fmt.Println(string(publicKeyPEM))

	err = os.WriteFile("certs/public.pem", publicKeyPEM, 0644)
	if err != nil {
		panic(err)
	}
	fmt.Println("Public key saved to certs/public")

	// now sign
	input := &kms.SignInput{
		KeyId:            keyID,
		Message:          []byte(stringToSign),
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecMlDsaShake256,
	}

	dresp, err := kmsClient.Sign(ctx, input)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Signature: \n%s\n", base64.StdEncoding.EncodeToString(dresp.Signature))

	// now regenerate the public key from PEM

	s, err := GetSubjectPublicKeyInfoFromPEM(publicKeyPEM)
	if err != nil {
		panic(err)
	}
	err = mldsa.Verify(s, []byte(stringToSign), dresp.Signature, nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("Verified")
}

func GetSubjectPublicKeyInfoFromPEM(in []byte) (*mldsa.PublicKey, error) {

	pubPEMblock, rest := pem.Decode(in)
	if len(rest) != 0 {
		return &mldsa.PublicKey{}, fmt.Errorf("trailing data found during pemDecode")
	}

	var si SubjectPublicKeyInfo

	_, err := asn1.Unmarshal(pubPEMblock.Bytes, &si)
	if err != nil {
		return &mldsa.PublicKey{}, fmt.Errorf("Error unmarshalling pem key %v", err)
	}
	var params *mldsa.Parameters
	if si.Algorithm.Algorithm.Equal(OidMLDSA44) {
		params = mldsa.MLDSA44()
	} else if si.Algorithm.Algorithm.Equal(OidMLDSA65) {
		params = mldsa.MLDSA65()
	} else if si.Algorithm.Algorithm.Equal(OidMLDSA87) {
		params = mldsa.MLDSA87()
	} else {
		return &mldsa.PublicKey{}, fmt.Errorf("unsupported algorithm %s\n", si.Algorithm.Algorithm)
	}
	s, err := mldsa.NewPublicKey(params, si.PublicKey.Bytes)
	if err != nil {
		return &mldsa.PublicKey{}, fmt.Errorf("Error recreating public key %v", err)
	}
	return s, nil

}
