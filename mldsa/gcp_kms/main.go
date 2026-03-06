package main

import (
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	cloudkms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"

	"filippo.io/mldsa"
)

var (
	projectID  = flag.String("projectID", "", "ProjectID for where the kms key is held")
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
	parentName := fmt.Sprintf("projects/%s/locations/us-central1/keyRings/tkr1/cryptoKeys/mldsa1/cryptoKeyVersions/1", *projectID)

	kmsClient, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		panic(err)
	}
	defer kmsClient.Close()

	pk, err := kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name:            parentName,
		PublicKeyFormat: kmspb.PublicKey_NIST_PQC})
	if err != nil {
		panic(err)
	}

	var params *mldsa.Parameters
	switch pk.Algorithm {
	case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65:
		params = mldsa.MLDSA65()
	default:
		return
	}

	// write the public key to PEM
	s, err := mldsa.NewPublicKey(params, pk.PublicKey.Data)
	if err != nil {
		panic(err)
	}

	v, err := asn1.Marshal(struct {
		pkix.AlgorithmIdentifier
		asn1.BitString
	}{
		pkix.AlgorithmIdentifier{
			Algorithm: OidMLDSA65,
		},
		asn1.BitString{
			Bytes:     s.Bytes(),
			BitLength: len(s.Bytes()) * 8,
		},
	})
	if err != nil {
		panic(err)
	}

	str := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: v,
	})

	err = os.WriteFile("certs/public.pem", []byte(str), 0644)
	if err != nil {
		panic(err)
	}
	fmt.Println("Public key saved to certs/public")

	// now sign
	req := &kmspb.AsymmetricSignRequest{
		Name: parentName,
		Data: []byte(stringToSign),
	}
	dresp, err := kmsClient.AsymmetricSign(ctx, req)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Signature: \n%s\n", base64.StdEncoding.EncodeToString(dresp.Signature))

	// now regenerate the public key from PEM

	pubPEMblock, rest := pem.Decode([]byte(str))
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

	np, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pkix.PublicKey.Bytes)
	if err != nil {
		panic(err)
	}
	err = mldsa.Verify(np, []byte(stringToSign), dresp.Signature, nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("Verified")
}
