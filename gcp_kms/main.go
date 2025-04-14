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

	"github.com/cloudflare/circl/pki"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

var (
	projectID = flag.String("projectID", "", "ProjectID for where the kms key is held")
)

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

	presp, err := kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name:            parentName,
		PublicKeyFormat: kmspb.PublicKey_NIST_PQC})
	if err != nil {
		panic(err)
	}

	pubb := presp.PublicKey.Data
	s, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(pubb)
	if err != nil {
		panic(err)
	}

	publicKey, err := pki.MarshalPEMPublicKey(s)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile("certs/public.pem", []byte(publicKey), 0644)
	if err != nil {
		panic(err)
	}
	fmt.Println("Public key saved to certs/public")

	//***

	fmt.Println("converting public key to openssl compatible format (see https://github.com/cloudflare/circl/issues/535 )")
	p2, err := marshalPEMPublicKey(s)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile("certs/public_compat.pem", []byte(p2), 0644)
	if err != nil {
		panic(err)
	}
	fmt.Println("Public key saved to certs/public_compat")
	//***

	req := &kmspb.AsymmetricSignRequest{
		Name: parentName,
		Data: []byte(stringToSign),
	}
	dresp, err := kmsClient.AsymmetricSign(ctx, req)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Signature: \n%s\n", base64.StdEncoding.EncodeToString(dresp.Signature))

	ok := mldsa65.Verify(s.(*mldsa65.PublicKey), []byte(stringToSign), nil, dresp.Signature)
	if !ok {
		panic(err)
	}
	fmt.Printf("\n%t\n", ok)
}

func marshalPEMPublicKey(pk sign.PublicKey) ([]byte, error) {
	data, err := marshalPKIXPublicKey(pk)
	if err != nil {
		return nil, err
	}
	str := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	})
	return str, nil
}

func marshalPKIXPublicKey(pk sign.PublicKey) ([]byte, error) {
	data, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// static const OSSL_PARAM param_sigalg_list[][10] = {
	// 	TLS_SIGALG_ENTRY("mldsa44", "ML-DSA-44", "2.16.840.1.101.3.4.3.17", 0),
	// 	TLS_SIGALG_ENTRY("mldsa65", "ML-DSA-65", "2.16.840.1.101.3.4.3.18", 1),
	// 	TLS_SIGALG_ENTRY("mldsa87", "ML-DSA-87", "2.16.840.1.101.3.4.3.19", 2),
	// };
	var o asn1.ObjectIdentifier
	switch pk.Scheme().Name() {
	case "ML-DSA-44":
		o = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	case "ML-DSA-65":
		o = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	case "ML-DSA-87":
		o = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	default:
		return nil, fmt.Errorf("unknown key type %s", pk.Scheme().Name())
	}

	pk.Scheme().Name()
	return asn1.Marshal(struct {
		pkix.AlgorithmIdentifier
		asn1.BitString
	}{
		pkix.AlgorithmIdentifier{
			Algorithm: o,
		},
		asn1.BitString{
			Bytes:     data,
			BitLength: len(data) * 8,
		},
	})
}
