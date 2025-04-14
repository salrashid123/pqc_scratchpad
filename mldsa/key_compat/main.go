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
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const ()

var ()

func main() {
	flag.Parse()

	ppu, ppr, err := mldsa65.GenerateKey(rand.Reader)
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

	err = os.WriteFile("certs/ml-dsa-65-public.pem", puPem, 0644)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile("certs/ml-dsa-65-private.pem", prPem, 0644)
	if err != nil {
		panic(err)
	}
	data := []byte("foo")

	sig, err := ppr.Sign(rand.Reader, data, crypto.Hash(0))
	if err != nil {
		panic(err)
	}
	log.Printf("Signature %s", base64.StdEncoding.EncodeToString(sig))

	ok := mldsa65.Verify(ppu, data, nil, sig)
	if !ok {
		log.Printf("Error verifying")
	}
	log.Println("Signature Verified")

	// now convert

	fmt.Println("converting public key to openssl compatible format (see https://github.com/cloudflare/circl/issues/535 )")

	//  ** Public

	pb, err := os.ReadFile("certs/ml-dsa-65-public.pem")
	if err != nil {
		panic(err)
	}

	skp, err := pki.UnmarshalPEMPublicKey(pb)
	if err != nil {
		panic(err)
	}

	p2, err := MarshalPEMPublicKey(skp)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile("certs/public_compat.pem", []byte(p2), 0644)
	if err != nil {
		panic(err)
	}

	// ** Private

	prb, err := os.ReadFile("certs/ml-dsa-65-private.pem")
	if err != nil {
		panic(err)
	}

	skpr, err := pki.UnmarshalPEMPrivateKey(prb)
	if err != nil {
		panic(err)
	}

	pr2, err := MarshalPEMPrivateKey(skpr)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile("certs/private_compat.pem", []byte(pr2), 0644)
	if err != nil {
		panic(err)
	}

	fmt.Println("Public key saved to certs/public_compat")

}

func MarshalPEMPublicKey(pk sign.PublicKey) ([]byte, error) {
	data, err := MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, err
	}
	str := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	})
	return str, nil
}

func MarshalPKIXPublicKey(pk sign.PublicKey) ([]byte, error) {
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
		o = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
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

func MarshalPEMPrivateKey(pk sign.PrivateKey) ([]byte, error) {
	data, err := MarshalPKIXPrivateKey(pk)
	if err != nil {
		return nil, err
	}
	str := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: data,
	})
	return str, nil
}

type pkixPrivKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func MarshalPKIXPrivateKey(pk sign.PrivateKey) ([]byte, error) {
	data, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// static const OSSL_PARAM param_sigalg_list[][10] = {
	// 	TLS_SIGALG_ENTRY("mldsa44", "ML-DSA-44", "2.16.840.1.101.3.4.17", 0),
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
		o = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
	default:
		return nil, fmt.Errorf("unknown key type %s", pk.Scheme().Name())
	}

	pk.Scheme().Name()

	return asn1.Marshal(pkixPrivKey{
		0,
		pkix.AlgorithmIdentifier{
			Algorithm: o,
		},
		data,
	})

}
