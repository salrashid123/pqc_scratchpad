package main

import (
	"crypto/mlkem"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

/*
https://github.com/openssl/openssl/blob/master/doc/man7/EVP_PKEY-ML-KEM.pod


$ openssl genpkey  -algorithm mlkem768   -out priv-ml-kem-768.pem
$ openssl pkey -provider default -in priv-ml-kem-768.pem -pubout -out pub-ml-kem-768.pem

$ openssl pkey -provparam ml-kem.output_formats=seed-only  -in  priv-ml-kem-768.pem -out seed-only.pem

$  openssl asn1parse -inform PEM -in seed-only.pem
    0:d=0  hl=2 l=  84 cons: SEQUENCE
    2:d=1  hl=2 l=   1 prim: INTEGER           :00
    5:d=1  hl=2 l=  11 cons: SEQUENCE
    7:d=2  hl=2 l=   9 prim: OBJECT            :ML-KEM-768
   18:d=1  hl=2 l=  66 prim: OCTET STRING      [HEX DUMP]:804067E6BC81C8468080...

openssl asn1parse -inform PEM -in pub-ml-kem-768.pem
    0:d=0  hl=4 l=1202 cons: SEQUENCE
    4:d=1  hl=2 l=  11 cons: SEQUENCE
    6:d=2  hl=2 l=   9 prim: OBJECT            :ML-KEM-768
   17:d=1  hl=4 l=1185 prim: BIT STRING
*/

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

	pubBytes, err := os.ReadFile("certs/pub-ml-kem-768.pem")
	if err != nil {
		panic(err)
	}
	pubPEMblock, rest := pem.Decode(pubBytes)
	if len(rest) != 0 {
		fmt.Printf("trailing data found during pemDecode")
		return
	}
	var pkix pkixPubKey
	if rest, err := asn1.Unmarshal(pubPEMblock.Bytes, &pkix); err != nil {
		panic(err)
	} else if len(rest) != 0 {
		fmt.Printf("rest not nil")
		return
	}

	var cipherText []byte
	var kemSharedSecret []byte
	if pkix.Algorithm.Algorithm.Equal(mlkem758OID) {
		fmt.Println("Found MLKEM758")

		ek, err := mlkem.NewEncapsulationKey768(pkix.PublicKey.Bytes)
		if err != nil {
			panic(err)
		}
		kemSharedSecret, cipherText = ek.Encapsulate()
	}

	fmt.Printf("SharedSecret: kemShared (%s) \n", base64.StdEncoding.EncodeToString(kemSharedSecret))

	/// ********************************************

	privBytes, err := os.ReadFile("certs/bare-seed.pem")
	if err != nil {
		panic(err)
	}
	privPEMblock, rest := pem.Decode(privBytes)
	if len(rest) != 0 {
		fmt.Printf("trailing data found during pemDecode")
		return
	}
	var prkix pkixPrivKey
	if rest, err := asn1.Unmarshal(privPEMblock.Bytes, &prkix); err != nil {
		panic(err)
	} else if len(rest) != 0 {
		fmt.Printf("rest not nil")
	}

	if prkix.Algorithm.Algorithm.Equal(mlkem758OID) {
		fmt.Println("Found MLKEM758")

		// https://github.com/openssl/openssl/blob/ba90c491254fd3cee8a2f791fc191dcff27036c1/providers/implementations/encode_decode/ml_kem_codecs.c#L52C34-L52C38
		// prefix seed-only: 0x8040  so remove first two bytes
		// static const ML_COMMON_PKCS8_FMT ml_kem_768_p8fmt[NUM_PKCS8_FORMATS] = {
		// 	{ "seed-priv",  0x09aa, 0, 0x308209a6, 0x0440, 6, 0x40, 0x04820960, 0x4a, 0x0960, 0,      0,     },
		// 	{ "priv-only",  0x0964, 0, 0x04820960, 0,      0, 0,    0,          0x04, 0x0960, 0,      0,     },
		// 	{ "oqskeypair", 0x0e04, 0, 0x04820e00, 0,      0, 0,    0,          0x04, 0x0960, 0x0964, 0x04a0 },
		// 	{ "seed-only",  0x0042, 2, 0x8040,     0,      2, 0x40, 0,          0,    0,      0,      0,     },
		// 	{ "bare-priv",  0x0960, 4, 0,          0,      0, 0,    0,          0,    0x0960, 0,      0,     },
		// 	{ "bare-seed",  0x0040, 4, 0,          0,      0, 0x40, 0,          0,    0,      0,      0,     },
		// };

		// openssl pkey -provparam ml-kem.output_formats=bare-seed  -in  priv-ml-kem-768.pem -out bare-seed.pem

		// if bytes.Equal(prkix.PrivateKey[:2], []byte{80, 40}) {
		// 	log.Printf("private key not `seed-only`")
		// 	return
		// }

		// dk, err := mlkem.NewDecapsulationKey768(prkix.PrivateKey[2:])
		// if err != nil {
		// 	log.Fatal(err)
		// }

		// openssl pkey -provparam ml-kem.output_formats=bare-seed  -in  priv-ml-kem-768.pem -out bare-seed.pem
		dk, err := mlkem.NewDecapsulationKey768(prkix.PrivateKey)
		if err != nil {
			panic(err)
		}

		sharedKey, err := dk.Decapsulate(cipherText)
		if err != nil {
			panci(err)
		}
		fmt.Printf("SharedSecret: kemShared (%s) \n", base64.StdEncoding.EncodeToString(sharedKey))
	}

}
