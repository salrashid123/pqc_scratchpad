package main

import (
	"crypto/mlkem"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpmutil"
	tpmrand "github.com/salrashid123/tpmrand"
)

const ()

var (
	private = flag.String("private", "/tmp/private.pem", "PrivateKey")
	public  = flag.String("public", "/tmp/public.pem", "PublicKey")
	keyType = flag.String("keyType", "mlkem768", "KeyType must be mlkem768 or mlkem1024")
)

var (
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

/*

### start swtpm
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm && swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2341 --ctrl type=tcp,port=2342 --flags not-need-init,startup-clear --log level=2
export TPM2TOOLS_TCTI="swtpm:port=2341"
*/

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2341", "Path to the TPM device (character device or a Unix socket).")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.Get()
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {
	flag.Parse()

	var privteKeyBytes []byte
	var publicKeyBytes []byte

	// A) generate key in code
	// nk, err := mlkem.GenerateKey768()
	// if err != nil {
	// 	fmt.Printf("error creating encapsulation key %v", err)
	// 	os.Exit(1)
	// }

	// B) generate key using default rand reader for bytes
	externalSeed := make([]byte, mlkem.SeedSize) // mlkem.SeedSize is 64 bytes
	// _, err := rand.Read(externalSeed)
	// if err != nil {
	// 	log.Fatalf("failed to create get random seed: %v", err)
	// }

	// C) generate a key using a TPM as the rand source
	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		fmt.Printf("Unable to open TPM at %s", *tpmPath)
	}
	defer rwc.Close()

	r, err := tpmrand.NewTPMRand(&tpmrand.Reader{
		TpmDevice: rwc,
	})
	_, err = r.Read(externalSeed) // Fill it with random data
	if err != nil {
		log.Fatalf("failed to create get random seed: %v", err)
	}

	fmt.Printf("%s\n", hex.EncodeToString(externalSeed))

	// D) generate key using a given hex string statically
	// externalSeed, err = hex.DecodeString("e0c311ae778d5208fc799d1f50e278ba1b86762ab463620bf4d1affd415e75c9a520b688a19ebb7b997c1a03cb3e9e170ae8b13f3c09776e58fad1f23d08ec05")
	// if err != nil {
	// 	log.Fatalf("failed decoding hex: %v", err)
	// }

	// now create the key
	nk, err := mlkem.NewDecapsulationKey768(externalSeed)
	if err != nil {
		log.Fatalf("failed to create decapsulation key from seed: %v", err)
	}

	fmt.Println("ML-KEM key pair successfully derived from external seed.")
	fmt.Printf("Decapsulation Key (seed) size: %d bytes\n", len(nk.Bytes()))
	fmt.Printf("Encapsulation Key size: %d bytes\n", len(nk.EncapsulationKey().Bytes()))

	privateKey := PrivateKeyInfo{
		Version: 0,
		PrivateKeyAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: mlkem768_OID,
		},
		PrivateKey: nk.Bytes(),
	}
	pkb, err := asn1.Marshal(privateKey)
	if err != nil {
		fmt.Printf("error marshalling key %v", err)
		os.Exit(1)
	}
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkb,
	}
	privteKeyBytes = pem.EncodeToMemory(privateKeyBlock)

	// encode public key

	nk.EncapsulationKey().Bytes()
	publicKey := SubjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: mlkem768_OID,
		},
		PublicKey: asn1.BitString{
			BitLength: len(nk.EncapsulationKey().Bytes()),
			Bytes:     nk.EncapsulationKey().Bytes(),
		},
	}
	ppkb, err := asn1.Marshal(publicKey)
	if err != nil {
		fmt.Printf("error marshalling key %v", err)
		os.Exit(1)
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: ppkb,
	}
	publicKeyBytes = pem.EncodeToMemory(publicKeyBlock)

	fmt.Printf("raw private key \n%s\n", privteKeyBytes)
	fmt.Printf("raw public key \n%s\n", publicKeyBytes)

	err = os.WriteFile(*private, privteKeyBytes, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing private key to file %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(*public, publicKeyBytes, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing public key to file %v\n", err)
		os.Exit(1)
	}

	/// ***********************************************

	// encapsulate
	rpub_bytes, err := os.ReadFile(*public)
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
	if pkix.Algorithm.Algorithm.Equal(mlkem768_OID) {
		fmt.Println("Found MLKEM758 in public key")

		ek, err := mlkem.NewEncapsulationKey768(pkix.PublicKey.Bytes)
		if err != nil {
			panic(err)
		}
		kemSharedSecret, cipherText = ek.Encapsulate()
	}

	fmt.Printf("sharedSecret %s \n", base64.StdEncoding.EncodeToString(kemSharedSecret))
	fmt.Printf("cipherText %s \n", base64.StdEncoding.EncodeToString(cipherText))

	// decapsulate
	// now read the privarte key back from pem
	privBytes, err := os.ReadFile(*private)
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

	if rprkix.PrivateKeyAlgorithm.Algorithm.Equal(mlkem768_OID) {
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
