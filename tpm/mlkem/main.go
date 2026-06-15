package main

import (
	"crypto/mlkem"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var (
	tpmPath    = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	dataToSign = flag.String("datatosign", "foo", "data to sign")
)
var (
	mlkem758OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
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

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {
	flag.Parse()

	log.Println("======= Init  ========")

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)
	// first try to read what the max bufffers
	// 11.3.4 MAX_SHARED_SECRET_SIZE, MAX_MLKEM_CT_SIZE  pg 139 https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-2-Structures_Version-185_pub.pdf
	getCmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTInputBuffer),
		PropertyCount: 1,
	}

	getRsp, err := getCmd.Execute(rwr)
	if err != nil {
		log.Fatalf("can't get capabilities %v", err)
	}

	tp, err := getRsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		log.Fatalf("can't read capabilities%v", err)
	}

	blockSize := int(tp.TPMProperty[0].Value)
	log.Printf("TPM Max buffer %d", blockSize)

	log.Printf("======= createPrimary ========")

	cmdPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}
	primaryKey, err := cmdPrimary.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// create the MLKEM Key and load it

	mlkemTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgMLKEM,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			Decrypt:             true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgMLKEM,
			&tpm2.TPMSMLKEMParms{
				ParameterSet: tpm2.TPMIMLKEMParam(tpm2.TPMMLKEM768),
			},
		),
	}

	kemResponse, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(mlkemTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create mlkem %v", err)
	}

	mlkemKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
		},
		InPrivate: kemResponse.OutPrivate,
		InPublic:  kemResponse.OutPublic,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load object %q: %v", *tpmPath, err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: mlkemKey.ObjectHandle,
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	//*****

	// Now acquire the public part of the kem and create a PEM key
	//  you don't have to create a PEM key but i do that here since IRL you'll send this away

	pub, err := kemResponse.OutPublic.Contents()
	if err != nil {
		log.Fatalf("Failed to get Contents: %v", err)
	}
	kemDetail, err := pub.Parameters.MLKEMDetail()
	if err != nil {
		log.Fatalf("Failed to get rsa details: %v", err)
	}
	fmt.Printf("KEM Type: %v\n", kemDetail.ParameterSet)

	kemu, err := pub.Unique.KEM()
	if err != nil {
		log.Fatalf("Failed to get rsa unique: %v", err)
	}

	// encode as pem
	pux := &SubjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: mlkem758OID},
		PublicKey: asn1.BitString{
			Bytes:     kemu.Buffer,
			BitLength: len(kemu.Buffer) * 8,
		},
	}
	b, err := asn1.Marshal(*pux)
	if err != nil {
		log.Fatal(err)
	}
	pstr := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})
	fmt.Printf("%s\n", pstr)

	// now immediately do the reverse to extract out the private key der
	///  again, the encoding and decoding to PEM is just for demonstration
	pubPEMblock, rest := pem.Decode(pstr)
	if len(rest) != 0 {
		fmt.Printf("trailing data found during pemDecode")
		return
	}
	var pkix SubjectPublicKeyInfo
	if rest, err := asn1.Unmarshal(pubPEMblock.Bytes, &pkix); err != nil {
		log.Fatalf("Failed to unmarshall private key: %v", err)
	} else if len(rest) != 0 {
		fmt.Printf("rest not nil")
		return
	}

	// Encapsulation
	// now use the public key to construct an mlkem primitive
	ek, err := mlkem.NewEncapsulationKey768(pkix.PublicKey.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	// now create an encapsulation
	kemSharedSecret, ciphertext := ek.Encapsulate()
	fmt.Println()
	fmt.Println("Encapsulate")
	fmt.Printf("CipherText %s\n", base64.StdEncoding.EncodeToString(ciphertext))
	fmt.Println()
	fmt.Printf("SharedSecret %s\n", base64.StdEncoding.EncodeToString(kemSharedSecret))

	//*******

	// if for whatever reason you're on the tpm and want to encapsulate there w/o the using the public key...
	// r, err := tpm2.Encapsulate{
	// 	KeyHandle: tpm2.NamedHandle{
	// 		Handle: mlkemKey.ObjectHandle,
	// 		Name:   mlkemKey.Name,
	// 	},
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("can't encapsulate %q: %v", *tpmPath, err)
	// }
	// fmt.Println("Encapsulate")
	// fmt.Printf("CipherText %s\n", base64.StdEncoding.EncodeToString(r.CipherText.Buffer))
	// fmt.Printf("SharedSecret %s\n", base64.StdEncoding.EncodeToString(r.SharedSecret.Buffer))

	///  now decapsulate
	fmt.Println()
	fmt.Println("Decapsulate")
	dcapResp, err := tpm2.Decapsulate{
		KeyHandle: tpm2.NamedHandle{
			Handle: mlkemKey.ObjectHandle,
			Name:   mlkemKey.Name,
		},
		// CipherText:  r.CipherText,
		CipherText: tpm2.TPM2BKEMCipherText{
			Buffer: ciphertext,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't decapsulate %q: %v", *tpmPath, err)
	}
	fmt.Printf("SharedSecret from decapsulation %s\n", base64.StdEncoding.EncodeToString(dcapResp.SharedSecret.Buffer))

}
