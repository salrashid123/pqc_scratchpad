package main

import (
	"crypto/sha3"
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
	"slices"

	"filippo.io/mldsa"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const (
	maxInputBuffer = 1024
)

var (
	tpmPath    = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	dataToSign = flag.String("datatosign", "foobarbarbarbar", "data to sign")
)

var (
	// id-ML-DSA-65 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2)
	//         country(16) us(840) organization(1) gov(101) csor(3)
	//         nistAlgorithm(4) sigAlgs(3) TBD }

	idmldsa65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
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

	// first create a primary
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

	// then an mldsa key and load it

	mldsaTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgMLDSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgMLDSA,
			&tpm2.TPMSMLDSAParms{
				ParameterSet:    tpm2.TPMIMLDSAParam(tpm2.TPMMLDSA65),
				AllowExternalMu: false, // <<<<<<<<<<<<<   wolfTPM apparently doens't allow "true"
			},
		),
	}

	mldsaResponse, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(mldsaTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create mldsa %v", err)
	}

	mldsaKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
		},
		InPrivate: mldsaResponse.OutPrivate,
		InPublic:  mldsaResponse.OutPublic,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load object %q: %v", *tpmPath, err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: mldsaKey.ObjectHandle,
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	/// read the public key

	pub, err := mldsaResponse.OutPublic.Contents()
	if err != nil {
		log.Fatalf("Failed to get Contents: %v", err)
	}
	kemDetail, err := pub.Parameters.MLDSADetail()
	if err != nil {
		log.Fatalf("Failed to get mldsa details: %v", err)
	}
	fmt.Printf("MLDSA Type: %v\n", kemDetail.ParameterSet)

	mldsaPubKey, err := pub.Unique.MLDSA()
	if err != nil {
		log.Fatalf("Failed to get mldsa unique: %v", err)
	}

	// encode as pem and decode it.  This is optional and added in just as a demonstration
	// we dont' have to do this but presumably, you'll want to send the public key to someone to verify externally
	pux := &SubjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: idmldsa65},
		PublicKey: asn1.BitString{
			Bytes:     mldsaPubKey.Buffer,
			BitLength: len(mldsaPubKey.Buffer) * 8,
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
	fmt.Printf("MLDSA Public Key: \n%s\n", pstr)

	/// ============================ =================================================================================================

	// if you wanted to caluclate the mu externally, you can do that here
	// unfortunately, i can't test this on the TPM becasue wolftpm  doesn't seem to support externalmu
	// mpub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), kemu.Buffer)
	// if err != nil {
	// 	fmt.Printf("error signing %v", err)
	// 	return
	// }
	//mu := computeMu(mpub, []byte(*dataToSign), "")

	data := []byte(*dataToSign)

	log.Printf("======= generate test signature  ========")
	//digest := sha256.Sum256(data)

	// since allowExternalMu: No...
	// If NO, this key cannot be used with
	// TPM2_VerifyDigestSignature() and
	// TPM2_SignDigest().
	// if you have a TPM that does allow this, the signDigest might look like this (again, i can't test this out)
	//  https://github.com/salrashid123/pqc_scratchpad/blob/main/mldsa/std_go/main.go#L168
	// sign := tpm2.SignDigest{
	// 	KeyHandle: tpm2.NamedHandle{
	// 		Handle: mldsaKey.ObjectHandle,
	// 		Name:   mldsaKey.Name,
	// 	},
	// 	Digest: tpm2.TPM2BDigest{
	// 		Buffer: mu,
	// 	},
	// 	Validation: tpm2.TPMTTKHashCheck{
	// 		Tag: tpm2.TPMSTHashCheck,
	// 	},
	// }

	// rspSign, err := sign.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("Failed to Sign: %v", err)
	// }

	//fmt.Println(rspSign)

	// At this point we need to sign using SignSequenceStart + SequenceUpdate + SignSequenceComplete
	objAuth := &tpm2.TPM2BAuth{
		Buffer: []byte(""),
	}
	sessionSign, sessionCloserSign, err := tpm2.HMACSession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Auth(objAuth.Buffer))
	if err != nil {
		log.Fatalf("can't load object %q: %v", *tpmPath, err)
	}
	defer func() {
		_ = sessionCloserSign()
	}()
	sSeqStart, err := tpm2.SignSequenceStart{
		KeyHandle: tpm2.AuthHandle{
			Handle: mldsaKey.ObjectHandle,
			Name:   mldsaKey.Name,
			Auth:   sessionSign,
		},
		Auth: *objAuth,
		Context: tpm2.TPM2BSignatureContext{
			Buffer: []byte(""),
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't start sequence %q: %v", *tpmPath, err)
	}

	authHandle := tpm2.AuthHandle{
		Name:   mldsaKey.Name,
		Handle: sSeqStart.SequenceHandle,
		Auth:   tpm2.PasswordAuth(objAuth.Buffer),
	}

	for len(data) > maxInputBuffer {
		sequenceUpdate := tpm2.SequenceUpdate{
			SequenceHandle: authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: data[:maxInputBuffer],
			},
		}
		_, err = sequenceUpdate.Execute(rwr)
		if err != nil {
			log.Fatalf("can't update sequence %q: %v", *tpmPath, err)
		}
		data = data[maxInputBuffer:]
	}

	sSeqComplete, err := tpm2.SignSequenceComplete{
		SequenceHandle: authHandle,
		KeyHandle: tpm2.NamedHandle{
			Handle: mldsaKey.ObjectHandle,
			Name:   mldsaKey.Name,
		},

		Buffer: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't complete sequence %v", err)
	}

	// now extract the Signature
	s, err := sSeqComplete.Signature.Signature.MLDSA()
	if err != nil {
		log.Fatalf("can't get signature %v", err)
	}

	fmt.Printf("Signature : %s\n", base64.StdEncoding.EncodeToString(s.Signature.Buffer))
	fmt.Println()

	//  ***************** verify
	// since we have the signature, we can verify using the public key and standard go libraries
	mldsaKeyPub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), mldsaPubKey.Buffer)
	if err != nil {
		fmt.Printf("error signing %v", err)
		return
	}
	err = mldsa.Verify(mldsaKeyPub, []byte(*dataToSign), s.Signature.Buffer, &mldsa.Options{
		Context: "",
	})
	if err != nil {
		fmt.Printf("error verifying %v", err)
		return
	}
	fmt.Println("Verified signature using standard go")

	// You can also verify using the TPM and  VerifySequenceStart +  SequenceUpdate + VerifySequenceComplete

	data = []byte(*dataToSign)

	sessVerify, sessionCloserVerify, err := tpm2.HMACSession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Auth(objAuth.Buffer))
	if err != nil {
		log.Fatalf("can't load object %q: %v", *tpmPath, err)
	}
	defer func() {
		_ = sessionCloserVerify()
	}()
	verifySeqStart, err := tpm2.VerifySequenceStart{
		KeyHandle: tpm2.AuthHandle{
			Handle: mldsaKey.ObjectHandle,
			Name:   mldsaKey.Name,
			Auth:   sessVerify,
		},
		Auth: *objAuth,
		Hint: tpm2.TPM2BData{},
		Context: tpm2.TPM2BSignatureContext{
			Buffer: []byte(""),
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't start sequence %v", err)
	}

	authHandleVerify := tpm2.AuthHandle{
		Name:   mldsaKey.Name,
		Handle: verifySeqStart.SequenceHandle,
		Auth:   tpm2.PasswordAuth(objAuth.Buffer),
	}

	if len(data) > maxInputBuffer {
		for len(data) > maxInputBuffer {
			sequenceUpdate := tpm2.SequenceUpdate{
				SequenceHandle: authHandleVerify,
				Buffer: tpm2.TPM2BMaxBuffer{
					Buffer: data[:maxInputBuffer],
				},
			}
			_, err = sequenceUpdate.Execute(rwr)
			if err != nil {
				log.Fatalf("can't update sequence %v", err)
			}
			data = data[maxInputBuffer:]
		}
	} else {
		sequenceUpdate := tpm2.SequenceUpdate{
			SequenceHandle: authHandleVerify,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: data, //data[:maxInputBuffer],
			},
		}
		_, err = sequenceUpdate.Execute(rwr)
		if err != nil {
			log.Fatalf("can't update sequence %v", err)
		}
	}

	verifySequeceResponse, err := tpm2.VerifySequenceComplete{
		SequenceHandle: authHandleVerify,
		KeyHandle: tpm2.NamedHandle{
			Handle: mldsaKey.ObjectHandle,
			Name:   mldsaKey.Name,
		},

		Signature: sSeqComplete.Signature,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't complete sequence %v", err)
	}

	fmt.Printf("Verify validation digest: %s\n", hex.EncodeToString(verifySequeceResponse.Validation.Digest.Buffer))
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
