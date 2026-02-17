package main

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

var (
	mlkem758OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
)

func main() {

	pk, sk, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}

	// fmt.Printf("Public Key Length: %d bytes\n", len(pkBytes))
	// fmt.Printf("Secret Key Length: %d bytes\n", len(skBytes))
	// // Example of outputting the first 16 bytes of the public key
	// fmt.Printf("Public Key (hex): %x...\n", pkBytes[:16])

	// write the public private to PEM files

	pk2, err := mlkem768.Scheme().UnmarshalBinaryPublicKey(pkBytes)
	if err != nil {
		log.Fatal(err)
	}
	/// ********************************* READ

	// ciphertext := make([]byte, mlkem768.CiphertextSize)
	// sharedSecret := make([]byte, mlkem768.SharedKeySize)

	ciphertext, sharedSecret, err := mlkem768.Scheme().Encapsulate(pk2)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ciphertext:  %s\n", hex.EncodeToString(ciphertext))
	fmt.Printf("sharedtext:  %s\n", hex.EncodeToString(sharedSecret))

	sk2, err := mlkem768.Scheme().UnmarshalBinaryPrivateKey(skBytes)
	if err != nil {
		log.Fatal(err)
	}
	ss2, err := mlkem768.Scheme().Decapsulate(sk2, ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("sharedtext:  %s\n", hex.EncodeToString(ss2))

}
