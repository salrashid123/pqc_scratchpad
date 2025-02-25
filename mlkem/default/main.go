package main

import (
	"crypto/mlkem"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

func main() {

	mk, err := mlkem.GenerateKey768()
	if err != nil {
		log.Fatal(err)
	}

	pubbin := mk.EncapsulationKey().Bytes()
	privbin := mk.Bytes()

	// err = os.WriteFile("bpub.dat", pubbin, 0644)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// err = os.WriteFile("bpriv.dat", privbin, 0644)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	pu, err := mlkem.NewEncapsulationKey768(pubbin)
	if err != nil {
		log.Fatal(err)
	}

	shared, ciphertext := pu.Encapsulate()
	fmt.Fprintf(os.Stdout, "SharedSecret: kemShared (%s) \n", hex.EncodeToString(shared))

	// now read the bytes to decapsulate
	pr, err := mlkem.NewDecapsulationKey768(privbin)
	if err != nil {
		log.Fatal(err)
	}

	recovered, err := pr.Decapsulate(ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stdout, "SharedSecret: kemShared (%s) \n", hex.EncodeToString(recovered))

}
