package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"filippo.io/mldsa"
	"github.com/hashicorp/vault/api"
)

var (
	vault_token = flag.String("vault_token", "hvs.CAESIFlBXnLygT9UdIVU92IitpBl_Ob4MsVgZbLrV3wcmn69GicKImh2cy5IZW9PTmZmZXpSZmlyaldRZmRnbmhySm4uYnFBcFoQ1VE", "vault token")
	vault_addr  = flag.String("vault_addr", "https://vault-cluster-public-vault-c305537c.8639af5b.z1.hashicorp.cloud:8200", "vault address")
	namespace   = flag.String("namespace", "admin", "vault namespace")
	keyName     = flag.String("keyName", "my-sign-key", "name of the Key")

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

	client, err := getVaultClient()
	if err != nil {
		log.Fatal(err)
	}

	k, err := getKey(client, *keyName)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("bar")
	s, err := signData(client, *keyName, msg)
	if err != nil {
		log.Fatal(err)
	}

	sig := strings.Split(s, ":")[2]

	sigB, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		log.Fatal(err)
	}
	err = mldsa.Verify(k, msg, sigB, &mldsa.Options{})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("verified\n")
}

func getVaultClient() (*api.Client, error) {
	config := api.DefaultConfig()
	config.Address = *vault_addr

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("error initializing vault client: %w", err)
	}

	// Set the enterprise client token
	client.SetToken(*vault_token)

	client.SetNamespace(*namespace)

	return client, nil
}

func getKey(client *api.Client, lkeyName string) (*mldsa.PublicKey, error) {
	path := fmt.Sprintf("transit/keys/%s", lkeyName)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	var pk *mldsa.PublicKey
	var keytype string
	if data, ok := secret.Data["keys"].(map[string]interface{}); ok {

		if k2, exists := data["1"].(map[string]interface{}); exists {

			if namestr, exists := k2["name"].(string); exists {
				keytype = namestr
			}
			fmt.Println(keytype)
			if pubKeyStr, exists := k2["public_key"].(string); exists {
				pkb, err := base64.StdEncoding.DecodeString(pubKeyStr)
				if err != nil {
					fmt.Printf("Error marshallling %v", err)
					return nil, err
				}

				pu := SubjectPublicKeyInfo{
					Algorithm: pkix.AlgorithmIdentifier{
						Algorithm: OidMLDSA65,
					},
					PublicKey: asn1.BitString{
						Bytes: pkb,
					},
				}

				publicDER, err := asn1.Marshal(pu)
				if err != nil {
					fmt.Printf("Error marshallling %v", err)
					return nil, err
				}

				if err := pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}); err != nil {
					fmt.Printf("Failed to write data: %s", err)
					return nil, err
				}

				pk, err = mldsa.NewPublicKey(mldsa.MLDSA65(), pkb)
				if err != nil {
					fmt.Printf("error signing %v", err)
					return nil, err
				}
			}

		} else {
			log.Fatalf("Public key version '1' not found in response")
		}
	} else {
		log.Fatalf("Invalid response format from Transit API")
	}

	return pk, nil
}

func signData(client *api.Client, lkeyName string, payload []byte) (string, error) {
	path := fmt.Sprintf("transit/sign/%s", lkeyName)
	data := map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString(payload),
	}

	secret, err := client.Logical().Write(path, data)
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %w", err)
	}

	signature, ok := secret.Data["signature"].(string)
	if !ok {
		return "", fmt.Errorf("signature not found in vault response")
	}

	return signature, nil
}

func verifySignature(client *api.Client, keyName, signature string, payload []byte) (bool, error) {
	path := fmt.Sprintf("/v1/transit/sign/%s", keyName) // Verify endpoint is /v1/transit/verify/%s
	data := map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString(payload),
		"signature": signature,
	}

	secret, err := client.Logical().Write(path, data)
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %w", err)
	}

	isValid, ok := secret.Data["valid"].(bool)
	if !ok {
		return false, fmt.Errorf("validity flag not found in vault response")
	}

	return isValid, nil
}
