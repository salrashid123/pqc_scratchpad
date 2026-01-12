package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"io"
	"os"

	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"time"

	keywrap "github.com/nickball/go-aes-key-wrap"
	"golang.org/x/crypto/hkdf"
)

const ()

var (

	//OID_MLKEM512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}
	OID_MLKEM768 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}

	OID_AES_GCM_256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
	OID_AES_GCM_128 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}

	OID_AES_128_KEYWRAP = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 5}

	OID_EnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}

	OID_KEMRecipientInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 13, 3}
	// Content type OIDs

	OID_HKDF_SHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 3, 28}

	OID_PKCS7_DATA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

	OID_AUTH_AuthEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 23}
)

//	EnvelopedData ::= SEQUENCE {
//		version CMSVersion,
//		originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
//		recipientInfos RecipientInfos,
//		encryptedContentInfo EncryptedContentInfo,
//		unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
type EnvelopedData struct {
	Version          int
	OriginatorInfo   asn1.RawValue        `asn1:"optional,tag:0"`
	RecipientInfos   []RecipientInfo      `asn1:"set,choice"`
	ECI              EncryptedContentInfo ``
	UnprotectedAttrs []Attribute          `asn1:"set,optional,tag:1"`
}

// https://datatracker.ietf.org/doc/html/rfc3852#page-19
//
//	OtherRecipientInfo ::= SEQUENCE {
//	  oriType OBJECT IDENTIFIER,
//	  oriValue ANY DEFINED BY oriType }
type OtherRecipientInfo struct {
	OriType  asn1.ObjectIdentifier
	OriValue interface{} `asn1:"implicit"` // // `asn1:"optional"` // asn1.RawValue
}

//  CMSORIforKEMOtherInfo ::= SEQUENCE {
//    wrap KeyEncryptionAlgorithmIdentifier,
//    kekLength INTEGER (1..65535),
//    ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL }

type CMSORIforKEMOtherInfo struct {
	Wrap      pkix.AlgorithmIdentifier
	KEKLength int
	UKM       []byte `asn1:"explicit,optional,tag:1"`
}

//	RecipientInfo ::= CHOICE {
//		ktri KeyTransRecipientInfo,
//		kari [1] KeyAgreeRecipientInfo,
//		kekri [2] KEKRecipientInfo,
//		pwri [3] PasswordRecipientInfo,
//		ori [4] OtherRecipientInfo }
type RecipientInfo struct {
	KTRI  KeyTransRecipientInfo `asn1:"optional"`
	KARI  KeyAgreeRecipientInfo `asn1:"optional,tag:1"` //KeyAgreeRecipientInfo
	KEKRI asn1.RawValue         `asn1:"optional,tag:2"`
	PWRI  asn1.RawValue         `asn1:"optional,tag:3"`
	ORI   OtherRecipientInfo    `asn1:"optional,tag:4"` // asn1.RawValue         `asn1:"optional,tag:4"`
}

// UserKeyingMaterial ::= OCTET STRING
type UserKeyingMaterial []byte

type KEMRecipientInfo struct {
	Version                int
	Recipient              asn1.RawValue            `asn1:"choice"` // RecipientIdentifier      `asn1:"choice,implicit"`
	KEMAlgorithm           pkix.AlgorithmIdentifier `asn1:"implicit,tag:0"`
	KEMCipherText          []byte
	KeyDerivationAlgorithm pkix.AlgorithmIdentifier
	KekLength              int
	UserKeyingMaterial     []byte `asn1:"explicit,tag:1,optional"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

//	AuthEnvelopedData ::= SEQUENCE {
//		version CMSVersion,
//		originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
//		recipientInfos RecipientInfos,
//		authEncryptedContentInfo EncryptedContentInfo,
//
// /	authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
//
//	mac MessageAuthenticationCode,
//	unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }
//
// https://tools.ietf.org/html/rfc5083##section-2.1
type AuthEnvelopedData struct {
	Version        int
	OriginatorInfo asn1.RawValue `asn1:"optional,implicit,tag:0"`
	RecipientInfos RecipientInfo `asn1:"set,implicit"`
	AECI           EncryptedContentInfo
	AauthAttrs     []Attribute `asn1:"set,optional,implicit,tag:1"`
	MAC            []byte
	UnAauthAttrs   []Attribute `asn1:"set,optional,implicit,tag:2"`
}

//	KeyTransRecipientInfo ::= SEQUENCE {
//		version CMSVersion,  -- always set to 0 or 2
//		rid RecipientIdentifier,
//		keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//		encryptedKey EncryptedKey }
type KeyTransRecipientInfo struct {
	Version                int
	Rid                    RecipientIdentifier `asn1:"choice"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

//	KeyAgreeRecipientInfo ::= SEQUENCE {
//		version CMSVersion,  -- always set to 3
//		originator [0] EXPLICIT OriginatorIdentifierOrKey,
//		ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
//		keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//		recipientEncryptedKeys RecipientEncryptedKeys }
type KeyAgreeRecipientInfo struct {
	Version                int
	Originator             OriginatorIdentifierOrKey `asn1:"explicit,choice,tag:0"`
	UKM                    []byte                    `asn1:"explicit,optional,tag:1"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier  ``
	RecipientEncryptedKeys []RecipientEncryptedKey   `asn1:"sequence"` //RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
}

//	RecipientEncryptedKey ::= SEQUENCE {
//		rid KeyAgreeRecipientIdentifier,
//		encryptedKey EncryptedKey }
type RecipientEncryptedKey struct {
	RID          KeyAgreeRecipientIdentifier `asn1:"choice"`
	EncryptedKey []byte
}

//	KeyAgreeRecipientIdentifier ::= CHOICE {
//		issuerAndSerialNumber IssuerAndSerialNumber,
//		rKeyId [0] IMPLICIT RecipientKeyIdentifier }
type KeyAgreeRecipientIdentifier struct {
	IAS    IssuerAndSerialNumber  `asn1:"optional"`
	RKeyID RecipientKeyIdentifier `asn1:"optional,tag:0"`
}

//	RecipientKeyIdentifier ::= SEQUENCE {
//		subjectKeyIdentifier SubjectKeyIdentifier,
//		date GeneralizedTime OPTIONAL,
//		other OtherKeyAttribute OPTIONAL }
type RecipientKeyIdentifier struct {
	SubjectKeyIdentifier []byte            //SubjectKeyIdentifier ::= OCTET STRING
	Date                 time.Time         `asn1:"optional"`
	Other                OtherKeyAttribute `asn1:"optional"`
}

//	OtherKeyAttribute ::= SEQUENCE {
//		keyAttrId OBJECT IDENTIFIER,
//		keyAttr ANY DEFINED BY keyAttrId OPTIONAL }
type OtherKeyAttribute struct {
	KeyAttrID asn1.ObjectIdentifier
	KeyAttr   asn1.RawValue `asn1:"optional"`
}

//	OriginatorIdentifierOrKey ::= CHOICE {
//		issuerAndSerialNumber IssuerAndSerialNumber,
//		subjectKeyIdentifier [0] SubjectKeyIdentifier,
//		originatorKey [1] OriginatorPublicKey }
type OriginatorIdentifierOrKey struct {
	IAS           IssuerAndSerialNumber `asn1:"optional"`
	SKI           []byte                `asn1:"optional,tag:0"`
	OriginatorKey OriginatorPublicKey   `asn1:"optional,tag:1"`
}

//	OriginatorPublicKey ::= SEQUENCE {
//		algorithm AlgorithmIdentifier,
//		publicKey BIT STRING
type OriginatorPublicKey struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
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

//	EncryptedContentInfo ::= SEQUENCE {
//		contentType ContentType,
//		contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
//		encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
type EncryptedContentInfo struct {
	Raw                        asn1.RawContent
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"` //[]byte `asn1:"optional,implicit,tag:0"` //
}

type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0"`
}

type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type pkixPrivKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// type pkixPubKey struct {
// 	Algorithm pkix.AlgorithmIdentifier
// 	PublicKey asn1.BitString
// }

// SubjectKeyIdentifier ::= OCTET STRING
type SubjectKeyIdentifier []byte

type RecipientIdentifier struct {
	IssuerAndSerialNumber asn1.RawValue        `asn1:"optional"`
	SubjectKeyIdentifier  SubjectKeyIdentifier `asn1:"tag:0,optional"`
}

// https://github.com/avast/apkverifier/blob/master/fullsailor/pkcs7/pkcs7.go#L809
type aesGCMParameters struct {
	Nonce  []byte //`asn1:"tag:4"`
	ICVLen int
}

func marshalEncryptedContent(content []byte) asn1.RawValue {
	asn1Content, _ := asn1.Marshal(content)
	return asn1.RawValue{Tag: 0, Class: asn1.ClassContextSpecific, Bytes: asn1Content, IsCompound: false}
}

var (
	kemPrivate = `-----BEGIN PRIVATE KEY-----
MFICAQAwCwYJYIZIAWUDBAQCBEBn5ryByEaAgALO1xu/ioxBla8qN2FMTIHAtklg
Gym+qjPL/yFKDcRZdJNiyLPU3Xx1Sg1hHVHTRJwvpHwdxJxe
-----END PRIVATE KEY-----`

	kemPublic = `-----BEGIN PUBLIC KEY-----
MIIEsjALBglghkgBZQMEBAIDggShALraLQOZyoFjK7rDe1b0Ad26le2DCS4aMOcs
epTpCH4znnTUDp+7oyHlGJiIdJFTKorJtDuhIL0BspbXdcOGzy1cNT7jH8RTNt/A
yrubNg8JKvPHDlwrqo6awoWbR0fToic6kzTnH/j1I34kijaiPLGjRMZKyWKRcZE8
TPjjYfOZYlrTsZ+Gie72MO06toi4JAA6XvcrkqkzSnoYNw9lEOj7YP1lRcklAtDk
DgZ3x8tDAuXlepJUuI2GQ2tzptiUcCCSfkp8o7wazmMVSAcGylXoI1ToHmCWQbn4
J6aHGTFZLc0gzg9KgYFXBQc0PJjaiSJQze8FsfwlAmVJlAGRno/1PN6nqjXQHdZh
JJFyWNJ8NNCWBSYZYnAWuev6yb9ymTJEKL7TtaMXOIBIz6OzyXUHmPt2SVerJhrl
O5Mzrvd7Ge5Uf8FRR4CaqgalwOw5ifl7DCj6kgyomf9XgxR6TLusSKhQqyl6Po1Z
xjRVY028g2+0P7Gnyky6gBZVzguWyQCsL1CMEXCAWb7YewXhciOgfqC6A7+bG335
vET6J5p0Hj0CV5CZYNmck22zaX1DTmroNkWKIqwnoGhwVL0RMSxiM8PwJgZ7bkap
LJ1XYT7nYEracifKrVqWltZ6u42QcnLhY0wlxo97UIeTv9IJRcvqDeLbMDoyWMWV
b65VKzpTJjnLdr5CwSdFkgCXprY1TisYUkvsmuuVrGW2FKjMJkfyfutaG6UkLlSa
fskontOKI+voICmmKaXzS+KSNM+YY2HphNekB+63v0WMNtJaSfuCm+RzBm2KhU9k
oj8nHpnDJQ/6HXipNbtYZF4FI+XaX+bBWPcSHghDxQNCCZVIiCt8QAngw5Wcp4ZK
akPccTCbM3RwnNWhpk7yQ+bMH97sCO5FWA3nFWmmm4KRDsNqzPUcvbZgngyqSVfQ
IGBHKmrXLmHjox2qRRKjs0+Byb27ePKqnbpMQBnZMYkzaY78Pb+6ykP0jfL1uJzB
TbMQwRNTKVacL7vKGd3hPmc4n1GELQVVJHA6xRIpzhIFgug0g7WXJ76nllWSPpfS
xdAE0JhhIX17Y1RzSdiwDTp8LVr5M99WCqGSmi3nSVK3vHEJPPEEEGj4PDQJly0r
IuKlTiLkTKDLFiCgE8IhJ/OyHpVHRqOwugEEBqgqojm5xWkbeBH5OFujjsCDVBmB
Kny5BI8cv6PiJHDFTqO6S1gEgqNSN7k3zuKgL8W2lrMHYc7mGo3LnPCYVgicc1EM
IHL5pmJcj9vQuelEnccrXjLCi4ucGwCHAtTQLwPils9EYkjXYQhrRLGJfk7RP9zD
xIjrlUnHMvrBoYabUioFAKoRiT1yU4m6tw1UQzxrBdT8BgpIEc+UaYOKEcfzy1Q8
LpsRMLVQGnSEgcM6b9P2ISTzdW1MB7sZsNtTO2dCSdcQANgGhwPsvdRQyoP1Vd96
MPvjEQQkk/Y5diXnXzkxzXY7G18AVI7yjOchE5MwkXApTr5XuDeGuF4AS6oGVbgn
gWaMQV2SDKMXm0JkCK4gKGFjlH1STOPKaPBgYZEoSSQEThDCiFUptisUDv9YsxNk
WVoNQQLF
-----END PUBLIC KEY-----`

	caPublicCert = `-----BEGIN CERTIFICATE-----
MIIDdjCCAl6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBMMQswCQYDVQQGEwJVUzEP
MA0GA1UECgwGR29vZ2xlMRMwEQYDVQQLDApFbnRlcnByaXNlMRcwFQYDVQQDDA5T
aW5nbGUgUm9vdCBDQTAeFw0yMzEyMjcxNzM4MDJaFw0zMzEyMjYxNzM4MDJaMEwx
CzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZHb29nbGUxEzARBgNVBAsMCkVudGVycHJp
c2UxFzAVBgNVBAMMDlNpbmdsZSBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAvU5LpbBExIrggs/y4jACCJvDMYIpfEmRJKnr824u+JdRbbJU
vo7pGBjkJG9OnnyCw9EbCnzxb5A3Olwm/0orclPceiKP5asUE+lEvgNgOtDd5ZVh
QIRb5xkBX8aHXUf64gpuvZ17sYisj6OPl7dtVwOjbL97JR7wugnCR34K67jDn+eH
yaFLD3DKdQvus46jmpL2GGVa4DeM70i7zUU1hREZ3Njxb42l1+9IFZ8aR/oW3Xcp
aQZtHtkdT4Zh32u4kfFDtoDkZSBmkKrRTaY9OXyiGY4Wp2Gi8hhLEyXuG3I4uY88
UK3NiPrcCKVnjg+KyGaNE1Akwx+ox6lWf8MVPwIDAQABo2MwYTAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7PDqU1M/nyPcwQ4xEDcH
3t7nbvMwHwYDVR0jBBgwFoAU7PDqU1M/nyPcwQ4xEDcH3t7nbvMwDQYJKoZIhvcN
AQELBQADggEBAHeqVgMEOYb8yGmLwwKuh0Ppr2Zg/fDfmD7z8eq7jhpAzhjStCiT
5E0cFRSJI4UQf8/2N7RkyI5XZ0EuCA8Zh+Z6ikrmk5KWUycZISQ4xy9DZ76khTzk
sBDXFHZI6IHgunomxPMdumG9zZZOnfa25a1qecCJAakem1SVl277mReEf7agBaEL
QabI06QI9tb/bx6Uh9DDS9qKSqpCqGAsVSWxYryjVA7eSjYHeO0q7dDi2EVF805P
HD+lXVm/Xmb09ncbh5DAeJSqqBuDbQ/5gzJbGHgbmUZhZEZhgL3YPWrlb883xr8y
yaBu9JVO3gc1ry7VH51s+7RZ25C7uURDQJI=
-----END CERTIFICATE-----`

	caPrivate = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9TkulsETEiuCC
z/LiMAIIm8Mxgil8SZEkqevzbi74l1FtslS+jukYGOQkb06efILD0RsKfPFvkDc6
XCb/SityU9x6Io/lqxQT6US+A2A60N3llWFAhFvnGQFfxoddR/riCm69nXuxiKyP
o4+Xt21XA6Nsv3slHvC6CcJHfgrruMOf54fJoUsPcMp1C+6zjqOakvYYZVrgN4zv
SLvNRTWFERnc2PFvjaXX70gVnxpH+hbddylpBm0e2R1PhmHfa7iR8UO2gORlIGaQ
qtFNpj05fKIZjhanYaLyGEsTJe4bcji5jzxQrc2I+twIpWeOD4rIZo0TUCTDH6jH
qVZ/wxU/AgMBAAECggEACqYJVlAkhiPDvkgBQxztOFu+rp3CRKYEvpm6Vo6noL8u
SuvhnXh/fyYDS1NhikO5vVcZXM0rbZmgqa0+WlTrPbqe59Xi30nwzq/r+H5LHvPZ
z4zIFC991fGPpLoPqj0ezTFGCm994j4sasYKEUA1q9PeEQNyY2OqqeRbo9bguWKq
AyPnCjf7Kp7mU6p+mnfcLU1iyRd/Cb9P6oGlZe+MD+tb28sP8aY15K2WsSCp+95I
l+ovKzsXbN5Gq1mW0rfqviCqlVmoAQmXVCUUihDlP4dLpRhgF39NU6T0xyDaBVOw
pvsaiRJ86cpBYfbW/uy9JBrNP84Uc2W8tim2TIn+fQKBgQDjCkQKGq+nVFMovU4Y
J8j7Ty1wk3h03ThUTMmhhKXXNlIBGbk7jhM+DQM0cKQulY0c8z/7PhMKpnJH2w2+
fuXOhG/OiVdXNMd3V/Im5Zbb1wvH/dVccRPBSbmExK89B78nTVS1qIrR6r2LOpIS
uIwsyKUlI7naO8PXOpEsGJPDqwKBgQDVc9xaFez+sZATojoNVrh0BxhvKQiHERqs
prGGS8BRq9/atGhUt0fz1NGpsd8rr6EhWDF68UK2QWyGhlWyUg/4AfMnvy7xhRhu
fk8iiC6Jzi2M04jeVMMc3HebEphcagB/ejQZ94rnmW+vKYQS++7t3DRyn2SNcC+/
62/6eGLgvQKBgD61+TEpSddYLVgVYdq+Mn9n0U9FDIKLECIIy7C3aO9W67OuHUHb
7mi3Q2laq57KZB3Y+pU1AiFw9CPw140ElAlE/3T27o8B3w6R1ir0Q4UZkwF8lVBh
U2mSKZIImbaryxrZ+0np8d4ljpFEblCJdP5xtVva0Fz9IQzz+mFJsJbdAoGAAOzL
m6hUqpXiZfNiBQTHL9mIBZNL8inkz7K5OjfB0ZjJE42MljFlIm1dqzqWGP5d2GMl
c77v5xJJghu661bnss9vWlC9x1YoUPJDLYchjH9UOzP/d9cuMUXTTty5xEzBS8wf
xa0I8Q/9J+kqJVrqIiW+JHEEYoiF7HL8vT0gUJECgYEAvXelQqOU+4Ghd2uC4N1K
B7+51cCEXvVUxDbnyXTiH3krUKnq9AOYUBmJxyTxg4sauS1daW1RezBb8BW86ogo
Hwi1iXy6ro4Vptjc6i3VS4kXGKOV5B60/we0GgHIBUiEkEsilNbzENoLKgHTUDl8
fy3ucMmR6WghE+dP51B6Jho=
-----END PRIVATE KEY-----
`
)

func main() {

	flag.Parse()

	//*********************** RECEIVER *************************************
	// read recepients public private key

	pubPEMblock, rest := pem.Decode([]byte(kemPublic))
	if len(rest) != 0 {
		fmt.Printf("trailing data found during pemDecode")
		return
	}
	//var pkixa pkixPubKey
	var pkixa x509.MLKEMPublicKeyInfo
	if rest, err := asn1.Unmarshal(pubPEMblock.Bytes, &pkixa); err != nil {
		panic(err)
	} else if len(rest) != 0 {
		fmt.Printf("rest not nil")
		return
	}

	privPEMblock, rest := pem.Decode([]byte(kemPrivate))
	if len(rest) != 0 {
		fmt.Printf("trailing data found during pemDecode")
		return
	}
	var prkix pkixPrivKey
	if rest, err := asn1.Unmarshal(privPEMblock.Bytes, &prkix); err != nil {
		panic(err)
	} else if len(rest) != 0 {
		fmt.Printf("rest not nil")
		return
	}

	// read in a dummy CA certificate an dkey

	block, _ := pem.Decode([]byte(caPublicCert))
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	rkblock, _ := pem.Decode([]byte(caPrivate))

	priv, err := x509.ParsePKCS8PrivateKey(rkblock.Bytes)
	if err != nil {
		log.Fatalf("Unable to get read private ocsp key: %v", err)
	}

	/// create a CSR where the public key is the kem public
	var csrtemplate = x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         "recepient1",
		},
		DNSNames:  []string{"recipient1"},
		PublicKey: &pkixa, // <<<<<<<<<<<<<< kem public key
	}

	// csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, nkp)
	// if err != nil {
	// 	log.Fatalf("Failed to create CSR: %s", err)
	// }
	// pemcsr := pem.EncodeToMemory(
	// 	&pem.Block{
	// 		Type:  "CERTIFICATE REQUEST",
	// 		Bytes: csrBytes,
	// 	},
	// )
	// log.Printf("CSR \n%s\n", string(pemcsr))

	//  now issue a certificate for the kem key

	fmt.Printf("Creating public x509")

	var notBefore time.Time
	notBefore = time.Now()

	notAfter := notBefore.Add(time.Hour * 1)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %s", err)
	}

	// calculate skid
	// The actual key bytes are in pubKeyInfo.PublicKey.Bytes.
	// Hash these bytes using SHA-1.
	hash := sha1.Sum(pkixa.PublicKey.Bytes)
	sk := hash[:]

	// now create a certificate and sign it.
	// this certificate represents the kem recepient
	//  the skid value is the hash of the public key
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         "mycn",
		},
		SubjectKeyId:          sk,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              []string{"mysni"},
		KeyUsage:              x509.KeyUsage(x509.KeyUsageKeyEncipherment),
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, csrtemplate.PublicKey, priv.(*rsa.PrivateKey))
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	certOut, err := os.Create("issued.pem")
	if err != nil {
		log.Fatalf("Failed writing to file %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write data: %s", err)
	}
	certOut.Close()
	fmt.Print("wrote issued.pem\n")

	//*********************** SENDER *************************************

	// now
	// read the recipeents x509
	issuedEKMCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		log.Fatal(err)
	}

	// first verify the CA issued it

	issuerPool := x509.NewCertPool()
	issuerPool.AddCert(caCert)

	verifyOptions := x509.VerifyOptions{
		Roots: issuerPool,
	}
	if _, err := issuedEKMCert.Verify(verifyOptions); err != nil {
		fmt.Printf("Certificate verification failed: %v\n", err)
		return
	}
	// you can verify other stuff if you want

	// now get the public key from the cert and get its hash

	publicKeyDER, err := x509.MarshalPKIXPublicKey(issuedEKMCert.PublicKey)
	if err != nil {
		log.Fatalf("Error marshaling public key to DER: %v", err)
	}

	var pkixaa x509.MLKEMPublicKeyInfo
	if rest, err := asn1.Unmarshal(publicKeyDER, &pkixaa); err != nil {
		panic(err)
	} else if len(rest) != 0 {
		fmt.Printf("rest not nil")
		return
	}

	phash := sha1.Sum(pkixaa.PublicKey.Bytes)
	phashk := phash[:]
	// compare if the issued cert matches the subjectKeyID
	if !bytes.Equal(phashk, issuedEKMCert.SubjectKeyId) {
		fmt.Println("SubjectKeyID does not match hash of the public key")
		return
	}

	fmt.Printf("SubjectKeyId %s\n", hex.EncodeToString(phashk))

	ie, err := NewIssuerAndSerialNumberRaw(issuedEKMCert)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Issuer and serialNumber %s\n", hex.EncodeToString(ie.Bytes))

	var kemcipherText []byte
	var kemSharedSecret []byte

	// here is where the sender generates a new keypair:

	if pkixa.Algorithm.Algorithm.Equal(OID_MLKEM768) {
		ek, err := mlkem.NewEncapsulationKey768(pkixa.PublicKey.Bytes)
		if err != nil {
			panic(err)
		}
		kemSharedSecret, kemcipherText = ek.Encapsulate()
	}

	fmt.Printf("kemcipherText %s\n", hex.EncodeToString(kemcipherText))
	fmt.Printf("SharedSecret: kemShared (%s) \n", base64.StdEncoding.EncodeToString(kemSharedSecret))

	// create payload_encryption_key and payload_encryption_nonce and encrypt the payload
	payload_encryption_key := make([]byte, 32)
	_, err = rand.Read(payload_encryption_key)
	if err != nil {
		panic(err)
	}
	fmt.Printf("root_key %s \n", base64.StdEncoding.EncodeToString(payload_encryption_key))

	bobpubPEMblock, rest := pem.Decode([]byte(kemPublic))
	if len(rest) != 0 {
		fmt.Printf("trailing data found during pemDecode")
		return
	}
	//var pkixa pkixPubKey
	var bobpkixa x509.MLKEMPublicKeyInfo
	if rest, err := asn1.Unmarshal(bobpubPEMblock.Bytes, &bobpkixa); err != nil {
		panic(err)
	} else if len(rest) != 0 {
		fmt.Printf("rest not nil")
		return
	}
	bhash := sha1.Sum(bobpkixa.PublicKey.Bytes)
	bsk := bhash[:]

	fmt.Printf("spi %s\n", hex.EncodeToString(bsk))

	cori := CMSORIforKEMOtherInfo{
		Wrap:      pkix.AlgorithmIdentifier{Algorithm: OID_AES_128_KEYWRAP},
		KEKLength: 16, // aes 128 key
		UKM:       nil,
	}

	coribytes, err := asn1.Marshal(cori)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("CMSORIforKEMOtherInfo %s\n", hex.EncodeToString(coribytes))

	salt := []byte("")
	kdf := hkdf.New(sha256.New, kemSharedSecret, salt, coribytes)
	kek_derived_key := make([]byte, 16)
	_, err = io.ReadFull(kdf, kek_derived_key)
	if err != nil {
		panic(err)
	}
	fmt.Printf("KEK %s\n", hex.EncodeToString(kek_derived_key))

	// this is where you generate an aes key
	content_encryption_key_bytes := make([]byte, 32)
	_, err = rand.Read(content_encryption_key_bytes)
	if err != nil {
		panic(err)
	}

	kek_block, err := aes.NewCipher(kek_derived_key)
	if err != nil {
		panic(err.Error())
	}

	encrypted_content_key, err := keywrap.Wrap(kek_block, content_encryption_key_bytes)
	if err != nil {
		panic(err.Error())
	}

	//fmt.Printf("encrypted_content_key %s\n", hex.EncodeToString(encrypted_content_key))

	// default
	// nonce for aes128 keywrap:
	// //   var defaultIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

	content_encryption_block, err := aes.NewCipher(content_encryption_key_bytes)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(content_encryption_block)
	if err != nil {
		panic(err.Error())
	}

	content_encryption_nonce_bytes := make([]byte, 12)
	_, err = rand.Read(content_encryption_nonce_bytes)
	if err != nil {
		panic(err)
	}

	plainTextPayload := []byte("Hello, world!")
	var aad = []byte("foo")

	ciphertextWithMac := aesgcm.Seal(nil, content_encryption_nonce_bytes, plainTextPayload, aad)

	tagSize := aesgcm.Overhead() // Overhead() returns the tag size, which is 16 bytes for GCM

	// The actual encrypted data (excluding the MAC)
	actualCiphertext := ciphertextWithMac[:len(ciphertextWithMac)-tagSize]

	// The Message Authentication Code (MAC) / Authentication Tag
	mac := ciphertextWithMac[len(ciphertextWithMac)-tagSize:]

	fmt.Printf("actualCiphertext %x\n", actualCiphertext)
	fmt.Printf("ciphertextWithMac %x\n", ciphertextWithMac)
	fmt.Printf("mac %x\n", mac)
	fmt.Printf("tagSize %d\n", tagSize)

	// Prepare ASN.1 Encrypted Content Info
	ciphertextWithMac_paramSeq := aesGCMParameters{
		Nonce:  content_encryption_nonce_bytes,
		ICVLen: tagSize,
	}

	ciphertextWithMac_parameter_bytes, err := asn1.Marshal(ciphertextWithMac_paramSeq)
	if err != nil {
		log.Fatal(err)
	}

	/// ***********************

	// rii := RecipientIdentifier{
	// 	IssuerAndSerialNumber: ie,
	// 	// or
	// 	//SubjectKeyIdentifier: phashk, // tag=0
	// }
	// rib, err := asn1.Marshal(rii)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	kcms := KEMRecipientInfo{
		Version: 0,
		// for IssuerAndSerialNumber
		// Recipient: asn1.RawValue{
		// 	Class:      asn1.ClassContextSpecific,
		// 	Bytes:      rib,
		// 	IsCompound: true,
		// },

		// for SubjectKeyIdentifier
		Recipient: asn1.RawValue{
			Tag:   asn1.TagOctetString,
			Bytes: phashk,
		},
		KEMAlgorithm:  pkix.AlgorithmIdentifier{Algorithm: OID_MLKEM768},
		KEMCipherText: kemcipherText,
		KeyDerivationAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: OID_HKDF_SHA256,
		},
		KekLength: len(kek_derived_key),
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: OID_AES_128_KEYWRAP,
		},
		EncryptedKey: encrypted_content_key,
	}

	ori := OtherRecipientInfo{
		OriType:  OID_KEMRecipientInfo,
		OriValue: kcms,
	}

	ri := RecipientInfo{
		ORI: ori,
	}

	eci := EncryptedContentInfo{
		ContentType: OID_PKCS7_DATA,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: OID_AES_GCM_128,
			Parameters: asn1.RawValue{
				Class:      asn1.ClassUniversal,
				Tag:        asn1.TagSequence,
				FullBytes:  ciphertextWithMac_parameter_bytes,
				IsCompound: true,
			}},
		EncryptedContent: marshalEncryptedContent(actualCiphertext),
	}

	//const der = "\xA0\x5D\x30\x18\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x03\x31\x0B\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x01\x30\x1C\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x05\x31\x0F\x17\x0D\x31\x37\x30\x31\x31\x37\x30\x31\x33\x31\x32\x36\x5A\x30\x23\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x04\x31\x16\x04\x14\x6C\x07\xE3\x58\x71\x40\x4C\xCB\x0F\xC3\xB2\xD9\xE8\x53\xC4\x8E\x87\x1D\x94\xD7"
	// var attributes []Attribute
	// brest, err := asn1.UnmarshalWithParams([]byte(der), &attributes, "set,tag:0")
	// if err != nil {
	// 	panic(err)
	// }
	// for _, attr := range attributes {
	// 	fmt.Println(attr)
	// }
	// fmt.Println(brest)

	// idaaintendedRecipients := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 33}

	// //
	// authAttr := Attribute{
	// 	Type: idaaintendedRecipients,
	// 	RawValue: []asn1.RawValue{{
	// 		Class: asn1.ClassUniversal,
	// 		Tag:   asn1.TagOctetString,
	// 		Bytes: aad,
	// 	},
	// 	},
	// }

	ed := AuthEnvelopedData{
		Version:        0,
		RecipientInfos: ri,
		AECI:           eci,
		MAC:            mac,
		//AauthAttrs:     []Attribute{authAttr},
	}
	edBytes, err := asn1.Marshal(ed)
	if err != nil {
		log.Fatal(err)
	}

	ci := ContentInfo{
		ContentType: OID_AUTH_AuthEnvelopedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			Bytes:      edBytes,
			IsCompound: true,
		},
	}

	result, err := asn1.Marshal(ci)
	if err != nil {
		log.Fatal(err)
	}

	kemblock := &pem.Block{
		Type:  "CMS",
		Bytes: result,
	}
	pemBytes := pem.EncodeToMemory(kemblock)

	fmt.Println(string(pemBytes))

	ccertOut, err := os.Create("c.cms")
	if err != nil {
		log.Fatalf("Failed writing to file %v", err)
	}
	if err := pem.Encode(ccertOut, &pem.Block{Type: "CMS", Bytes: result}); err != nil {
		log.Fatalf("Failed to write data: %s", err)
	}
	ccertOut.Close()

	/// *******************************************  RECEIVER *******************************************

}

// https://github.com/github/ietf-cms/blob/fc9159fd2309603704c36ee361b1668d093b2940/protocol/protocol.go#L363
func NewIssuerAndSerialNumberRaw(cert *x509.Certificate) (rv asn1.RawValue, err error) {
	sid := IssuerAndSerialNumber{
		SerialNumber: new(big.Int).Set(cert.SerialNumber),
	}
	if _, err = asn1.Unmarshal(cert.RawIssuer, &sid.Issuer); err != nil {
		return
	}
	var der []byte
	if der, err = asn1.Marshal(sid); err != nil {
		return
	}
	if _, err = asn1.Unmarshal(der, &rv); err != nil {
		return
	}
	return
}
