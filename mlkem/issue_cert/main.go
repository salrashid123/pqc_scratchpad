package main

import (
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"

	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

const ()

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
-----END PUBLIC KEY-----
`

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

	var cipherText []byte
	var kemSharedSecret []byte
	if pkixa.Algorithm.Algorithm.Equal(mlkem758OID) {
		ek, err := mlkem.NewEncapsulationKey768(pkixa.PublicKey.Bytes)
		if err != nil {
			panic(err)
		}
		kemSharedSecret, cipherText = ek.Encapsulate()
	}

	fmt.Printf("SharedSecret: kemShared (%s) \n", base64.StdEncoding.EncodeToString(kemSharedSecret))

	/// ********************************************

	privPEMblock, rest := pem.Decode([]byte(kemPrivate))
	if len(rest) != 0 {
		fmt.Printf("trailing data found during pemDecode")
		return
	}
	var prkix PrivateKeyInfo
	if rest, err := asn1.Unmarshal(privPEMblock.Bytes, &prkix); err != nil {
		panic(err)
	} else if len(rest) != 0 {
		fmt.Printf("rest not nil")
		return
	}

	if prkix.PrivateKeyAlgorithm.Algorithm.Equal(mlkem758OID) {
		// openssl pkey -provparam ml-kem.output_formats=bare-seed  -in  priv-ml-kem-768.pem -out bare-seed.pem
		dk, err := mlkem.NewDecapsulationKey768(prkix.PrivateKey)
		if err != nil {
			panic(err)
		}

		sharedKey, err := dk.Decapsulate(cipherText)
		if err != nil {
			panic(err)
		}
		fmt.Printf("SharedSecret: kemShared (%s) \n", base64.StdEncoding.EncodeToString(sharedKey))
	}

	block, _ := pem.Decode([]byte(caPublicCert))
	CAcert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", CAcert.Issuer)

	rkblock, _ := pem.Decode([]byte(caPrivate))

	priv, err := x509.ParsePKCS8PrivateKey(rkblock.Bytes)
	if err != nil {
		log.Fatalf("Unable to get read private ocsp key: %v", err)
	}

	var csrtemplate = x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         "mytpm",
		},
		DNSNames:  []string{"mytpm"},
		PublicKey: &pkixa,
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

	log.Printf("Creating public x509")

	var notBefore time.Time
	notBefore = time.Now()

	notAfter := notBefore.Add(time.Hour * 24 * 365)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %s", err)
	}

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
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              []string{"mysni"},
		KeyUsage:              x509.KeyUsage(x509.KeyUsageKeyEncipherment),
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, CAcert, csrtemplate.PublicKey, priv.(*rsa.PrivateKey))
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
	log.Printf("wrote issued.pem\n")

}
