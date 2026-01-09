#### Cryptographic Message Syntax (CMS) for KEM RFC8629


Just an interpretation/implementation in go of

* [Using Key Encapsulation Mechanism (KEM) Algorithms in the Cryptographic Message Syntax (CMS)](https://datatracker.ietf.org/doc/rfc9629/)

>> please note this is *draft* and just a **best guess** on what the implementation would look like; do not use this in prod

> also, critically, stadnard go does **NOT** support parsing KEM public keys types.  The code below uses a modified `crypto/x509.go` described in [../issue_cert/x509.diff](../issue_cert/x509.diff)

the code here does the following

to encrypt  `payload_text` for the receiver

1. receiver: read in a CA certificate and key
2. receiver: generate an ml keypair (`kemPriv`, `kemPub`)
3. receiver; create an x509 certificate where the public key is kemPub
4. receiver: sign the certificte by the ca
5. receiver->sender: send the  x509
6. sender: verify the certificate is signed by the trusted ca
6. sender: extract the kem public key

7. sender: verify the parameters in the certificate (issuer, public key (kemPub), spi)
8. sender: generate a random `payload_encryption_key` and `payload_encryption_nonce`
9. sender: `encrypted_payload = aes.Seal( plaintext=payload_text, key=payload_encryption_key, nonce=payload_encryption_nonce )`

10. sender: `sharedSecret, kemcipherText = kem.Encapsulate( kemPub )`
11: sender: generate a `kdf_nonce`
12. sender: `kek_derived_key = kdf( nonce=kdf_nonce, ikm=sharedSecret )`

13. sender: generate `kek_nonce`
14. sender: `encrypted_key = aes.Seal( plaintext=payload_encryption_key, key=kek_derived_key, nonce=kek_nonce )`
15. sender: generate the `KEMRecipientInfo` and encode to pem or der

```golang
type KEMRecipientInfo struct {
	Version                int
	Recipient              RecipientIdentifier
	KEMAlgorithm           pkix.AlgorithmIdentifier
	KEMCipherText          []byte                     /// <<< this is the kem ciphertext
	KeyDerivationAlgorithm pkix.AlgorithmIdentifier   // <<< incudes kdf_nonce
	KekLength              int
	UserKeyingMaterial     []byte `asn1:"explicit,tag:1,optional"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier    // <<< includes kek_nonce
	EncryptedKey           []byte                // <<<< this is the encrypted_key
}
```

16. Generate `CMS` using the following chain

```golang
type RecipientInfo struct {
	KTRI  KeyTransRecipientInfo `asn1:"optional"`
	KARI  KeyAgreeRecipientInfo `asn1:"optional,tag:1"` 
	KEKRI asn1.RawValue         `asn1:"optional,tag:2"`
	PWRI  asn1.RawValue         `asn1:"optional,tag:3"`
	ORI   asn1.RawValue         `asn1:"optional,tag:4"`
	KEMRI KEMRecipientInfo      `asn1:"optional,tag:5"`    // <<<< this includes the KEMRecipientInfo 
}

type EncryptedContentInfo struct {
	EContentType               asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier     // <<  this includes the payload_encryption_nonce
	EContent                   []byte `asn1:"optional,implicit,tag:0"`  // <<<  this is the encrypted_payload
}

type EnvelopedData struct {
	Version          int
	OriginatorInfo   asn1.RawValue        `asn1:"optional,tag:0"`
	RecipientInfos   []RecipientInfo      `asn1:"set,choice"`  // <<<< this includdes the RecipientInfo
	ECI              EncryptedContentInfo ``                       // << this includes EncryptedContentInfo
	UnprotectedAttrs []Attribute          `asn1:"set,optional,tag:1"`
}


ContentInfo{
		ContentType: OIDEnvelopedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			Bytes:      edBytes,  // <<< asn1 marshaled bytes of EnvelopeData
			IsCompound: true,
		},
	}
```


17. sender->receiver: send the pem or der
18. receiver decodes ContentInfo and extracts 

  `(encrypted_payload, payload_encryption_nonce)`  // from `ContentInfo.EnvelopedData.ECI` 

  `(encrypted_key, kek_nonce, kdf_nonce, kemcipherText )`  // from  `ContentInfo.EnvelopedData.RecipientInfos[0].(KEMRecipientInfo)`

19. reverse the ecryption by the sender 
   
    `sharedSecret = kem.Decapsulate( kemcipherText, key=kemPriv )`

    `derived_key = kdf( kdf_nonce, sharedSecret )`

    `payload_encryption_key = aes_gcm.open( key=derived_key, ciphertext=encrypted_key, nonce=kek_nonce )`

    `payload_text = aes_gcm.open( key=payload_encryption_key, ciphertext=encrypted_payload, nonce=payload_encryption_nonce )`

```bash
$ go run main.go 


Creating public x509wrote issued.pem
SharedSecret: kemShared (60W48k/bcUBjzQYdwL+Cf96locoK5etw+IDb1p/VIGU=) 
root_key ED9J9kANOuAmy9/iolxJWLOA6X7Offd3TthZesJtF74= 
sender derivedKey 89b90917a97f7e03fa469d90ba2f7364b46972bbb77ff777acdb3601240146ee
encrypted payload_encryption_key a38fe9c52bdb7457debdd2d0e02688e8c036b6214229c5b9a41d5577cf6a8076ee77818c3f34ba31aa408cf43a4835d5
Issuer And SerialNumber: MEwxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZHb29nbGUxEzARBgNVBAsMCkVudGVycHJpc2UxFzAVBgNVBAMMDlNpbmdsZSBSb290IENBAhEA6PZclKaqVqZCqIhFqdkfHQ==
-----BEGIN CMS-----
MIIHZAYJKoZIhvcNAQcDoIIHVTCCB1ECAQAxggVPMIIFS6WCBUcCAQAwYzBhMEwx
CzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZHb29nbGUxEzARBgNVBAsMCkVudGVycHJp
c2UxFzAVBgNVBAMMDlNpbmdsZSBSb290IENBAhEA6PZclKaqVqZCqIhFqdkfHTAL
BglghkgBZQMEBAIEggRAKBj2iAzSygklnmO57ZGcJhRb+DH3OHtUMarE/tXqpVQz
xQcnZYaDBQr13lA/+gRovvFUNtkYkNkNgeB9XrjlbjO+f/5jgHHGgPuEKHcn/BJP
34XgA+D3Z3+DBJcNbD8MkW1YzZtM/QvHR5V2+DY/QkXlhUUPks71cB0/reSEjtCI
AtYbjP/FkkuZZMs+2UuWAsYGk+S7oUjFzl1UExDXggS8ssccq2gxiT0lA56LfwEv
uOaxSBqvo3qeWIFe4KjnMG1CgQYiQsEr1eRP3uu7urLSgoEAjU7cQRPvxtZL+v3V
yxfA+Hw4nFtrtG2DtH5Etd8ec5X/SO7uHu3C5apKOGSza/wfTj5gn6ihZmkzDrgO
L12Pe+ZZJLhOnsWrb8TpesYg4zt4Pf0cGHNnKiiFB6KfR/YqQ1k1/VM3iSehhCHR
NOhuMRROBwuV7X1SczcmMOY22N9Aj85S3XzTfrzj2c2eH5I3Prro503zNAVAxrHp
NNZ8iKRUdYqRfadBDsBRqKJZ2glWsktv9DR5ee4KKpBRIujq7oeByR2oFJBAHila
wTNNJoVtQU45AYycWaxAW2NHS/P4oeBrUS5goz0c/fG68mKMAQs9DJf26aMiKTcl
cCaN+VRg2XiJpd3+v7q0KEuqS5WpyGeMsX5YadE6ZG5CZQi36fD0bxKobs2Uwnu1
u/6oe4RCaULxG2z0mpucifRI5eHyEDevN1DcmPstnVJq3/swxUjcEnt8qfREd+4S
LZjaNk8nTCRc8jm72jbrvuKFDJvGngOPFnl+uQ8zGsZOpGPbmI8jxm8cn30/A3KI
QliKsey7kiLu+Cz2Jv7ymP/eiM7T83oFz2q3UacOu/49WsNbgrjOSQfYDRXzooMg
9Ipsqq3JClnqf/DuV7rQrEfKUpZMrWch5TpZcbn3tfdSW+llFNSLyXRYTKtLZkdD
ZC1efLvNw4GVS6qrKwjsew6M5EhKYc79OZdFslC8xW9LEzdnWBcRIVHfyWRPoymX
VLdW8IbmhbarSj+DO/ggoR43bQ1j84woTefX2cqVx8hZ4MYTwrGD7trQbMNhiVLK
dsU+628E1H0ZPDaTgdo7KtdxfGasnZquiG312FpRhMkxgJLrbfJsiAEQkP52sRSe
o0G58EwEbl9BEtM/lNHBvXcUhI1tgZ2BpwtfrROoiPeAS964N674SHiNn62XLzAh
jxh66cRFhQyZLcx038FyvdnGsu+vQQlWrKeIEYQze5lWZA3673ZF9KUuH9CILNVa
XFdhX+IUg+O+GiELL+lksIbU0RNo4SQpTwczLNKdRHSqEx7hPKs1r2QiPcC3cmvs
cJS0DuceoZsvNOzJ/VtfaO+Bk5Y2jLDojFxMY7LqhgQ0+chc/58GZjdYQAEhSWAL
GlSlIumHXFT07mrTAxw84OCnXmiNqkOmnI/U2VmnWM5az1NKgsxmK8i2FLKh4JUw
LAYIKwYBBQUIAQUAIKK1piKHroFKg8N1YYEJlwYOibyTCnq8SqNrrqWtn6wRAgEg
oQ4EDG9wdGlvbmFsIHVrbTAZBglghkgBZQMEAS4ADD8ng/HUBzQYtg67HgQwo4/p
xSvbdFfevdLQ4CaI6MA2tiFCKcW5pB1Vd89qgHbud4GMPzS6MapAjPQ6SDXVMIIB
9wYJYIZIAWUDBAEtMBkGCWCGSAFlAwQBLgAMyx7eeyN/6wSagO8HgIIBzflT1Ta4
ZeRMruSJjCOJ4s/Nm9gARysb7zTJCt17YT4qK2KkjLhX5t0u5fiDdkH26wE3qpuP
jcFIoYVPWuqZgzLH8qF3Li6xvQBgcarCCmfNoeKACZqgFNzlMxUqYzQqRufhqam/
nKCcayMr2NUiseALfaDfXCC6ZqOEDd9mHdLMOMJCyebv4G8kYeWIfwKAEB01oX4R
k+UANkMQyhcU85osvMRh9VkemEZHTEGWN+qdq3RE4RjgrxnGWEwtTMrLP1NOFElg
jLIstA90BDcVmBplngp3spGQwrROhpAYy+7J4Ng8EcMXn8jMx0bRNcSuzRpu/34A
6/XIx4H7CpUUYrJcqe9Stc3TfIYKuSmHnn9BE78ANZ48zr9WPibPTkcIvtSS9Eo/
8+cBrFlE0xa4TOcNvnOOtjEnqtAZmNCWpbObFsvVO8WXzhJkHMYSdQL2z5lb7AQT
dhW5G62pbYE0JmvR+8Yx1l3XdtWzCztkcxZ2gGhN8Xwv1TQ1LPg19neZmSTRqytT
H95Xu4+R813isfHehOTqDwr5OsHuM/aRni6fN/LKKCnlomood7shvzs6XMD08uYO
mj0tFpQmK/Aqf5XaGIsnlyFWCio4ncCf
-----END CMS-----



ContentInfo Content Type 1.2.840.113549.1.7.3
SharedSecret: kemShared (60W48k/bcUBjzQYdwL+Cf96locoK5etw+IDb1p/VIGU=) 
receiver derivedKey 89b90917a97f7e03fa469d90ba2f7364b46972bbb77ff777acdb3601240146ee
plain_root_key ED9J9kANOuAmy9/iolxJWLOA6X7Offd3TthZesJtF74=
plain_encrypted_data: 
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
```

as asn1:

```bash
$ openssl asn1parse -inform PEM -in a.cms
    0:d=0  hl=4 l=1892 cons: SEQUENCE          
    4:d=1  hl=2 l=   9 prim: OBJECT            :pkcs7-envelopedData
   15:d=1  hl=4 l=1877 cons: cont [ 0 ]        
   19:d=2  hl=4 l=1873 cons: SEQUENCE          
   23:d=3  hl=2 l=   1 prim: INTEGER           :00
   26:d=3  hl=4 l=1359 cons: SET               
   30:d=4  hl=4 l=1355 cons: SEQUENCE          
   34:d=5  hl=4 l=1351 cons: cont [ 5 ]        
   38:d=6  hl=2 l=   1 prim: INTEGER           :00
   41:d=6  hl=2 l=  99 cons: SEQUENCE          
   43:d=7  hl=2 l=  97 cons: SEQUENCE          
   45:d=8  hl=2 l=  76 cons: SEQUENCE          
   47:d=9  hl=2 l=  11 cons: SET               
   49:d=10 hl=2 l=   9 cons: SEQUENCE          
   51:d=11 hl=2 l=   3 prim: OBJECT            :countryName
   56:d=11 hl=2 l=   2 prim: PRINTABLESTRING   :US
   60:d=9  hl=2 l=  15 cons: SET               
   62:d=10 hl=2 l=  13 cons: SEQUENCE          
   64:d=11 hl=2 l=   3 prim: OBJECT            :organizationName
   69:d=11 hl=2 l=   6 prim: UTF8STRING        :Google
   77:d=9  hl=2 l=  19 cons: SET               
   79:d=10 hl=2 l=  17 cons: SEQUENCE          
   81:d=11 hl=2 l=   3 prim: OBJECT            :organizationalUnitName
   86:d=11 hl=2 l=  10 prim: UTF8STRING        :Enterprise
   98:d=9  hl=2 l=  23 cons: SET               
  100:d=10 hl=2 l=  21 cons: SEQUENCE          
  102:d=11 hl=2 l=   3 prim: OBJECT            :commonName
  107:d=11 hl=2 l=  14 prim: UTF8STRING        :Single Root CA
  123:d=8  hl=2 l=  17 prim: INTEGER           :E8F65C94A6AA56A642A88845A9D91F1D
  142:d=6  hl=2 l=  11 cons: SEQUENCE          
  144:d=7  hl=2 l=   9 prim: OBJECT            :ML-KEM-768
  155:d=6  hl=4 l=1088 prim: OCTET STRING      [HEX DUMP]:2818F6880CD2CA09259E63B9ED919C26145BF831F7387B5431AAC4FED5EAA55433C50727658683050AF5DE503FFA0468BEF15436D91890D90D81E07D5EB8E56E33BE7FFE638071C680FB84287727FC124FDF85E003E0F7677F8304970D6C3F0C916D58CD9B4CFD0BC7479576F8363F4245E585450F92CEF5701D3FADE4848ED08802D61B8CFFC5924B9964CB3ED94B9602C60693E4BBA148C5CE5D541310D78204BCB2C71CAB6831893D25039E8B7F012FB8E6B1481AAFA37A9E58815EE0A8E7306D4281062242C12BD5E44FDEEBBBBAB2D28281008D4EDC4113EFC6D64BFAFDD5CB17C0F87C389C5B6BB46D83B47E44B5DF1E7395FF48EEEE1EEDC2E5AA4A3864B36BFC1F4E3E609FA8A16669330EB80E2F5D8F7BE65924B84E9EC5AB6FC4E97AC620E33B783DFD1C1873672A288507A29F47F62A435935FD53378927A18421D134E86E31144E070B95ED7D5273372630E636D8DF408FCE52DD7CD37EBCE3D9CD9E1F92373EBAE8E74DF3340540C6B1E934D67C88A454758A917DA7410EC051A8A259DA0956B24B6FF4347979EE0A2A905122E8EAEE8781C91DA81490401E295AC1334D26856D414E39018C9C59AC405B63474BF3F8A1E06B512E60A33D1CFDF1BAF2628C010B3D0C97F6E9A32229372570268DF95460D97889A5DDFEBFBAB4284BAA4B95A9C8678CB17E5869D13A646E426508B7E9F0F46F12A86ECD94C27BB5BBFEA87B84426942F11B6CF49A9B9C89F448E5E1F21037AF3750DC98FB2D9D526ADFFB30C548DC127B7CA9F44477EE122D98DA364F274C245CF239BBDA36EBBEE2850C9BC69E038F16797EB90F331AC64EA463DB988F23C66F1C9F7D3F03728842588AB1ECBB9222EEF82CF626FEF298FFDE88CED3F37A05CF6AB751A70EBBFE3D5AC35B82B8CE4907D80D15F3A28320F48A6CAAADC90A59EA7FF0EE57BAD0AC47CA52964CAD6721E53A5971B9F7B5F7525BE96514D48BC974584CAB4B664743642D5E7CBBCDC381954BAAAB2B08EC7B0E8CE4484A61CEFD399745B250BCC56F4B1337675817112151DFC9644FA3299754B756F086E685B6AB4A3F833BF820A11E376D0D63F38C284DE7D7D9CA95C7C859E0C613C2B183EEDAD06CC3618952CA76C53EEB6F04D47D193C369381DA3B2AD7717C66AC9D9AAE886DF5D85A5184C9318092EB6DF26C88011090FE76B1149EA341B9F04C046E5F4112D33F94D1C1BD7714848D6D819D81A70B5FAD13A888F7804BDEB837AEF848788D9FAD972F30218F187AE9C445850C992DCC74DFC172BDD9C6B2EFAF410956ACA7881184337B9956640DFAEF7645F4A52E1FD0882CD55A5C57615FE21483E3BE1A210B2FE964B086D4D11368E124294F07332CD29D4474AA131EE13CAB35AF64223DC0B7726BEC7094B40EE71EA19B2F34ECC9FD5B5F68EF819396368CB0E88C5C4C63B2EA860434F9C85CFF9F0666375840012149600B1A54A522E9875C54F4EE6AD3031C3CE0E0A75E688DAA43A69C8FD4D959A758CE5ACF534A82CC662BC8B614B2A1E095
 1247:d=6  hl=2 l=  44 cons: SEQUENCE          
 1249:d=7  hl=2 l=   8 prim: OBJECT            :1.3.6.1.5.5.8.1.5
 1259:d=7  hl=2 l=  32 prim: EOC               
 1293:d=6  hl=2 l=   1 prim: INTEGER           :20
 1296:d=6  hl=2 l=  14 cons: cont [ 1 ]        
 1298:d=7  hl=2 l=  12 prim: OCTET STRING      :optional ukm
 1312:d=6  hl=2 l=  25 cons: SEQUENCE          
 1314:d=7  hl=2 l=   9 prim: OBJECT            :aes-256-gcm
 1325:d=7  hl=2 l=  12 prim: EOC               
 1339:d=6  hl=2 l=  48 prim: OCTET STRING      [HEX DUMP]:A38FE9C52BDB7457DEBDD2D0E02688E8C036B6214229C5B9A41D5577CF6A8076EE77818C3F34BA31AA408CF43A4835D5
 1389:d=3  hl=4 l= 503 cons: SEQUENCE          
 1393:d=4  hl=2 l=   9 prim: OBJECT            :id-aes256-wrap
 1404:d=4  hl=2 l=  25 cons: SEQUENCE          
 1406:d=5  hl=2 l=   9 prim: OBJECT            :aes-256-gcm
 1417:d=5  hl=2 l=  12 prim: EOC               
 1431:d=4  hl=4 l= 461 prim: cont [ 0 ]        
```


---


```yaml
     CMS-KEMRecipientInfo-2023
       { iso(1) member-body(2) us(840) rsadsi(113549)
         pkcs(1) pkcs-9(9) smime(16) modules(0)
         id-mod-cms-kemri-2023(77) }

     DEFINITIONS IMPLICIT TAGS ::=
     BEGIN
     -- EXPORTS ALL;
     IMPORTS
       OTHER-RECIPIENT, CMSVersion, RecipientIdentifier,
       EncryptedKey, KeyDerivationAlgorithmIdentifier,
       KeyEncryptionAlgorithmIdentifier, UserKeyingMaterial
         FROM CryptographicMessageSyntax-2010  -- RFC 6268
           { iso(1) member-body(2) us(840) rsadsi(113549)
             pkcs(1) pkcs-9(9) smime(16) modules(0)
             id-mod-cms-2009(58) }
       KEM-ALGORITHM
         FROM KEMAlgorithmInformation-2023  -- RFC 9629
           { iso(1) identified-organization(3) dod(6) internet(1)
             security(5) mechanisms(5) pkix(7) id-mod(0)
             id-mod-kemAlgorithmInformation-2023(109) }
       AlgorithmIdentifier{}
         FROM AlgorithmInformation-2009  -- RFC 5912
           { iso(1) identified-organization(3) dod(6) internet(1)
             security(5) mechanisms(5) pkix(7) id-mod(0)
             id-mod-algorithmInformation-02(58) } ;

     --
     -- OtherRecipientInfo Types (ori-)
     --

     SupportedOtherRecipInfo OTHER-RECIPIENT ::= { ori-KEM, ... }

     ori-KEM OTHER-RECIPIENT ::= {
       KEMRecipientInfo IDENTIFIED BY id-ori-kem }

     id-ori OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
       rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) 13 }

     id-ori-kem OBJECT IDENTIFIER ::= { id-ori 3 }

     --
     -- KEMRecipientInfo
     --

     KEMRecipientInfo ::= SEQUENCE {
       version CMSVersion,  -- always set to 0
       rid RecipientIdentifier,
       kem KEMAlgorithmIdentifier,
       kemct OCTET STRING,
       kdf KeyDerivationAlgorithmIdentifier,
       kekLength INTEGER (1..65535),
       ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL,
       wrap KeyEncryptionAlgorithmIdentifier,
       encryptedKey EncryptedKey }

     KEMAlgSet KEM-ALGORITHM ::= { ... }

     KEMAlgorithmIdentifier ::=
       AlgorithmIdentifier{ KEM-ALGORITHM, {KEMAlgSet} }

     --
     -- CMSORIforKEMOtherInfo
     --

     CMSORIforKEMOtherInfo ::= SEQUENCE {
       wrap KeyEncryptionAlgorithmIdentifier,
       kekLength INTEGER (1..65535),
       ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL }

     END

```

Just for reference, this is standard PEM RSA based cms using openssl.

You can't parse the PEM using `openssl cms` since i don't belive it will understand `KEMRecipientInfo`


```bash
echo -n "foooo" > secret.txt

openssl cms -encrypt -in secret.txt -out encrypted.cms -outform PEM recipient.crt
openssl cms -decrypt -in encrypted.cms -inform PEM -out decrypted.txt -recip recipient.crt -inkey recipient.key

$ cat encrypted.cms
-----BEGIN CMS-----
MIIBxQYJKoZIhvcNAQcDoIIBtjCCAbICAQAxggFtMIIBaQIBADBRMEwxCzAJBgNV
BAYTAlVTMQ8wDQYDVQQKDAZHb29nbGUxEzARBgNVBAsMCkVudGVycHJpc2UxFzAV
BgNVBAMMDlNpbmdsZSBSb290IENBAgEDMA0GCSqGSIb3DQEBAQUABIIBAH3+AsSO
rw11kE14X+dfvnv5FpikhkbfO1FIUCVan9KUT90JI48NzZZbNMIOWQWTOsTQAdig
9QiaonxpjFuebf117ETZm94yMz+t/M4J5EqJhjeTvIDtY6hwUlerCBQDzIyjAYVM
F37/s2osjpwqZ92HXWfeL7YcJwFqg9HSNBabtjmrmaU+H0mCJajBORGi9v1V1Bxs
LBwoF3pJ4Ioon2PX6Y+Wu+ZMCo+Jms3TsIaZJq6uCUnriMX+Is9IAd0Gi0mazM4f
RsuwL8OlXsYqIXuYMuWZOtJEpnXDhR17omxuY79EssGMoso+gi4htvaE/bIi2EOV
DrUWNViASxA7J2kwPAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBKgQQRjCZo3GL9zmq
aM+OzaaYdYAQLE/d+O7BA5GeEGf5piJtcQ==
-----END CMS-----


openssl cms -cmsout -print -noout -inform PEM -in encrypted.cms

  CMS_ContentInfo: 
    contentType: pkcs7-envelopedData (1.2.840.113549.1.7.3)
    d.envelopedData: 
      version: 0
      originatorInfo: <ABSENT>
      recipientInfos:
        d.ktri: 
          version: 0
          d.issuerAndSerialNumber: 
            issuer:           C=US, O=Google, OU=Enterprise, CN=Single Root CA
            serialNumber: 3
          keyEncryptionAlgorithm: 
            algorithm: rsaEncryption (1.2.840.113549.1.1.1)
            parameter: NULL
          encryptedKey: 
            0000 - 7d fe 02 c4 8e af 0d 75-90 4d 78 5f e7 5f be   }......u.Mx_._.
            000f - 7b f9 16 98 a4 86 46 df-3b 51 48 50 25 5a 9f   {.....F.;QHP%Z.
            001e - d2 94 4f dd 09 23 8f 0d-cd 96 5b 34 c2 0e 59   ..O..#....[4..Y
            002d - 05 93 3a c4 d0 01 d8 a0-f5 08 9a a2 7c 69 8c   ..:.........|i.
            003c - 5b 9e 6d fd 75 ec 44 d9-9b de 32 33 3f ad fc   [.m.u.D...23?..
            004b - ce 09 e4 4a 89 86 37 93-bc 80 ed 63 a8 70 52   ...J..7....c.pR
            005a - 57 ab 08 14 03 cc 8c a3-01 85 4c 17 7e ff b3   W.........L.~..
            0069 - 6a 2c 8e 9c 2a 67 dd 87-5d 67 de 2f b6 1c 27   j,..*g..]g./..'
            0078 - 01 6a 83 d1 d2 34 16 9b-b6 39 ab 99 a5 3e 1f   .j...4...9...>.
            0087 - 49 82 25 a8 c1 39 11 a2-f6 fd 55 d4 1c 6c 2c   I.%..9....U..l,
            0096 - 1c 28 17 7a 49 e0 8a 28-9f 63 d7 e9 8f 96 bb   .(.zI..(.c.....
            00a5 - e6 4c 0a 8f 89 9a cd d3-b0 86 99 26 ae ae 09   .L.........&...
            00b4 - 49 eb 88 c5 fe 22 cf 48-01 dd 06 8b 49 9a cc   I....".H....I..
            00c3 - ce 1f 46 cb b0 2f c3 a5-5e c6 2a 21 7b 98 32   ..F../..^.*!{.2
            00d2 - e5 99 3a d2 44 a6 75 c3-85 1d 7b a2 6c 6e 63   ..:.D.u...{.lnc
            00e1 - bf 44 b2 c1 8c a2 ca 3e-82 2e 21 b6 f6 84 fd   .D.....>..!....
            00f0 - b2 22 d8 43 95 0e b5 16-35 58 80 4b 10 3b 27   .".C....5X.K.;'
            00ff - 69                                             i
      encryptedContentInfo: 
        contentType: pkcs7-data (1.2.840.113549.1.7.1)
        contentEncryptionAlgorithm: 
          algorithm: aes-256-cbc (2.16.840.1.101.3.4.1.42)
          parameter: OCTET STRING:
            0000 - 46 30 99 a3 71 8b f7 39-aa 68 cf 8e cd a6 98   F0..q..9.h.....
            000f - 75                                             u
        encryptedContent: 
          0000 - 2c 4f dd f8 ee c1 03 91-9e 10 67 f9 a6 22 6d   ,O........g.."m
          000f - 71                                             q
      unprotectedAttrs:
        <ABSENT>

```


