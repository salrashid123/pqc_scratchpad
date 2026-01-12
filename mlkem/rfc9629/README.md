#### Cryptographic Message Syntax (CMS) for KEM RFC8629


Just an interpretation/implementation in go of

* [Using Key Encapsulation Mechanism (KEM) Algorithms in the Cryptographic Message Syntax (CMS)](https://datatracker.ietf.org/doc/rfc9629/)


also see draft:

* [Use of ML-KEM in the Cryptographic Message Syntax (CMS)](https://datatracker.ietf.org/doc/draft-ietf-lamps-cms-kyber/)

>> please note this is example below just a **best guess** on what the implementation would look like; do not use this in prod

> also, critically, stadnard go does **NOT** support parsing KEM public keys types.  The code below uses a modified `crypto/x509.go` described in [../issue_cert/x509.diff](../issue_cert/x509.diff)

the code here does the following

to encrypt  `payload_text` for the receiver

`receiver`

1. `receiver`: read in a CA certificate and key
2. `receiver`: generate an ml keypair (`kemPriv`, `kemPub`)
3. `receiver`; create an x509 certificate where the public key is `kemPub`
4. `receiver`: sign the certificte by the ca
5. `receiver`->sender: send the  x509

---

`sender`

6. `sender`: verify the certificate is signed by the trusted ca
7. `sender`: extract the kem public key

8. `sender`: verify the parameters in the certificate (issuer, public key (kemPub), spi)
9. `sender`: generate a random `payload_encryption_key` and `payload_encryption_nonce`
10. `sender`:

   `encrypted_payload = aes.Seal( plaintext=payload_text, key=payload_encryption_key, nonce=payload_encryption_nonce )`

11. `sender`:

    `sharedSecret, kemcipherText = kem.Encapsulate( kemPub )`
    
12: `sender`: generate a `kdf_nonce`

13. `sender`:

    `kek_derived_key = kdf( nonce=kdf_nonce, ikm=sharedSecret )`

14. `sender`: generate `kek_nonce`
15. `sender`:
 
      `encrypted_key = aes.Seal( plaintext=payload_encryption_key, key=kek_derived_key, nonce=kek_nonce )`

16. `sender`: generate the `RecipientInfo.OtherRecipientInfo.KEMRecipientInfo` and encode to pem or der

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

17. Generate `CMS` using the following chain

```golang
type RecipientInfo struct {
	KTRI  KeyTransRecipientInfo `asn1:"optional"`
	KARI  KeyAgreeRecipientInfo `asn1:"optional,tag:1"` 
	KEKRI asn1.RawValue         `asn1:"optional,tag:2"`
	PWRI  asn1.RawValue         `asn1:"optional,tag:3"`
	ORI   asn1.RawValue         `asn1:"optional,tag:4"`
}

ori := OtherRecipientInfo{
	OriType:  OID_KEMRecipientInfo,
	OriValue: kcms,   //   <<<<<<<< this is KEMRecipientInfo
}
ri := RecipientInfo{
		ORI: ori,
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


18. `sender`->`receiver`: send the pem or der

---

`receiver`

19. `receiver` decodes ContentInfo and extracts 

  `(encrypted_payload, payload_encryption_nonce)`  // from `ContentInfo.EnvelopedData.ECI` 

  `(encrypted_key, kek_nonce, kdf_nonce, kemcipherText )`  // from  `ContentInfo.EnvelopedData.RecipientInfos[0].(RecipientInfo.OtherRecipientInfo.KEMRecipientInfo)`

20. reverse the ecryption by the sender 
   
    `sharedSecret = kem.Decapsulate( kemcipherText, key=kemPriv )`

    `derived_key = kdf( kdf_nonce, sharedSecret )`

    `payload_encryption_key = aes_gcm.open( key=derived_key, ciphertext=encrypted_key, nonce=kek_nonce )`

    `payload_text = aes_gcm.open( key=payload_encryption_key, ciphertext=encrypted_payload, nonce=payload_encryption_nonce )`

---

```bash
$ go run main.go 


    Creating public x509wrote issued.pem
    SharedSecret: kemShared (UttWSQV/iebgTFViYd1cfTfqATA6I4YbpaislI+lC4c=) 
    root_key YuzLBHEEUlU3gTh4BPSfF9S1hu8NZzxQrEdfqwatf6A= 
    sender derivedKey 36c272b4568d289e9e4c7a7508ec30f114d3b4aa82f6e80f79f8a8446a44a132
    encrypted payload_encryption_key a4ad92692200566accff45cf132e45b5c4c9c11471a51ae5abdc4a920e77d021a00c2d7fdc28ba7a120be22fd6d34270
    Issuer And SerialNumber: MEwxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZHb29nbGUxEzARBgNVBAsMCkVudGVycHJpc2UxFzAVBgNVBAMMDlNpbmdsZSBSb290IENBAhEAsawHe+kra1jvirWlsrQfNQ==
    payload_encrytion_nonce a73f3db2f4e6701e08f72495
    -----BEGIN CMS-----
    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
    w5BVF/rj5w9i
    -----END CMS-----

    ContentInfo Content Type 1.2.840.113549.1.7.3
    r ori 1.2.840.113549.1.9.16.13.3
    SharedSecret: kemShared (UttWSQV/iebgTFViYd1cfTfqATA6I4YbpaislI+lC4c=) 
    receiver derivedKey 36c272b4568d289e9e4c7a7508ec30f114d3b4aa82f6e80f79f8a8446a44a132
    plain_root_key YuzLBHEEUlU3gTh4BPSfF9S1hu8NZzxQrEdfqwatf6A=
    plain_encrypted_data: 
    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.

```

as asn1:

```bash
$ openssl asn1parse -inform PEM -in a.cms

    0:d=0  hl=4 l=1829 cons: SEQUENCE          
    4:d=1  hl=2 l=   9 prim: OBJECT            :pkcs7-envelopedData
   15:d=1  hl=4 l=1814 cons: cont [ 0 ]        
   19:d=2  hl=4 l=1810 cons: SEQUENCE          
   23:d=3  hl=2 l=   1 prim: INTEGER           :00
   26:d=3  hl=4 l=1296 cons: SET               
   30:d=4  hl=4 l=1292 cons: cont [ 4 ]        
   34:d=5  hl=2 l=  11 prim: OBJECT            :1.2.840.113549.1.9.16.13.3
   47:d=5  hl=4 l=1275 cons: SEQUENCE          
   51:d=6  hl=2 l=   1 prim: INTEGER           :00
   54:d=6  hl=2 l=  20 prim: OCTET STRING      [HEX DUMP]:CF51CC7C3EB2B06D6DA02A0FAB7F7C86AF840A78
   76:d=6  hl=2 l=  11 cons: cont [ 0 ]        
   78:d=7  hl=2 l=   9 prim: OBJECT            :ML-KEM-768
   89:d=6  hl=4 l=1088 prim: OCTET STRING      [HEX DUMP]:243C9D39D5D69118E0B38058E2F0C68F678CB6D61ACF83A27CC71315416E6C9A1D24B9881D81A4C888CD6828855A48871B7C78EEDD57C5742A36785FAABE5E72E113CB79AFEBEEB5D7DB43D7FC5ECFCF127CA8B4EE1B3860712F347D7C1A91A075617D0CEB6A3F5A9D6D727AF225F895BE0C705DF2C61316029F685030C031D9B9E154F4C77C8679F6121A7424C6A6D7F6918D4EA69588B900C5836000F9B49AC9B1F5772A6A9656D33BECF4A99F50EAE7E0E95CBD5AC82C7D753E83AE765A4351C4112EC4A61570175F61BF56F45FBBCFBD6EF4C8222114C284BD997889433775F8BC6A9E79E97BCC095A7B0E3F8A24F06F356D431CF28F8C67E4FBE13D729702E8AE1091C22FECBC7D2C4E58B8227DAEF290E95008DA674B07C6C7AC5E4B6B360321F8FCCD256A28B70F27299B6E65FC058E870ED5B34EEAB979F94DEC3C73F0384C956A504E8F847A010DEDDBA2EEDA9C49ED177DB4E3F6FBCBFE65FE43D910F4D187AA5037488C4C3A733E535C4A312BF2753239FCCD021656E531A2BFFABD71149C1A68B34654B82997382A3CC151E88230A2417D2CE1208B53BF5617FAAE93F8E78C99D996CE4B23697300A6FFCD8C484456283870BF8BC2DF94CB52B102E1D8314699CA44B4DC680BA2ED535DD618A27DEBA5AE63553E390171B907C7D3D1EDDDC0DF634B50E37B27FBF5F402E4D064CD14EBC21B62853AACF4AEC8315371981CB32AC8E0139C01EAB0DA8200A8FEF80B48626186DCB42C5997E8ECA0876B181C988E07DB494BB68B8420506F88CBF656CB06F79D7A581C73DB41FDDF5253856E6DAB7DA8ADBB39E30089ABD7C958D0AB08B8AB3CB005DEE03F3016E3872A201EED2A6E7874ABEC774E61ACF8FA46E731D0F549A65B100271821188E99EBF8AF68ADA160B590C5E4C580082502ECAD3B4779451DD0DD4B5CA7DADD57F1A157A6107EB17D7DD732ECBFFCA972D8133F0FE4BEF3C5925046D4D0E869AC0E21FB9F4B3944204224B0B54D734B1F00F928934738DCB980A58B38B7DE96CD6099BD4BE65DF085A79857C4A46ABFD1F4751A22B126D3A503ADC7BB1DC0E8FC298B4EAB05AA3E807041BA0AA65B0D14D312E7048BD90C986D69F4167B1C3FF0348CB4E0205C6679832BFA777F85E24C2FEF6802359760BF64A3A1D8148E1C114B21E62131A57665DFF0A2439AE1F338CDC22CDC1018F07A1DAA7163049650C24C34226BE02F6BCD190C6F4B5B00AD2AB7DDB7D70D4BAE3163F083C0AEF6D6D9EE0FC4492D0B166268B5D1A383773E6AD709FB886A2C974E94BDD7317E2381B82692133C3996CEDC090B22801A25CB97F87081F019C10B49F419E2C8272D9AF58BAFE519F115CCE51C6D3F9200962B4A3630F709EF9380AACFDEF39FA303FF14755618AA8929AF05C2038912389116E57B8EA771FA4C076D925CC4D2B2EEC409E0B223C4BE47672B16F4C3DBA2484C47B1B21704BEBA27650E810527517CAAAF9A9CA37782B827E960A39967F50099282DB1E43935665108B0837D2BE1D8C7066
 1181:d=6  hl=2 l=  47 cons: SEQUENCE          
 1183:d=7  hl=2 l=  11 prim: OBJECT            :1.2.840.113549.1.9.16.3.28
 1196:d=7  hl=2 l=  32 prim: EOC               
 1230:d=6  hl=2 l=   1 prim: INTEGER           :20
 1233:d=6  hl=2 l=  14 cons: cont [ 1 ]        
 1235:d=7  hl=2 l=  12 prim: OCTET STRING      :optional ukm
 1249:d=6  hl=2 l=  25 cons: SEQUENCE          
 1251:d=7  hl=2 l=   9 prim: OBJECT            :aes-256-gcm
 1262:d=7  hl=2 l=  12 prim: EOC               
 1276:d=6  hl=2 l=  48 prim: OCTET STRING      [HEX DUMP]:A4AD92692200566ACCFF45CF132E45B5C4C9C11471A51AE5ABDC4A920E77D021A00C2D7FDC28BA7A120BE22FD6D34270
 1326:d=3  hl=4 l= 503 cons: SEQUENCE          
 1330:d=4  hl=2 l=   9 prim: OBJECT            :id-aes256-wrap
 1341:d=4  hl=2 l=  25 cons: SEQUENCE          
 1343:d=5  hl=2 l=   9 prim: OBJECT            :aes-256-gcm
 1354:d=5  hl=2 l=  12 prim: OCTET STRING      [HEX DUMP]:A73F3DB2F4E6701E08F72495
 1368:d=4  hl=4 l= 461 prim: cont [ 0 ]        

```

using openssl to decode the cms:

```bash
$ openssl cms -cmsout -print -noout -inform PEM -in c.cms 
CMS_ContentInfo: 
  contentType: pkcs7-envelopedData (1.2.840.113549.1.7.3)
  d.envelopedData: 
    version: 0
    originatorInfo: <ABSENT>
    recipientInfos:
      d.ori: 
        oriType: undefined (1.2.840.113549.1.9.16.13.3)
        oriValue: SEQUENCE:
    0:d=0  hl=4 l=1275 cons: SEQUENCE          
    4:d=1  hl=2 l=   1 prim:  INTEGER           :00
    7:d=1  hl=2 l=  20 prim:  OCTET STRING      [HEX DUMP]:CF51CC7C3EB2B06D6DA02A0FAB7F7C86AF840A78
   29:d=1  hl=2 l=  11 cons:  cont [ 0 ]        
   31:d=2  hl=2 l=   9 prim:   OBJECT            :ML-KEM-768
   42:d=1  hl=4 l=1088 prim:  OCTET STRING      [HEX DUMP]:243C9D39D5D69118E0B38058E2F0C68F678CB6D61ACF83A27CC71315416E6C9A1D24B9881D81A4C888CD6828855A48871B7C78EEDD57C5742A36785FAABE5E72E113CB79AFEBEEB5D7DB43D7FC5ECFCF127CA8B4EE1B3860712F347D7C1A91A075617D0CEB6A3F5A9D6D727AF225F895BE0C705DF2C61316029F685030C031D9B9E154F4C77C8679F6121A7424C6A6D7F6918D4EA69588B900C5836000F9B49AC9B1F5772A6A9656D33BECF4A99F50EAE7E0E95CBD5AC82C7D753E83AE765A4351C4112EC4A61570175F61BF56F45FBBCFBD6EF4C8222114C284BD997889433775F8BC6A9E79E97BCC095A7B0E3F8A24F06F356D431CF28F8C67E4FBE13D729702E8AE1091C22FECBC7D2C4E58B8227DAEF290E95008DA674B07C6C7AC5E4B6B360321F8FCCD256A28B70F27299B6E65FC058E870ED5B34EEAB979F94DEC3C73F0384C956A504E8F847A010DEDDBA2EEDA9C49ED177DB4E3F6FBCBFE65FE43D910F4D187AA5037488C4C3A733E535C4A312BF2753239FCCD021656E531A2BFFABD71149C1A68B34654B82997382A3CC151E88230A2417D2CE1208B53BF5617FAAE93F8E78C99D996CE4B23697300A6FFCD8C484456283870BF8BC2DF94CB52B102E1D8314699CA44B4DC680BA2ED535DD618A27DEBA5AE63553E390171B907C7D3D1EDDDC0DF634B50E37B27FBF5F402E4D064CD14EBC21B62853AACF4AEC8315371981CB32AC8E0139C01EAB0DA8200A8FEF80B48626186DCB42C5997E8ECA0876B181C988E07DB494BB68B8420506F88CBF656CB06F79D7A581C73DB41FDDF5253856E6DAB7DA8ADBB39E30089ABD7C958D0AB08B8AB3CB005DEE03F3016E3872A201EED2A6E7874ABEC774E61ACF8FA46E731D0F549A65B100271821188E99EBF8AF68ADA160B590C5E4C580082502ECAD3B4779451DD0DD4B5CA7DADD57F1A157A6107EB17D7DD732ECBFFCA972D8133F0FE4BEF3C5925046D4D0E869AC0E21FB9F4B3944204224B0B54D734B1F00F928934738DCB980A58B38B7DE96CD6099BD4BE65DF085A79857C4A46ABFD1F4751A22B126D3A503ADC7BB1DC0E8FC298B4EAB05AA3E807041BA0AA65B0D14D312E7048BD90C986D69F4167B1C3FF0348CB4E0205C6679832BFA777F85E24C2FEF6802359760BF64A3A1D8148E1C114B21E62131A57665DFF0A2439AE1F338CDC22CDC1018F07A1DAA7163049650C24C34226BE02F6BCD190C6F4B5B00AD2AB7DDB7D70D4BAE3163F083C0AEF6D6D9EE0FC4492D0B166268B5D1A383773E6AD709FB886A2C974E94BDD7317E2381B82692133C3996CEDC090B22801A25CB97F87081F019C10B49F419E2C8272D9AF58BAFE519F115CCE51C6D3F9200962B4A3630F709EF9380AACFDEF39FA303FF14755618AA8929AF05C2038912389116E57B8EA771FA4C076D925CC4D2B2EEC409E0B223C4BE47672B16F4C3DBA2484C47B1B21704BEBA27650E810527517CAAAF9A9CA37782B827E960A39967F50099282DB1E43935665108B0837D2BE1D8C7066
 1134:d=1  hl=2 l=  47 cons:  SEQUENCE          
 1136:d=2  hl=2 l=  11 prim:   OBJECT            :1.2.840.113549.1.9.16.3.28
 1149:d=2  hl=2 l=  32 prim:   EOC               
 1183:d=1  hl=2 l=   1 prim:  INTEGER           :20
 1186:d=1  hl=2 l=  14 cons:  cont [ 1 ]        
 1188:d=2  hl=2 l=  12 prim:   OCTET STRING      :optional ukm
 1202:d=1  hl=2 l=  25 cons:  SEQUENCE          
 1204:d=2  hl=2 l=   9 prim:   OBJECT            :aes-256-gcm
 1215:d=2  hl=2 l=  12 prim:   EOC               
 1229:d=1  hl=2 l=  48 prim:  OCTET STRING      [HEX DUMP]:A4AD92692200566ACCFF45CF132E45B5C4C9C11471A51AE5ABDC4A920E77D021A00C2D7FDC28BA7A120BE22FD6D34270
    encryptedContentInfo: 
      contentType: id-aes256-wrap (2.16.840.1.101.3.4.1.45)
      contentEncryptionAlgorithm: 
        algorithm: aes-256-gcm (2.16.840.1.101.3.4.1.46)
        parameter: OCTET STRING:
          0000 - a7 3f 3d b2 f4 e6 70 1e-08 f7 24 95            .?=...p...$.
      encryptedContent: 
        0000 - a6 8a 50 c0 79 5e c2 15-f7 a6 a4 6a 66 7b 28   ..P.y^.....jf{(
        000f - d9 a6 11 ce 2c 07 91 c3-0c 74 77 f7 60 ca b9   ....,....tw.`..
        001e - 23 9c d8 52 9a ad 87 2f-15 e6 c1 d9 e9 8b 70   #..R.../......p
        002d - 8c ce dc a7 3e 00 88 d1-0f fe 00 26 83 4c 1a   ....>......&.L.
        003c - 1a 8f 6e b0 81 b4 db 0e-5e 02 7d 89 e7 6d 72   ..n.....^.}..mr
        004b - e9 cf c3 8a 88 ec d1 da-e1 b6 ff 4e 4e de 49   ...........NN.I
        005a - fd 9e b8 bf 48 c3 77 10-c8 7a 1b 43 17 9d 4c   ....H.w..z.C..L
        0069 - e9 68 1e 70 e0 19 95 c2-63 0d 0b 02 da 1c 74   .h.p....c.....t
        0078 - 72 50 23 0f ef dc 71 17-7d fe 9f e3 0f a3 f1   rP#...q.}......
        0087 - 40 23 7e cb 80 99 40 07-b1 a9 13 7b bc cf a9   @#~...@....{...
        0096 - 8a fd 37 67 82 e5 7c 9b-90 46 b0 5c 1c 8e 02   ..7g..|..F.\...
        00a5 - 16 cf b3 08 c3 a8 a6 62-5e 9c e2 af 3b 0d af   .......b^...;..
        00b4 - a2 a1 b3 03 92 e9 54 a3-e1 9e 1f 11 cf b0 c9   ......T........
        00c3 - 60 40 6c 8e 5b e2 27 a2-46 1e e1 dc 08 fc 2c   `@l.[.'.F.....,
        00d2 - 81 d1 fb e3 1d ca 93 b3-6f 2d 3a 52 38 e6 0c   ........o-:R8..
        00e1 - 45 05 9e b4 eb a7 f0 19-38 77 67 25 4f 01 c8   E.......8wg%O..
        00f0 - 66 4b dc 11 10 5c f9 6f-d2 75 b6 ac 07 62 db   fK...\.o.u...b.
        00ff - 26 66 8d c9 ff 18 1d 73-92 f1 64 f6 9a 2f 99   &f.....s..d../.
        010e - aa 23 e5 e7 ca 89 56 51-9c 90 92 a1 73 20 2f   .#....VQ....s /
        011d - be 05 cf 3e 8d c0 e2 85-49 01 56 7b 17 c9 d4   ...>....I.V{...
        012c - f5 ff 85 c2 d9 fc b1 20-be 41 91 e1 38 70 cb   ....... .A..8p.
        013b - a6 11 87 80 4f 07 c2 ab-98 21 3b c4 53 84 81   ....O....!;.S..
        014a - 49 3e 47 c6 82 1a fb d3-ed 36 18 1a f4 e1 0e   I>G......6.....
        0159 - 97 f9 f7 ad c9 14 73 a4-d6 b0 51 7a 09 8e 15   ......s...Qz...
        0168 - a9 f2 4e 69 cc 52 4e 78-14 47 63 a4 36 e6 f1   ..Ni.RNx.Gc.6..
        0177 - 70 c4 a3 22 35 26 03 6c-80 c8 b3 d7 31 3b 18   p.."5&.l....1;.
        0186 - 89 49 3e 9a 25 95 7f 76-18 93 7b 59 fb b6 5d   .I>.%..v..{Y..]
        0195 - be 1a b7 aa 84 48 74 32-ff f3 c4 b4 72 a0 1b   .....Ht2....r..
        01a4 - c8 95 61 ec 9a fe d6 c2-98 06 1a 28 39 64 47   ..a........(9dG
        01b3 - 0e 18 dd 1c a9 c7 52 6a-b9 5e 95 af 23 ec 51   ......Rj.^..#.Q
        01c2 - 01 ed c3 90 55 17 fa e3-e7 0f 62               ....U.....b
    unprotectedAttrs:
      <ABSENT>
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


