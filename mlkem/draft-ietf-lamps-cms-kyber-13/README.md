#### Cryptographic Message Syntax (CMS) for KEM draft-ietf-lamps-cms-kyber-13

Just an interpretation/implementation in go of

* [Use of ML-KEM in the Cryptographic Message Syntax (CMS)](https://datatracker.ietf.org/doc/draft-ietf-lamps-cms-kyber/)

>> please note this is *draft* and just a **best guess** on what the implementation would look like; do not use this in prod

> also, critically, stadnard go does **NOT** support parsing KEM public keys types.  The code below uses a modified `crypto/x509.go` described in [../issue_cert/x509.diff](../issue_cert/x509.diff)

i.,e if you run the code as-is, you'll see the following because go doesn't understand mlkem public keys yet.  To 

```bash
$ go run main.go 
****************  RECEIVER **********************
generate key and issue x509
Creating public x509
Failed to create certificate: x509: unsupported public key type: *x509.MLKEMPublicKeyInfo
exit status 1
```

the code here just does something very simple: it just uses a static KEM public/private key, a static aes key and nonce to generate a cms.


The reason this uses a static keypair was just to try and create the same 'test vector' described at the bottom of `draft-ietf-lamps-cms-kyber`.  You can see that by running `baseline/main.go`.  If you wanted to generate a new aes keypair, run `main.go` (theyr'e similar except to comply/mimic the "test vector", used the same nonce and 'random' static aes key in baseline)

Ofcourse in real life, you'd use your own keypair and random aes key...

but if you run this app, you'll end up with `c.cms` file which when you use openssl to decode, you'll get


```bash
$ openssl cms -cmsout -print -noout -inform PEM -in c.cms

CMS_ContentInfo: 
  contentType: id-smime-ct-authEnvelopedData (1.2.840.113549.1.9.16.1.23)
  d.authEnvelopedData: 
    version: 0
    originatorInfo: <ABSENT>
    recipientInfos:
      d.ori: 
        oriType: undefined (1.2.840.113549.1.9.16.13.3)
        oriValue: SEQUENCE:
    0:d=0  hl=4 l=1203 cons: SEQUENCE          
    4:d=1  hl=2 l=   1 prim:  INTEGER           :00
    7:d=1  hl=2 l=  20 prim:  OCTET STRING      [HEX DUMP]:CF51CC7C3EB2B06D6DA02A0FAB7F7C86AF840A78
   29:d=1  hl=2 l=  11 cons:  cont [ 0 ]        
   31:d=2  hl=2 l=   9 prim:   OBJECT            :ML-KEM-768
   42:d=1  hl=4 l=1088 prim:  OCTET STRING      [HEX DUMP]:03041EC64CFC5396A0A1F95CBB579C130E30A3FFBCC9BEF541A5398907A930C9573DE9477BA6A93B35201E3B48A63AA56E8279AEAD27F7B89D42960FAE99A79121C3BB4DBC4E35807A930FD296AC7828E2FD388296CBB0FB754225D0384029E613C2B6E644B3F74A77EDDE95549DD21321E89EE125F20FA4B68E6065F0017851493DCCC2E03B7BCBA9825CFFC8D480E3F9E796D2EEA17F46FBA5A941FD35EF8D45B463398268A2B875159F51779C5EA8FD6220201DF7927A0020C50B1B1568E1D5A28C8175732DF553950EFC1BE436F5D1BE17B2F7210D118240E4853C76A789D08D0FB9639E77F18C38BA798D8ABC41A4204B3D48B6893D3D953040C400582948911137036102DB9558E2B4EF9583038DD57FDE0FC482CA09421AD3F401173261420869FF40D1049DEB98D92AE997C698441469BCCA83523FD7077AF0822F781355138F6EF6EC3AD55146B28F979036611DCFEFA1B10D944EF13740035677A5EE9CD54D676DEDD3AA75835A4742BFF87F43BF4B967B6ECECB5E409701B74FFFB7D045425E3525BE035F529EF43D0EA3E0919C9DE166D4419948AFC2FAA0DFEF95584CEA6E9A101D4A9FBA33C775A3CD7B3B39B4AA715E7AF2D5557EB62324460E7B4BAAD63428CCA3964C816B20E83084B106BA8BD2B8F7984FED86312999B0F1D1FB177907B3A231B7CD32176A9AADE14F00A2C23BA3D55E9BD3D8F5277D8E90B7885508EE1AA5DE4CAC79EC27ED170C7902B1FF5177A3B060F5DF453EE198DDAF576E884BBF8664FCE972E4F1351F7972ADB4BD96ADF5565971E9D98A4AD813876D12F7360F16066A7B7F69E96ACD65E64D44001DD1FC8B17E2C7520F1877E9B3603272EF53A5BAF46D8F550226B4CCDE25CE1B622BBFD8A62EDC3691107F1ED5927B78ED848756A06EBFC074DCA5528A5A67A9141C361AABC4EC9304F0066C96FD6CFE2D5F9EFEAED0308E6E87421B81628053B2395F05347714B219EEDE50B34CEF07112D5FDB31E104302648F5FC205CF2172FEC9BE68B4509AFF81527A660CA7E0810E353456F7A64230EB6B016E1FD5CAAD8750B161B95BC18AC331593F9566D9DCD88E2D8C970412382F42C1A140485039F35BD2FDA4F4F41E079C9A7A6E3744D20AF8D5A67D2CB446BB5635A2FAEDFA8C2573874138FE5FAB8B802463C48FB600E31512B0C59AECCB7CB7B2C81B8368729295F27EE9BC85A58F4F383ABA066ED608B334F3C9B47EC8ED5704A4206705006AFD894D55D3BAB3A218AE0033E14559114A9C35BCA13CF18E9EAD0E6ACB2623E850BFF1F4C25AAB18F1A3297D8CDCB23083D22D7EEBDF80CC737405AA389B9DBD4D57AFDE91BDFA99F3E4737EF74F20997DE52B79396BE7034EBA38F1B9798468978A20FCF5D0CB307A99F29D07793D95FC34BCD1CE95ED481BCB80BEE3FCAEC7D0C3C0161818354AD7BDF75A73F344705B41BCE8E871CD3500B6BD9F98EB069AC1F6AFC7218B92799AC1AAF2199323AB7F474D66770DDFAAB5110FDD900E4E9681ED0D74102E6923019
 1134:d=1  hl=2 l=  13 cons:  SEQUENCE          
 1136:d=2  hl=2 l=  11 prim:   OBJECT            :1.2.840.113549.1.9.16.3.28
 1149:d=1  hl=2 l=   1 prim:  INTEGER           :10
 1152:d=1  hl=2 l=  11 cons:  SEQUENCE          
 1154:d=2  hl=2 l=   9 prim:   OBJECT            :id-aes128-wrap
 1165:d=1  hl=2 l=  40 prim:  OCTET STRING      [HEX DUMP]:7543C33AF7804BDE5BCF48F0CBE65175A596C7F2D8D2A7A45626ADD4B97F5FFE4CA5C93C567AB932
    authEncryptedContentInfo: 
      contentType: pkcs7-data (1.2.840.113549.1.7.1)
      contentEncryptionAlgorithm: 
        algorithm: aes-128-gcm (2.16.840.1.101.3.4.1.6)
        parameter: SEQUENCE:
    0:d=0  hl=2 l=  17 cons: SEQUENCE          
    2:d=1  hl=2 l=  12 prim:  OCTET STRING      [HEX DUMP]:C2838A9C652172DEA20F4BE3
   16:d=1  hl=2 l=   1 prim:  INTEGER           :10
      encryptedContent: 
        0000 - 04 0d 82 4e fb e6 b6 90-3b 6b 80 82 3f e4 af   ...N....;k..?..
    authAttrs:
      <ABSENT>
    mac: 
      0000 - a6 56 b6 10 dd 8a 42 fb-09 05 d8 6c 9b bf 18 5f   .V....B....l..._
    unauthAttrs:
      <ABSENT>

```

you can compare that to the `baseline.cms` file described in the draft/proposal.   

Note that you get pretty much the same cms file (with the exception that i encded the subketidentifier into the PEM for completness sake)


```bash
$ openssl cms -cmsout -print -noout -inform PEM -in baseline.cms 

CMS_ContentInfo: 
  contentType: id-smime-ct-authEnvelopedData (1.2.840.113549.1.9.16.1.23)
  d.authEnvelopedData: 
    version: 0
    originatorInfo: <ABSENT>
    recipientInfos:
      d.ori: 
        oriType: undefined (1.2.840.113549.1.9.16.13.3)
        oriValue: SEQUENCE:
    0:d=0  hl=4 l= 867 cons: SEQUENCE          
    4:d=1  hl=2 l=   1 prim:  INTEGER           :00
    7:d=1  hl=2 l=  20 prim:  cont [ 0 ]        
   29:d=1  hl=2 l=  11 cons:  SEQUENCE          
   31:d=2  hl=2 l=   9 prim:   OBJECT            :ML-KEM-512
   42:d=1  hl=4 l= 768 prim:  OCTET STRING      [HEX DUMP]:3EA40FC6CA090E2C8AF76E2727AB38E0652D9515986FE186827FE84E596E421B85FD459CC78997372C9DE31D191B39C1D5A3EB6DDB56AADEDE765CC390FDBBC2F88CB175681D4201B81CCDFCB24FEF13AF2F5A1ABCF8D8AF384F02A010A6E919F1987A5E9B1C0E2D3F07F58A9FA539CE86CC149910A1692C0CA4CE0ECE4EEED2E6699CB976332452DE4A2EB5CA61F7B081330C34798EF712A24E59C33CEA1F1F9E6D4FBF3743A38467430011336F62D870792B866BEFCD1D1B365BED1952673D3A5B0C20B386B4EFD1CF63FD376BD47CCC46AC4DD8EC66B047C4C95ACFF1CFD028A419B002FDA1B617CBA61D2E91CFE8FFFBCB8FFD4D5F6AD8B158C219E36DC51405DC0C0B234979AC658E72BDDF1B6773B96B2AE3E4D07BE86048040C0167436FA839E7529B00CC9AB55A2F25DB63CC9F557594E691C11E553D4A3EBC760F5F19E5FE144838B4C7D1591DA9B5D467494FD9CAC52CC5504060399DBDB72298EB9A4C017B00786FDC7D9D7AA57ADBB8B61C34DE1E288B2AB728171DCE143CD16953F984C1AED559E56BAA0CE658D32CCE42F4407504CD7A579AD0EF9B77135EAA39B6F93A3A2E5997807F06361C83F4E67F8E3F9CF68316011514F5D85A181CEAD714CD4940E4EBAC01D66528DA32F89CEA0428E8EBCADCF8AA188C9F62E85B1957655B7FE2B8D7973B7A7226B66D93BF7B232F3DCF653C84B4ECF1A9920DB1949AD750B546A5552A20E54909719B8C0C07056FCB7E574AD2A32EC95001DDE84481BE77D039ED5BF74262ECF3981F1B00D3366A9C2E061C47E241A061C6249560D2B8446A480C38C28BA989D9F68ADC4BBAF2A20B47E4923128C72342D597FDA259DE0B83C2056D6B77E799B319324AA50B1D659C2A56029B7453C5F3BA5243D9FA749D917C40D9D101E453BC8B10E42A7C089323C026F783E100B9FA6E7014424DA6FA3792BC957EE8219D016B773F28FEDCC962A485ABAFFEC023281971E29AA689839ECFD2619E92287CD230DB26A2507CC500EB1C7A5293B5FE917AE29BF1AD350124F8A311635214B411DB9F67D3B85BD715018537EA45B41F41B4C66051
  814:d=1  hl=2 l=  13 cons:  SEQUENCE          
  816:d=2  hl=2 l=  11 prim:   OBJECT            :1.2.840.113549.1.9.16.3.28
  829:d=1  hl=2 l=   1 prim:  INTEGER           :10
  832:d=1  hl=2 l=  11 cons:  SEQUENCE          
  834:d=2  hl=2 l=   9 prim:   OBJECT            :id-aes128-wrap
  845:d=1  hl=2 l=  24 prim:  OCTET STRING      [HEX DUMP]:C050E4392F9C14DD0AC2220203F317D701F94F9DD92778F5
    authEncryptedContentInfo: 
      contentType: pkcs7-data (1.2.840.113549.1.7.1)
      contentEncryptionAlgorithm: 
        algorithm: aes-128-gcm (2.16.840.1.101.3.4.1.6)
        parameter: SEQUENCE:
    0:d=0  hl=2 l=  17 cons: SEQUENCE          
    2:d=1  hl=2 l=  12 prim:  OCTET STRING      [HEX DUMP]:5CA57468B81BF03B8DA7186C
   16:d=1  hl=2 l=   1 prim:  INTEGER           :10
      encryptedContent: 
        0000 - 94 c8 68 9a 99 d2 c3 8e-19 2f a6 ba 08         ..h....../...
    authAttrs:
      <ABSENT>
    mac: 
      0000 - 5c f1 78 6c 57 c7 40 2b-54 fc 93 c3 0a 4a 45 33   \.xlW.@+T....JE3
    unauthAttrs:
      <ABSENT>

```


```bash
### go to the `issue_cert` filder and apply the diff to the custom go release
# cd ../issue_cert
# git clone --branch go1.25.1 --single-branch --depth 1 https://github.com/golang/go.git goroot

# cd goroot
# git apply ../x509.diff
# git apply ../version.diff

# cd src/
# ./make.bash

# cd ../../
# export GOROOT=`pwd`/goroot
# export PATH=$GOROOT/bin:$PATH

## notice you'll see the modified version of go

# $ goroot/bin/go version go1.25.1-mod linux/amd64


$ go run main.go 

****************  RECEIVER **********************
generate key and issue x509
Creating public x509
wrote issued.pem


****************  SENDER **********************
SubjectKeyId cf51cc7c3eb2b06d6da02a0fab7f7c86af840a78
Issuer and serialNumber 304c310b3009060355040613025553310f300d060355040a0c06476f6f676c6531133011060355040b0c0a456e74657270726973653117301506035504030c0e53696e676c6520526f6f742043410210694ca09814e950c4bf8247c7cded7780
kemcipherText 5c291fb8b61e1e2d3b32c0d8bbde4c0a902452ca3de546eb51fd02bfc4dfdebe48d1213c3aca2f9aec1f0417c331fbebe6f67939e87c03ef20f661ce56a21b8dd440cff8a2635d8a90a2cc276c8eaf4f7ea92a92bec4a1070f60140196743ed1ba2196077590cc52e33c8bd70a5070955ff651d76f13804204e7465d531cc568ecccd24de98886003c1ddac7ff39fdde59efc61914d0ad57d210f52a5f54592de93a7e8429f085d9a7d167e4d24c8cc8258c09da30b5d22416c3b98321888a9f6ffe5f33ac645b1969c69294a916404d7dbd509ff872bf9023299cea425bddd12e7d601f370e059bd279d8ea6a25c540a384f1b2a4f8caf5d69d02682c330ab49d7962406b40bb85a89c92bc30d994bcb7739efb1d3b5cdc1397355619ed64389304c624acebdfdb5fb1dcd5f15a08d4f653cf2dcae38ea1c86a1556fccf49fb962568caba8f89af560b70cc72cc0595ca11b7e521d8eeada6d5f24b1d69c21419cf4398df25f84ba6c1c4cc4c40b2a3d0bbfd8e51821b13a921fb074eac7ea01cca3bf73e9f4bcd9d54deed73785e64e462ba92f7e97d2eb0b1aee9576ab969aaa6187e25236b469622d860b674de676acac01864477508af3251eecbee56a4efe1e1b608018afad1efb2f23da6a67ef0f896f144316b77355b94a542877674d20ffecf52158acea6da6e2207b2cc613d9243047576fe997772953b2be0ed9920ed2d793508efc81ac206da0546539f4aaa1c017c69090ee2f3d5c6383a708acef3789f56350a5c075589a371fefc3bcf6167c4834f5bdd4c8de1089f6e1f4366c6dc89c40efcd7238dfd56481c4d8918f20aeedd014d9316f0c0b82defd6850fad4af087abed3f3a1d76a4ac922262001d7eccce415e1152ba688b3a73c66750c6c4efc9024851d7959fb46254f0825b3d838143576586f6641143f15752e7625cd25863c3ca29e44bc3555c7ece58ffaf56fcdfaf7c37ddc22884a04e95cedaad0b30c4702560ac733c1e80c4100237508760250d2b2867547999ab8385deb99007534f0b018fcb98547419dd931a0ce6b87fcb66d64cc085ba88f4c543c9254a087ee733db71bd3c434815b756504e8e88b131970c70e6b5d7f9a68281ff68362a625abded1dc9df1ae782e7dbcd70f16de46bbd92bb28428b918144a742ef9d5dbbbb4ad80109d9f0f2a6a549c1ff71fc7c88ebcc74448764074c3dff8826274932dabb7b3b8cafc10155b1f246211c1be279f9007d1326593b04362dfddc6e9adf8d4854a785dc44992325b7cff8304da0dc2f975041c84412a82b337113920bff361e41bfe3af9774cf99fb6e122f14ec8d445058527678999020b538252d291b80da833e9981df580be881dd1530a20de243e717e445750fba2cbbbd32be44a120abd2bd87a3e94d4748fc9418fc1d657d8c334dce43716a2c78189bd1b9f981b00e69bd82669aa1def5bd1fed2fdda11d7d58d74a87e28695f49b7bea9b0418a47911bcda6c71eb1fbd55a1b3ab5283a882c0fa241108d69eac384b
SharedSecret: kemShared daLaj1QxJx9mHbpwKAvqYeSStzmIXKMteNjpldmw5ys= 
root_key KqgLx3sbo1a2ezqfhSUIlEdU3KK5z73DRZJDQxYmlUg= 
spi cf51cc7c3eb2b06d6da02a0fab7f7c86af840a78
CMSORIforKEMOtherInfo 3010300b0609608648016503040105020110
KEK 140da405e94f58f340574e98fdc4c88f
encrypted_content_key f668befb2a85c735ff05e7eef0d97deb85d26755fd428d09180026b15304613a65314fc45c423b27
content_encryption_nonce_bytes af00b9df86d93d8a7479c87e
actualCiphertext 53148f804aa9547c9084cf747a
ciphertextWithMac 53148f804aa9547c9084cf747ad4faf908e09a1105d99e478883a27fd0
mac d4faf908e09a1105d99e478883a27fd0
tagSize 16
-----BEGIN CMS-----
MIIFSgYLKoZIhvcNAQkQARegggU5MIIFNQIBADGCBMikggTEBgsqhkiG9w0BCRAN
AzCCBLMCAQAEFM9RzHw+srBtbaAqD6t/fIavhAp4oAsGCWCGSAFlAwQEAgSCBEBc
KR+4th4eLTsywNi73kwKkCRSyj3lRutR/QK/xN/evkjRITw6yi+a7B8EF8Mx++vm
9nk56HwD7yD2Yc5WohuN1EDP+KJjXYqQoswnbI6vT36pKpK+xKEHD2AUAZZ0PtG6
IZYHdZDMUuM8i9cKUHCVX/ZR128TgEIE50ZdUxzFaOzM0k3piIYAPB3ax/85/d5Z
78YZFNCtV9IQ9SpfVFkt6Tp+hCnwhdmn0Wfk0kyMyCWMCdowtdIkFsO5gyGIip9v
/l8zrGRbGWnGkpSpFkBNfb1Qn/hyv5AjKZzqQlvd0S59YB83DgWb0nnY6molxUCj
hPGypPjK9dadAmgsMwq0nXliQGtAu4WonJK8MNmUvLdznvsdO1zcE5c1VhntZDiT
BMYkrOvf21+x3NXxWgjU9lPPLcrjjqHIahVW/M9J+5YlaMq6j4mvVgtwzHLMBZXK
EbflIdjurabV8ksdacIUGc9DmN8l+EumwcTMTECyo9C7/Y5RghsTqSH7B06sfqAc
yjv3Pp9LzZ1U3u1zeF5k5GK6kvfpfS6wsa7pV2q5aaqmGH4lI2tGliLYYLZ03mdq
ysAYZEd1CK8yUe7L7lak7+HhtggBivrR77LyPaamfvD4lvFEMWt3NVuUpUKHdnTS
D/7PUhWKzqbabiIHssxhPZJDBHV2/pl3cpU7K+DtmSDtLXk1CO/IGsIG2gVGU59K
qhwBfGkJDuLz1cY4OnCKzvN4n1Y1ClwHVYmjcf78O89hZ8SDT1vdTI3hCJ9uH0Nm
xtyJxA781yON/VZIHE2JGPIK7t0BTZMW8MC4Le/WhQ+tSvCHq+0/Oh12pKySImIA
HX7MzkFeEVK6aIs6c8ZnUMbE78kCSFHXlZ+0YlTwgls9g4FDV2WG9mQRQ/FXUudi
XNJYY8PKKeRLw1Vcfs5Y/69W/N+vfDfdwiiEoE6VztqtCzDEcCVgrHM8HoDEEAI3
UIdgJQ0rKGdUeZmrg4XeuZAHU08LAY/LmFR0Gd2TGgzmuH/LZtZMwIW6iPTFQ8kl
Sgh+5zPbcb08Q0gVt1ZQTo6IsTGXDHDmtdf5poKB/2g2KmJave0dyd8a54Ln281w
8W3ka72SuyhCi5GBRKdC751du7tK2AEJ2fDypqVJwf9x/HyI68x0RIdkB0w9/4gm
J0ky2rt7O4yvwQFVsfJGIRwb4nn5AH0TJlk7BDYt/dxumt+NSFSnhdxEmSMlt8/4
ME2g3C+XUEHIRBKoKzNxE5IL/zYeQb/jr5d0z5n7bhIvFOyNRFBYUnZ4mZAgtTgl
LSkbgNqDPpmB31gL6IHdFTCiDeJD5xfkRXUPuiy7vTK+RKEgq9K9h6PpTUdI/JQY
/B1lfYwzTc5DcWoseBib0bn5gbAOab2CZpqh3vW9H+0v3aEdfVjXSofihpX0m3vq
mwQYpHkRvNpscesfvVWhs6tSg6iCwPokEQjWnqw4SzANBgsqhkiG9w0BCRADHAIB
EDALBglghkgBZQMEAQUEKPZovvsqhcc1/wXn7vDZfeuF0mdV/UKNCRgAJrFTBGE6
ZTFPxFxCOycwOgYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBBjARBAyvALnfhtk9inR5
yH4CARCADVMUj4BKqVR8kITPdHqiFjAUBgsqhkiG9w0BCRACITEFBANmb28EENT6
+QjgmhEF2Z5HiIOif9A=
-----END CMS-----



****************  RECEIVER **********************
ContentType 1.2.840.113549.1.9.16.1.23
ContenrauthedInfo.VersiontType 0
KEMRecipientInfo Alg 1.2.840.113549.1.9.16.13.3
Found MLKEM758 in private key
recovered shared secret: kemShared daLaj1QxJx9mHbpwKAvqYeSStzmIXKMteNjpldmw5ys= 
AuthEnvelopedData  2.16.840.1.101.3.4.1.6
expected spi cf51cc7c3eb2b06d6da02a0fab7f7c86af840a78
recalled CMSORIforKEMOtherInfo 3010300b0609608648016503040105020110
recalled KEK 140da405e94f58f340574e98fdc4c88f
recalled encrypted_content_key 7b023af1f41f280588b9af6762d79dbeab6958235090f0cf8813a0848e16d612
content_encryption_nonce_bytes af00b9df86d93d8a7479c87e
Attribute Type 1.2.840.113549.1.9.16.2.33
Recalled AAD foo
rplainText Hello, world!
```


---

TODO:

AAD text is supposed to get encoded into the envelope as authenticated attributes but unfortunately,  openssl uses the wrong tag value  [openssl/issues/26101](https://github.com/openssl/openssl/issues/26101)

and you'll see the following error

```bash
$ openssl cms -cmsout -print -noout -inform PEM -in c.cms 
Error reading SMIME Content Info
80ABE529AF7F0000:error:068000A8:asn1 encoding routines:asn1_check_tlen:wrong tag:crypto/asn1/tasn_dec.c:1194:
80ABE529AF7F0000:error:0688010A:asn1 encoding routines:asn1_d2i_ex_primitive:nested asn1 error:crypto/asn1/tasn_dec.c:752:
80ABE529AF7F0000:error:0688010A:asn1 encoding routines:asn1_template_noexp_d2i:nested asn1 error:crypto/asn1/tasn_dec.c:685:Field=mac, Type=CMS_AuthEnvelopedData
80ABE529AF7F0000:error:0688010A:asn1 encoding routines:asn1_template_noexp_d2i:nested asn1 error:crypto/asn1/tasn_dec.c:685:
80ABE529AF7F0000:error:0688010A:asn1 encoding routines:asn1_template_ex_d2i:nested asn1 error:crypto/asn1/tasn_dec.c:537:Field=d.authEnvelopedData, Type=CMS_ContentInfo
```

as a workaround i modified the local asn parsing tage `main.go` to compensate for this just so i can parse it with openssl

ofcourse you don't have to make this change if you don't want to "see" the structure with openssl...

```golang
type AuthEnvelopedData struct {
	Version        int
	OriginatorInfo asn1.RawValue `asn1:"optional,implicit,tag:0"`
	RecipientInfos RecipientInfo `asn1:"set,implicit"`
	AECI           EncryptedContentInfo
	AauthAttrs     []Attribute `asn1:"set,optional,implicit,tag:2"` /// <<< modified from 1 to 2 to accoodate  https://github.com/openssl/openssl/issues/26101
	MAC            []byte
	UnAauthAttrs   []Attribute `asn1:"set,optional,implicit,tag:3"` /// <<< modified from 2 to 3 to accoodate  https://github.com/openssl/openssl/issues/26101
}
```