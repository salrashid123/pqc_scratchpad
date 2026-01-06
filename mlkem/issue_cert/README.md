#### Using go to generate MLKEM x509 certificate


The following is just an unreviewed _hack_ to get an *RSA* based CA to issue an `x509` where the CSR includes a public `ML_KEM key`.

Note no validation is done to ensure the ML-KEM key is legit ...what this does is only takes the CSR and allows `x509.CreateCertificate` to work.

Go doens't yet understand MLKEM certificates issuance so what the follwoing does is overrides `crypto/x509` with [x509.diff](x509.diff) patch.

Basically, that patch adds in the oid and structure to allow parsing and interpretation of MLKEM certificates. I used `go1.25.1` as a basis for that diff

>> again, this is just a hack, please don't use this in prod and wait for upstream go to support all this

also see 

* [KEM Certificate Signing Request Protocol and Key Exchange Protocol](https://csrc.nist.gov/csrc/media/Presentations/2025/kem-based-certificate-signing/images-media/kem-based-certificate-signing-request.pdf)

---

Anyway, the program main.go requires you to first apply the diff to your go installation.  From there if you runit

the `issued.pem` (which will be different for you) is actually an RSA signed certificate by a CA which internally includes an ml-kem public key


```bash
$ go run main.go 
SharedSecret: kemShared (XnZWhWFhESwSfFfdlpLFMvQr5TuH6f0UfW6G7RMQtdU=) 
SharedSecret: kemShared (XnZWhWFhESwSfFfdlpLFMvQr5TuH6f0UfW6G7RMQtdU=) 
CN=Single Root CA,OU=Enterprise,O=Google,C=US
Creating public x509
wrote issued.pem


$ cat issued.pem 
-----BEGIN CERTIFICATE-----
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
ZmI0lQBa3eMu6TeX4qA=
-----END CERTIFICATE-----
```


you can verify it using openssl which support pqs like this docker file.    

Notice the certificate's `Public Key Algorithm: ML-KEM-768` and that when we extract the publicKey, its the same as what the MLKEM Public we embeeded in the go program.

```bash
docker run -v /dev/urandom:/dev/urandom  -ti salrashid123/openssl-pqs:3.5.0-dev

openssl x509 -noout -text -in issued.pem 


Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            c4:06:54:ad:d4:f5:6e:4f:7f:f5:eb:8e:00:76:49:91
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Google, OU=Enterprise, CN=Single Root CA
        Validity
            Not Before: Jan  6 14:33:16 2026 GMT
            Not After : Jan  6 14:33:16 2027 GMT
        Subject: C=US, ST=California, L=Mountain View, O=Acme Co, OU=Enterprise, CN=mycn
        Subject Public Key Info:
            Public Key Algorithm: ML-KEM-768  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                ML-KEM-768 Public-Key:
                ek:
                    ba:da:2d:03:99:ca:81:63:2b:ba:c3:7b:56:f4:01:
                    dd:ba:95:ed:83:09:2e:1a:30:e7:2c:7a:94:e9:08:
                    7e:33:9e:74:d4:0e:9f:bb:a3:21:e5:18:98:88:74:
                    91:53:2a:8a:c9:b4:3b:a1:20:bd:01:b2:96:d7:75:
                    c3:86:cf:2d:5c:35:3e:e3:1f:c4:53:36:df:c0:ca:
                    bb:9b:36:0f:09:2a:f3:c7:0e:5c:2b:aa:8e:9a:c2:
                    85:9b:47:47:d3:a2:27:3a:93:34:e7:1f:f8:f5:23:
                    7e:24:8a:36:a2:3c:b1:a3:44:c6:4a:c9:62:91:71:
                    91:3c:4c:f8:e3:61:f3:99:62:5a:d3:b1:9f:86:89:
                    ee:f6:30:ed:3a:b6:88:b8:24:00:3a:5e:f7:2b:92:
                    a9:33:4a:7a:18:37:0f:65:10:e8:fb:60:fd:65:45:
                    c9:25:02:d0:e4:0e:06:77:c7:cb:43:02:e5:e5:7a:
                    92:54:b8:8d:86:43:6b:73:a6:d8:94:70:20:92:7e:
                    4a:7c:a3:bc:1a:ce:63:15:48:07:06:ca:55:e8:23:
                    54:e8:1e:60:96:41:b9:f8:27:a6:87:19:31:59:2d:
                    cd:20:ce:0f:4a:81:81:57:05:07:34:3c:98:da:89:
                    22:50:cd:ef:05:b1:fc:25:02:65:49:94:01:91:9e:
                    8f:f5:3c:de:a7:aa:35:d0:1d:d6:61:24:91:72:58:
                    d2:7c:34:d0:96:05:26:19:62:70:16:b9:eb:fa:c9:
                    bf:72:99:32:44:28:be:d3:b5:a3:17:38:80:48:cf:
                    a3:b3:c9:75:07:98:fb:76:49:57:ab:26:1a:e5:3b:
                    93:33:ae:f7:7b:19:ee:54:7f:c1:51:47:80:9a:aa:
                    06:a5:c0:ec:39:89:f9:7b:0c:28:fa:92:0c:a8:99:
                    ff:57:83:14:7a:4c:bb:ac:48:a8:50:ab:29:7a:3e:
                    8d:59:c6:34:55:63:4d:bc:83:6f:b4:3f:b1:a7:ca:
                    4c:ba:80:16:55:ce:0b:96:c9:00:ac:2f:50:8c:11:
                    70:80:59:be:d8:7b:05:e1:72:23:a0:7e:a0:ba:03:
                    bf:9b:1b:7d:f9:bc:44:fa:27:9a:74:1e:3d:02:57:
                    90:99:60:d9:9c:93:6d:b3:69:7d:43:4e:6a:e8:36:
                    45:8a:22:ac:27:a0:68:70:54:bd:11:31:2c:62:33:
                    c3:f0:26:06:7b:6e:46:a9:2c:9d:57:61:3e:e7:60:
                    4a:da:72:27:ca:ad:5a:96:96:d6:7a:bb:8d:90:72:
                    72:e1:63:4c:25:c6:8f:7b:50:87:93:bf:d2:09:45:
                    cb:ea:0d:e2:db:30:3a:32:58:c5:95:6f:ae:55:2b:
                    3a:53:26:39:cb:76:be:42:c1:27:45:92:00:97:a6:
                    b6:35:4e:2b:18:52:4b:ec:9a:eb:95:ac:65:b6:14:
                    a8:cc:26:47:f2:7e:eb:5a:1b:a5:24:2e:54:9a:7e:
                    c9:28:9e:d3:8a:23:eb:e8:20:29:a6:29:a5:f3:4b:
                    e2:92:34:cf:98:63:61:e9:84:d7:a4:07:ee:b7:bf:
                    45:8c:36:d2:5a:49:fb:82:9b:e4:73:06:6d:8a:85:
                    4f:64:a2:3f:27:1e:99:c3:25:0f:fa:1d:78:a9:35:
                    bb:58:64:5e:05:23:e5:da:5f:e6:c1:58:f7:12:1e:
                    08:43:c5:03:42:09:95:48:88:2b:7c:40:09:e0:c3:
                    95:9c:a7:86:4a:6a:43:dc:71:30:9b:33:74:70:9c:
                    d5:a1:a6:4e:f2:43:e6:cc:1f:de:ec:08:ee:45:58:
                    0d:e7:15:69:a6:9b:82:91:0e:c3:6a:cc:f5:1c:bd:
                    b6:60:9e:0c:aa:49:57:d0:20:60:47:2a:6a:d7:2e:
                    61:e3:a3:1d:aa:45:12:a3:b3:4f:81:c9:bd:bb:78:
                    f2:aa:9d:ba:4c:40:19:d9:31:89:33:69:8e:fc:3d:
                    bf:ba:ca:43:f4:8d:f2:f5:b8:9c:c1:4d:b3:10:c1:
                    13:53:29:56:9c:2f:bb:ca:19:dd:e1:3e:67:38:9f:
                    51:84:2d:05:55:24:70:3a:c5:12:29:ce:12:05:82:
                    e8:34:83:b5:97:27:be:a7:96:55:92:3e:97:d2:c5:
                    d0:04:d0:98:61:21:7d:7b:63:54:73:49:d8:b0:0d:
                    3a:7c:2d:5a:f9:33:df:56:0a:a1:92:9a:2d:e7:49:
                    52:b7:bc:71:09:3c:f1:04:10:68:f8:3c:34:09:97:
                    2d:2b:22:e2:a5:4e:22:e4:4c:a0:cb:16:20:a0:13:
                    c2:21:27:f3:b2:1e:95:47:46:a3:b0:ba:01:04:06:
                    a8:2a:a2:39:b9:c5:69:1b:78:11:f9:38:5b:a3:8e:
                    c0:83:54:19:81:2a:7c:b9:04:8f:1c:bf:a3:e2:24:
                    70:c5:4e:a3:ba:4b:58:04:82:a3:52:37:b9:37:ce:
                    e2:a0:2f:c5:b6:96:b3:07:61:ce:e6:1a:8d:cb:9c:
                    f0:98:56:08:9c:73:51:0c:20:72:f9:a6:62:5c:8f:
                    db:d0:b9:e9:44:9d:c7:2b:5e:32:c2:8b:8b:9c:1b:
                    00:87:02:d4:d0:2f:03:e2:96:cf:44:62:48:d7:61:
                    08:6b:44:b1:89:7e:4e:d1:3f:dc:c3:c4:88:eb:95:
                    49:c7:32:fa:c1:a1:86:9b:52:2a:05:00:aa:11:89:
                    3d:72:53:89:ba:b7:0d:54:43:3c:6b:05:d4:fc:06:
                    0a:48:11:cf:94:69:83:8a:11:c7:f3:cb:54:3c:2e:
                    9b:11:30:b5:50:1a:74:84:81:c3:3a:6f:d3:f6:21:
                    24:f3:75:6d:4c:07:bb:19:b0:db:53:3b:67:42:49:
                    d7:10:00:d8:06:87:03:ec:bd:d4:50:ca:83:f5:55:
                    df:7a:30:fb:e3:11:04:24:93:f6:39:76:25:e7:5f:
                    39:31:cd:76:3b:1b:5f:00:54:8e:f2:8c:e7:21:13:
                    93:30:91:70:29:4e:be:57:b8:37:86:b8:5e:00:4b:
                    aa:06:55:b8:27:81:66:8c:41:5d:92:0c:a3:17:9b:
                    42:64:08:ae:20:28:61:63:94:7d:52:4c:e3:ca:68:
                    f0:60:61:91:28:49:24:04:4e:10:c2:88:55:29:b6:
                    2b:14:0e:ff:58:b3:13:64:59:5a:0d:41:02:c5
        X509v3 extensions:
            X509v3 Key Usage: critical
                Key Encipherment                    <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Authority Key Identifier: 
                EC:F0:EA:53:53:3F:9F:23:DC:C1:0E:31:10:37:07:DE:DE:E7:6E:F3
            X509v3 Subject Alternative Name: 
                DNS:mysni
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        6d:81:a3:32:04:f4:06:e9:96:fd:90:44:59:c4:1c:16:f3:59:
        ea:5b:ea:5f:96:a6:e0:42:c6:2a:c2:8e:d5:33:c8:bd:24:9d:
        d3:34:0e:98:36:29:1c:06:7f:13:37:d6:01:7d:58:82:87:22:
        ef:09:0a:40:9e:e6:0a:37:45:de:43:78:90:f3:8c:6b:2c:69:
        fa:a4:92:dd:de:ea:04:22:66:b6:9b:33:95:53:f2:48:cb:a6:
        bd:ff:6b:c9:55:e6:88:60:e0:c4:88:aa:a1:f3:0a:28:41:11:
        a6:e6:f7:8d:81:7e:bb:a3:5d:5a:b2:cd:e2:08:47:b2:6b:83:
        4c:5f:62:99:c8:87:80:31:80:4c:81:2d:56:a9:8e:de:db:af:
        a1:7e:d4:36:09:a6:b1:33:12:e3:c2:ca:e0:2c:0b:45:df:e3:
        c7:d8:94:52:49:97:9c:aa:24:4e:17:d4:73:3b:a8:c3:79:6a:
        72:f0:72:d2:83:e7:63:20:0d:2b:01:87:e2:e4:af:ad:14:32:
        a5:c2:ea:5b:5d:6d:80:50:2b:d1:7c:fe:2e:e1:57:74:a9:da:
        50:8c:a5:3a:2b:20:eb:4f:6d:88:46:a8:52:30:bc:c2:e4:62:
        ef:f3:aa:7f:53:85:cb:b0:66:62:34:95:00:5a:dd:e3:2e:e9:
        37:97:e2:a0


openssl x509 -pubkey -noout -in issued.pem 

-----BEGIN PUBLIC KEY-----
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

```

