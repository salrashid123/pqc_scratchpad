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
eKwabYxlXu798cuwhg==
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
            7b:84:59:a2:43:46:fd:5c:d5:ae:0d:af:35:97:77:a1
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Google, OU=Enterprise, CN=Single Root CA
        Validity
            Not Before: Jan  6 12:49:45 2026 GMT
            Not After : Jan  6 12:49:45 2027 GMT
        Subject: C=US, ST=California, L=Mountain View, O=Acme Co, OU=Enterprise, CN=mycn
        Subject Public Key Info:
            Public Key Algorithm: ML-KEM-768  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
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
                Digital Signature, Non Repudiation
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Authority Key Identifier: 
                EC:F0:EA:53:53:3F:9F:23:DC:C1:0E:31:10:37:07:DE:DE:E7:6E:F3
            X509v3 Subject Alternative Name: 
                DNS:mysni
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        6b:b9:83:67:3f:36:a2:79:f4:49:77:f0:15:9c:d3:f2:2f:2d:
        a5:61:ba:b6:69:a4:0c:2b:f7:a7:a6:e0:c4:85:d7:2c:66:dc:
        d6:12:7d:d1:ac:91:e1:10:b3:86:29:8e:c3:cf:8c:e7:66:f2:
        47:71:1d:8e:ae:97:17:64:43:09:d1:75:df:27:23:87:38:e7:
        be:10:a8:ae:2d:bf:d4:7e:62:97:0c:67:c5:91:20:ef:b3:d9:
        5f:e1:94:19:40:85:6a:dd:9f:88:b1:73:f5:f1:a8:dc:d3:03:
        6b:ab:e2:92:17:e1:b2:8d:0d:29:63:0d:82:e5:d9:5d:11:02:
        45:a8:51:04:1f:84:98:d0:8c:7f:ac:01:9f:c1:15:0e:a8:91:
        c3:b5:fa:ed:97:eb:60:43:76:55:fb:02:bf:8f:94:4a:89:11:
        7b:1e:8b:44:b9:8a:67:53:8e:ef:8f:e0:41:7a:cc:56:75:0f:
        c6:47:8a:66:54:d1:fb:fc:b5:c5:26:11:84:f2:8a:f6:92:d5:
        0f:d9:64:09:bd:14:b0:89:d1:82:cf:82:6e:3a:cb:e8:33:9f:
        41:87:bf:4b:12:06:40:46:ea:ac:0e:0f:9f:aa:77:67:aa:a1:
        76:f3:25:80:fe:ef:20:c8:eb:78:ac:1a:6d:8c:65:5e:ee:fd:
        f1:cb:b0:86


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

