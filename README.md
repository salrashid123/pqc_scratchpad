# Post-Quantum Cryptography (PQC) scratchpad


This repo is just a collection of `PQC` tools and sample code.

* [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography)
* [crypto: post-quantum support roadmap](https://github.com/golang/go/issues/64537)

---

* [MLDSA](#mldsa)
  - [JWT Signature](#jwt-signature)
* [MLKEM](#mlkem)
* [TLS](#tls)
  - [curl](#curl)
  - [PKI](#pki)
    - [ML-DSA](#ml-dsa)
    - [ML-KEM](#ml-kem)
* [Docker Images](#docker-images)
  - [Openssl 3.5.0](#openssl-350)
  - [Openssl 3.4.1 with OQSProvider](#openssl-341-with-oqsprovider)
  - [OpenQuantumSafe Docker images](#openquantumsafe-docker-images)

---

## MLDSA

Digital Signatures using [ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)

* [Internet X.509 Public Key Infrastructure: Algorithm Identifiers for ML-DSA](https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates/)
* [https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/](Composite ML-DSA For use in X.509 Public Key Infrastructure and CMS)
* [EVP_PKEY-ML-DSA](https://github.com/openssl/openssl/blob/master/doc/man7/EVP_PKEY-ML-DSA.pod)


Using `openssl3.5.0` (if you don't have that version, use the dockerfile below)

```bash
openssl genpkey -algorithm ML-DSA-44  -out private.pem
openssl pkey -in private.pem -pubout -out public.pem

echo -n "bar" > /tmp/data.in.raw
openssl dgst -sign private.pem -out /tmp/data.out.signed /tmp/data.in.raw 
openssl dgst -verify public.pem -signature /tmp/data.out.signed  /tmp/data.in.raw  
```

as a dockerimage using pre-generated certificates

```bash
cd mldsa/
docker run -v /dev/urandom:/dev/urandom -v `pwd`/certs:/apps/certs -ti salrashid123/openssl-pqs:3.5.0-dev 

  echo -n "bar" > /tmp/data.in.raw
  openssl dgst -sign /apps/certs/server.key -out /tmp/data.out.signed /tmp/data.in.raw 
  openssl dgst -verify /apps/certs/server.pem -signature /tmp/data.out.signed  /tmp/data.in.raw  
```

For golang, `ML-DSA` isn't implemented yet at time of writing so we're using CloudFlares one here `github.com/cloudflare/circl/sign/mldsa/mldsa44`.

To see the signatures, run

```bash
 go run default/main.go
```

Please note that the PEM files generated by circl is not compatible with openssl yet [circl/issue535](https://github.com/cloudflare/circl/issues/535)


#### JWT Signature

* [golang-jwt for post quantum cryptography](https://github.com/salrashid123/golang-jwt-pqc)
* [ML-DSA for JOSE and COSE](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/)
* [JWT Thumprint calculation for ML-DSA-44](https://gist.github.com/salrashid123/fed96fd8adc36c5ab090d680071869bc)


## MLKEM

Key Encapsulation [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)

* [Internet X.509 Public Key Infrastructure - Algorithm Identifiers for the Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)](https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/08/)
* [EVP_PKEY-ML-KEM](https://github.com/openssl/openssl/blob/master/doc/man7/EVP_PKEY-ML-KEM.pod)

```bash
## generate a key as 'seed-only'
openssl genpkey  -algorithm mlkem768 -provparam ml-kem.output_formats=bare-seed  -out priv-ml-kem-768-bare-seed.pem
openssl pkey  -in priv-ml-kem-768-bare-seed.pem  -pubout -out pub-ml-kem-768.pem

## encapsulate with public key
openssl pkeyutl -encap -inkey pub-ml-kem-768.pem  -secret /tmp/encap.dat -out /tmp/ctext.dat

## print shared key
cat /tmp/encap.dat | xxd -p -c 100
  ca08986c403dec7505bfcb214ad53c9a9af24d1547f5c87f74b785699b7eb94c

## decapsulate with private key and arrive at shared key
openssl pkeyutl -decap -inkey priv-ml-kem-768-bare-seed.pem  -in /tmp/ctext.dat | xxd -p -c 100
  ca08986c403dec7505bfcb214ad53c9a9af24d1547f5c87f74b785699b7eb94c
```

For golang, you can use `crypto/mlkem` package.  The following shows how to generate and arrive at shared keys

```bash
$ go run default/main.go 
  SharedSecret: kemShared (2dae99717ffe984dac326f695a28eaea4cb314addc9000d7c8ea19a53ce06062) 
  SharedSecret: kemShared (2dae99717ffe984dac326f695a28eaea4cb314addc9000d7c8ea19a53ce06062) 
```

If you wanted to create a keypair using `openssl` and consume it in golang, you need to export the private key from openssl as `seed-only`:

```bash
$ go run openssl_parse/main.go 
  SharedSecret: kemShared (6mt5mhJ9iztKWZGpe1kdXCJv8/lxQuMpmZgvYJTWlyw=) 
  SharedSecret: kemShared (6mt5mhJ9iztKWZGpe1kdXCJv8/lxQuMpmZgvYJTWlyw=) 
```


## TLS

For TLS, the key exchange can use a `ML-KEM` as shown here:

* [X25519MLKEM768 client server in go](https://github.com/salrashid123/ml-kem-tls-keyexchange)

while the certificate signature can use `ML-DSA`.  The certificates in the `mldsa/certs/` folder uses this signature scheme:

```bash
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
        Signature Algorithm: ML-DSA-44
        Issuer: C=US, O=Google, OU=Enterprise, CN=Single Root CA
        Validity
            Not Before: Feb 17 17:36:32 2025 GMT
            Not After : Feb 17 17:36:32 2035 GMT
        Subject: C=US, O=Google, OU=Enterprise, CN=server.domain.com
        Subject Public Key Info:
            Public Key Algorithm: ML-DSA-44  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                ML-DSA-44 Public-Key:
                pub:
                    7c:e6:e4:4b:.....
```

Then for key exchange with openssl, set the `-curves=X25519MLKEM768`

To test a client/server with openssl where the certificate 

```bash
cd mldsa/

### run server
$ docker run -v /dev/urandom:/dev/urandom -v `pwd`/certs:/apps/certs --net=host -ti salrashid123/openssl-pqs:3.5.0-dev

  openssl s_server  -accept 8081    -tls1_3      -key certs/server.key -cert certs/server.crt -curves X25519MLKEM768   -www -trace

### run client
$ docker run -v /dev/urandom:/dev/urandom -v `pwd`/certs:/apps/certs --net=host -ti salrashid123/openssl-pqs:3.5.0-dev

  openssl s_client -connect localhost:8081 --servername  server.domain.com  -tls1_3 -curves X25519MLKEM768   --trace 
```

Then for key exchange, you'll notice `X25519MLKEM768`

```bash
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 1210
    ServerHello, Length=1206
      server_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0x8994AA65
        random_bytes (len=28): 25EC949FCA8BCA01BA9D5FE8BEFD0EBD15CF9A09C6043E832F5E377A
      session_id (len=32): 52FE38957B58B19EA15082E7612C3BBAA8391495ADD4B5335001AD23F0B78396
      cipher_suite {0x13, 0x02} TLS_AES_256_GCM_SHA384
      compression_method: No Compression (0x00)
      extensions, length = 1134
        extension_type=supported_versions(43), length=2
            TLS 1.3 (772)
        extension_type=key_share(51), length=1124
            NamedGroup: X25519MLKEM768 (4588)                  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
            key_exchange:  (len=1120): E56779A73A10B66A1AEE597374F0231F....
```

While the certificate returned used the `ML-DSA` algorithm:

```bash
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 2445
  Inner Content Type = Handshake (22)
    CertificateVerify, Length=2424
      Signature Algorithm: mldsa44 (0x0904) 
      Signature (len=2420): 0A86BE0E95077266EB0....
```

### curl

To test if a server has pqs enabled, you can use the [curl oqs Dockerfile](https://github.com/open-quantum-safe/oqs-demos/blob/main/curl/Dockerfile):

```bash
### test with openquantumsafe server
docker run -ti openquantumsafe/curl curl -vk --curves p521_kyber1024  https://test.openquantumsafe.org/CA.crt

 ## * SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / p521_kyber1024 / id-ecPublicKey

### test with aws
docker run -ti openquantumsafe/curl curl -vk   https://kms.us-west-1.amazonaws.com

  ## * SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / p384_kyber768 / RSASSA-PSS
```

### PKI

#### ML-DSA

The certificates above uses ML-DSA signatures which you can generate using the openssl providers shown below and by specifying the scheme see [ca_scratchpad](https://github.com/salrashid123/ca_scratchpad)

```bash
docker run -v /dev/urandom:/dev/urandom  -ti salrashid123/openssl-pqs:3.5.0-dev

git clone https://github.com/salrashid123/ca_scratchpad.git
cd ca_scratchpad

mkdir -p ca/root-ca/private ca/root-ca/db crl certs
chmod 700 ca/root-ca/private
cp /dev/null ca/root-ca/db/root-ca.db
cp /dev/null ca/root-ca/db/root-ca.db.attr

echo 01 > ca/root-ca/db/root-ca.crt.srl
echo 01 > ca/root-ca/db/root-ca.crl.srl

export SAN=single-root-ca

openssl genpkey -algorithm ML-DSA-44 \
      -out ca/root-ca/private/root-ca.key

openssl req -new  -config single-root-ca.conf  -key ca/root-ca/private/root-ca.key \
   -out ca/root-ca.csr  

openssl ca -selfsign     -config single-root-ca.conf  \
   -in ca/root-ca.csr     -out ca/root-ca.crt  \
   -extensions root_ca_ext
```

SLso see

* [Architecting PKI Hierarchies for Graceful PQ Migration](https://pkic.org/events/2025/pqc-conference-austin-us/WED_BREAKOUT_1200_Mike-Ounsworth_Architecting-PKI-Hierarchies-for-Graceful-PQ-Migration.pdf)

#### ML-KEM

For `ML-KEM` you can create a certificate based on draft [Internet X.509 Public Key Infrastructure - Algorithm Identifiers for the Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/)

```bash
docker run -v /dev/urandom:/dev/urandom  -ti salrashid123/openssl-pqs:3.5.0-dev

git clone https://github.com/salrashid123/ca_scratchpad.git
cd ca_scratchpad

mkdir -p ca/root-ca/private ca/root-ca/db crl certs
chmod 700 ca/root-ca/private
cp /dev/null ca/root-ca/db/root-ca.db
cp /dev/null ca/root-ca/db/root-ca.db.attr

echo 01 > ca/root-ca/db/root-ca.crt.srl
echo 01 > ca/root-ca/db/root-ca.crl.srl

export SAN=single-root-ca

openssl genpkey -algorithm ML-DSA-44 \
      -out ca/root-ca/private/root-ca.key

openssl req -new  -config single-root-ca.conf  -key ca/root-ca/private/root-ca.key \
   -out ca/root-ca.csr  

openssl ca -selfsign     -config single-root-ca.conf  \
   -in ca/root-ca.csr     -out ca/root-ca.crt  \
   -extensions root_ca_ext

# openssl genpkey  -algorithm mlkem768 -provparam ml-kem.output_formats=bare-seed  -out priv-ml-kem-768-bare-seed.pem
# openssl pkey  -in priv-ml-kem-768-bare-seed.pem  -pubout -out pub-ml-kem-768.pem


wget https://raw.githubusercontent.com/salrashid123/pqc_scratchpad/refs/heads/main/mlkem/certs/pub-ml-kem-768.pem

cat > key.conf << EOF
[ kem_ext ]
keyUsage                = critical,keyEncipherment
basicConstraints        = CA:false
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always
subjectAltName          = DNS:key1.domain.com
EOF


openssl x509 -new -CAkey ca/root-ca/private/root-ca.key \
   -CA ca/root-ca.crt -force_pubkey pub-ml-kem-768.pem -subj "/CN=ML-KEM Certificate" -out ml-kem.crt -extfile key.conf -extensions kem_ext

openssl x509 -noout -text -in ml-kem.crt

openssl x509 -pubkey -noout -in ml-kem.crt

openssl asn1parse -inform PEM -in ml-kem.crt
```

This will generate an x509 like this.  Notice the signer is `ml-dsa-44` and the key is `Public Key Algorithm: ML-KEM-768`

```bash
# openssl x509 -noout -text -in ml-kem.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            67:6a:d4:93:80:25:a6:d5:0b:5d:b4:0a:9e:bf:30:c7:ea:d4:96:f4
        Signature Algorithm: ML-DSA-44
        Issuer: C=US, O=Google, OU=Enterprise, CN=Single Root CA
        Validity
            Not Before: Feb 26 22:03:39 2025 GMT
            Not After : Mar 28 22:03:39 2025 GMT
        Subject: CN=ML-KEM Certificate
        Subject Public Key Info:
            Public Key Algorithm: ML-KEM-768
                ML-KEM-768 Public-Key:
                ek:
                    ba:da:2d:03:99:ca:8....
        X509v3 extensions:
            X509v3 Key Usage: critical
                Key Encipherment
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                CF:51:CC:7C:3E:B2:B0:6D:6D:A0:2A:0F:AB:7F:7C:86:AF:84:0A:78
            X509v3 Authority Key Identifier: 
                FA:5A:E1:FC:76:BF:E2:D2:9D:D9:88:47:BF:33:1A:76:DA:99:BC:6E
            X509v3 Subject Alternative Name: 
                DNS:key1.domain.com
    Signature Algorithm: ML-DSA-44
    Signature Value:
        03:2d:ea:fd:db:01:a0:a6,,,,
```

## Docker images

Openssl with the built-in PQC support as well as the  [oqs-provider](https://github.com/open-quantum-safe/oqs-provider) can be found on dockerhub or built from scratch:

### Openssl 3.5.0

```bash
docker build -t salrashid123/openssl-pqs:3.5.0-dev -f Dockerfile .
docker run -v /dev/urandom:/dev/urandom -ti salrashid123/openssl-pqs:3.5.0-dev

  openssl -version
    OpenSSL 3.5.0-dev  (Library: OpenSSL 3.5.0-dev )
```


### Openssl 3.4.1 with OQSProvider

```bash
docker build -t salrashid123/openssl-pqs:3.5.0-oqsprovider  -f Dockerfile.provider .
docker run -v /dev/urandom:/dev/urandom -ti salrashid123/openssl-pqs:3.5.0-oqsprovider 

  openssl list -kem-algorithms --provider oqsprovider
```

### OpenQuantumSafe Docker images

[Open Quantum Safe interop test server for quantum-safe cryptography](https://test.openquantumsafe.org/)


---
