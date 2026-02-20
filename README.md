# Post-Quantum Cryptography (PQC) scratchpad


This repo is just a collection of `PQC` tools and sample code.

* [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography)
* [crypto: post-quantum support roadmap](https://github.com/golang/go/issues/64537)

---

* [MLDSA](#mldsa)
  - [JWT Signature](#jwt-signature)
  - [Google Cloud KMS PQC signature verification](#google-cloud-kms-pqc-signature-verification) 
* [MLKEM](#mlkem)
  - [Using standard go library](#mlkem-standard-go)
  - [Using circl library](#mlkem-circl)
  - [JSON Web Encryption (JWE)](#mlkem-json-web-encryption)
  - [Source random from Trusted Platform Module](#mlkem-tpm)
  - [Parse openssl PEM keys](#mlkem-parse-pem-keys)
  - [Issue x509 MLKEM Certificate](#mlkem-x509)
  - [MLKEM with Cryptographic Message Syntax (CMS)](#mlkem-cms-rfc9629)
  - [MLKEM Python](#mlkem-python)
  - [MLKEM CMS](#mlkem-cms)
* [SLH-DSA](#slh-dsa)
* [Openssl key formats](#openssl-key-formats)
  - [ML-KEM Format](#ml-kem-format)
  - [ML-DSA Format](#ml-dsa-format)
  - [PEM Key Conversion](#pem-key-conversion)
  - [Python PEM](#python-pem)
  - [crypto/mldsa package](#crypto-mldsa)
* [TLS](#tls)
  - [curl](#curl)
* [PKI](#pki)
    - [ML-DSA](#ml-dsa)
    - [ML-KEM](#ml-kem)
* [Docker Images](#docker-images)
  - [Openssl 3.5.0](#openssl-350)
  - [Openssl 3.4.1 with OQSProvider](#openssl-341-with-oqsprovider)
  - [OpenQuantumSafe Docker images](#openquantumsafe-docker-images)

---

shameless plug by the author

* [AEAD encryption using Post Quantum Cryptography (ML-KEM)](https://github.com/salrashid123/go-pqc-wrapping)
* [Python AEAD encryption using Post Quantum Cryptography (ML-KEM)](https://github.com/salrashid123/python_pqc_wrapping)
* [Json Web Encryption (JWE) using Post Quantum Cryptography (ML-KEM)](https://github.com/salrashid123/jwe-pqc)
* [golang-jwt for post quantum cryptography](https://github.com/salrashid123/golang-jwt-pqc)
* [OCICrypt Container Image Post Quantum Cryptography Provider](https://github.com/salrashid123/ocicrypt-pqc-keyprovider)
* [Generate MLKEM key using Trusted Platfrom Module as random number generator](https://gist.github.com/salrashid123/761101aa94e9b26b114390fd966b1358)

>> note, most if not all the examples uses the `bare-seed` format for the private keys. 

---

## MLDSA

Digital Signatures using [ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)

* [Internet X.509 Public Key Infrastructure: Algorithm Identifiers for ML-DSA](https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates/)
* [Composite ML-DSA For use in X.509 Public Key Infrastructure and CMS](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)
* [EVP_PKEY-ML-DSA](https://github.com/openssl/openssl/blob/master/doc/man7/EVP_PKEY-ML-DSA.pod)


Using `openssl3.5.0` (if you don't have that version, use the dockerfile below)

```bash
## using the 'bare-seed' PEM format for the private key
openssl genpkey -algorithm ML-DSA-44 -provparam ml-dsa.output_formats=bare-seed   -out private.pem
openssl pkey -in private.pem -pubout -out public.pem

echo -n "bar" > /tmp/data.in.raw
openssl dgst -sign private.pem -out /tmp/data.out.signed /tmp/data.in.raw 
openssl dgst -verify public.pem -signature /tmp/data.out.signed  /tmp/data.in.raw  
```

For golang, `ML-DSA` isn't implemented yet at time of writing so we're using CloudFlares one here `github.com/cloudflare/circl/sign/mldsa/mldsa44`.


>> **Note** that `github.com/cloudflare/circl/sign/mldsa/mldsa6` by default generates the `seed-only` private key format (key prefix `8020`) 
** and prepends** a PEM type of of `BEGIN ML-DSA-65 PRIVATE KEY`, the latter which is apparently incompatible with openssl


```bash
$ cat seed-only.pem 
-----BEGIN ML-DSA-65 PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMSBCKAIEfKuXz2ilU1mRtl5QAgvCAaFH0Crzw+VeX/
BJXSXodV
-----END ML-DSA-65 PRIVATE KEY-----


### note the 8020 prefix in the HEX DUMP below
$ openssl asn1parse -inform PEM -in certs/seed-only.pem 
    0:d=0  hl=2 l=  52 cons: SEQUENCE          
    2:d=1  hl=2 l=   1 prim: INTEGER           :00
    5:d=1  hl=2 l=  11 cons: SEQUENCE          
    7:d=2  hl=2 l=   9 prim: OBJECT            :ML-DSA-65
   18:d=1  hl=2 l=  34 prim: OCTET STRING      [HEX DUMP]:802047CAB97CF68A5535991B65E50020BC201A147D02AF3C3E55E5FF0495D25E8755
```

to convert to `bare-seed`, first remove the PEM Header to only have `PRIVATE KEY`

```bash
$ cat seed-only.pem 
-----BEGIN PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMSBCKAIEfKuXz2ilU1mRtl5QAgvCAaFH0Crzw+VeX/
BJXSXodV
-----END PRIVATE KEY-----

$ openssl pkey -in seed-only.pem -text

    ML-DSA-65 Private-Key:
    seed:
        47:ca:b9:7c:f6:8a:55:35:99:1b:65:e5:00:20:bc:
        20:1a:14:7d:02:af:3c:3e:55:e5:ff:04:95:d2:5e:
        87:55

### as asn1:
$ openssl asn1parse -inform PEM -in seed-only.pem
    0:d=0  hl=2 l=  52 cons: SEQUENCE          
    2:d=1  hl=2 l=   1 prim: INTEGER           :00
    5:d=1  hl=2 l=  11 cons: SEQUENCE          
    7:d=2  hl=2 l=   9 prim: OBJECT            :ML-DSA-65
   18:d=1  hl=2 l=  34 prim: OCTET STRING      [HEX DUMP]:802047CAB97CF68A5535991B65E50020BC201A147D02AF3C3E55E5FF0495D25E8755
```

Now convert to `bare-seed`

```bash
$ openssl pkey -in seed-only.pem  -provparam ml-dsa.output_formats=bare-seed   -out bare-seed.pem

$ cat bare-seed.pem 
-----BEGIN PRIVATE KEY-----
MDICAQAwCwYJYIZIAWUDBAMSBCBHyrl89opVNZkbZeUAILwgGhR9Aq88PlXl/wSV
0l6HVQ==
-----END PRIVATE KEY-----

$ openssl pkey -in bare-seed.pem -text

  ML-DSA-65 Private-Key:
  seed:
      47:ca:b9:7c:f6:8a:55:35:99:1b:65:e5:00:20:bc:
      20:1a:14:7d:02:af:3c:3e:55:e5:ff:04:95:d2:5e:
      87:55

$ openssl asn1parse -inform PEM -in bare-seed.pem 
    0:d=0  hl=2 l=  50 cons: SEQUENCE          
    2:d=1  hl=2 l=   1 prim: INTEGER           :00
    5:d=1  hl=2 l=  11 cons: SEQUENCE          
    7:d=2  hl=2 l=   9 prim: OBJECT            :ML-DSA-65
   18:d=1  hl=2 l=  32 prim: OCTET STRING      [HEX DUMP]:47CAB97CF68A5535991B65E50020BC201A147D02AF3C3E55E5FF0495D25E8755

### to get the public key
openssl pkey  -in bare-seed.pem   -pubout -out public.pem
```

### JWT Signature

* [golang-jwt for post quantum cryptography](https://github.com/salrashid123/golang-jwt-pqc)
* [ML-DSA for JOSE and COSE](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/)
* [JWT Thumbprint calculation for ML-DSA-44](https://gist.github.com/salrashid123/fed96fd8adc36c5ab090d680071869bc)


### Google Cloud KMS PQC signature verification

GCP KMS allows for certain PQC signatures and the following snippet will generate one and then use it to sign/verify in golang and openssl.

See:

* [GCP KMS PQC signing algorithms](https://cloud.google.com/kms/docs/algorithms#pqc_signing_algorithms)

```bash
export GCLOUD_USER=`gcloud config get-value core/account`
export PROJECT_ID=`gcloud config get-value core/project`

gcloud kms keys create mldsa1 --keyring=tkr1 \
   --location=us-central1 --purpose=asymmetric-signing    --default-algorithm=pq-sign-ml-dsa-65

gcloud kms keys add-iam-policy-binding mldsa1  \
        --keyring=tkr1 --location=us-central1  \
        --member=user:$GCLOUD_USER  --role=roles/cloudkms.signer

gcloud kms keys add-iam-policy-binding mldsa1 \
        --keyring=tkr1 --location=us-central1  \
        --member=user:$GCLOUD_USER  --role=roles/cloudkms.viewer

$ gcloud kms keys list --keyring=tkr1 --location=us-central1

NAME                                                                      PURPOSE          ALGORITHM                   PROTECTION_LEVEL  LABELS  PRIMARY_ID  PRIMARY_STATE
projects/core-eso/locations/us-central1/keyRings/tkr1/cryptoKeys/mldsa1   ASYMMETRIC_SIGN  PQ_SIGN_ML_DSA_65           SOFTWARE

echo -n "foo" > certs/plain.txt

## to sign
gcloud kms asymmetric-sign \
    --version 1 \
    --key mldsa1 \
    --keyring tkr1 \
    --location us-central1 \
    --input-file certs/plain.txt \
    --signature-file certs/signed.bin

## to recall the public key as b64 standard nist-pqc format
gcloud kms keys versions get-public-key 1  \
  --key=mldsa1 --keyring=tkr1   --location=us-central1 \
   --public-key-format=nist-pqc
```

To use golang and gcp kms to sign/verify, run

```bash
cd gcp_kms/
go run main.go --projectID=$PROJECT_ID
```

This will 

1. use GCP KMS to sign some data
2. use GCP KMS to download the public key
3. use [https://github.com/cloudflare/circl/tree/main/sign/mldsa](https://github.com/cloudflare/circl/tree/main/sign/mldsa) to convert the public key into PEM format
4. convert the PEM format key to include ASN Object identifer that openssl understands 
  * [issue#535:openssl parsing compatiblity issue for MLDSA](https://github.com/cloudflare/circl/issues/535)
5. Verify the signature using the public key



## MLKEM

Key Encapsulation [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)

* [Internet X.509 Public Key Infrastructure - Algorithm Identifiers for the Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)](https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/08/)
* [EVP_PKEY-ML-KEM](https://github.com/openssl/openssl/blob/master/doc/man7/EVP_PKEY-ML-KEM.pod)


* [AEAD encryption using Post Quantum Cryptography (ML-KEM)](https://github.com/salrashid123/go-pqc-wrapping)
* [Python AEAD encryption using Post Quantum Cryptography (ML-KEM)](https://github.com/salrashid123/python_pqc_wrapping)
* [Generate MLKEM key using Trusted Platfrom Module as random number generator](https://gist.github.com/salrashid123/761101aa94e9b26b114390fd966b1358)

 For reference the basic flow is described here in [FIPS 203 (page 12)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)

![images/key_exchange.png](images/key_exchange.png)

### MLKEM Parse PEM Keys

To use openssl to generate keys and parse them, see the following and the example in go under `mlkem/openssl_parse`

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

### MLKEM standard go

For golang, you can use `crypto/mlkem` package.  The following shows how to generate and arrive at shared keys

```bash
$ go run default/main.go 
  SharedSecret: kemShared (2dae99717ffe984dac326f695a28eaea4cb314addc9000d7c8ea19a53ce06062) 
  SharedSecret: kemShared (2dae99717ffe984dac326f695a28eaea4cb314addc9000d7c8ea19a53ce06062) 
```

### MLKEM CIRCL library

For golang, you can also use `"github.com/cloudflare/circl/kem/mlkem/mlkem768"` package though i don't know how to convert the keys back into a compatible format

### MLKEM JSON Web Encryption

see 

* [Json Web Encryption (JWE) using Post Quantum Cryptography (ML-KEM)](https://github.com/salrashid123/jwe-pqc)

### MLKEM CIRCL library

### MLKEM x509

at the time of writing 3/15/26, You can issue an mlkem x509 by **Overriding** standard go's crypto/x509 library (note this isn't recommended becasue its an override)...but just to see it, look at the `mlkem/issue_cert` folder

### MLKEM cms rfc9629

If you wanted to issue issue a cryptographic message formatted as the RFC9629, see the `mlkem/rfc9629` foldder

### MLKEM CMS

If you wanted to see a draft CMS format specific to MLKEM, see the `mlkem/draft-ietf-lams-cms-kyber-13` folder

### MLKEM Python

For an example in python, see `mlkem/python` folder`

### MLKEM TPM

Finally,  you can use a TPM to generate the keyapir.  See the `mlkem/tpm` folder

the idea is that the `d`, `z` parameters are random values from a TPM and fed into the algorithm here:

* [Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)



```
7.1 ML-KEM Key Generation
The key generation algorithm ML-KEM.KeyGen for ML-KEM (Algorithm 19) accepts no input,
generates randomness internally, and produces an encapsulation key and a decapsulation key.
While the encapsulation key can be made public, the decapsulation key shall remain private.
The seed (𝑑,𝑧) generated in steps 1 and 2 of ML-KEM.KeyGen can be stored for later expansion using ML-KEM.KeyGen_internal (see Section 3.3). As the seed can be used to compute
the decapsulation key, it is sensitive data and shall be treated with the same safeguards as a
decapsulation key (see SP 800-227 [1]).
Algorithm 19 ML-KEM.KeyGen()
Generates an encapsulation key and a corresponding decapsulation key.

Output: encapsulation key ek ∈ 𝔹384𝑘+32.
Output: decapsulation key dk ∈ 𝔹768𝑘+96. $

1: 𝑑 ←− 𝔹32 ▷ 𝑑 is 32 random bytes (see Section 3.3) <<<<<<<<<<<<<<<
2: 𝑧 ←− 𝔹32 ▷ 𝑧 is 32 random bytes (see Section 3.3) <<<<<<<<<<<<<<<
3: if 𝑑 == NULL or 𝑧 == NULL then
4: return ⊥ ▷ return an error indication if random bit generation failed
5: end if
6: (ek,dk) ← ML-KEM.KeyGen_internal(𝑑,𝑧) ▷ run internal key generation algorithm
```

## SLH-DSA

At the moment (3/7/25), its available in the opessl provider:

```bash
docker run -v /dev/urandom:/dev/urandom -ti salrashid123/openssl-pqs:3.5.0-dev

  openssl genpkey -algorithm SLH-DSA-SHA2-128s -provparam ml-kem.output_formats=bare-seed  -out bare-seed.pem
  openssl pkey -in bare-seed.pem -pubout -out public.pem
  openssl pkey -in bare-seed.pem -text 
```

If you wanted to read in a `bare-seed` keyfile using `https://pkg.go.dev/github.com/cloudflare/circl@v1.6.2/sign/slhdsa` then sign/verify, see [slhdsa/](slhdsa/) folder

## Openssl key formats

Openssl PEM files encodes a custom 'format' prefix as shown 

* [ml_kem_codecs.c](https://github.com/openssl/openssl/blob/master/providers/implementations/encode_decode/ml_kem_codecs.c)
* [ml_dsa_codecs.c](https://github.com/openssl/openssl/blob/master/providers/implementations/encode_decode/ml_dsa_codecs.c)

>> note, just use the `bare-seed` format, IMO

also see

* [OpenSSL Position and Plans on Private Key Formats for the ML-KEM and ML-DSA Post-quantum (PQ) Algorithms](https://openssl-library.org/post/2025-01-21-blog-positionandplans/)
* [Let’s All Agree to Use Seeds as ML-KEM Keys](https://words.filippo.io/ml-kem-seeds/)

### ML-KEM Format

For example, if you generated the key with a `seed-only`, the PEM file will have a prefix of `0x8040` for the raw key:

```bash
$  openssl asn1parse -inform PEM -in  example/certs/seed-only-768.pem 
    0:d=0  hl=2 l=  84 cons: SEQUENCE          
    2:d=1  hl=2 l=   1 prim: INTEGER           :00
    5:d=1  hl=2 l=  11 cons: SEQUENCE          
    7:d=2  hl=2 l=   9 prim: OBJECT            :ML-KEM-768
   18:d=1  hl=2 l=  66 prim: OCTET STRING      [HEX DUMP]:804067E6BC81C846808002CED71BBF8A8C4195AF2A37614C4C81C0B649601B29BEAA33CBFF214A0DC459749362C8B3D4DD7C754A0D611D51D3449C2FA47C1DC49C5E
```

while the suggested format is the `bare-seed`

```bash
$  openssl asn1parse -inform PEM -in  example/certs/bare-seed-768.pem 
    0:d=0  hl=2 l=  82 cons: SEQUENCE          
    2:d=1  hl=2 l=   1 prim: INTEGER           :00
    5:d=1  hl=2 l=  11 cons: SEQUENCE          
    7:d=2  hl=2 l=   9 prim: OBJECT            :ML-KEM-768
   18:d=1  hl=2 l=  64 prim: OCTET STRING      [HEX DUMP]:67E6BC81C846808002CED71BBF8A8C4195AF2A37614C4C81C0B649601B29BEAA33CBFF214A0DC459749362C8B3D4DD7C754A0D611D51D3449C2FA47C1DC49C5E
```

For a list of all prefixes for mlkem

```cpp
static const ML_COMMON_PKCS8_FMT ml_kem_768_p8fmt[NUM_PKCS8_FORMATS] = {
    { "seed-priv",  0x09aa, 0, 0x308209a6, 0x0440, 6, 0x40, 0x04820960, 0x4a, 0x0960, 0,      0,     },
    { "priv-only",  0x0964, 0, 0x04820960, 0,      0, 0,    0,          0x04, 0x0960, 0,      0,     },
    { "oqskeypair", 0x0e04, 0, 0x04820e00, 0,      0, 0,    0,          0x04, 0x0960, 0x0964, 0x04a0 },
    { "seed-only",  0x0042, 2, 0x8040,     0,      2, 0x40, 0,          0,    0,      0,      0,     },
    { "bare-priv",  0x0960, 4, 0,          0,      0, 0,    0,          0,    0x0960, 0,      0,     },
    { "bare-seed",  0x0040, 4, 0,          0,      0, 0x40, 0,          0,    0,      0,      0,     },
};
```

Note, you can extract the `seed` from a key using openssl:

```bash
$ openssl pkey -in example/certs/seed-only-768.pem -text

      ML-KEM-768 Private-Key:
      seed:
         67:e6:bc:81:c8:46:80:80:02:ce:d7:1b:bf:8a:8c:
         41:95:af:2a:37:61:4c:4c:81:c0:b6:49:60:1b:29:
         be:aa:33:cb:ff:21:4a:0d:c4:59:74:93:62:c8:b3:
         d4:dd:7c:75:4a:0d:61:1d:51:d3:44:9c:2f:a4:7c:
         1d:c4:9c:5e
```

Which as hex is `67E6BC81C846808002CED71BBF8A8C4195AF2A37614C4C81C0B649601B29BEAA33CBFF214A0DC459749362C8B3D4DD7C754A0D611D51D3449C2FA47C1DC49C5E`

Since in go we'd ultimately need the  the `bare-seed` key, you'll need to convert it

```bash
## create a key with default seed-priv (implicitly by default or by specifying  ml-kem.output_formats )
openssl genpkey  -algorithm mlkem768   -out priv-ml-kem-768-seed-priv.pem
openssl asn1parse -in priv-ml-kem-768-seed-priv.pem

openssl genpkey  -algorithm mlkem768 \
   -provparam ml-kem.output_formats=seed-priv \
   -out priv-ml-kem-768-seed-priv.pem

openssl asn1parse -in priv-ml-kem-768-seed-priv.pem

## print the  seed
openssl pkey -in priv-ml-kem-768-seed-priv.pem -text  

   ML-KEM-768 Private-Key:
   seed:
      bf:bd:29:76:bd:01:87:e3:75:0e:5c:46:4e:fc:e0:
      5a:0a:b6:ca:0a:b4:0c:f7:c4:90:08:1b:54:83:1f:
      12:18:25:50:15:7f:49:e0:24:7b:92:b7:b9:b2:de:
      49:21:74:53:71:9a:81:71:c6:cd:15:83:23:da:d2:
      c6:6d:ef:2b

### now convert
openssl pkey -in priv-ml-kem-768-seed-priv.pem \
   -provparam ml-kem.output_formats=bare-seed \
   -out priv-ml-kem-768-bare-seed.pem

### and veify the seed is the same
openssl pkey -in priv-ml-kem-768-bare-seed.pem -text
   ML-KEM-768 Private-Key:
   seed:
      bf:bd:29:76:bd:01:87:e3:75:0e:5c:46:4e:fc:e0:
      5a:0a:b6:ca:0a:b4:0c:f7:c4:90:08:1b:54:83:1f:
      12:18:25:50:15:7f:49:e0:24:7b:92:b7:b9:b2:de:
      49:21:74:53:71:9a:81:71:c6:cd:15:83:23:da:d2:
      c6:6d:ef:2b
```

### ML-DSA Format

for `ml-dsa-65` from [ml_dsa_codecs.c](https://github.com/openssl/openssl/blob/master/providers/implementations/encode_decode/ml_dsa_codecs.c#L160C1-L160C72) 

```cpp
static const ML_COMMON_PKCS8_FMT ml_dsa_65_p8fmt[NUM_PKCS8_FORMATS] = {
    {
        "seed-only",
        0x0022,
        2,
        0x8020,               <<<<<<<<<<<<<<<<<<<<<
        0,
        2,
        0x20,
        0,
        0,
        0,
        0,
        0,
    },
```

so if you generate an mldsa using go

```bash
cd mldsa/seed_only

$ docker run -v /dev/urandom:/dev/urandom -v `pwd`/certs:/apps/certs  -ti salrashid123/openssl-pqs:3.5.0-dev 

$ openssl asn1parse -in certs/pub-ml-dsa.pem 
    0:d=0  hl=4 l=1970 cons: SEQUENCE          
    4:d=1  hl=2 l=  11 cons: SEQUENCE          
    6:d=2  hl=2 l=   9 prim: OBJECT            :ML-DSA-65
   17:d=1  hl=4 l=1953 prim: BIT STRING

### note the 8020 prefix
$ openssl asn1parse -in certs/priv-ml-dsa.pem 
    0:d=0  hl=2 l=  52 cons: SEQUENCE          
    2:d=1  hl=2 l=   1 prim: INTEGER           :00
    5:d=1  hl=2 l=  11 cons: SEQUENCE          
    7:d=2  hl=2 l=   9 prim: OBJECT            :ML-DSA-65
   18:d=1  hl=2 l=  34 prim: OCTET STRING      [HEX DUMP]:802052735167E396B956C2EB559E2248BC6908302D45088E195F6455028E01377277


$ cat certs/priv-ml-dsa.pem 
-----BEGIN ML-DSA-65 PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMSBCKAIFJzUWfjlrlWwutVniJIvGkIMC1FCI4ZX2RV
Ao4BN3J3
-----END ML-DSA-65 PRIVATE KEY-----

### remove the prefix

$ cat certs/priv-ml-dsa-raw.pem 
-----BEGIN PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMSBCKAIFJzUWfjlrlWwutVniJIvGkIMC1FCI4ZX2RV
Ao4BN3J3
-----END PRIVATE KEY-----

### to convert to bare-seed
# openssl pkey -in certs/priv-ml-dsa-raw.pem   -provparam ml-dsa.output_formats=bare-seed -out certs/priv-ml-dsa-bare-seed.pem

## sign/verify
echo "This is the message to be signed." > /tmp/message.txt

openssl dgst -sign certs/priv-ml-dsaraw.pem  -out /tmp/signature.bin /tmp/message.txt

openssl dgst -verify certs/pub-ml-dsa.pem  -signature /tmp/signature.bin /tmp/message.txt
```

### PEM Key Conversion

The following will generate a new keypair using go `mldsa` package and write the keys to a file.

Note that we're writing the **seed only** as the private key

to convert with openssl from one format to another use the `-provparam ml-kem.output_formats=` parameter

```bash
## create a key with default seed-priv (implicitly by default or by specifying  ml-kem.output_formats )
openssl genpkey  -algorithm mlkem768   -out priv-ml-kem-768-seed-priv.pem
openssl asn1parse -in priv-ml-kem-768-seed-priv.pem

openssl genpkey  -algorithm mlkem768 \
   -provparam ml-kem.output_formats=seed-priv \
   -out priv-ml-kem-768-seed-priv.pem
openssl asn1parse -in priv-ml-kem-768-seed-priv.pem

## print the  seed
openssl pkey -in priv-ml-kem-768-seed-priv.pem -text  

   ML-KEM-768 Private-Key:
   seed:
      bf:bd:29:76:bd:01:87:e3:75:0e:5c:46:4e:fc:e0:
      5a:0a:b6:ca:0a:b4:0c:f7:c4:90:08:1b:54:83:1f:
      12:18:25:50:15:7f:49:e0:24:7b:92:b7:b9:b2:de:
      49:21:74:53:71:9a:81:71:c6:cd:15:83:23:da:d2:
      c6:6d:ef:2b

### now convert
openssl pkey -in priv-ml-kem-768-seed-priv.pem \
   -provparam ml-kem.output_formats=bare-seed \
   -out priv-ml-kem-768-bare-seed.pem

### and veify the seed is the same
openssl pkey -in priv-ml-kem-768-bare-seed.pem -text
   ML-KEM-768 Private-Key:
   seed:
      bf:bd:29:76:bd:01:87:e3:75:0e:5c:46:4e:fc:e0:
      5a:0a:b6:ca:0a:b4:0c:f7:c4:90:08:1b:54:83:1f:
      12:18:25:50:15:7f:49:e0:24:7b:92:b7:b9:b2:de:
      49:21:74:53:71:9a:81:71:c6:cd:15:83:23:da:d2:
      c6:6d:ef:2b
```

This repo also contains an unsupported guess at what [rfc9629](https://www.rfc-editor.org/rfc/rfc9629.html) looks like

### Python PEM 

The [mlkem/python](mlkem/python/) folder contains a sample to read the PEM files directly in python

Note, only `bare-seed` PEM private keys are supported

```bash
#### https://github.com/open-quantum-safe/liboqs-python
# export OQS_INSTALL_PATH=/path/to/liboqs
virtualenv env 
source env/bin/activate 
pip3 install pem asn1tools
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python
pip install .


$ python3 kem_key_parser.py 
liboqs-python faulthandler is disabled
Decoded PrivateKeyInfo:
bare seed from pem private key 67e6bc81c846808002ced71bbf8a8c4195af2a37614c4c81c0b649601b29beaa33cbff214a0dc459749362c8b3d4dd7c754a0d611d51d3449c2fa47c1dc49c5e
Decoded subjectPublicKey:
Shared secretes coincide: True
```
### Crypto MLDSA

the `mldsa/std_go` folder contains a sample application which exercises the proposal [#77626](https://github.com/golang/go/issues/77626)

It uses code from [https://github.com/FiloSottile/mldsa](https://github.com/FiloSottile/mldsa)

Eventually, this will be in the standard go branch so I'll update the samples here as well as update `golang-jwt-pqc` 

## TLS

For TLS, the key exchange can use a `ML-KEM` as shown here:

* [X25519MLKEM768 client server in go](https://github.com/salrashid123/ml-kem-tls-keyexchange)

while the certificate signature can use `ML-DSA`.  The certificates in the `mldsa/x509/` folder uses this signature scheme:

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

## PKI

### ML-DSA

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

### ML-KEM

For `ML-KEM` you can create a certificate based on draft [Internet X.509 Public Key Infrastructure - Algorithm Identifiers for the Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/)

For golang see [mlkem/issue_cert/](mlkem/issue_cert/)

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
