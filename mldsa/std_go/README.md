### Generating and verifying MLDSA signatures using standard go

this folder just contains a sample application which exercises the proposal [#77626](https://github.com/golang/go/issues/77626)

It uses code from [https://github.com/FiloSottile/mldsa](https://github.com/FiloSottile/mldsa) and applies a patch using that to `go1.26.0`

Eventually, i'll remove all this when its merged upstream


To setup
 
```bash
git clone --branch go1.26.0 --single-branch --depth 1 https://github.com/golang/go.git goroot
cd goroot
git apply ../version.diff

cd src/
./make.bash

cd ../../

export GOROOT=`pwd`/goroot
export PATH=$GOROOT/bin:$PATH:

$ go version
go version go1.26.0-test linux/amd64
```

Then to sign/verify, run

```bash
go run main.go --public=public.pem --private=private.pem --data=foo --signature=signature.dat
```

what this will do is generate a new keypair, sign/verify some data using it, then write the public and private keys as PEM format to disk.

The private key is in the `bare-seed` format


You can also use openssl to verify the signatures generated

```bash

$ openssl list -signature-algorithms | grep ml-dsa
  { 2.16.840.1.101.3.4.3.17, id-ml-dsa-44, ML-DSA-44, MLDSA44 } @ default
  { 2.16.840.1.101.3.4.3.18, id-ml-dsa-65, ML-DSA-65, MLDSA65 } @ default
  { 2.16.840.1.101.3.4.3.19, id-ml-dsa-87, ML-DSA-87, MLDSA87 } @ default


$ openssl asn1parse -inform PEM -in private.pem 
    0:d=0  hl=2 l=  50 cons: SEQUENCE          
    2:d=1  hl=2 l=   1 prim: INTEGER           :00
    5:d=1  hl=2 l=  11 cons: SEQUENCE          
    7:d=2  hl=2 l=   9 prim: OBJECT            :ML-DSA-65
   18:d=1  hl=2 l=  32 prim: OCTET STRING      [HEX DUMP]:08603C2117A3BE0A6DFE4E055E1BDD8BC5CDFDA609779242A31851D1A6E88890

$ openssl asn1parse -inform PEM -in public.pem  
    0:d=0  hl=4 l=1970 cons: SEQUENCE          
    4:d=1  hl=2 l=  11 cons: SEQUENCE          
    6:d=2  hl=2 l=   9 prim: OBJECT            :ML-DSA-65
   17:d=1  hl=4 l=1953 prim: BIT STRING 


echo -n "foo" > data.in.raw
# sign verify with generated keys
openssl dgst -sign private.pem -out data.out.signed data.in.raw 
openssl dgst -verify public.pem -signature data.out.signed  data.in.raw  

## verify with go golang generated signature
openssl dgst -verify public.pem -signature signature.dat  data.in.raw 
```
