import logging

from sys import stdout

import oqs
import base64
import pem
import asn1tools

### requires  liboqs-python
##### https://github.com/open-quantum-safe/liboqs-python
# virtualenv env 
# source env/bin/activate 
# pip3 install pem asn1tools
# git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
# cd liboqs-python
# pip install .

### you can either generate a new key or use the static ones in this sample
#### generate bare-seed
# openssl genpkey  -algorithm mlkem768 \
#    -provparam ml-kem.output_formats=bare-seed \
#    -out priv-ml-kem-768-bare-seed.pem
# openssl pkey  -in priv-ml-kem-768-bare-seed.pem  -pubout -out pub-ml-kem-768-bare-seed.pem

### generate seed-priv
####  seed-priv
# openssl genpkey  -algorithm mlkem768 \
#    -provparam ml-kem.output_formats=seed-priv \
#    -out priv-ml-kem-768-seed-priv.pem
# openssl pkey  -in priv-ml-kem-768-seed-priv.pem  -pubout -out pub-ml-kem-768-seed-priv.pem

### convert seed-priv (or any other format) to bare-seed
# openssl pkey -in priv-ml-kem-768-seed-priv.pem -provparam ml-kem.output_formats=bare-seed -out priv-ml-kem-768-bare-seed.pem

# to print the bare seed from the pem of any format  using openssl

# $ openssl pkey -in priv-ml-kem-768-bare-seed.pem -text
# ML-KEM-768 Private-Key:
#   seed:
#       67:e6:bc:81:c8:46:80:80:02:ce:d7:1b:bf:8a:8c:
#       41:95:af:2a:37:61:4c:4c:81:c0:b6:49:60:1b:29:
#       be:aa:33:cb:ff:21:4a:0d:c4:59:74:93:62:c8:b3:
#       d4:dd:7c:75:4a:0d:61:1d:51:d3:44:9c:2f:a4:7c:
#       1d:c4:9c:5e


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler(stdout))

private_key_pem = """
-----BEGIN PRIVATE KEY-----
MFICAQAwCwYJYIZIAWUDBAQCBEBn5ryByEaAgALO1xu/ioxBla8qN2FMTIHAtklg
Gym+qjPL/yFKDcRZdJNiyLPU3Xx1Sg1hHVHTRJwvpHwdxJxe
-----END PRIVATE KEY-----
"""

private_asn_spec = """
PKCS8-PRIVATE-KEY-INFO DEFINITIONS ::= BEGIN
     PrivateKeyInfo ::= SEQUENCE {
       version                   Version,
       privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
       privateKey                PrivateKey,
       attributes           [0]  IMPLICIT Attributes OPTIONAL 
     }
     
     Version ::= INTEGER { v1(0) }

     AlgorithmIdentifier ::=  SEQUENCE  {
        algorithm            OBJECT IDENTIFIER,
        parameter            ANY DEFINED BY algorithm OPTIONAL 
      }      
     Attribute ::= SEQUENCE {
        attrType          OBJECT IDENTIFIER,
        attrValues        SET OF ANY
     }

     PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier

     PrivateKey ::= OCTET STRING

     Attributes ::= SET OF Attribute

END
"""


pkcs8_spec = asn1tools.compile_string(private_asn_spec)

pem_object = pem.parse(private_key_pem.encode())

encoded_bytes = pem_object[0].bytes_payload
privkey_bytes =  base64.b64decode(encoded_bytes)
decoded_key = pkcs8_spec.decode('PrivateKeyInfo', privkey_bytes)
print("Decoded PrivateKeyInfo:")
bare_seed_pem=decoded_key['privateKey']
print("bare seed from pem private key {}".format(bare_seed_pem.hex()))
# bare_seed_hex = "67E6BC81C846808002CED71BBF8A8C4195AF2A37614C4C81C0B649601B29BEAA33CBFF214A0DC459749362C8B3D4DD7C754A0D611D51D3449C2FA47C1DC49C5E"
# bare_seed = bytes.fromhex(bare_seed_hex)

#=====================================================


public_key_pem = """
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
# """

public_asn_spec = """
PKCS8-PUBLIC-KEY-INFO DEFINITIONS ::= BEGIN
    SubjectPublicKeyInfo ::= SEQUENCE {
        algorithm AlgorithmIdentifier,
        subjectPublicKey BIT STRING
    }
     
     AlgorithmIdentifier ::=  SEQUENCE  {
        algorithm            OBJECT IDENTIFIER,
        parameter            ANY DEFINED BY algorithm OPTIONAL 
      }      
END
"""

pkcs8pub_spec = asn1tools.compile_string(public_asn_spec)
pem_object = pem.parse(public_key_pem.encode())

encoded_bytes = pem_object[0].bytes_payload
pubkey_bytes = base64.b64decode(encoded_bytes)
decoded_key = pkcs8pub_spec.decode('SubjectPublicKeyInfo', pubkey_bytes)
print("Decoded subjectPublicKey:")
public_key=decoded_key['subjectPublicKey']

## now use it
kemalg = "ML-KEM-768"
with oqs.KeyEncapsulation(kemalg) as client:
    with oqs.KeyEncapsulation(kemalg) as server:
        ### initialize the client using just the bare seed from just the private key
        public_key_client = client.generate_keypair_seed(seed=bare_seed_pem)
        
        ### initialize the server using just the public key from the pem file
        public_key_bytes = bytes(public_key[0])
        ciphertext, shared_secret_server = server.encap_secret(public_key_bytes)

        shared_secret_client = client.decap_secret(ciphertext)
    logger.info(
        "Shared secretes coincide: %s",
        shared_secret_client == shared_secret_server,
    )
