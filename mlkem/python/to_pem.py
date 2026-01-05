

from sys import stdout

import oqs
import base64
import asn1tools


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


def bytes_to_pem(binary_data: bytes, marker: str) -> bytes:
    b64_bytes = base64.standard_b64encode(binary_data)
    pem_lines = [f"-----BEGIN {marker}-----".encode('ascii')]
    for i in range(0, len(b64_bytes), 64):
        pem_lines.append(b64_bytes[i:i+64])
    pem_lines.append(f"-----END {marker}-----".encode('ascii'))
    
    return b'\n'.join(pem_lines)


pkcs8_private_spec = asn1tools.compile_string(private_asn_spec)
pkcs8_public_spec = asn1tools.compile_string(public_asn_spec)


# PRIVATE KEY

# $ openssl asn1parse -inform PEM -in certs/bare-seed-768.pem 
#     0:d=0  hl=2 l=  82 cons: SEQUENCE          
#     2:d=1  hl=2 l=   1 prim: INTEGER           :00
#     5:d=1  hl=2 l=  11 cons: SEQUENCE          
#     7:d=2  hl=2 l=   9 prim: OBJECT            :ML-KEM-768
#    18:d=1  hl=2 l=  64 prim: OCTET STRING      [HEX DUMP]:67E6BC81C846808002CED71BBF8A8C4195AF2A37614C4C81C0B649601B29BEAA33CBFF214A0DC459749362C8B3D4DD7C754A0D611D51D3449C2FA47C1DC49C5E

# $ cat certs/bare-seed-768.pem 
# -----BEGIN PRIVATE KEY-----
# MFICAQAwCwYJYIZIAWUDBAQCBEBn5ryByEaAgALO1xu/ioxBla8qN2FMTIHAtklg
# Gym+qjPL/yFKDcRZdJNiyLPU3Xx1Sg1hHVHTRJwvpHwdxJxe
# -----END PRIVATE KEY-----

bare_seed_hex = "67E6BC81C846808002CED71BBF8A8C4195AF2A37614C4C81C0B649601B29BEAA33CBFF214A0DC459749362C8B3D4DD7C754A0D611D51D3449C2FA47C1DC49C5E"
bare_seed = bytes.fromhex(bare_seed_hex)

## now use it
kemalg = "ML-KEM-768"
with oqs.KeyEncapsulation(kemalg) as client:
    with oqs.KeyEncapsulation(kemalg) as server:
        public_key_client = client.generate_keypair_seed(seed=bare_seed)
        ## to create a new key, just don't specify a seed
        # public_key_client = client.generate_keypair_seed()
        ciphertext, shared_secret_server = server.encap_secret(public_key_client)
        shared_secret_client = client.decap_secret(ciphertext)

private_data_encode = {'version': 0, 'privateKeyAlgorithm': {'algorithm': '2.16.840.1.101.3.4.4.2'}, 'privateKey': bare_seed}
private_encoded_bytes = pkcs8_private_spec.encode('PrivateKeyInfo', private_data_encode)
private_pem_output = bytes_to_pem(private_encoded_bytes, "PRIVATE KEY")

print(private_pem_output.decode('utf-8'))

######################################


# $ cat certs/pub-ml-kem-768-bare-seed.pem 
# -----BEGIN PUBLIC KEY-----
# MIIEsjALBglghkgBZQMEBAIDggShALraLQOZyoFjK7rDe1b0Ad26le2DCS4aMOcs
# epTpCH4znnTUDp+7oyHlGJiIdJFTKorJtDuhIL0BspbXdcOGzy1cNT7jH8RTNt/A
# yrubNg8JKvPHDlwrqo6awoWbR0fToic6kzTnH/j1I34kijaiPLGjRMZKyWKRcZE8
# TPjjYfOZYlrTsZ+Gie72MO06toi4JAA6XvcrkqkzSnoYNw9lEOj7YP1lRcklAtDk
# DgZ3x8tDAuXlepJUuI2GQ2tzptiUcCCSfkp8o7wazmMVSAcGylXoI1ToHmCWQbn4
# J6aHGTFZLc0gzg9KgYFXBQc0PJjaiSJQze8FsfwlAmVJlAGRno/1PN6nqjXQHdZh
# JJFyWNJ8NNCWBSYZYnAWuev6yb9ymTJEKL7TtaMXOIBIz6OzyXUHmPt2SVerJhrl
# O5Mzrvd7Ge5Uf8FRR4CaqgalwOw5ifl7DCj6kgyomf9XgxR6TLusSKhQqyl6Po1Z
# xjRVY028g2+0P7Gnyky6gBZVzguWyQCsL1CMEXCAWb7YewXhciOgfqC6A7+bG335
# vET6J5p0Hj0CV5CZYNmck22zaX1DTmroNkWKIqwnoGhwVL0RMSxiM8PwJgZ7bkap
# LJ1XYT7nYEracifKrVqWltZ6u42QcnLhY0wlxo97UIeTv9IJRcvqDeLbMDoyWMWV
# b65VKzpTJjnLdr5CwSdFkgCXprY1TisYUkvsmuuVrGW2FKjMJkfyfutaG6UkLlSa
# fskontOKI+voICmmKaXzS+KSNM+YY2HphNekB+63v0WMNtJaSfuCm+RzBm2KhU9k
# oj8nHpnDJQ/6HXipNbtYZF4FI+XaX+bBWPcSHghDxQNCCZVIiCt8QAngw5Wcp4ZK
# akPccTCbM3RwnNWhpk7yQ+bMH97sCO5FWA3nFWmmm4KRDsNqzPUcvbZgngyqSVfQ
# IGBHKmrXLmHjox2qRRKjs0+Byb27ePKqnbpMQBnZMYkzaY78Pb+6ykP0jfL1uJzB
# TbMQwRNTKVacL7vKGd3hPmc4n1GELQVVJHA6xRIpzhIFgug0g7WXJ76nllWSPpfS
# xdAE0JhhIX17Y1RzSdiwDTp8LVr5M99WCqGSmi3nSVK3vHEJPPEEEGj4PDQJly0r
# IuKlTiLkTKDLFiCgE8IhJ/OyHpVHRqOwugEEBqgqojm5xWkbeBH5OFujjsCDVBmB
# Kny5BI8cv6PiJHDFTqO6S1gEgqNSN7k3zuKgL8W2lrMHYc7mGo3LnPCYVgicc1EM
# IHL5pmJcj9vQuelEnccrXjLCi4ucGwCHAtTQLwPils9EYkjXYQhrRLGJfk7RP9zD
# xIjrlUnHMvrBoYabUioFAKoRiT1yU4m6tw1UQzxrBdT8BgpIEc+UaYOKEcfzy1Q8
# LpsRMLVQGnSEgcM6b9P2ISTzdW1MB7sZsNtTO2dCSdcQANgGhwPsvdRQyoP1Vd96
# MPvjEQQkk/Y5diXnXzkxzXY7G18AVI7yjOchE5MwkXApTr5XuDeGuF4AS6oGVbgn
# gWaMQV2SDKMXm0JkCK4gKGFjlH1STOPKaPBgYZEoSSQEThDCiFUptisUDv9YsxNk
# WVoNQQLF
# -----END PUBLIC KEY-----

# $ openssl asn1parse -inform PEM -in certs/pub-ml-kem-768-bare-seed.pem
#     0:d=0  hl=4 l=1202 cons: SEQUENCE          
#     4:d=1  hl=2 l=  11 cons: SEQUENCE          
#     6:d=2  hl=2 l=   9 prim: OBJECT            :ML-KEM-768
#    17:d=1  hl=4 l=1185 prim: BIT STRING        


bit_string_value = (bytearray(public_key_client), len(public_key_client)*8) # 9472)
public_data_encode = {'algorithm': {'algorithm': '2.16.840.1.101.3.4.4.2'}, 'subjectPublicKey':bit_string_value}
public_encoded_bytes = pkcs8_public_spec.encode('SubjectPublicKeyInfo', public_data_encode)
public_pem_output = bytes_to_pem(public_encoded_bytes, "PUBLIC KEY")

print(public_pem_output.decode('utf-8'))