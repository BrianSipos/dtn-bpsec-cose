#!/usr/bin/env python3
import binascii
import cbor2
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def encode_protected(map):
    if len(map) == 0:
        return b''
    return cbor2.dumps(map)


# 2048-bit key
privkey_pem = '''\
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAN21GdS0faAYgacepRmbr7TAT0wEuahjrBfAO0Dg1M5d37O9Tx9H
vZw2OEcLq2WTvf0Kja1JWpqdoJm17LghhPkCAwEAAQJBAMgkJo9n6EhQFyrgdTZq
3vES8gKz+U3TvJUsSdFFpZYsZhUaLKP9oxyIxl3IvK5iS0oAsW0nqI7aMcBoPmxZ
pQECIQDuyd5uzvS0wnrsDWoDhiTm6O+PJoMQix9yH99HBUhWKQIhAO2wDP7e/Nnr
A7rDSgM6+REGmt8I00NglFwShBUi4HJRAiAiJrLuTCEJXSsxaXW5DU1nzPa+FXb3
Pb6Alvha8vF2iQIgbC7WK2dJBNKv9uCOHlxIItSzxtIYfjFGNYYD8i7Wo5ECIQDp
5++fp04AMVAnE0uqNEnITkTWb91hAS8IjaYCqLGyEA==
-----END RSA PRIVATE KEY-----
'''
privkey = serialization.load_pem_private_key(privkey_pem, None, default_backend())
print('Key: {}'.format(privkey))

# Primary block
prim_dec = [
    7,
    0,
    0,
    [1, '//dst/'],
    [1, '//src/'],
    [1, '//src/'],
    [0, 40],
    1000000
]
prim_enc = cbor2.dumps(prim_dec)
print('Primary: {}'.format(prim_dec))
print('Encoded: {}'.format(binascii.hexlify(prim_enc)))

# Block-to-sign
target_dec = [
    7,
    2,
    0,
    0,
    binascii.unhexlify('19012c')
]
target_enc = cbor2.dumps(target_dec)
print('Block: {}'.format(target_dec))
print('Encoded: {}'.format(binascii.hexlify(target_enc)))

# COSE Headers
protected_dec = {
    1:-37,  # alg: PS256
}
unprotected_dec = {
    4: b'mykey'  # kid: 'mykey'
}
protected_enc = encode_protected(protected_dec)
print('Protected: {}'.format(protected_dec))
print('Encoded: {}'.format(binascii.hexlify(protected_enc)))

# Sig_structure Section 4.4
sig_struct_dec = list()
sig_struct_dec.append(b'Signature1')
sig_struct_dec.append(protected_enc)
sig_struct_dec.append(prim_enc)
sig_struct_dec.append(target_enc)
sig_struct_enc = cbor2.dumps(sig_struct_dec)
print('Sig_structure (hex): {}'.format(map(binascii.hexlify, sig_struct_dec)))
print('Encoded: {}'.format(binascii.hexlify(sig_struct_enc)))

sig = privkey.sign(
    sig_struct_enc,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=0  # Force deterministic result
    ),
    hashes.SHA256()
)
print('Signature: {}'.format(binascii.hexlify(sig)))

# COSE_Sign1 structure
message_dec = [
    protected_enc,
    unprotected_dec,
    None,
    sig
]
print('Result: {}'.format(message_dec))

# BIB structure
asb_dec = [
    [2],  # Targets
    0,  # TBD-CI
    0,  # Flags
    [
        # Target num 2
        [
            [
                18,  # COSE_Sign1
                message_dec
            ]
        ]
    ]
]

asb_enc = cbor2.dumps(asb_dec)
print('ASB: {}'.format(asb_dec))
print('Encoded: {}'.format(binascii.hexlify(asb_enc)))
