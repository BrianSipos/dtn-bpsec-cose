#!/usr/bin/env python3
import binascii
import cbor2
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

# 256-bit key
privkey = binascii.unhexlify('13BF9CEAD057C0ACA2C9E52471CA4B19DDFAF4C0784E3F3E8E3999DBAE4CE45C')
print('Key: {}'.format(binascii.hexlify(privkey)))

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

# Block-to-MAC
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

# Compute tag
hasher = hmac.HMAC(privkey, hashes.SHA256(), backend=default_backend())
hasher.update(prim_enc + target_enc)
tag = hasher.finalize()
print('Digest: {}'.format(binascii.hexlify(tag)))

# COSE_MAC0 structure
result_dec = [
    binascii.unhexlify('a10105'),
    {},
    None,
    'tag'  # placeholder
]
print('Result: {}'.format(result_dec))

# BIB structure
asb_dec = [
    [2],  # Targets
    0,  # TBD-CI
    0,  # Flags
    [
        # Target num 2
        [
            [
                17,  # COSE_Mac0
                result_dec
            ]
        ]
    ]
]

asb_enc = cbor2.dumps(asb_dec)
print('ASB: {}'.format(asb_dec))
print('Encoded: {}'.format(binascii.hexlify(asb_enc)))
