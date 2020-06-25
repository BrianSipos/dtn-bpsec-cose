#!/usr/bin/env python3
import binascii
import cbor2
import hashlib
from cryptography.hazmat.primitives.ciphers import aead

# 256-bit key
privkey=binascii.unhexlify('13BF9CEAD057C0ACA2C9E52471CA4B19DDFAF4C0784E3F3E8E3999DBAE4CE45C')
print('Key: {}'.format(binascii.hexlify(privkey)))

iv = binascii.unhexlify('6F3093EBA5D85143C3DC484A')

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

# Block-to-encrypt
target_dec = [
    7,
    2,
    0,
    0,
    binascii.unhexlify('19012c')
]
plaintext = target_dec[4]
print('Block: {}'.format(target_dec))

# Augmented block
aug_dec = target_dec[:-1] + [bytes()]
aug_enc = cbor2.dumps(aug_dec)
print('Augmented block: {}'.format(aug_dec))
print('Encoded: {}'.format(binascii.hexlify(aug_enc)))

# Encrypt original block data
cipher = aead.AESGCM(privkey)
ciphertext = cipher.encrypt(iv, plaintext, prim_enc + aug_enc)
print('IV: {}'.format(binascii.hexlify(iv)))
print('Plaintext: {}'.format(binascii.hexlify(plaintext)))
print('Ciphertext: {}'.format(binascii.hexlify(ciphertext)))

# COSE_Encrypt0 structure
result_dec = [
    binascii.unhexlify('a10103'),
    {
        5: iv
    },
    None,
]
print('Result: {}'.format(result_dec))

# BIB structure
asb_dec = [
    [2], # Targets
    0, # TBD-CI
    0, # Flags
    [
        # Target num 2
        [
            [
                17, # COSE_Encrypt0
                result_dec
            ]
        ]
    ]
]
    
asb_enc = cbor2.dumps(asb_dec)
print('ASB: {}'.format(asb_dec))
print('Encoded: {}'.format(binascii.hexlify(asb_enc)))
