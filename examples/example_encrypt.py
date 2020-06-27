#!/usr/bin/env python3
import binascii
import cbor2
import hashlib
from cryptography.hazmat.primitives.ciphers import aead


def encode_protected(map):
    if len(map) == 0:
        return b''
    return cbor2.dumps(map)


# 256-bit key
privkey = binascii.unhexlify('13BF9CEAD057C0ACA2C9E52471CA4B19DDFAF4C0784E3F3E8E3999DBAE4CE45C')
print('Key: {}'.format(binascii.hexlify(privkey)))
# session IV
iv = binascii.unhexlify('6F3093EBA5D85143C3DC484A')
print('IV: {}'.format(binascii.hexlify(iv)))

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
print('Plaintext: {}'.format(binascii.hexlify(plaintext)))

# Augmented block
aug_dec = target_dec[:-1] + [bytes()]
aug_enc = cbor2.dumps(aug_dec)
print('Augmented block: {}'.format(aug_dec))
print('Encoded: {}'.format(binascii.hexlify(aug_enc)))

# COSE Headers
protected_dec = {
    1: 3  # alg: A256GCM
}
unprotected_dec = {
    4: b'mykey',  # kid: 'mykey'
    5: iv  # iv
}
protected_enc = encode_protected(protected_dec)
print('Protected: {}'.format(protected_dec))
print('Encoded: {}'.format(binascii.hexlify(protected_enc)))

# Enc_structure Section 5.3
enc_struct_dec = list()
enc_struct_dec.append(b'Encrypt0')
enc_struct_dec.append(protected_enc)
enc_struct_dec.append(prim_enc + aug_enc)
enc_struct_enc = cbor2.dumps(enc_struct_dec)
print('Enc_structure(hex): {}'.format(map(binascii.hexlify, enc_struct_dec)))
print('Encoded: {}'.format(binascii.hexlify(enc_struct_enc)))

# Encrypt original block data
cipher = aead.AESGCM(privkey)
ciphertext = cipher.encrypt(iv, plaintext, enc_struct_enc)
print('Ciphertext: {}'.format(binascii.hexlify(ciphertext)))

# COSE_Encrypt0 structure
message_dec = [
    protected_enc,
    unprotected_dec,
    None,
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
                17,  # COSE_Encrypt0
                message_dec
            ]
        ]
    ]
]

asb_enc = cbor2.dumps(asb_dec)
print('ASB: {}'.format(asb_dec))
print('Encoded: {}'.format(binascii.hexlify(asb_enc)))
