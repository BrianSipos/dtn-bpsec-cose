#!/usr/bin/env python3
import binascii
import cbor2
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac


def encode_protected(map):
    if len(map) == 0:
        return b''
    return cbor2.dumps(map)


# 256-bit key
privkey = binascii.unhexlify('13BF9CEAD057C0ACA2C9E52471CA4B19DDFAF4C0784E3F3E8E3999DBAE4CE45C')
print('Key: {}'.format(binascii.hexlify(privkey)))

# Primary block
prim_dec = [
    7,
    0,
    0,
    [1, '//dst/svc'],
    [1, '//src/bp'],
    [1, '//src/bp'],
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

# COSE Headers
protected_dec = {
    1: 5  # alg: HMAC 256/256
}
unprotected_dec = {
}
protected_enc = encode_protected(protected_dec)
print('Protected: {}'.format(protected_dec))
print('Encoded: {}'.format(binascii.hexlify(protected_enc)))

ext_aad = prim_enc
print('Encoded External AAD: {}'.format(binascii.hexlify(ext_aad)))

# MAC_structure Section 6.3
mac_struct_dec = list()
mac_struct_dec.append('MAC0')
mac_struct_dec.append(protected_enc)
mac_struct_dec.append(ext_aad)
mac_struct_dec.append(target_enc)
mac_struct_enc = cbor2.dumps(mac_struct_dec)
print('MAC_structure: {}'.format(mac_struct_dec))
print('Encoded: {}'.format(binascii.hexlify(mac_struct_enc)))

hasher = hmac.HMAC(privkey, hashes.SHA256(), backend=default_backend())
hasher.update(mac_struct_enc)
tag = hasher.finalize()
print('Tag: {}'.format(binascii.hexlify(tag)))

# COSE_MAC0 structure
message_dec = [
    protected_enc,
    unprotected_dec,
    None,
    tag
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
                17,  # COSE_MAC0
                message_dec
            ]
        ]
    ]
]

asb_enc = cbor2.dumps(asb_dec)
print('ASB: {}'.format(asb_dec))
print('Encoded: {}'.format(binascii.hexlify(asb_enc)))
