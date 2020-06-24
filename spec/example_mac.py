#!/usr/bin/env python3
import binascii
import cbor2
import hashlib
import hmac

# 256-bit key
privkey=binascii.unhexlify('13BF9CEAD057C0ACA2C9E52471CA4B19DDFAF4C0784E3F3E8E3999DBAE4CE45C')
print('Key: {}'.format(binascii.hexlify(privkey)))

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
tag = hmac.new(privkey, target_enc, hashlib.sha256).digest()
print('Digest: {}'.format(binascii.hexlify(tag)))

# COSE_MAC0 structure
result_dec = [
    binascii.unhexlify('a10105'),
    {},
    None,
    'tag' # placeholder
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
                17, # COSE_Mac0
                result_dec
            ]
        ]
    ]
]
    
asb_enc = cbor2.dumps(asb_dec)
print('ASB: {}'.format(asb_dec))
print('Encoded: {}'.format(binascii.hexlify(asb_enc)))
