#!/usr/bin/env python3
import sys
import binascii
import cbor2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from .util import encode_protected, encode_diagnostic


def main():
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
    print('Primary: {}'.format(encode_diagnostic(prim_dec)))
    print('Encoded: {}'.format(encode_diagnostic(prim_enc)))

    # Block-to-MAC
    target_dec = [
        7,  # bundle age
        2,
        0,
        0,
        cbor2.dumps(300)
    ]
    target_enc = cbor2.dumps(target_dec)
    print('Block: {}'.format(encode_diagnostic(target_dec)))
    print('Encoded: {}'.format(encode_diagnostic(target_enc)))

    # COSE Headers
    protected_dec = {
        1: 5  # alg: HMAC 256/256
    }
    unprotected_dec = {
    }
    protected_enc = encode_protected(protected_dec)
    print('Layer-1 Protected: {}'.format(encode_diagnostic(protected_dec)))
    print('Layer-1 Encoded: {}'.format(encode_diagnostic(protected_enc)))

    ext_aad = prim_enc
    print('Encoded External AAD: {}'.format(encode_diagnostic(ext_aad)))

    # MAC_structure Section 6.3
    mac_struct_dec = list()
    mac_struct_dec.append('MAC0')
    mac_struct_dec.append(protected_enc)
    mac_struct_dec.append(ext_aad)
    mac_struct_dec.append(target_enc)
    mac_struct_enc = cbor2.dumps(mac_struct_dec)
    print('MAC_structure: {}'.format(encode_diagnostic(mac_struct_dec)))
    print('Encoded: {}'.format(encode_diagnostic(mac_struct_enc)))

    hasher = hmac.HMAC(privkey, hashes.SHA256(), backend=default_backend())
    hasher.update(mac_struct_enc)
    tag = hasher.finalize()
    print('Tag: {}'.format(encode_diagnostic(tag)))

    # COSE_MAC0 structure
    message_dec = [
        protected_enc,
        unprotected_dec,
        None,
        tag
    ]

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

    print('ASB: {}'.format(encode_diagnostic(asb_dec)))


if __name__ == '__main__':
    sys.exit(main())
