#!/usr/bin/env python3
import sys
import binascii
import cbor2
from cryptography.hazmat.primitives.ciphers import aead
from .util import encode_protected, encode_diagnostic


def main():
    # 256-bit content encryption key
    cek = binascii.unhexlify('13BF9CEAD057C0ACA2C9E52471CA4B19DDFAF4C0784E3F3E8E3999DBAE4CE45C')
    print('CEK: {}'.format(binascii.hexlify(cek)))
    # session IV
    iv = binascii.unhexlify('6F3093EBA5D85143C3DC484A')
    print('IV: {}'.format(binascii.hexlify(iv)))

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

    # Block-to-encrypt
    target_dec = [
        7,  # bundle age
        2,
        0,
        0,
        cbor2.dumps(300)
    ]
    content_plaintext = target_dec[4]
    print('Block: {}'.format(encode_diagnostic(target_dec)))
    print('Plaintext: {}'.format(encode_diagnostic(content_plaintext)))

    # Augmented block
    aug_dec = target_dec[:-1] + [bytes()]
    aug_enc = cbor2.dumps(aug_dec)
    print('Augmented block: {}'.format(encode_diagnostic(aug_dec)))
    print('Encoded: {}'.format(encode_diagnostic(aug_enc)))

    # COSE Headers
    protected_dec = {
        1: 3  # alg: A256GCM
    }
    unprotected_dec = {
        5: iv  # iv
    }
    protected_enc = encode_protected(protected_dec)
    print('Layer-1 Protected: {}'.format(encode_diagnostic(protected_dec)))
    print('Layer-1 Encoded: {}'.format(encode_diagnostic(protected_enc)))

    ext_aad = prim_enc + aug_enc
    print('Encoded External AAD: {}'.format(encode_diagnostic(ext_aad)))

    # Enc_structure Section 5.3
    enc_struct_dec = list()
    enc_struct_dec.append('Encrypt0')
    enc_struct_dec.append(protected_enc)
    enc_struct_dec.append(ext_aad)
    enc_struct_enc = cbor2.dumps(enc_struct_dec)
    print('Enc_structure: {}'.format(encode_diagnostic(enc_struct_dec)))
    print('Encoded: {}'.format(binascii.hexlify(enc_struct_enc)))

    # Encrypt original block data
    content_cipher = aead.AESGCM(cek)
    content_ciphertext = content_cipher.encrypt(iv, content_plaintext, enc_struct_enc)
    print('Content Ciphertext: {}'.format(encode_diagnostic(content_ciphertext)))

    # COSE_Encrypt0 structure
    message_dec = [
        protected_enc,
        unprotected_dec,
        None,  # content_ciphertext
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
                    17,  # COSE_Encrypt0
                    message_dec
                ]
            ]
        ]
    ]

    print('ASB: {}'.format(encode_diagnostic(asb_dec)))


if __name__ == '__main__':
    sys.exit(main())
