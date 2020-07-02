#!/usr/bin/env python3
import sys
import binascii
import cbor2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from  jwcrypto import jwk
from .util import encode_protected, encode_diagnostic


def main():
    # 512-bit key
    privkey_pem = b'''\
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCwtf2F9SyRhEAHRDyfk3GYACX3bVH8nGdoEjHaYQyykbpjfOgT
v/2y6cZTJYYHOJ7Jfa09spX97Wd0TtYgcH2zaATnTlaklAMKc2CPyNkvLwV40thc
wgHvD/IteDXS0UfTuQpohCdiNaAcK+md/Fl/eVVDYvwesDY5ysXMrdspJQIDAQAB
AoGBAJtdJq1kRe8aq4C4CeTzKWhOmRLVVsQWbwQdGx+5PAS0A3/9Db5vioqG5wur
bg9jRJg6mton7Z/33oFv3utee+SOYHzl/aRYHKYzip4Bn7NomyiTQZK2oZDN2pEK
u1qGove2+c1QEQSdjeUt3+9zqgbfQBxVYj7BlnIPVJIN608BAkEA2yLZTneEontW
jL+YUwfqjWQw/2uIwYpwhv1PV6MmVy8iUMOeSKb44iAWYcLf4SxzhoNbZJcU0FCq
NhI+w9AOdQJBAM5wFq3F8ya3UgOXxZeO4vUOaSeZg9VMXXbwW81h3gh51wVskjVA
3/nLrpXcwOXoa1KzyQLclmnIAhxpVX7/ufECQGpvyszqEGo7Lha/GOV7etmiSIpH
WO1oqK9oahlPDVhbdHd2DHONZmWu4DArz0I3rQUw2DtLhriH9aS9x+6kJ+ECQCik
yuJFsdyyhRQuAnoXaLnEr5FbWShak6BCLGDgXt2eV2Y6/QI9FpvQrTvWLahWPSMY
QIAuu/JxrXC4kFujr5ECQAe1phcziWJwpr0rsWVBlMVOK8DgYbVDpO2fpzxLx5yH
FIqpKkUcSrgmK2N3qce5f4aRYMpvXYU+5LZfT5KGXKM=
-----END RSA PRIVATE KEY-----
'''
    privkey = serialization.load_pem_private_key(privkey_pem, None, default_backend())
    pubkey = privkey.public_key()
    print('Private Key: {}'.format(jwk.JWK.from_pem(privkey_pem).export()))
    print('Public Key: {}'.format(pubkey))

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

    recip_protected_dec = {
    }
    recip_unprotected_dec = {
        1: -41,  # alg: RSAES-OAEP SHA-256
        4: 'ExampleRSA',  # kid
    }
    recip_protected_enc = encode_protected(recip_protected_dec)
    print('Layer-2 Protected: {}'.format(encode_diagnostic(recip_protected_dec)))
    print('Layer-2 Encoded: {}'.format(encode_diagnostic(recip_protected_enc)))

    ext_aad = prim_enc + aug_enc
    print('Encoded External AAD: {}'.format(encode_diagnostic(ext_aad)))

    # Enc_structure Section 5.3
    enc_struct_dec = list()
    enc_struct_dec.append('Encrypt')
    enc_struct_dec.append(protected_enc)
    enc_struct_dec.append(ext_aad)
    enc_struct_enc = cbor2.dumps(enc_struct_dec)
    print('Enc_structure: {}'.format(encode_diagnostic(enc_struct_dec)))
    print('Encoded: {}'.format(encode_diagnostic(enc_struct_enc)))

    # Encrypt original block data
    content_cipher = aead.AESGCM(cek)
    content_ciphertext = content_cipher.encrypt(iv, content_plaintext, enc_struct_enc)
    print('Content Ciphertext: {}'.format(encode_diagnostic(content_ciphertext)))

    cek_ciphertext = pubkey.encrypt(
        cek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print('CEK Ciphertext: {}'.format(encode_diagnostic(cek_ciphertext)))

    # COSE_Encrypt0 structure
    message_dec = [
        protected_enc,
        unprotected_dec,
        None,  # ciphertext
        [  # recipients
            recip_protected_dec,
            recip_unprotected_dec,
            cek_ciphertext,
            []  # no more ops
        ]
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
                    97,  # COSE_Encrypt
                    message_dec
                ]
            ]
        ]
    ]

    print('ASB: {}'.format(encode_diagnostic(asb_dec)))


if __name__ == '__main__':
    sys.exit(main())
