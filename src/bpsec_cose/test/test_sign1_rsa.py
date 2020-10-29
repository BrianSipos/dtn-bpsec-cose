import unittest
import cbor2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from  jwcrypto import jwk
from ..util import encode_protected, encode_diagnostic


class TestExample(unittest.TestCase):

    def test(self):
        print()
        # 512-bit key
        privkey_pem = b'''\
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
        print('Private Key: {}'.format(jwk.JWK.from_pem(privkey_pem).export()))
        print('Public Key: {}'.format(jwk.JWK.from_pem(privkey_pem).export_public()))

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

        # Block-to-sign
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
            1:-37,  # alg: PS256
        }
        unprotected_dec = {
        }
        protected_enc = encode_protected(protected_dec)
        print('Layer-1 Protected: {}'.format(encode_diagnostic(protected_dec)))
        print('Layer-1 Encoded: {}'.format(encode_diagnostic(protected_enc)))

        ext_aad = prim_enc
        print('Encoded External AAD: {}'.format(encode_diagnostic(ext_aad)))

        # Sig_structure Section 4.4
        sig_struct_dec = list()
        sig_struct_dec.append('Signature1')
        sig_struct_dec.append(protected_enc)
        sig_struct_dec.append(ext_aad)
        sig_struct_dec.append(target_enc)
        sig_struct_enc = cbor2.dumps(sig_struct_dec)
        print('Sig_structure: {}'.format(encode_diagnostic(sig_struct_dec)))
        print('Encoded: {}'.format(encode_diagnostic(sig_struct_enc)))

        sig = privkey.sign(
            sig_struct_enc,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=0  # Force deterministic result
            ),
            hashes.SHA256()
        )
        print('Signature: {}'.format(encode_diagnostic(sig)))

        # COSE_Sign1 structure
        message_dec = [
            protected_enc,
            unprotected_dec,
            None,
            sig
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
                        18,  # COSE_Sign1
                        message_dec
                    ]
                ]
            ]
        ]

        print('ASB: {}'.format(encode_diagnostic(asb_dec)))
