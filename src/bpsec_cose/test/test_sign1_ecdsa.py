import unittest
import cbor2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from  jwcrypto import jwk
from ..util import encode_protected, encode_diagnostic


class TestExample(unittest.TestCase):

    def test(self):
        print()
        # prime256v1 curve
        privkey_pem = b'''\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHRDyBLw7wF9MC7MYdTYNrt8C6URcMk90J9psGHqiTNcoAoGCCqGSM49
AwEHoUQDQgAE/S3qJJKIEOjCdMHi8af1RBZ4MtcRZ+BoHtKlRpEs751yhos5f9Si
pxt8jlxc8vyMRJQsvzeBE6kJgLultqzSyw==
-----END EC PRIVATE KEY-----
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
            ec.ECDSA(hashes.SHA256())
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
