import binascii
import cbor2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cose import SymmetricKey, EncMessage, CoseHeaderKeys, CoseAlgorithms, RSA
import cose.keys.cosekey as cosekey
from cose.messages.recipient import CoseRecipient, RcptParams
from ..util import encode_diagnostic
from .base import BaseTest


class TestExample(BaseTest):

    def test(self):
        print()
        # 1024-bit key
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
        ext_key = serialization.load_pem_private_key(privkey_pem, None, default_backend())
        private_key = RSA.from_cryptograpy_key_obj(ext_key)
        private_key.kid = b'ExampleRSA'
        print('Private Key: {}'.format(encode_diagnostic(private_key.encode('_kid', 'n', 'e', 'd', 'p', 'q', 'dP', 'dQ', 'qInv'), bstr_as='base64')))
        print('Public Key: {}'.format(encode_diagnostic(private_key.encode('_kid', 'n', 'e'), bstr_as='base64')))
        # 256-bit content encryption key
        cek = SymmetricKey(
            kid=b'ExampleCEK',
            k=binascii.unhexlify('13BF9CEAD057C0ACA2C9E52471CA4B19DDFAF4C0784E3F3E8E3999DBAE4CE45C'),
        )
        print('CEK: {}'.format(encode_diagnostic(cek.encode('_kid', 'k'), bstr_as='base64')))
        # session IV
        iv = binascii.unhexlify('6F3093EBA5D85143C3DC484A')
        print('IV: {}'.format(binascii.hexlify(iv)))

        # Primary block
        prim_dec = self._get_primary_item()
        prim_enc = cbor2.dumps(prim_dec)
        print('Primary Block: {}'.format(encode_diagnostic(prim_dec)))
        print('Encoded: {}'.format(encode_diagnostic(prim_enc)))

        # Security target block
        target_dec = self._get_target_item()
        content_plaintext = target_dec[4]
        print('Target Block: {}'.format(encode_diagnostic(target_dec)))
        print('Plaintext: {}'.format(encode_diagnostic(content_plaintext)))

        # Combined AAD
        ext_aad_dec = self._get_aad_item()
        ext_aad_enc = cbor2.dumps(ext_aad_dec)
        print('External AAD: {}'.format(encode_diagnostic(ext_aad_dec)))
        print('Encoded: {}'.format(encode_diagnostic(ext_aad_enc)))

        private_key.key_ops = cosekey.KeyOps.WRAP
        cek.key_ops = cosekey.KeyOps.ENCRYPT
        msg_obj = EncMessage(
            phdr={
                CoseHeaderKeys.ALG: CoseAlgorithms.A256GCM,
            },
            uhdr={
                CoseHeaderKeys.IV: iv,
            },
            payload=content_plaintext,
            recipients=[
                CoseRecipient(
                    uhdr={
                        CoseHeaderKeys.ALG: CoseAlgorithms.RSAES_OAEP_SHA_256,
                        CoseHeaderKeys.KID: private_key.kid,
                    },
                    payload=cek.k,
                ),
            ],
            # Non-encoded parameters
            external_aad=ext_aad_enc,
        )

        # COSE internal structure
        cose_struct_enc = msg_obj._enc_structure
        cose_struct_dec = cbor2.loads(cose_struct_enc)
        print('COSE Structure: {}'.format(encode_diagnostic(cose_struct_dec)))
        print('Encoded: {}'.format(encode_diagnostic(cose_struct_enc)))

        # Encoded message
        message_enc = msg_obj.encode(
            key=cek,
            nonce=msg_obj.uhdr[CoseHeaderKeys.IV],
            alg=msg_obj.phdr[CoseHeaderKeys.ALG],
            enc_params=[
                RcptParams(
                    key=private_key,
                    alg=msg_obj.recipients[0].uhdr[CoseHeaderKeys.ALG],
                ),
            ],
            tagged=False
        )
        message_dec = cbor2.loads(message_enc)
        # Detach the payload
        content_ciphertext = message_dec[2]
        message_dec[2] = None
        self._print_message(message_dec, recipient_idx=3)

        # ASB structure
        asb_dec = self._get_asb_item([
            msg_obj.cbor_tag,
            message_dec
        ])
        asb_enc = cbor2.dumps(asb_dec)
        print('ASB: {}'.format(encode_diagnostic(asb_dec)))
        print('Encoded: {}'.format(encode_diagnostic(asb_enc)))

        bpsec_dec = self._get_bpsec_item(
            block_type=99,  # FIXME: not real
            asb_dec=asb_dec,
        )
        bpsec_enc = cbor2.dumps(bpsec_dec)
        print('BPSec block: {}'.format(encode_diagnostic(bpsec_dec)))
        print('Encoded: {}'.format(encode_diagnostic(bpsec_enc)))

        # Change from detached payload
        message_dec[2] = content_ciphertext
        decode_obj: EncMessage = EncMessage.decode(cbor2.dumps(cbor2.CBORTag(EncMessage.cbor_tag, message_dec)))
        decode_obj.external_aad = ext_aad_enc
        cek.key_ops = cosekey.KeyOps.DECRYPT
        decode_plaintext = decode_obj.decrypt(key=cek, nonce=decode_obj.uhdr[CoseHeaderKeys.IV])
        print('Loopback plaintext:', encode_diagnostic(decode_plaintext))
        self.assertEqual(content_plaintext, decode_plaintext)
        private_key.key_ops = cosekey.KeyOps.UNWRAP
        decode_cek = private_key.key_unwrap(decode_obj.recipients[0].payload)
        print('Loopback CEK:', encode_diagnostic(decode_cek, bstr_as='base64'))
        self.assertEqual(cek.k, decode_cek)
