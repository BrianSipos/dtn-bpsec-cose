import cbor2
from pycose import headers, algorithms
from pycose.keys import SymmetricKey, RSAKey, keyops, keyparam
from pycose.messages import EncMessage
from pycose.messages.recipient import KeyWrap
from ..util import dump_cborseq, encode_diagnostic
from ..bpsec import BlockType
from .base import BaseTest


class TestExample(BaseTest):

    def test(self):
        print('\nTest: ' + __name__ + '.' + type(self).__name__)
        # 3072-bit key
        private_pem = '''\
-----BEGIN PRIVATE KEY-----
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
nnhbrNRnJTT2g/gLLMeSe/j3
-----END PRIVATE KEY-----
'''
        private_key = RSAKey.from_pem_private_key(
            private_pem,
            optional_params={
                keyparam.KpKid: b'ExampleA.9',
                keyparam.KpAlg: algorithms.RsaesOaepSha512,
                keyparam.KpKeyOps: [keyops.WrapOp, keyops.UnwrapOp],
            }
        )
        print('Private Key: {}'.format(encode_diagnostic(cbor2.loads(private_key.encode()))))
        # 256-bit content encryption key
        cek = SymmetricKey(
            k=bytes.fromhex('13BF9CEAD057C0ACA2C9E52471CA4B19DDFAF4C0784E3F3E8E3999DBAE4CE45C'),
            optional_params={
                keyparam.KpAlg: algorithms.A256GCM,
                keyparam.KpKeyOps: [keyops.EncryptOp, keyops.DecryptOp],
            }
        )
        print('CEK: {}'.format(encode_diagnostic(cbor2.loads(cek.encode()))))
        # session IV
        iv = bytes.fromhex('6F3093EBA5D85143C3DC484A')
        print('IV: {}'.format(iv.hex()))

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
        ext_aad_dec = self._get_aad_array()
        ext_aad_enc = dump_cborseq(ext_aad_dec)
        print('External AAD: {}'.format(encode_diagnostic(ext_aad_dec)))
        print('Encoded: {}'.format(encode_diagnostic(ext_aad_enc)))

        msg_obj = EncMessage(
            phdr={
                headers.Algorithm: cek.alg,
            },
            uhdr={
                headers.IV: iv,
            },
            payload=content_plaintext,
            recipients=[
                KeyWrap(
                    uhdr={
                        headers.Algorithm: private_key.alg,
                        headers.KID: private_key.kid,
                    },
                    payload=cek.k,
                ),
            ],
            # Non-encoded parameters
            external_aad=ext_aad_enc,
        )
        msg_obj.recipients[0].key = private_key

        # COSE internal structure
        cose_struct_enc = msg_obj._enc_structure
        cose_struct_dec = cbor2.loads(cose_struct_enc)
        print('COSE Structure: {}'.format(encode_diagnostic(cose_struct_dec)))
        print('Encoded: {}'.format(encode_diagnostic(cose_struct_enc)))

        # Encoded message
        message_enc = msg_obj.encode(tag=False)
        message_dec = cbor2.loads(message_enc)
        # Detach the payload
        content_ciphertext = message_dec[2]
        message_dec[2] = None
        self._print_message(message_dec, recipient_idx=3)
        print('Ciphertext: {}'.format(encode_diagnostic(content_ciphertext)))
        message_enc = cbor2.dumps(message_dec)

        # ASB structure
        asb_dec = self._get_asb_item([
            msg_obj.cbor_tag,
            message_enc
        ])
        asb_enc = self._get_asb_enc(asb_dec)
        print('ASB: {}'.format(encode_diagnostic(asb_dec)))
        print('Encoded: {}'.format(encode_diagnostic(asb_enc)))

        bpsec_dec = self._get_bpsec_item(
            block_type=BlockType.BCB,
            asb_dec=asb_dec,
        )
        bpsec_enc = cbor2.dumps(bpsec_dec)
        print('BPSec block: {}'.format(encode_diagnostic(bpsec_dec)))
        print('Encoded: {}'.format(encode_diagnostic(bpsec_enc)))

        # Change from detached payload
        message_dec[2] = content_ciphertext
        decode_obj = EncMessage.from_cose_obj(message_dec, allow_unknown_attributes=False)
        decode_obj.external_aad = ext_aad_enc

        recip = decode_obj.recipients[0]
        recip.key = private_key
        decode_plaintext = decode_obj.decrypt(recipient=recip)
        print('Loopback plaintext:', encode_diagnostic(decode_plaintext))
        self.assertEqual(content_plaintext, decode_plaintext)

        print('Loopback CEK:', encode_diagnostic(cbor2.loads(decode_obj.key.encode())))
        self.assertEqual(cek.k, decode_obj.key.k)

        target_dec[4] = content_ciphertext
        target_enc = cbor2.dumps(target_dec)
        bundle = self._assemble_bundle([prim_enc, bpsec_enc, target_enc])
        self._print_bundle(bundle)
