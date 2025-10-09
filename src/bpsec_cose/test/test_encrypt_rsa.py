import binascii
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
        # 1024-bit key
        private_key = RSAKey(
            n=binascii.unhexlify(b'b0b5fd85f52c91844007443c9f9371980025f76d51fc9c67681231da610cb291ba637ce813bffdb2e9c653258607389ec97dad3db295fded67744ed620707db36804e74e56a494030a73608fc8d92f2f0578d2d85cc201ef0ff22d7835d2d147d3b90a6884276235a01c2be99dfc597f79554362fc1eb03639cac5ccaddb2925'),
            e=binascii.unhexlify(b'010001'),
            d=binascii.unhexlify(b'9b5d26ad6445ef1aab80b809e4f329684e9912d556c4166f041d1b1fb93c04b4037ffd0dbe6f8a8a86e70bab6e0f6344983a9ada27ed9ff7de816fdeeb5e7be48e607ce5fda4581ca6338a9e019fb3689b28934192b6a190cdda910abb5a86a2f7b6f9cd5011049d8de52ddfef73aa06df401c55623ec196720f54920deb4f01'),
            p=binascii.unhexlify(b'db22d94e7784a27b568cbf985307ea8d6430ff6b88c18a7086fd4f57a326572f2250c39e48a6f8e2201661c2dfe12c7386835b649714d050aa36123ec3d00e75'),
            q=binascii.unhexlify(b'ce7016adc5f326b7520397c5978ee2f50e69279983d54c5d76f05bcd61de0879d7056c923540dff9cbae95dcc0e5e86b52b3c902dc9669c8021c69557effb9f1'),
            dp=binascii.unhexlify(
                b'6a6fcaccea106a3b2e16bf18e57b7ad9a2488a4758ed68a8af686a194f0d585b7477760c738d6665aee0302bcf4237ad0530d83b4b86b887f5a4bdc7eea427e1'),
            dq=binascii.unhexlify(
                b'28a4cae245b1dcb285142e027a1768b9c4af915b59285a93a0422c60e05edd9e57663afd023d169bd0ad3bd62da8563d231840802ebbf271ad70b8905ba3af91'),
            qinv=binascii.unhexlify(
                b'07b5a61733896270a6bd2bb1654194c54e2bc0e061b543a4ed9fa73c4bc79c87148aa92a451c4ab8262b6377a9c7b97f869160ca6f5d853ee4b65f4f92865ca3'),
            optional_params={
                keyparam.KpKid: b'ExampleRSA',
                keyparam.KpAlg: algorithms.RsaesOaepSha256,
                keyparam.KpKeyOps: [keyops.WrapOp, keyops.UnwrapOp],
            }
        )
        print('Private Key: {}'.format(encode_diagnostic(cbor2.loads(private_key.encode()))))
        # 256-bit content encryption key
        cek = SymmetricKey(
            k=binascii.unhexlify('13BF9CEAD057C0ACA2C9E52471CA4B19DDFAF4C0784E3F3E8E3999DBAE4CE45C'),
            optional_params={
                keyparam.KpKid: b'ExampleCEK',
                keyparam.KpAlg: algorithms.A256GCM,
                keyparam.KpKeyOps: [keyops.EncryptOp, keyops.DecryptOp],
            }
        )
        print('CEK: {}'.format(encode_diagnostic(cbor2.loads(cek.encode()))))
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
        ext_aad_dec = self._get_aad_array()
        ext_aad_enc = dump_cborseq(ext_aad_dec)
        print('External AAD: {}'.format(encode_diagnostic(ext_aad_dec)))
        print('Encoded: {}'.format(encode_diagnostic(ext_aad_enc)))

        msg_obj = EncMessage(
            phdr={
                headers.Algorithm: algorithms.A256GCM,
            },
            uhdr={
                headers.IV: iv,
            },
            payload=content_plaintext,
            recipients=[
                KeyWrap(
                    uhdr={
                        headers.Algorithm: algorithms.RsaesOaepSha256,
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
