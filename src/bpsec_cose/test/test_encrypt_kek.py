import binascii
import cbor2
from pycose import headers, algorithms
from pycose.keys import SymmetricKey, keyops, keyparam
from pycose.messages import EncMessage
from pycose.messages.recipient import KeyWrap
from ..util import dump_cborseq, encode_diagnostic
from ..bpsec import BlockType
from .base import BaseTest


class TestExample(BaseTest):

    def test(self):
        print('\nTest: ' + __name__ + '.' + type(self).__name__)
        # 256-bit key encryption key
        kek = SymmetricKey(
            k=binascii.unhexlify('0E8A982B921D1086241798032FEDC1F883EAB72E4E43BB2D11CFAE38AD7A972E'),
            optional_params={
                keyparam.KpKid: b'ExampleKEK',
                keyparam.KpAlg: algorithms.A256KW,
                keyparam.KpKeyOps: [keyops.WrapOp, keyops.UnwrapOp],
            }
        )
        print('KEK: {}'.format(encode_diagnostic(cbor2.loads(kek.encode()))))
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
                        headers.Algorithm: algorithms.A256KW,
                        headers.KID: kek.kid,
                    },
                    payload=cek.k,
                    key=kek,
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
        recip.key = kek
        decode_plaintext = decode_obj.decrypt(recipient=recip)
        print('Loopback plaintext:', encode_diagnostic(decode_plaintext))
        self.assertEqual(content_plaintext, decode_plaintext)

        print('Loopback CEK:', encode_diagnostic(cbor2.loads(decode_obj.key.encode())))
        self.assertEqual(cek.k, decode_obj.key.k)

        target_dec[4] = content_ciphertext
        target_enc = cbor2.dumps(target_dec)
        bundle = self._assemble_bundle([prim_enc, bpsec_enc, target_enc])
        self._print_bundle(bundle)
