import binascii
import cbor2
from cose import curves, headers, algorithms
from cose.keys import EC2Key, keyops, keyparam
from cose.messages import Sign1Message
from ..util import encode_diagnostic
from ..bpsec import BlockType
from .base import BaseTest


class TestExample(BaseTest):

    def test(self):
        print('\nTest: ' + __name__ + '.' + type(self).__name__)
        private_key = EC2Key(
            crv=curves.P256,
            x=binascii.unhexlify('44c1fa63b84f172b50541339c50beb0e630241ecb4eebbddb8b5e4fe0a1787a8'),
            y=binascii.unhexlify('059451c7630d95d0b550acbd02e979b3f4f74e645b74715fafbc1639960a0c7a'),
            d=binascii.unhexlify('dd6e7d8c4c0e0c0bd3ae1b4a2fa86b9a09b7efee4a233772cf5189786ea63842'),
            optional_params={
                keyparam.KpKid: b'ExampleEC2',
                keyparam.KpKeyOps: [keyops.SignOp, keyops.VerifyOp],
            }
        )
        print('Private Key: {}'.format(encode_diagnostic(cbor2.loads(private_key.encode()))))

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

        msg_obj = Sign1Message(
            phdr={
                headers.Algorithm: algorithms.Es256,
            },
            uhdr={
                headers.KID: private_key.kid,
            },
            payload=content_plaintext,
            # Non-encoded parameters
            external_aad=ext_aad_enc,
        )
        msg_obj.key = private_key

        # COSE internal structure
        cose_struct_enc = msg_obj._sig_structure
        cose_struct_dec = cbor2.loads(cose_struct_enc)
        print('COSE Structure: {}'.format(encode_diagnostic(cose_struct_dec)))
        print('Encoded: {}'.format(encode_diagnostic(cose_struct_enc)))

        # Encoded message
        message_enc = msg_obj.encode(tag=False)
        message_dec = cbor2.loads(message_enc)
        # Detach the payload
        content_signature = message_dec[2]
        message_dec[2] = None
        self._print_message(message_dec, recipient_idx=4)
        message_enc = cbor2.dumps(message_dec)

        # ASB structure
        asb_dec = self._get_asb_item([
            msg_obj.cbor_tag,
            message_enc
        ])
        asb_enc = cbor2.dumps(asb_dec)
        print('ASB: {}'.format(encode_diagnostic(asb_dec)))
        print('Encoded: {}'.format(encode_diagnostic(asb_enc)))

        bpsec_dec = self._get_bpsec_item(
            block_type=BlockType.BIB,
            asb_dec=asb_dec,
        )
        bpsec_enc = cbor2.dumps(bpsec_dec)
        print('BPSec block: {}'.format(encode_diagnostic(bpsec_dec)))
        print('Encoded: {}'.format(encode_diagnostic(bpsec_enc)))

        # Change from detached payload
        message_dec[2] = content_signature
        decode_obj = Sign1Message.from_cose_obj(message_dec)
        decode_obj.external_aad = ext_aad_enc
        decode_obj.key = private_key

        verify_valid = decode_obj.verify_signature()
        self.assertTrue(verify_valid)
        print('Loopback verify:', verify_valid)
