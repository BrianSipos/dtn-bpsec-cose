import unittest
import binascii
import cbor2
from cose import Sign1Message, CoseHeaderKeys, CoseAlgorithms, EC2
import cose.keys.cosekey as cosekey
from cose.messages.recipient import CoseRecipient, RcptParams
from ..util import encode_diagnostic
from .base import BaseTest


class TestExample(BaseTest):

    def test(self):
        print()
        private_key = EC2(
            kid=b'ExampleEC2',
            x=binascii.unhexlify('0cbc52712bbf1567b7c086e904901091afc10d2da912951d48aefb4b1d46f32b'),
            y=binascii.unhexlify('f0a76e7251588607542a02d322e2bc0896e7e147546a8ebade7f8c75c8aa7ecf'),
            d=binascii.unhexlify('57226c6f7082a7d5128d309975f5766ebf38fb797d2c9a7700f542c4b0e997d1'),
        )
        print('Private Key: {}'.format(encode_diagnostic(private_key.encode('_kid', 'x', 'y', 'd'), bstr_as='base64')))
        print('Public Key: {}'.format(encode_diagnostic(private_key.encode('_kid', 'x', 'y'), bstr_as='base64')))

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

        private_key.key_ops = cosekey.KeyOps.SIGN
        msg_obj = Sign1Message(
            phdr={
                CoseHeaderKeys.ALG: CoseAlgorithms.ES256,
            },
            uhdr={
                CoseHeaderKeys.KID: private_key.kid,
            },
            payload=content_plaintext,
            # Non-encoded parameters
            external_aad=ext_aad_enc,
        )

        # COSE internal structure
        cose_struct_enc = msg_obj._sig_structure
        cose_struct_dec = cbor2.loads(cose_struct_enc)
        print('COSE Structure: {}'.format(encode_diagnostic(cose_struct_dec)))
        print('Encoded: {}'.format(encode_diagnostic(cose_struct_enc)))

        # Encoded message
        message_enc = msg_obj.encode(
            private_key=private_key,
            alg=msg_obj.phdr[CoseHeaderKeys.ALG],
            tagged=False
        )
        message_dec = cbor2.loads(message_enc)
        # Detach the payload
        content_signature = message_dec[2]
        message_dec[2] = None
        self._print_message(message_dec, recipient_idx=4)

        # ASB structure
        asb_dec = self._get_asb_item([
            msg_obj.cbor_tag,
            message_dec
        ])
        asb_enc = cbor2.dumps(asb_dec)
        print('ASB: {}'.format(encode_diagnostic(asb_dec)))
        print('Encoded: {}'.format(encode_diagnostic(asb_enc)))

        bpsec_dec = self._get_bpsec_item(
            block_type=98,  # FIXME: not real
            asb_dec=asb_dec,
        )
        bpsec_enc = cbor2.dumps(bpsec_dec)
        print('BPSec block: {}'.format(encode_diagnostic(bpsec_dec)))
        print('Encoded: {}'.format(encode_diagnostic(bpsec_enc)))

        # Change from detached payload
        message_dec[2] = content_signature
        decode_obj: Sign1Message = Sign1Message.decode(cbor2.dumps(cbor2.CBORTag(Sign1Message.cbor_tag, message_dec)))
        decode_obj.external_aad = ext_aad_enc
        private_key.key_ops = cosekey.KeyOps.VERIFY
        verify_valid = decode_obj.verify_signature(public_key=private_key)
        self.assertTrue(verify_valid)
        print('Loopback verify:', verify_valid)
