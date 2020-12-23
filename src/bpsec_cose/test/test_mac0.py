import binascii
import cbor2
from cose import Mac0Message, CoseHeaderKeys, CoseAlgorithms, SymmetricKey
import cose.keys.cosekey as cosekey
from ..util import encode_diagnostic
from ..bpsec import BlockType
from .base import BaseTest


class TestExample(BaseTest):

    def test(self):
        print('\nTest: ' + __name__ + '.' + type(self).__name__)
        # 256-bit key
        key = SymmetricKey(
            kid=b'ExampleKey',
            k=binascii.unhexlify('13BF9CEAD057C0ACA2C9E52471CA4B19DDFAF4C0784E3F3E8E3999DBAE4CE45C')
        )
        print('Key: {}'.format(encode_diagnostic(key.encode('_kid', 'k'))))

        # Primary block
        prim_dec = self._get_primary_item()
        prim_enc = cbor2.dumps(prim_dec)
        print('Primary Block: {}'.format(encode_diagnostic(prim_dec)))
        print('Encoded: {}'.format(encode_diagnostic(prim_enc)))

        # Block-to-MAC
        target_dec = self._get_target_item()
        content_plaintext = target_dec[4]
        print('Target Block: {}'.format(encode_diagnostic(target_dec)))
        print('Plaintext: {}'.format(encode_diagnostic(content_plaintext)))

        # Combined AAD
        ext_aad_dec = self._get_aad_item()
        ext_aad_enc = cbor2.dumps(ext_aad_dec)
        print('External AAD: {}'.format(encode_diagnostic(ext_aad_dec)))
        print('Encoded: {}'.format(encode_diagnostic(ext_aad_enc)))

        key.key_ops = cosekey.KeyOps.MAC_CREATE
        msg_obj = Mac0Message(
            phdr={
                CoseHeaderKeys.ALG: CoseAlgorithms.HMAC_256_256,
            },
            uhdr={
                CoseHeaderKeys.KID: key.kid,
            },
            payload=content_plaintext,
            # Non-encoded parameters
            external_aad=ext_aad_enc,
        )

        # COSE internal structure
        cose_struct_enc = msg_obj._mac_structure
        cose_struct_dec = cbor2.loads(cose_struct_enc)
        print('COSE Structure: {}'.format(encode_diagnostic(cose_struct_dec)))
        print('Encoded: {}'.format(encode_diagnostic(cose_struct_enc)))

        # Encoded message
        message_enc = msg_obj.encode(
            key=key,
            alg=msg_obj.phdr[CoseHeaderKeys.ALG],
            tagged=False
        )
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
        decode_obj: Mac0Message = Mac0Message.decode(cbor2.dumps(cbor2.CBORTag(Mac0Message.cbor_tag, message_dec)))
        decode_obj.external_aad = ext_aad_enc
        key.key_ops = cosekey.KeyOps.MAC_VERIFY
        verify_valid = decode_obj.verify_tag(key=key)
        self.assertTrue(verify_valid)
        print('Loopback verify:', verify_valid)
