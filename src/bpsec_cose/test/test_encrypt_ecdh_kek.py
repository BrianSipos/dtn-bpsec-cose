import binascii
import cbor2
from cose import curves, headers, algorithms
from cose.keys import SymmetricKey, EC2Key, keyops, keyparam
from cose.messages import EncMessage
from cose.messages.recipient import KeyAgreementWithKeyWrap
from cose.messages.context import CoseKDFContext, PartyInfo, SuppPubInfo
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
                keyparam.KpKeyOps: [keyops.DeriveKeyOp],
            }
        )
        print('Private Key: {}'.format(encode_diagnostic(cbor2.loads(private_key.encode()))))
        # 256-bit content encryption key
        cek = SymmetricKey(
            key=binascii.unhexlify('13BF9CEAD057C0ACA2C9E52471CA4B19DDFAF4C0784E3F3E8E3999DBAE4CE45C'),
            optional_params={
                keyparam.KpKid: b'ExampleCEK',
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
        ext_aad_dec = self._get_aad_item()
        ext_aad_enc = cbor2.dumps(ext_aad_dec)
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
                KeyAgreementWithKeyWrap(
                    uhdr={
                        headers.Algorithm: algorithms.EcdhEsA256KW,
                        headers.KID: private_key.kid,
                        # Would be random nonce, but test constant
                        headers.PartyUNonce: binascii.unhexlify(b'e6bd83a5a06841c2ea1dd4eebaaaf252'),
                    },
                    payload=cek.k,
                ),
            ],
            # Non-encoded parameters
            external_aad=ext_aad_enc,
        )
        msg_obj.recipients[0].local_attrs = {
            headers.StaticKey: private_key,
        }

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
        asb_enc = cbor2.dumps(asb_dec)
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
        decode_obj = EncMessage.from_cose_obj(message_dec)
        decode_obj.external_aad = ext_aad_enc

        recip = decode_obj.recipients[0]
        recip.key = private_key
        decode_plaintext = decode_obj.decrypt(recipient=recip)
        print('Loopback plaintext:', encode_diagnostic(decode_plaintext))
        self.assertEqual(content_plaintext, decode_plaintext)

        print('Loopback CEK:', encode_diagnostic(cbor2.loads(decode_obj.key.encode())))
        self.assertEqual(cek.k, decode_obj.key.k)
