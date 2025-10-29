import binascii
import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from pycose import headers, algorithms
from pycose.keys import SymmetricKey, EC2Key, curves, keyops, keyparam
from pycose.messages import EncMessage
from pycose.messages.recipient import DirectKeyAgreement
from ..util import dump_cborseq, encode_diagnostic
from ..bpsec import BlockType
from .base import BaseTest


class TestExample(BaseTest):

    def test(self):
        print('\nTest: ' + __name__ + '.' + type(self).__name__)
        recipient_key = EC2Key(
            crv=curves.P256,
            x=binascii.unhexlify('44c1fa63b84f172b50541339c50beb0e630241ecb4eebbddb8b5e4fe0a1787a8'),
            y=binascii.unhexlify('059451c7630d95d0b550acbd02e979b3f4f74e645b74715fafbc1639960a0c7a'),
            d=binascii.unhexlify('dd6e7d8c4c0e0c0bd3ae1b4a2fa86b9a09b7efee4a233772cf5189786ea63842'),
            optional_params={
                keyparam.KpKid: b'ExampleEC2',
                keyparam.KpAlg: algorithms.EcdhSsHKDF256,
                keyparam.KpKeyOps: [keyops.DeriveKeyOp],
            }
        )
        print('Private Key: {}'.format(encode_diagnostic(cbor2.loads(recipient_key.encode()))))
        recipient_public = EC2Key(
            crv=recipient_key.crv,
            x=recipient_key.x,
            y=recipient_key.y
        )
        kdf_salt = binascii.unhexlify('2fa8c8352aea17faf7407271a5e90eb8')
        print('KDF salt: {}'.format(binascii.hexlify(kdf_salt)))

        ckey = ec.EllipticCurvePrivateNumbers(
            int.from_bytes(recipient_key.d, 'big'),
            ec.EllipticCurvePublicNumbers(
                x=int.from_bytes(recipient_key.x, 'big'),
                y=int.from_bytes(recipient_key.y, 'big'),
                curve=recipient_key.crv.curve_obj
            )
        ).private_key()
        ckey_pem = ckey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        print('Private PEM:\n{}'.format(ckey_pem.decode('utf-8')))
        serialization.load_pem_private_key(ckey_pem, password=None)

        # session IV
        iv = binascii.unhexlify('6F3093EBA5D85143C3DC484A')
        print('IV: {}'.format(binascii.hexlify(iv)))

        # Would be random ephemeral key, but test constant
        sender_key = EC2Key(
            crv=curves.P256,
            x=binascii.unhexlify('fedaba748882050d1bef8ba992911898f554450952070aeb4788ca57d1df6bcc'),
            y=binascii.unhexlify('ceaa8e7ff4751a4f81c70e98f1713378b0bd82a1414a2f493c1c9c0670f28d62'),
            d=binascii.unhexlify('a2e4ed4f2e21842999b0e9ebdaad7465efd5c29bd5761f5c20880f9d9c3b122a'),
            optional_params={
                keyparam.KpKid: b'SenderEC2',
                keyparam.KpAlg: algorithms.EcdhSsHKDF256,
                keyparam.KpKeyOps: [keyops.DeriveKeyOp],
            }
        )
        print('Sender Private Key: {}'.format(encode_diagnostic(cbor2.loads(sender_key.encode()))))
        sender_public = EC2Key(
            crv=sender_key.crv,
            x=sender_key.x,
            y=sender_key.y
        )

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
                DirectKeyAgreement(
                    phdr={
                        headers.Algorithm: recipient_key.alg,
                    },
                    uhdr={
                        headers.KID: recipient_key.kid,
                        headers.StaticKeyID: sender_key.kid,
                        headers.Salt: kdf_salt,
                    },
                ),
            ],
            # Non-encoded parameters
            external_aad=ext_aad_enc,
        )
        recip = msg_obj.recipients[0]
        recip.key = sender_key
        recip.local_attrs = {
            headers.StaticKey: recipient_public,
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
        # recipient's view of keys
        recip.uhdr[headers.StaticKey] = sender_public
        recip.key = recipient_key
        decode_plaintext = decode_obj.decrypt(recipient=recip)
        print('Loopback plaintext:', encode_diagnostic(decode_plaintext))
        self.assertEqual(content_plaintext, decode_plaintext)

        print('Loopback CEK:', encode_diagnostic(cbor2.loads(decode_obj.key.encode())))
        self.assertIsNotNone(decode_obj.key.k)

        target_dec[4] = content_ciphertext
        target_enc = cbor2.dumps(target_dec)
        bundle = self._assemble_bundle([prim_enc, bpsec_enc, target_enc])
        self._print_bundle(bundle)
