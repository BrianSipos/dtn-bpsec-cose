import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from pycose import headers, algorithms
from pycose.keys import SymmetricKey, EC2Key, curves, keyops, keyparam
from pycose.messages import EncMessage
from pycose.messages.recipient import KeyAgreementWithKeyWrap
from ..util import dump_cborseq, encode_diagnostic
from ..bpsec import BlockType
from .base import BaseTest


class TestExample(BaseTest):

    def test(self):
        print('\nTest: ' + __name__ + '.' + type(self).__name__)
        recipient_key = EC2Key(
            crv=curves.P384,
            x=bytes.fromhex('0057ea0e6fdc50ddc1111bd810eae7c0ba24645d44d4712db0c8354c234b2970b4ac27e78f38250069d128f98e51ceb1'),
            y=bytes.fromhex('4b72c50b27267637c40adcd78bd025e4b654a645d2ba7ba9894cc73b2431d4cdc040d66e8eb2dad731f7dca57108545c'),
            d=bytes.fromhex('7931af7cc3010ae457bcb8be100acdafab8492de633b20384c3e4de5e5e94899d9d9de25c04d6205ae6bb9385ce16ff7'),
            optional_params={
                keyparam.KpKid: b'ExampleEC2',
                keyparam.KpAlg: algorithms.EcdhEsA256KW,
                keyparam.KpKeyOps: [keyops.DeriveKeyOp],
            }
        )
        print('Private Key: {}'.format(encode_diagnostic(cbor2.loads(recipient_key.encode()))))
        recipient_public = EC2Key(
            crv=recipient_key.crv,
            x=recipient_key.x,
            y=recipient_key.y
        )

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

        # 256-bit content encryption key
        cek = SymmetricKey(
            k=bytes.fromhex('13BF9CEAD057C0ACA2C9E52471CA4B19DDFAF4C0784E3F3E8E3999DBAE4CE45C'),
            optional_params={
                keyparam.KpKid: b'ExampleCEK',
                keyparam.KpAlg: algorithms.A256GCM,
                keyparam.KpKeyOps: [keyops.EncryptOp, keyops.DecryptOp],
            }
        )
        print('CEK: {}'.format(encode_diagnostic(cbor2.loads(cek.encode()))))
        # session IV
        iv = bytes.fromhex('6F3093EBA5D85143C3DC484A')
        print('IV: {}'.format(iv.hex()))

        # Would be random ephemeral key, but test constant
        sender_key = EC2Key(
            crv=curves.P384,
            x=bytes.fromhex('2f88f095c45c96e377e18d717a5e6007ce8f6076ae82009d16375e1b9abaa9497a4bde513be6c9b0e7dae96033968c45'),
            y=bytes.fromhex('fd27656fbb97f789d667f40d73b65ab362b22dd23bf492bee72bf3409f68dddf208040a5fcbcbee74545741e2866cb2d'),
            d=bytes.fromhex('c4fff15193b8bceff5e221cc37b919fa8d33581a37c08d3e8520a658b4040a443f8fb3b54fb4ce882510e76017b66261'),
            optional_params={
                keyparam.KpKid: b'SenderEC2',
                keyparam.KpAlg: algorithms.EcdhEsA256KW,
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
                headers.Algorithm: cek.alg,
            },
            uhdr={
                headers.IV: iv,
            },
            payload=content_plaintext,
            recipients=[
                KeyAgreementWithKeyWrap(
                    phdr={
                        headers.Algorithm: recipient_key.alg,
                    },
                    uhdr={
                        headers.KID: recipient_key.kid,
                        headers.EphemeralKey: sender_public,
                    },
                    payload=cek.k,
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
        recip.key = recipient_key
        decode_plaintext = decode_obj.decrypt(recipient=recip)
        print('Loopback plaintext:', encode_diagnostic(decode_plaintext))
        self.assertEqual(content_plaintext, decode_plaintext)

        print('Loopback CEK:', encode_diagnostic(cbor2.loads(decode_obj.key.encode())))
        self.assertEqual(cek.k, decode_obj.key.k)

        target_dec[4] = content_ciphertext
        target_enc = cbor2.dumps(target_dec)
        bundle = self._assemble_bundle([prim_enc, bpsec_enc, target_enc])
        self._print_bundle(bundle)
