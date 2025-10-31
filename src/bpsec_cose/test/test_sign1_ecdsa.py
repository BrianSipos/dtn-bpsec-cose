import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from pycose import headers, algorithms
from pycose.keys import EC2Key, curves, keyops, keyparam
from pycose.messages import Sign1Message
from ..util import dump_cborseq, encode_diagnostic
from ..bpsec import BlockType
from .base import BaseTest


class TestExample(BaseTest):

    def test(self):
        print('\nTest: ' + __name__ + '.' + type(self).__name__)
        private_key = EC2Key(
            crv=curves.P384,
            x=bytes.fromhex('02dfc49747f5d3d219fe6185744729fa1672ef7d11cb57ca0320c632be06ca3fdcc118e63140ba3ec57ea7b85d419568'),
            y=bytes.fromhex('4526e81bf0d9ea0924f05a3453ad75b92806671511544c993f6bd908a7a4239d476cfdfd74d6c68836488ad1e60b0e7d'),
            d=bytes.fromhex('3494803544d85a84d802400b50f51eea23b72d7d850b53cbf3006e5be2940d4a2c18d510a412efc7dc7875fbba22cca9'),
            optional_params={
                keyparam.KpKid: b'ExampleEC2',
                keyparam.KpAlg: algorithms.Esp384,
                keyparam.KpKeyOps: [keyops.SignOp, keyops.VerifyOp],
            }
        )
        print('Private Key: {}'.format(encode_diagnostic(cbor2.loads(private_key.encode()))))

        ckey = ec.EllipticCurvePrivateNumbers(
            int.from_bytes(private_key.d, 'big'),
            ec.EllipticCurvePublicNumbers(
                x=int.from_bytes(private_key.x, 'big'),
                y=int.from_bytes(private_key.y, 'big'),
                curve=private_key.crv.curve_obj
            )
        ).private_key()
        ckey_pem = ckey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        print('Private PEM:\n{}'.format(ckey_pem.decode('utf-8')))
        serialization.load_pem_private_key(ckey_pem, password=None)

        # Primary block
        prim_dec = self._get_primary_item()
        prim_enc = cbor2.dumps(prim_dec)
        print('Primary Block: {}'.format(encode_diagnostic(prim_dec)))
        print('Encoded: {}'.format(encode_diagnostic(prim_enc)))

        # Security target block
        target_dec = self._get_target_item()
        target_enc = cbor2.dumps(target_dec)
        content_plaintext = target_dec[4]
        print('Target Block: {}'.format(encode_diagnostic(target_dec)))
        print('Plaintext: {}'.format(encode_diagnostic(content_plaintext)))

        # Combined AAD
        ext_aad_dec = self._get_aad_array()
        ext_aad_enc = dump_cborseq(ext_aad_dec)
        print('External AAD: {}'.format(encode_diagnostic(ext_aad_dec)))
        print('Encoded: {}'.format(encode_diagnostic(ext_aad_enc)))

        msg_obj = Sign1Message(
            phdr={
                headers.Algorithm: private_key.alg,
            },
            uhdr={
                headers.KID: private_key.kid,
            },
            # Non-encoded parameters
            external_aad=ext_aad_enc,
        )
        msg_obj.key = private_key

        # COSE internal structure
        cose_struct_enc = msg_obj._create_sig_structure(detached_payload=content_plaintext)
        cose_struct_dec = cbor2.loads(cose_struct_enc)
        print('COSE Structure: {}'.format(encode_diagnostic(cose_struct_dec)))
        print('Encoded: {}'.format(encode_diagnostic(cose_struct_enc)))

        # Encoded message
        message_enc = msg_obj.encode(detached_payload=content_plaintext, tag=False)
        message_dec = cbor2.loads(message_enc)
        self._print_message(message_dec, recipient_idx=4)
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
            block_type=BlockType.BIB,
            asb_dec=asb_dec,
        )
        bpsec_enc = cbor2.dumps(bpsec_dec)
        print('BPSec block: {}'.format(encode_diagnostic(bpsec_dec)))
        print('Encoded: {}'.format(encode_diagnostic(bpsec_enc)))

        decode_obj = Sign1Message.from_cose_obj(message_dec, allow_unknown_attributes=False)
        decode_obj.external_aad = ext_aad_enc
        decode_obj.key = private_key

        verify_valid = decode_obj.verify_signature(detached_payload=content_plaintext)
        self.assertTrue(verify_valid)
        print('Loopback verify:', verify_valid)

        bundle = self._assemble_bundle([prim_enc, bpsec_enc, target_enc])
        self._print_bundle(bundle)
