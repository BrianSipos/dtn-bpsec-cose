import cbor2
from pycose import headers, algorithms
from pycose.keys import RSAKey, keyops, keyparam
from pycose.messages import Sign1Message
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
pB+1auZY8nq3BAVdTCO7lfo=
-----END PRIVATE KEY-----
'''
        private_key = RSAKey.from_pem_private_key(
            private_pem,
            optional_params={
                keyparam.KpKid: b'ExampleA.3',
                keyparam.KpAlg: algorithms.Ps384,
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
