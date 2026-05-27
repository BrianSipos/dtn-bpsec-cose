import cbor2
from pycose import headers, algorithms
from pycose.keys import SymmetricKey, keyops, keyparam
from pycose.messages import Mac0Message
from ..util import dump_cborseq, cbor2diag
from ..bpsec import BlockType
from .base import BaseTest


class TestExample(BaseTest):

    def test(self):
        # 384-bit key (SHA-384 output size)
        key = SymmetricKey(
            k=(b'\x00' * 16),  # placeholder for below
            optional_params={
                keyparam.KpKid: b'ExampleA.1',
                keyparam.KpAlg: algorithms.HMAC384,
                keyparam.KpKeyOps: [keyops.MacCreateOp, keyops.MacVerifyOp],
            }
        )
        # work around pycose issue #133 of key length
        key.store[keyparam.SymKpK] = bytes.fromhex('3a5c74e32ab4558a99581ec3a816576812aabe895db04494cda25b711d7b5ed4077466e677860648412f1bf8c91d0624')
        self._logger.info('Key: %s', cbor2diag(key.encode()))

        # Primary block
        prim_dec = self._get_primary_item()
        prim_enc = cbor2.dumps(prim_dec)
        self._logger.info('Primary Block: %s', cbor2diag(prim_enc))
        self._logger.info('Encoded: %s', prim_enc.hex())

        # Security target block
        target_dec = self._get_target_item()
        content_plaintext = target_dec[4]
        self._logger.info('Target Block: %s', cbor2diag(cbor2.dumps(target_dec)))
        self._logger.info('Plaintext: %s', content_plaintext.hex())

        # Combined AAD
        ext_aad_dec = self._get_aad_array()
        ext_aad_enc = dump_cborseq(ext_aad_dec)
        self._logger.info('External AAD: %s', cbor2diag(ext_aad_enc))
        self._logger.info('Encoded: %s', ext_aad_enc.hex())

        msg_obj = Mac0Message(
            phdr={
                headers.Algorithm: key.alg,
            },
            uhdr={
                headers.KID: key.kid,
            },
            payload=content_plaintext,
            # Non-encoded parameters
            external_aad=ext_aad_enc,
        )
        msg_obj.key = key

        # COSE internal structure
        cose_struct_enc = msg_obj._mac_structure
        self._logger.info('COSE Structure: %s', cbor2diag(cose_struct_enc))
        self._logger.info('Encoded: %s', cose_struct_enc.hex())

        # Encoded message
        message_enc = msg_obj.encode(tag=False)
        message_dec = cbor2.loads(message_enc)
        # Detach the payload
        content_signature = message_dec[2]
        message_dec[2] = None
        self._print_message(message_dec, recipient_idx=4)
        message_enc = cbor2.dumps(message_dec)

        # ASB structure
        asb_dec = self._get_asb_item((
            msg_obj.cbor_tag,
            message_enc
        ))
        asb_enc = self._get_asb_enc(asb_dec)
        self._logger.info('ASB: %s', cbor2diag(asb_enc))
        self._logger.info('Encoded: %s', asb_enc.hex())

        bpsec_dec = self._get_bpsec_item(
            block_type=BlockType.BIB,
            asb_dec=asb_dec,
        )
        bpsec_enc = cbor2.dumps(bpsec_dec)
        self._logger.info('BPSec block: %s', cbor2diag(bpsec_enc))
        self._logger.info('Encoded: %s', bpsec_enc.hex())

        # Change from detached payload
        message_dec[2] = content_signature
        decode_obj = Mac0Message.from_cose_obj(message_dec, allow_unknown_attributes=False)
        decode_obj.external_aad = ext_aad_enc
        decode_obj.key = key

        verify_valid = decode_obj.verify_tag()
        self.assertTrue(verify_valid)
        self._logger.info('Loopback verify: %s', verify_valid)

        target_enc = cbor2.dumps(target_dec)
        bundle = self._assemble_bundle([prim_enc, bpsec_enc, target_enc])
        self._print_bundle(bundle)
