import cbor2
import copy
import os
from pycose import headers, algorithms
from pycose.keys import CoseKey, keyops, keyparam
from pycose.messages import Sign1Message
from ..util import dump_cborseq, cbor2diag
from ..bpsec import BlockType
from .base import BaseTest

SELFDIR = os.path.dirname(os.path.abspath(__file__))


class TestExample(BaseTest):

    _KEY_FILE_PATH = os.path.join(SELFDIR, '..', 'pki', 'data', 'nodes', 'src', 'ssl', 'private', 'node-sign-ml.pem')

    def _do_keygen(self):
        ''' One-time key generation helper '''
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        c_key = MLDSA87PrivateKey.generate()
        c_bytes = c_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        with open(self._KEY_FILE_PATH, 'wb') as outfile:
            outfile.write(c_bytes)

    def test(self):
        private_key = CoseKey.from_pem_private_key(
            open(self._KEY_FILE_PATH, 'r').read(),
            optional_params={
                keyparam.KpKid: b'ExampleA.10',
                keyparam.KpAlg: algorithms.MlDsa87,
                keyparam.KpKeyOps: [keyops.SignOp, keyops.VerifyOp],
            }
        )
        public_key = copy.deepcopy(private_key)
        del public_key[keyparam.AKPKpPriv]
        self._logger.info('Private Key: %s', cbor2diag(private_key.encode()))

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
        self._logger.info('COSE Structure: %s', cbor2diag(cose_struct_enc))
        self._logger.info('Encoded: %s', cose_struct_enc.hex())

        # Encoded message
        message_enc = msg_obj.encode(detached_payload=content_plaintext, tag=False)
        message_dec = cbor2.loads(message_enc)
        self._print_message(message_dec, recipient_idx=4)
        message_enc = cbor2.dumps(message_dec)
        self._logger.info('Signature size: %d', len(message_dec[3]))

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

        decode_obj = Sign1Message.from_cose_obj(message_dec, allow_unknown_attributes=False)
        decode_obj.external_aad = ext_aad_enc
        decode_obj.key = public_key

        verify_valid = decode_obj.verify_signature(detached_payload=content_plaintext)
        self.assertTrue(verify_valid)
        self._logger.info('Loopback verify: %s', verify_valid)

        target_enc = cbor2.dumps(target_dec)
        bundle = self._assemble_bundle([prim_enc, bpsec_enc, target_enc])
        self._print_bundle(bundle)
