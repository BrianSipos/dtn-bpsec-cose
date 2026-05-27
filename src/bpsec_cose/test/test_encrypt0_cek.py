import cbor2
from pycose import headers, algorithms
from pycose.keys import SymmetricKey, keyops, keyparam
from pycose.messages import Enc0Message
from ..util import dump_cborseq, cbor2diag
from ..bpsec import BlockType
from .base import BaseTest


def bytes_pad(val: bytes, size: int) -> bytes:
    return b'\x00' * (size - len(val)) + val


def bytes_xor(lt: bytes, rt: bytes) -> bytes:
    size = max([len(lt), len(rt)])
    lt = bytes_pad(lt, size)
    rt = bytes_pad(rt, size)
    return bytes(ltp ^ rtp for ltp, rtp in zip(lt, rt))


class TestExample(BaseTest):

    def test(self):
        # 256-bit content encryption key
        cek = SymmetricKey(
            k=bytes.fromhex('13BF9CEAD057C0ACA2C9E52471CA4B19DDFAF4C0784E3F3E8E3999DBAE4CE45C'),
            optional_params={
                keyparam.KpKid: b'ExampleA.4',
                keyparam.KpAlg: algorithms.A256GCM,
                keyparam.KpKeyOps: [keyops.EncryptOp, keyops.DecryptOp],
                keyparam.KpBaseIV: bytes.fromhex('6f3093eba5d85143c3dc0000'),
            }
        )
        self._logger.info('CEK: %s', cbor2diag(cek.encode()))
        # session IV
        partial_iv = bytes.fromhex('484A')

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

        msg_obj = Enc0Message(
            phdr={
                headers.Algorithm: cek.alg,
            },
            uhdr={
                headers.KID: cek.kid,
                headers.PartialIV: partial_iv,
            },
            payload=content_plaintext,
            # Non-encoded parameters
            external_aad=ext_aad_enc,
            key=cek,
        )
        self._logger.info('IV: %s', msg_obj._get_nonce().hex())

        # COSE internal structure
        cose_struct_enc = msg_obj._enc_structure
        self._logger.info('COSE Structure: %s', cbor2diag(cose_struct_enc))
        self._logger.info('Encoded: %s', cose_struct_enc.hex())

        # Encoded message
        message_enc = msg_obj.encode(tag=False)
        message_dec = cbor2.loads(message_enc)
        # Detach the payload
        content_ciphertext = message_dec[2]
        message_dec[2] = None
        self._print_message(message_dec, recipient_idx=3)
        self._logger.info('Ciphertext: %s', content_ciphertext.hex())
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
            block_type=BlockType.BCB,
            asb_dec=asb_dec,
        )
        bpsec_enc = cbor2.dumps(bpsec_dec)
        self._logger.info('BPSec block: %s', cbor2diag(bpsec_enc))
        self._logger.info('Encoded: %s', bpsec_enc.hex())

        # Change from detached payload
        message_dec[2] = content_ciphertext
        decode_obj = Enc0Message.from_cose_obj(message_dec, allow_unknown_attributes=False)
        decode_obj.external_aad = ext_aad_enc

        decode_obj.key = cek
        decode_plaintext = decode_obj.decrypt()
        self._logger.info('Loopback plaintext: %s', decode_plaintext.hex())
        self.assertEqual(content_plaintext, decode_plaintext)

        target_dec[4] = content_ciphertext
        self._replace_crc(target_dec, target_dec[3])
        target_enc = cbor2.dumps(target_dec)
        self._logger.info('Target with ciphertext: %s', cbor2diag(target_enc))
        bundle = self._assemble_bundle([prim_enc, bpsec_enc, target_enc])
        self._print_bundle(bundle)
