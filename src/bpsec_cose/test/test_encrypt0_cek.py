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
        print('\nTest: ' + __name__ + '.' + type(self).__name__)

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
        print('CEK: {}'.format(cbor2diag(cek.encode())))
        # session IV
        partial_iv = bytes.fromhex('484A')

        # Primary block
        prim_dec = self._get_primary_item()
        prim_enc = cbor2.dumps(prim_dec)
        print('Primary Block: {}'.format(cbor2diag(prim_enc)))
        print('Encoded: {}'.format(prim_enc.hex()))

        # Security target block
        target_dec = self._get_target_item()
        content_plaintext = target_dec[4]
        print('Target Block: {}'.format(cbor2diag(cbor2.dumps(target_dec))))
        print('Plaintext: {}'.format(content_plaintext.hex()))

        # Combined AAD
        ext_aad_dec = self._get_aad_array()
        ext_aad_enc = dump_cborseq(ext_aad_dec)
        print('External AAD: {}'.format(cbor2diag(ext_aad_enc)))
        print('Encoded: {}'.format(ext_aad_enc.hex()))

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
        print('IV: {}'.format(msg_obj._get_nonce().hex()))

        # COSE internal structure
        cose_struct_enc = msg_obj._enc_structure
        print('COSE Structure: {}'.format(cbor2diag(cose_struct_enc)))
        print('Encoded: {}'.format(cose_struct_enc.hex()))

        # Encoded message
        message_enc = msg_obj.encode(tag=False)
        message_dec = cbor2.loads(message_enc)
        # Detach the payload
        content_ciphertext = message_dec[2]
        message_dec[2] = None
        self._print_message(message_dec, recipient_idx=3)
        print('Ciphertext: {}'.format(content_ciphertext.hex()))
        message_enc = cbor2.dumps(message_dec)

        # ASB structure
        asb_dec = self._get_asb_item((
            msg_obj.cbor_tag,
            message_enc
        ))
        asb_enc = self._get_asb_enc(asb_dec)
        print('ASB: {}'.format(cbor2diag(asb_enc)))
        print('Encoded: {}'.format(asb_enc.hex()))

        bpsec_dec = self._get_bpsec_item(
            block_type=BlockType.BCB,
            asb_dec=asb_dec,
        )
        bpsec_enc = cbor2.dumps(bpsec_dec)
        print('BPSec block: {}'.format(cbor2diag(bpsec_enc)))
        print('Encoded: {}'.format(bpsec_enc.hex()))

        # Change from detached payload
        message_dec[2] = content_ciphertext
        decode_obj = Enc0Message.from_cose_obj(message_dec, allow_unknown_attributes=False)
        decode_obj.external_aad = ext_aad_enc

        decode_obj.key = cek
        decode_plaintext = decode_obj.decrypt()
        print('Loopback plaintext:', decode_plaintext.hex())
        self.assertEqual(content_plaintext, decode_plaintext)

        target_dec[4] = content_ciphertext
        self._replace_crc(target_dec, target_dec[3])
        target_enc = cbor2.dumps(target_dec)
        print('Target with ciphertext:', cbor2diag(target_enc))
        bundle = self._assemble_bundle([prim_enc, bpsec_enc, target_enc])
        self._print_bundle(bundle)
