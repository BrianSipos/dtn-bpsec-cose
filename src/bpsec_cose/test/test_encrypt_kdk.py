import cbor2
from typing import cast
from pycose import headers, algorithms
from pycose.keys import SymmetricKey, keyops, keyparam
from pycose.messages import EncMessage
from pycose.messages.recipient import DirectEncryption
from ..util import dump_cborseq, cbor2diag
from ..bpsec import BlockType
from .base import BaseTest


class TestExample(BaseTest):

    def test(self):
        # 256-bit key derivation key
        kdk = SymmetricKey(
            k=bytes.fromhex('6c4e5271e211e0c8329ab8f363097f16516a459f12a4060cf0164968fdccbd63'),
            optional_params={
                keyparam.KpKid: b'ExampleA.6',
                keyparam.KpAlg: algorithms.DirectHKDFSHA512,
                keyparam.KpKeyOps: [keyops.DeriveKeyOp],
            }
        )
        self._logger.info('KDK: %s', cbor2diag(kdk.encode()))
        kdf_salt = bytes.fromhex('2fa8c8352aea17faf7407271a5e90eb8')
        self._logger.info('KDF salt: %s', kdf_salt.hex())

        # session IV
        iv = bytes.fromhex('6F3093EBA5D85143C3DC484A')
        self._logger.info('IV: %s', iv.hex())

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

        msg_obj = EncMessage(
            phdr={
                headers.Algorithm: algorithms.A256GCM,
            },
            uhdr={
                headers.IV: iv,
            },
            payload=content_plaintext,
            recipients=[
                DirectEncryption(
                    phdr={
                        headers.Algorithm: kdk.alg,
                    },
                    uhdr={
                        headers.KID: kdk.kid,
                        headers.Salt: kdf_salt,
                    },
                    key=kdk,
                ),
            ],
            # Non-encoded parameters
            external_aad=ext_aad_enc,
        )
        recip = msg_obj.recipients[0]
        recip.local_attrs = {
            headers.SuppPubOther: self._get_kdf_pub_other(),
        }

        # COSE internal structure
        cose_struct_enc = msg_obj._enc_structure
        self._logger.info('COSE Structure: %s', cbor2diag(cose_struct_enc))
        self._logger.info('Encoded: %s', cose_struct_enc.hex())
        kdf_ctx_enc = recip.get_kdf_context(msg_obj.phdr[headers.Algorithm]).encode()
        self._logger.info('COSE_KDF_Context: %s', cbor2diag(kdf_ctx_enc))
        self._logger.info('Encoded: %s', kdf_ctx_enc.hex())

        # Encoded message
        message_enc = msg_obj.encode(tag=False)
        self._logger.info('CEK: %s', cbor2diag(msg_obj.key.encode()))
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
        decode_obj = EncMessage.from_cose_obj(message_dec, allow_unknown_attributes=False)
        decode_obj.external_aad = ext_aad_enc

        recip = decode_obj.recipients[0]
        recip.key = kdk
        recip.local_attrs = {
            headers.SuppPubOther: self._get_kdf_pub_other(),
        }

        decode_plaintext = decode_obj.decrypt(recipient=recip)
        self._logger.info('Loopback plaintext: %s', decode_plaintext.hex())
        self.assertEqual(content_plaintext, decode_plaintext)

        self._logger.info('Loopback CEK: %s', cbor2diag(decode_obj.key.encode()))
        self.assertIsInstance(decode_obj.key, SymmetricKey)
        self.assertEqual(cast(SymmetricKey, msg_obj.key).k, cast(SymmetricKey, decode_obj.key).k)

        target_dec[4] = content_ciphertext
        self._replace_crc(target_dec, target_dec[3])
        target_enc = cbor2.dumps(target_dec)
        self._logger.info('Target with ciphertext: %s', cbor2diag(target_enc))
        bundle = self._assemble_bundle([prim_enc, bpsec_enc, target_enc])
        self._print_bundle(bundle)
