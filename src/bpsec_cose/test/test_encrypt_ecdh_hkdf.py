import cbor2
import os
from typing import cast, Type
from pycose import headers, algorithms
from pycose.keys import CoseKey, EC2Key, SymmetricKey, keyops, keyparam
from pycose.keys.curves import CoseCurve
from pycose.messages import EncMessage
from pycose.messages.recipient import DirectKeyAgreement
from ..util import dump_cborseq, cbor2diag
from ..bpsec import BlockType
from .base import BaseTest

SELFDIR = os.path.dirname(os.path.abspath(__file__))


class TestExample(BaseTest):

    def test(self):
        recipient_key = cast(EC2Key, CoseKey.from_pem_private_key(
            open(os.path.join(SELFDIR, '..', 'pki', 'data', 'nodes', 'dst',
                              'ssl', 'private', 'node-encrypt-ecc.pem'), 'r').read(),
            optional_params={
                keyparam.KpKid: b'ExampleA.8',
                keyparam.KpAlg: algorithms.EcdhSsHKDF512,
                keyparam.KpKeyOps: [keyops.DeriveKeyOp],
            }
        ))
        self._logger.info('Private Key: %s', cbor2diag(recipient_key.encode()))
        recipient_public = EC2Key(
            crv=cast(Type[CoseCurve], recipient_key.crv),
            x=recipient_key.x,
            y=recipient_key.y
        )
        kdf_salt = bytes.fromhex('2fa8c8352aea17faf7407271a5e90eb8')
        self._logger.info('KDF salt: %s', kdf_salt.hex())

        # session IV
        iv = bytes.fromhex('6F3093EBA5D85143C3DC484A')
        self._logger.info('IV: %s', iv.hex())

        # Would be random ephemeral key, but test constant
        sender_pem = '''\
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDE//FRk7i87/XiIcw3uRn6jTNYGjfAjT6FIKZYtAQKRD+Ps7VPtM6I
JRDnYBe2YmGgBwYFK4EEACKhZANiAAQviPCVxFyW43fhjXF6XmAHzo9gdq6CAJ0W
N14bmrqpSXpL3lE75smw59rpYDOWjEX9J2Vvu5f3idZn9A1ztlqzYrIt0jv0kr7n
K/NAn2jd3yCAQKX8vL7nRUV0Hihmyy0=
-----END EC PRIVATE KEY-----
'''
        sender_key = cast(EC2Key, CoseKey.from_pem_private_key(
            sender_pem,
            optional_params={
                keyparam.KpKid: b'SenderA.8',
                keyparam.KpAlg: algorithms.EcdhSsHKDF512,
                keyparam.KpKeyOps: [keyops.DeriveKeyOp],
            }
        ))
        self._logger.info('Sender Private Key: %s', cbor2diag(sender_key.encode()))
        sender_public = EC2Key(
            crv=cast(Type[CoseCurve], sender_key.crv),
            x=sender_key.x,
            y=sender_key.y
        )

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
        # recipient's view of keys
        recip.key = recipient_key
        recip.uhdr[headers.StaticKey] = sender_public
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
