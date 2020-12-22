import binascii
import cbor2
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cose import (SymmetricKey, EncMessage, CoseHeaderKeys, CoseAlgorithms,
                  EC2, CoseEllipticCurves)
import cose.keys.cosekey as cosekey
from cose.attributes.context import (CoseKDFContext, PartyInfo, SuppPubInfo)
from cose.messages.recipient import CoseRecipient, RcptParams
from ..util import encode_diagnostic
from .base import BaseTest


class TestExample(BaseTest):

    def test(self):
        print()
        private_key = EC2(
            kid=b'ExampleEC2',
            key_ops=cosekey.KeyOps.DERIVE_KEY,
            crv=CoseEllipticCurves.P_256,
            x=binascii.unhexlify('0cbc52712bbf1567b7c086e904901091afc10d2da912951d48aefb4b1d46f32b'),
            y=binascii.unhexlify('f0a76e7251588607542a02d322e2bc0896e7e147546a8ebade7f8c75c8aa7ecf'),
            d=binascii.unhexlify('57226c6f7082a7d5128d309975f5766ebf38fb797d2c9a7700f542c4b0e997d1'),
        )
        print('Private Key: {}'.format(encode_diagnostic(private_key.encode('_kid', '_key_ops', 'crv', 'x', 'y', 'd'), bstr_as='base64')))
        print('Public Key: {}'.format(encode_diagnostic(private_key.encode('_kid', '_key_ops', 'crv', 'x', 'y'), bstr_as='base64')))
        # 256-bit content encryption key
        cek = SymmetricKey(
            kid=b'ExampleCEK',
            k=binascii.unhexlify('13BF9CEAD057C0ACA2C9E52471CA4B19DDFAF4C0784E3F3E8E3999DBAE4CE45C'),
        )
        print('CEK: {}'.format(encode_diagnostic(cek.encode('_kid', 'k'), bstr_as='base64')))
        # session IV
        iv = binascii.unhexlify('6F3093EBA5D85143C3DC484A')
        print('IV: {}'.format(binascii.hexlify(iv)))

        # Would be random ephemeral key, but test constant
        sender_key = EC2(
            key_ops=cosekey.KeyOps.DERIVE_KEY,
            crv=CoseEllipticCurves.P_256,
            x=binascii.unhexlify('fedaba748882050d1bef8ba992911898f554450952070aeb4788ca57d1df6bcc'),
            y=binascii.unhexlify('ceaa8e7ff4751a4f81c70e98f1713378b0bd82a1414a2f493c1c9c0670f28d62'),
            d=binascii.unhexlify('a2e4ed4f2e21842999b0e9ebdaad7465efd5c29bd5761f5c20880f9d9c3b122a'),
        )
        print('Sender Private Key: {}'.format(encode_diagnostic(sender_key.encode('_kid', '_key_ops', 'crv', 'x', 'y', 'd'), bstr_as='base64')))

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
        ext_aad_dec = self._get_aad_item()
        ext_aad_enc = cbor2.dumps(ext_aad_dec)
        print('External AAD: {}'.format(encode_diagnostic(ext_aad_dec)))
        print('Encoded: {}'.format(encode_diagnostic(ext_aad_enc)))

        cek.key_ops = cosekey.KeyOps.ENCRYPT
        msg_obj = EncMessage(
            phdr={
                CoseHeaderKeys.ALG: CoseAlgorithms.A256GCM,
            },
            uhdr={
                CoseHeaderKeys.IV: iv,
            },
            payload=content_plaintext,
            recipients=[
                CoseRecipient(
                    uhdr={
                        CoseHeaderKeys.ALG: CoseAlgorithms.ECDH_SS_A256KW,
                        CoseHeaderKeys.KID: private_key.kid,
                        CoseHeaderKeys.EPHEMERAL_KEY: sender_key.encode('crv', 'x', 'y'),
                        # Would be random nonce, but test constant
                        CoseHeaderKeys.PARTY_U_NONCE: binascii.unhexlify(b'e6bd83a5a06841c2ea1dd4eebaaaf252'),
                    },
                    payload=cek.k,
                ),
            ],
            # Non-encoded parameters
            external_aad=ext_aad_enc,
        )

        # Generate KEK for first recipient
        rcpt = msg_obj.recipients[0]
        ctx_v = PartyInfo(
            identity=rcpt.uhdr.get(CoseHeaderKeys.PARTY_V_IDENTITY),
            nonce=rcpt.uhdr.get(CoseHeaderKeys.PARTY_V_NONCE),
            other=rcpt.uhdr.get(CoseHeaderKeys.PARTY_V_OTHER)
        )
        ctx_u = PartyInfo(
            identity=rcpt.uhdr.get(CoseHeaderKeys.PARTY_U_IDENTITY),
            nonce=rcpt.uhdr.get(CoseHeaderKeys.PARTY_U_NONCE),
            other=rcpt.uhdr.get(CoseHeaderKeys.PARTY_U_OTHER)
        )
        ctx_s = SuppPubInfo(
            len(cek.k) * 8,
            rcpt.encode_phdr()
        )
        hkdf_context = CoseKDFContext(
            algorithm_id=msg_obj.phdr[CoseHeaderKeys.ALG],
            party_u_info=ctx_u,
            party_v_info=ctx_v,
            supp_pub_info=ctx_s
        )
        _, kek_bytes = sender_key.ecdh_key_derivation(
            alg=rcpt.uhdr[CoseHeaderKeys.ALG],
            public_key=private_key,
            context=hkdf_context
        )
        kek = SymmetricKey(k=kek_bytes)

        # COSE internal structure
        cose_struct_enc = msg_obj._enc_structure
        cose_struct_dec = cbor2.loads(cose_struct_enc)
        print('COSE Structure: {}'.format(encode_diagnostic(cose_struct_dec)))
        print('Encoded: {}'.format(encode_diagnostic(cose_struct_enc)))

        # Encoded message
        message_enc = msg_obj.encode(
            key=cek,
            nonce=msg_obj.uhdr[CoseHeaderKeys.IV],
            alg=msg_obj.phdr[CoseHeaderKeys.ALG],
            enc_params=[
                RcptParams(
                    key=kek,
                    alg=msg_obj.recipients[0].uhdr[CoseHeaderKeys.ALG],
                ),
            ],
            tagged=False
        )
        message_dec = cbor2.loads(message_enc)
        # Detach the payload
        content_ciphertext = message_dec[2]
        message_dec[2] = None
        self._print_message(message_dec, recipient_idx=3)

        # ASB structure
        asb_dec = self._get_asb_item([
            msg_obj.cbor_tag,
            message_dec
        ])
        asb_enc = cbor2.dumps(asb_dec)
        print('ASB: {}'.format(encode_diagnostic(asb_dec)))
        print('Encoded: {}'.format(encode_diagnostic(asb_enc)))

        bpsec_dec = self._get_bpsec_item(
            block_type=99,  # FIXME: not real
            asb_dec=asb_dec,
        )
        bpsec_enc = cbor2.dumps(bpsec_dec)
        print('BPSec block: {}'.format(encode_diagnostic(bpsec_dec)))
        print('Encoded: {}'.format(encode_diagnostic(bpsec_enc)))

        # Change from detached payload
        message_dec[2] = content_ciphertext
        decode_obj: EncMessage = EncMessage.decode(cbor2.dumps(cbor2.CBORTag(EncMessage.cbor_tag, message_dec)))
        decode_obj.external_aad = ext_aad_enc
        cek.key_ops = cosekey.KeyOps.DECRYPT
        decode_plaintext = decode_obj.decrypt(key=cek, nonce=decode_obj.uhdr[CoseHeaderKeys.IV])
        print('Loopback plaintext:', encode_diagnostic(decode_plaintext))
        self.assertEqual(content_plaintext, decode_plaintext)
        kek.key_ops = cosekey.KeyOps.UNWRAP
        decode_cek = kek.key_unwrap(decode_obj.recipients[0].payload)
        print('Loopback CEK:', encode_diagnostic(decode_cek, bstr_as='base64'))
        self.assertEqual(cek.k, decode_cek)
