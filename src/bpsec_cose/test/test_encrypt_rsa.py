import cbor2
from pycose import headers, algorithms
from pycose.keys import SymmetricKey, RSAKey, keyops, keyparam
from pycose.messages import EncMessage
from pycose.messages.recipient import KeyWrap
from ..util import dump_cborseq, encode_diagnostic
from ..bpsec import BlockType
from .base import BaseTest


class TestExample(BaseTest):

    def test(self):
        print('\nTest: ' + __name__ + '.' + type(self).__name__)
        # 3072-bit key
        # private_key = RSAKey.generate_key(3072)
        private_key = RSAKey(
            n=bytes.fromhex('c257bd2257000620d6c12e7fb988b891c0fa0f8eab597e2c56f0ae49da3f24eb9b99f9cc147820bd7f3feffc41cd63aa7a805a454c73d60cee478ac8e6be050943a134565c5b84aa619ba674f901314e2007bab3740c3b581720bc89d50c81726722d5c6bbb9966285dd66d4524561aadd0d6e8d7d970530a6c30af202e55e4e44505ce08ebe5217d2825edfa76397226ef58517abcc2e73873386ef9a0d14306466f2ed2c61ce6eaca12a026b62db054379e9f6575e802355f53ce3efd44d58dd9f2ba7385130815eed0e4649547fc38ff469a4f098d22214a6adf72c3f6a3b3ee3545835eaa9a9ab6467b17a62acb3179f31dc534539ffd21981fe5e5ea088ff4f1cdf051d8d97704101e81d8030e2e4863c1571452f94a9f47ec7339536058c287c376b0a6b5c6226fdefd716b4438a9f987d50de25a73537d42a54d9d042f8d623f493d1fe0fdea8cd750381796cc9af7fdbac6eb7c8b4aa2e3f227d0fbbfbece7fd707e0f739b23a63b5a5118f553e834facda493e276ec9663ba65bf2b'),
            e=bytes.fromhex('010001'),
            d=bytes.fromhex('132665ced99cce7dc8e643488c5b37b8b662784afa2bce33874e486ba2e9004b2e762c8d0562aaf33bf3ec6d6d2729d02ad45ffb73ce4c442797541fcf7634f52b3d5a1f67bd658eb6773473fd4a0bf638a61a546ee07a5932a4e3ff299d05afba104ed964e12390f4c392cb8edf2301c7ae22fbd294218ba03b183bd8638aa33d61b52d3428f684e8c0e0f6ba934fd95c440432876d63670de65ac05c6be2813c3b8014dfd53416bd7054bd3aa0af42a45a01df12253a8cd62908057be498746275851712623580de4cea4cefb2fbd154874bf13894d2a09ea9f18a9d6fcf66e8fefbf4029ce635ac1b60b444bab134ec67e397172a1dc79018ccc5713edaa21917cb34486a2a81c9e45ee21eb9bf465e7f42b4dfe17f17505b07d52bcf5233f215d96479201858e238b2672c2de6c589107f2877479a39728360a718400b3de94759f4e50049e279677481dd9151f82be9fef8289e297123e0ef08479010c4cc98096788857009fa41f867055603491dea29e74d30925b42cceb004e7a371d'),
            p=bytes.fromhex('e49562b275ab259750b010ade9720f0c1e07c42e73d969b9c28df2bb6a72a162c24101a9a97091a935ce5202015e9540971734ceb0f4014fecbaf7f0c4a6eeb6d82b46a69b4e5ed9a1099035e6dbfa3686985f8ae9c6a2f1afd2c1a5b60d16f4b1d22741bcfb12c103c11a3a68700c93e010906192289774f86400bbd513fad642b32fb7b9ddb05d5c48ce9bbcae48239ce41f7630f6ec6ccf9dbeffc84edc2944f749b16f445b829a7bc5dce644a377fa88035e0756aeca77c71dcb8f87514f'),
            q=bytes.fromhex('d9a6fee7a8e74201b5afe5188b0498fe4f902b7a4fd18fe64c1d6344188bb4ac26ccf3ff66f244ab2bb2d87fc94ac9e3e13482799f12585df2b6d556233c818853071912bc56c2b4c81ef9674e552af7bf8907f9ff9d318dcf7bc04eb0864a6c618468e3005721c1b9de436f81e9f9ae5d54228eba78af72760997e91d6f9481a43a5557fce42acf08868b460cfca2f3cdee7f47205f24343bceebb011e4aa80f94cc3a65f04dd5810e783d509f2346488338ec9012a046ad92ea9a10589e565'),
            dp=bytes.fromhex('a8b520fd3a1fb144f7069ba8e02d90b18ed08899086424c637b3f0bd2699a8476dbbf0f039e09d8157f7094bf59acb69ba9a241d9138e66709000dd3243158ea96ad8a1d996ec44eb7ae89435f3a687829eaf8495cb580ba04dcf693c9c3eb777a6ef30e6fde973ee1f879d53613cd14af414a6ed9232075f2864c8c557dc39ab3ebf08217aa696ade9bd5f1d7d681e3d6fdffc289ed151e5235c92c9bb8a881c52706baf0b6711bf9ccf4824f69c584dde1d92a631c3531b629bdf1e9e323bd'),
            dq=bytes.fromhex('a0fa7a9e2cb69e835535fb63e3ae4ada0d4ebc59829fa4a6d8b503ae61d932900142a554c977768283978bb937d030f272a6bbb9e88551066b75fee3eebbd9b25276757cfdffcd9298511075efe1de1dcf74328a1d1cce81ec6bc318704762d4366c108794c0dd1ec3b2387e48c01d0371d3c09b801fb2e41d998ad9c803b6fb0bd4793ad2b88f51012541ed55bda5685d6f8083c2d59b996682ec9f151ce35ef1046dd0a786998f81313ab85edadd155e07841bf6d874dbf23629100760ae61'),
            qinv=bytes.fromhex('598da6c558bf08c201b845b2dab3ff00a2ee74ce064d86f18af2f8b721205224526b7d8b9c42f6bc7f34a8c8623dcfc28ff800e28f23cd301814857a728b282a121ee6d47d031eef5c14d84d6aadfd2bdf3ef9d10dce7dda11ba466f125d67772b945b79baa5092f86f98dcfd1d8fc946fd24851bc3e49033c29d6509a73d64326d3981b165be7bb2fa15d2696200c786fe1098449ded9207af0391caabf617da3fd8c777e1ad755bd24855dc6d84933987543f12fba160c3c71de8bff439468'),
            optional_params={
                keyparam.KpKid: b'ExampleRSA',
                keyparam.KpAlg: algorithms.RsaesOaepSha512,
                keyparam.KpKeyOps: [keyops.WrapOp, keyops.UnwrapOp],
            }
        )
        print('Private Key: {}'.format(encode_diagnostic(cbor2.loads(private_key.encode()))))
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
                KeyWrap(
                    uhdr={
                        headers.Algorithm: private_key.alg,
                        headers.KID: private_key.kid,
                    },
                    payload=cek.k,
                ),
            ],
            # Non-encoded parameters
            external_aad=ext_aad_enc,
        )
        msg_obj.recipients[0].key = private_key

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
        recip.key = private_key
        decode_plaintext = decode_obj.decrypt(recipient=recip)
        print('Loopback plaintext:', encode_diagnostic(decode_plaintext))
        self.assertEqual(content_plaintext, decode_plaintext)

        print('Loopback CEK:', encode_diagnostic(cbor2.loads(decode_obj.key.encode())))
        self.assertEqual(cek.k, decode_obj.key.k)

        target_dec[4] = content_ciphertext
        target_enc = cbor2.dumps(target_dec)
        bundle = self._assemble_bundle([prim_enc, bpsec_enc, target_enc])
        self._print_bundle(bundle)
