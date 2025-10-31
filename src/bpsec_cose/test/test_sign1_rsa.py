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
        # private_key = RSAKey.generate_key(3072)
        private_key = RSAKey(
            n=bytes.fromhex('f47b7c275eff5bf74e9e69d2b50e9a5dc0666147ca2541fce9a253d00840e2481378733797a9db641911937aff7cbc579f16484cea2cd3fbe2db3bbb26b18e2b95b49b9255f378ee62f806227dd0ddeb48456358bfe1cadd861645e89208c5a5b1da34af0e3f0ad1f82633fb6b21b7ef901bffebf1144ed0d4cfcb51e21b820cfa6c829ca95cd08f3eb779b31569bb5e64c67f9976df92284ecea085a9a25882707a9ba2af769017983e58b48afde78149453ebdcf1bcad76c30c253deaacc21a4a91bce2b896776c1c5cfe0aaaae714c0b7e2063542ea81ec27af2746fd402e02e71040e41aa23c79179e20a93c921fb26d13e11f802c2836506d0f0be507997aa07454f8b74a807c9342c8697d670fe6b1c2574a18013296cca897c4ddb96215fd30a4c4ee5db5b4844c9d1e7bd6923ab0feaa30fe79d821fb63ed391b175837d53db1b207bc984b9a377c7b4fb58738cca4254c3273440830cee84552304e8aaed0c0187b59339b28f213076af2c77aa46fe37bef31910ada5e44643ac7b1'),
            e=bytes.fromhex('010001'),
            d=bytes.fromhex('5a4dfac0d33317ff5b1879ab793db7455f2ce0e596fd5ff1e90115a08087b18c413a15d4a007e41d8a71eaa81490a926bd4289d072e6b8102ba250731c02b238b95cc4f1d2d1ece45cb41c66a22bafcd0da48726daf2a20c159136e7d527944f46d73ee084184682e4ca0a287d26e92535c532a4790e8bb6589f0bce2f6f693d900db994f9fb92a95f01ed077cb667f938ab73f9cc27715bcc357fb4acb20630ad2c40893b0a6a9be0ab50b7d4bfbd088e85919e61f325a33b0fc2e709c879c33ab7675a395f45c8e5f08c1a7e1871f6bc12eef424566896eca111e42060ea64ea5ea11f693f6923525829a0e394434eb0ec1a5586677bcab8a7b8d961b6134236f027d3dd2c0fee03e46f534d782d73bf4b1b906dae037c4fc6982082b5c1946418780e3a2a14ba5717ddb98df721e42da8b419a7febc06c3948cd0612e2b3d861077d5622af774d6af4f19f1d38658174eded20954d45d4c1db848ea3c8805aaf338615ae9e40e3990352c0dfe84563b67d2e72638806807e8b56edb41'),
            p=bytes.fromhex('fd804ae7f7499d69cd3d1299879e9645b90e829e92c88d759bf2b3d4ed391b592407c2f1f26dd0f345bbe448b21a2248450652aebaa65a6815919dba29d66ea2c1d862cab37391190c5e1fb162d7101412588d913fecd0e675785522661aecbbc50e2678e60485080b472e5f5720854a21eb456e1c26de4102d99cc2e08afa13d2aa3e7f94d91e2fb43ab400c5e3061c69fcfcf78c7a81cdcc672d0f5630eb08ac9086a8c957d4f8c9c71dd75a78efe1e1d764d34d7043f0aac9a0d0beaf8921'),
            q=bytes.fromhex('f6e46eff1e17493b92e379a6ae2594970d6ab3ff43bb84fda7810b5feb89d94008fbf8de9ce8584aa95ad759261ce78fd421c26f5c1eaf482792e6fc25eeac320a2195db28ab9071182ca4d4d041cfea6d754940248527352337e87e7b4414d59b916808e977d97676cf97ee04b7f95aa3611f1fb98b7a341563ca42e9af810b67ecd8989deb96ddde66004efdda610c77cd75b9337b5e1993c6d2b3212c64461d61334193bad6ebb62ae67325e1157a394c8c7422a3d65ecd0212114d7e9c91'),
            dp=bytes.fromhex('ec2626217f38c17e3d26267c855d1389f2017566b940409f0dde82edd8eb38f1ca61bc95dd0bb5f9d9bd55c4eebcefb0b93451b3d9c67c33b7dc05bdd5999f48d92175ae748b34e0cba7a7087d15f1317181b2a75b90856e1a823574acff6a06e563f02cf1c1c6179f41f90df1c126c9cf5d373982da2673136f9adbe38733bd61a31c43876ad6f70383280a0c4e177442bbdcffd28a90ff20ea008ce7f2fc100189451859300c02931d7d4c0f48d7d669a758928af209285a4128212d71a261'),
            dq=bytes.fromhex('a0d29842f294f48d2bd7a56c9fcfb704d626856d67ef8467be6edebbf2afeea639b3f89ef9d29780bae483967caf235f9b2d0a7c83a331466d10d209b9a3c8e3279a4d055f6eb23e19232b93bcbcc1f4d0ac2fb4ea9519bf115bdfc454033b1711a91bfd822721ae7b222ab34ebb90602c409d878ad3821cdf3a0b8c9eb045fcea0b6be3ae2ac23170273d58371fc34bddd626332787dafa0a3adf10f430f8787bb6cf2e8e4e8ca52a1ab3d699fc0e83794395d228a6548398431b05ce570521'),
            qinv=bytes.fromhex('1f1b16da1f590fc9e6b174122d8c78554adee8627c31068abccf56f8a73c04fd677567d9fe246b1ff972c9b74e238bf4e04b9cef7e0ba76befea43a0e114a0aff45b2cbeff649614281017c1f00be91ba2562453a0a5ee25f6518fcf07dddf2da2c645bc337a51b8108dba1aab223893c7fcbabdb5b9c88b618e858eda994b7c04b1bffe2612f743e857707dccea4f7a93d711f818a8e6420890c2e73eb7f4fcc3c55c7d83b4d2bbd9bcea0c0668570e9ca7e92e5ca626754180da12a6b85a85'),
            optional_params={
                keyparam.KpKid: b'ExampleRSA',
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
