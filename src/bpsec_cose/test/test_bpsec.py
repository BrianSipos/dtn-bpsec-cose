import cbor2
import unittest
from bpsec_cose.bpsec import EndpointId, SecurityBlockData
from bpsec_cose.util import encode_diagnostic
from .base import BaseTest


class TestEndpointId(unittest.TestCase):

    def test_encode_dtn(self):
        eid = EndpointId('dtn://example/that')
        expect_item = [1, '//example/that']
        self.assertEqual(expect_item, eid.encode_item())

    def test_encode_dtn_none(self):
        eid = EndpointId('dtn:none')
        expect_item = [1, 0]
        self.assertEqual(expect_item, eid.encode_item())

    def test_encode_ipn(self):
        eid = EndpointId('ipn:974848.12.34')
        expect_item = [2, [974848, 12, 34]]
        self.assertEqual(expect_item, eid.encode_item())


class TestSecurityBlock(unittest.TestCase):

    def test_encode_some(self):
        asb = SecurityBlockData(
            context_id=123,
            targets=[1],
            security_source=EndpointId('dtn://node/').encode_item(),
            parameters=[
                (1, 2),
            ],
            results=[
                [
                    (3, 4),
                ],
            ],
        )
        expect_item = [
            [1],
            123,
            SecurityBlockData.Flags.HAS_PARAMS,  # flags
            [1, '//node/'],
            [  # parameters
                (1, 2),
            ],
            [  # results
                [
                    (3, 4),
                ],
            ],
        ]
        self.assertEqual(expect_item, asb.encode_item())


class TestInputs(BaseTest):
    def test_original_bundle(self):

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

        bundle = self._assemble_bundle([prim_enc, target_enc])
        self._print_bundle(bundle)
