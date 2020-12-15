from bpsec_cose.bpsec import EndpointId, SecurityBlockData
import unittest


class TestEndpointId(unittest.TestCase):

    def test_encode_dtn(self):
        eid = EndpointId('dtn://this/that')
        expect_item = [1, '//this/that']
        self.assertEqual(expect_item, eid.encode_item())

    def test_encode_ipn(self):
        eid = EndpointId('ipn:12.34')
        expect_item = [2, [12, 34]]
        self.assertEqual(expect_item, eid.encode_item())


class TestSecurityBlock(unittest.TestCase):

    def test_encode_empty(self):
        asb = SecurityBlockData()
        expect_item = [
            [],
            None,
            SecurityBlockData.Flags.NONE,  # flags
            [],
        ]
        self.assertEqual(expect_item, asb.encode_item())

    def test_encode_some(self):
        asb = SecurityBlockData(
            context_id=123,
            targets=[1],
            parameters=[
                [1, 2]
            ],
            results=[
                [
                    [3, 4],
                ],
            ],
        )
        expect_item = [
            [1],
            123,
            SecurityBlockData.Flags.HAS_PARAMS,  # flags
            [  # parameters
                [1, 2],
            ],
            [  # results
                [
                    [3, 4],
                ],
            ],
        ]
        self.assertEqual(expect_item, asb.encode_item())
