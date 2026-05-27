''' Common test behavior.
'''
import unittest
import cbor2
import crcmod.predefined
import datetime
import logging
import textwrap
from typing import List, Optional
from bpsec_cose.bp import EndpointId
from bpsec_cose.bpsec import SecurityBlockData, KeyValPair
from bpsec_cose.util import dump_cborseq, cbor2diag

DTN_EPOCH = datetime.datetime(2000, 1, 1, 0, 0, 0)

DEFAULT_CRC_TYPE = 2


class BaseTest(unittest.TestCase):

    _SECSRC_EID = EndpointId('dtn://src/')
    ''' ASB security source field '''
    _ADDL_PROTECTED: bytes = b''
    ''' ASB additional protected parameter (encoded) '''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._logger = logging.getLogger(self.__class__.__name__)

    def _replace_crc(self, dec: list, crc_type: int) -> Optional[bytes]:
        ''' Replace the last item of a decoded array with its CRC-32C value.
        '''
        if crc_type == 0:
            return None
        elif crc_type == 2:
            crc_obj = crcmod.predefined.PredefinedCrc('crc-32c')
        else:
            raise ValueError(f'invalid CRC type {crc_type}')
        crc_size = crc_obj.digest_size

        old = bytes(dec[-1])
        dec[-1] = crc_size * b'\x00'

        enc = cbor2.dumps(dec)
        crc_obj.update(enc)

        dec[-1] = crc_obj.digest()

        return old

    def _get_primary_item(self) -> list:
        # arbitrary nonzero time
        delta = datetime.datetime(2025, 10, 7, 0, 0, 0) - DTN_EPOCH
        crc_type = DEFAULT_CRC_TYPE
        dec = [
            7,  # version
            0,  # flags
            crc_type,  # CRC type
            EndpointId('dtn://dst/svc').encode_item(),
            EndpointId('dtn://src/svc').encode_item(),
            self._SECSRC_EID.encode_item(),
            [delta // datetime.timedelta(milliseconds=1), 0],
            1000000,
            b''
        ]
        self._replace_crc(dec, crc_type)
        return dec

    def _get_target_item(self) -> list:
        crc_type = DEFAULT_CRC_TYPE
        dec = [
            1,  # type code: payload
            1,  # always #1
            0,  # flags
            crc_type,  # CRC type
            cbor2.dumps("hello"),
            b''
        ]
        self._replace_crc(dec, crc_type)
        return dec

    def _block_identity(self, item: list) -> list:
        ''' Block identity is the first three fields of canonical block array.
        '''
        return item[:3]

    def _get_kdf_pub_other(self) -> bytes:
        ''' Get bytes for COSE_KDF_Context.SuppPubInfo.other field.
        This is encoded as a CBOR sequence.
        '''
        parts = [
            "BPSec",
            self._SECSRC_EID.encode_item(),
            self._ADDL_PROTECTED,
        ]
        return dump_cborseq(parts)

    def _get_aad_scope(self) -> dict[int, int]:
        ''' Get the AAD-scope parameter value.
        '''
        return {0: 0b01, -1: 0b01}

    def _get_aad_array(self) -> list:
        ''' Get the AAD-list array.
        '''
        return [
            self._SECSRC_EID.encode_item(),
            self._get_aad_scope(),  # scope
            self._get_primary_item(),  # primary-ctx
        ] + self._block_identity(self._get_target_item()) + [  # target-ctx
            self._ADDL_PROTECTED,
        ]

    def _get_asb_item(self, result: KeyValPair) -> list:
        ''' Get the ASB CBOR-item for a CBOR-item result.

        :param result: The single result item for target block number 1.
        :return: The ASB as a CBOR item.
        '''
        return SecurityBlockData(
            targets=[1],
            context_id=3,  # COSE
            security_source=self._SECSRC_EID,
            parameters=[
                (5, self._get_aad_scope()),
            ],
            results=[
                [  # target block #1
                    result,
                ],
            ],
        ).encode_item()

    def _get_asb_enc(self, asb_dec: list) -> bytes:
        ''' Encode ASB array as a CBOR sequence.
        '''
        return dump_cborseq(asb_dec)

    def _get_bpsec_item(self, block_type: int, asb_dec: Optional[list] = None) -> list:
        return [
            block_type,
            3,
            0,
            0,
            self._get_asb_enc(asb_dec or [])
        ]

    def _assemble_bundle(self, blocks_enc: List[bytes]) -> bytes:
        return b'\x9f' + b''.join(blocks_enc) + b'\xff'

    def _print_headers(self, item: list, name: str) -> None:
        ''' Print COSE Headers from a decoded item.
        '''
        phdr_enc = item[0]
        uhdr_enc = cbor2.dumps(item[1])
        self._logger.info('%s Protected: %s', name, cbor2diag(phdr_enc))
        self._logger.info('%s Encoded: %s', name, phdr_enc.hex())
        self._logger.info('%s Unprotected: %s', name, cbor2diag(uhdr_enc))

    def _print_message(self, item: list, recipient_idx: Optional[int] = None) -> None:
        ''' Print a top-level COSE message.
        '''
        self._logger.info('Message: %s', cbor2diag(cbor2.dumps(item)))
        self._print_headers(item, 'Layer-1')
        if recipient_idx and recipient_idx in item:
            for (ix, rcpt) in enumerate(item[recipient_idx]):
                self._print_headers(rcpt, 'Layer-2 #{}'.format(ix))

    def _print_bundle(self, bundle: bytes) -> None:
        self._logger.info('Total bundle: %s', cbor2diag(bundle))
        self._logger.info('Total bundle size %d:\n%s', len(bundle), textwrap.fill(bundle.hex(), 68))
