''' Bundle Protocol Version 7 structures.
'''
from dataclasses import dataclass, field
import enum
import re
from typing import Optional


@dataclass
class EndpointId():
    _re_dtn = re.compile(r'dtn:(//.+)')
    _re_ipn = re.compile(r'ipn:(\d+).(\d+)')

    @enum.unique
    class Scheme(enum.IntEnum):
        dtn = 1
        ipn = 2

    url: str

    def encode_item(self):
        match_dtn = EndpointId._re_dtn.match(self.url)
        if match_dtn is not None:
            scheme_val = EndpointId.Scheme.dtn
            ssp_item = match_dtn.group(1)
        else:
            match_ipn = EndpointId._re_ipn.match(self.url)
            if match_ipn is not None:
                scheme_val = EndpointId.Scheme.ipn
                ssp_item = [
                    int(match_ipn.group(1)),
                    int(match_ipn.group(2))
                ]
            else:
                raise ValueError('Invalid EID: {}'.format(self.url))

        return [
            int(scheme_val),
            ssp_item
        ]
