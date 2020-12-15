''' BPSec Abstract Security Block (ASB) structure and logic.
'''
from dataclasses import dataclass, field
import enum
import re
from typing import List, Union, Dict, Optional, Any
import urllib.parse
import cbor2
from .bp import EndpointId


@dataclass
class KeyValPair():
    key: int
    val: Any


@dataclass
class SecurityBlockData():
    ''' The abstract security block type-specific-data.
    '''

    @enum.unique
    class Flags(enum.IntFlag):
        ''' Flags derived from presence of optional data.
        '''
        NONE = 0x00
        HAS_PARAMS = 0x01
        HAS_SOURCE = 0x02

    targets: List[int] = field(default_factory=list)
    context_id: int = None
    security_source: Optional[EndpointId] = None
    parameters: Optional[List[KeyValPair]] = None
    results: List[List[KeyValPair]] = field(default_factory=list)

    def encode_item(self):
        flags = SecurityBlockData.Flags.NONE
        if self.security_source:
            flags |= SecurityBlockData.Flags.HAS_SOURCE
        if self.parameters:
            flags |= SecurityBlockData.Flags.HAS_PARAMS

        item = [
            self.targets,
            self.context_id,
            flags,
        ]
        if self.security_source:
            item.append(self.security_source)
        if self.parameters:
            item.append(self.parameters)
        item.append(self.results)
        return item
