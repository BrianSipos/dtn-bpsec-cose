''' Conversion and output utilites.
'''
import binascii
import enum
import six
import cbor2


def encode_protected(hdr):
    ''' Perform protected header encoding of RFC8152 Section 3.
    '''
    if not hdr:
        return b''
    return cbor2.dumps(hdr)


def decode_protected(hdr):
    ''' Perform protected header decoding of RFC8152 Section 3.
    '''
    if not hdr:
        return {}
    return cbor2.loads(hdr)


def encode_diagnostic(obj, **kwargs):
    ''' Encode a Python object as a CBOR Extended Diagnostic Notation string.
    
    Special options:
      bstr_as: either 'hex' (default) or 'base64'
    '''
    if isinstance(obj, list):
        parts = (encode_diagnostic(item, **kwargs) for item in obj)
        return '[ {} ]'.format(', '.join(parts))
    if isinstance(obj, dict):
        parts = (
            '{}:{}'.format(encode_diagnostic(key, **kwargs), encode_diagnostic(val, **kwargs))
            for (key, val) in obj.items()
        )
        return '{{ {} }}'.format(', '.join(parts))
    if isinstance(obj, six.binary_type):
        bstr_as = kwargs.get('bstr_as', 'hex')
        if bstr_as == 'hex':
            return "h'{}'".format(binascii.hexlify(obj).decode('utf8'))
        elif bstr_as == 'base64':
            return "b64'{}'".format(binascii.b2a_base64(obj, newline=False).decode('utf8'))
        else:
            raise ValueError('Invalid bstr_as parameter')
    if isinstance(obj, six.text_type):
        return '"{}"'.format(obj)
    if isinstance(obj, six.integer_types + (enum.Enum,)):
        return str(int(obj))
    if isinstance(obj, bool):
        return 'true' if obj else 'false'
    if obj is None:
        return 'null'
    print('Unencodable value', obj)
