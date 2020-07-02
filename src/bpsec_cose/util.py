''' Conversion and output utilites.
'''
import binascii
import six
import cbor2


def encode_protected(hdr):
    ''' Perform protected header encoding of RFC8152 Section 3.
    '''
    if not hdr:
        return b''
    return cbor2.dumps(hdr)


def encode_diagnostic(obj):
    ''' Encode a Python object as a CBOR Extended Diagnostic Notation string.
    '''
    if isinstance(obj, list):
        parts = (encode_diagnostic(item) for item in obj)
        return '[ {} ]'.format(', '.join(parts))
    if isinstance(obj, dict):
        parts = (
            '{}:{}'.format(encode_diagnostic(key), encode_diagnostic(val))
            for (key, val) in obj.items()
        )
        return '{{ {} }}'.format(', '.join(parts))
    if isinstance(obj, six.binary_type):
        return "h'{}'".format(binascii.hexlify(obj).decode('utf8'))
    if isinstance(obj, six.text_type):
        return '"{}"'.format(obj)
    if isinstance(obj, six.integer_types):
        return str(obj)
    if isinstance(obj, bool):
        return 'true' if obj else 'false'
    if obj is None:
        return 'null'
    print('Unencodable value', obj)
