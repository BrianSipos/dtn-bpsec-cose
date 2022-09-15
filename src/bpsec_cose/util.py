''' Conversion and output utilites.
'''
import binascii
import copy
import enum
import six
import cbor2


def dump_cborseq(items):
    ''' Concatenate a cborseq of encoded items '''
    return b''.join(map(cbor2.dumps, items))

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
      indent: if provided, indent this many spaces
      bstr_as: either 'hex' (default) or 'base64'
    '''
    indent = kwargs.get('indent')
    wsp_indent = ' ' * indent if indent is not None else ''

    if isinstance(obj, list):
        nextkw = copy.copy(kwargs)
        if indent is not None:
            nextkw['indent'] += 2
        parts = (encode_diagnostic(item, **nextkw) for item in obj)
        wsp_sep = '\n' if indent is not None else ' '
        mid = f',{wsp_sep}'.join(parts)
        text = f'[{wsp_sep}{mid}{wsp_sep}{wsp_indent}]'
    elif isinstance(obj, dict):
        nextkw = copy.copy(kwargs)
        if indent is not None:
            nextkw['indent'] += 2
        def encode_pair(key, val):
            enc_key = encode_diagnostic(key, **nextkw)
            enc_val = encode_diagnostic(val, **nextkw)
            if indent is not None:
                enc_val = enc_val[indent+2:]
            return f'{enc_key}:{enc_val}'
        parts = (encode_pair(*pair) for pair in obj.items())
        wsp_sep = '\n' if indent is not None else ' '
        mid = f',{wsp_sep}'.join(parts)
        text = f'{{{wsp_sep}{mid}{wsp_sep}{wsp_indent}}}'
    elif isinstance(obj, six.binary_type):
        bstr_as = kwargs.get('bstr_as', 'hex')
        if bstr_as == 'hex':
            text = "h'{}'".format(binascii.hexlify(obj).decode('utf8'))
        elif bstr_as == 'base64':
            text = "b64'{}'".format(binascii.b2a_base64(obj, newline=False).decode('utf8'))
        else:
            raise ValueError('Invalid bstr_as parameter')
    elif isinstance(obj, six.text_type):
        text = '"{}"'.format(obj)
    elif isinstance(obj, six.integer_types + (enum.Enum,)):
        text = str(int(obj))
    elif isinstance(obj, bool):
        text = 'true' if obj else 'false'
    elif obj is None:
        text = 'null'
    else:
        print('Unencodable value ({}): {}'.format(type(obj), repr(obj)))
        text = None
    # prepend unconditionally
    if text and wsp_indent:
        text = wsp_indent + text
    return text
