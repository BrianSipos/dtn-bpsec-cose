#!/usr/bin/env python3
''' An example PKI generator.
'''

import argparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import asn1
import datetime
import logging
import os
import sys
from typing import Union, Optional

LOGGER = logging.getLogger()
SELFDIR = os.path.dirname(os.path.abspath(__file__))

CERT_FORMS = [
    ('.pem', serialization.Encoding.PEM),
    # ('.der', serialization.Encoding.DER),
]


class PkiCa:
    ''' A local software PKI CA generator. '''

    def __init__(self):
        # same as test config
        self._nowtime = datetime.datetime(2025, 10, 6, 0, 0, 0)
        self._ca_key = None
        self._ca_cert = None

    def other_name_eid(self, eid: str) -> x509.OtherName:
        ''' Encode a text EID as an Other Name object.
        '''
        eid_enc = asn1.Encoder()
        eid_enc.start()
        eid_enc.write(eid.encode('ascii'), asn1.Numbers.IA5String)
        return x509.OtherName(
            x509.oid.ObjectIdentifier('1.3.6.1.5.5.7.8.11'),  # id-on-bundleEID
            eid_enc.output()
        )

    def generate_key(self, key_opts: dict) -> Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]:
        keytype = key_opts.get('keytype', 'SECP256R1').upper()
        if keytype == 'RSA':
            key_size = 2048
            node_key = rsa.generate_private_key(65537, key_size, backend=default_backend())
        elif keytype.startswith('SECP'):
            curve = getattr(ec, keytype)
            node_key = ec.generate_private_key(curve, backend=default_backend())  # Curve for COSE ES256
        else:
            raise ValueError(f'Unknown keytype: {keytype}')
        return node_key

    def generate_root_ca(self, certbase: str, keybase: str, serial: int) -> x509.Certificate:
        ''' Generate and retain a root CA. '''
        keyfile = keybase + '.pem'
        if os.path.exists(keyfile):
            with open(keyfile, 'rb') as infile:
                ca_key = serialization.load_pem_private_key(infile.read(), password=None)
            LOGGER.info('Loaded CA key from %s', keyfile)
        else:
            LOGGER.info('Generated CA key')
            ca_key = self.generate_key({})

        ca_name = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Certificate Authority'),
        ])
        ca_cert = x509.CertificateBuilder().subject_name(
            ca_name
        ).issuer_name(
            ca_name
        ).public_key(
            ca_key.public_key()
        ).serial_number(
            serial
        ).not_valid_before(
            self._nowtime
        ).not_valid_after(
            self._nowtime + datetime.timedelta(days=10)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            # This is mandated by some browser interpretations of chain validation
            x509.ExtendedKeyUsage([
                x509.oid.ObjectIdentifier('1.3.6.1.5.5.7.3.35')  # id-kp-bundleSecurity
            ]),
            critical=False,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        ).sign(ca_key, hashes.SHA256(), backend=default_backend())

        os.makedirs(os.path.dirname(keyfile), exist_ok=True)
        with open(keyfile, 'wb') as outfile:
            outfile.write(ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        for ext, enc in CERT_FORMS:
            certfile = certbase + ext
            os.makedirs(os.path.dirname(certfile), exist_ok=True)
            with open(certfile, 'wb') as outfile:
                outfile.write(ca_cert.public_bytes(enc))

        self._ca_key = ca_key
        self._ca_cert = ca_cert

    def generate_end_entity(self, cafile: Optional[str], certbase: str, keybase: str, mode: str, serial: int, node_name: str, node_id: str, fqdn: Optional[str] = None) -> x509.Certificate:
        '''
        :param mode: Either 'sign' or 'encrypt' or 'transport'.
        :param serial: The certificate serial number.
        :param node_name: The common name for the certificate.
        :param node_id: The Node ID for the entity as a URI string.
        :param fqdn: For transport mode, the FQDN of the node.
        '''

        sans = [
            self.other_name_eid(node_id)
        ]
        key_usage = dict(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        ekus = [
            x509.oid.ObjectIdentifier('1.3.6.1.5.5.7.3.35')  # id-kp-bundleSecurity
        ]

        keyfile = keybase + '.pem'
        if os.path.exists(keyfile):
            with open(keyfile, 'rb') as infile:
                node_key = serialization.load_pem_private_key(infile.read(), password=None)
            LOGGER.info('Loaded node %s key from %s', node_name, keyfile)
        else:
            LOGGER.info('Generated node %s key', node_name)
            node_key = self.generate_key({})

        if mode == 'transport':
            sans += [
                x509.DNSName(fqdn),
            ]
            key_usage['digital_signature'] = True
            ekus += [
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]
        elif mode == 'sign':
            key_usage['digital_signature'] = True
        elif mode == 'encrypt':
            key_usage['key_agreement'] = True

        node_cert = x509.CertificateBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, node_name),
            ]),
        ).issuer_name(
            self._ca_cert.subject
        ).public_key(
            node_key.public_key()
        ).serial_number(
            serial,
        ).not_valid_before(
            self._nowtime
        ).not_valid_after(
            self._nowtime + datetime.timedelta(days=10)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.SubjectAlternativeName(sans),
            critical=False,
        ).add_extension(
            x509.KeyUsage(**key_usage),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage(ekus),
            critical=False,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(node_key.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(self._ca_key.public_key()),
            critical=False,
        ).sign(self._ca_key, hashes.SHA256(), backend=default_backend())

        os.makedirs(os.path.dirname(keyfile), exist_ok=True)
        with open(keyfile, 'wb') as outfile:
            outfile.write(node_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        for ext, enc in CERT_FORMS:
            certfile = certbase + ext
            os.makedirs(os.path.dirname(certfile), exist_ok=True)
            with open(certfile, 'wb') as outfile:
                outfile.write(node_cert.public_bytes(enc))

        if cafile:
            os.makedirs(os.path.dirname(cafile), exist_ok=True)
            with open(cafile, 'wb') as outfile:
                outfile.write(self._ca_cert.public_bytes(serialization.Encoding.PEM))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', dest='log_level',
                        metavar='LEVEL',
                        default='INFO',
                        help='Console logging lowest severity.')
    parser.add_argument('--out-dir', default=os.path.join(SELFDIR, 'data'),
                        help='The staging file path')
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level.upper())
    LOGGER.debug('args %s', args)

    pca = PkiCa()

    cadir = os.path.join(args.out_dir, 'ca')
    pca.generate_root_ca(
        certbase=os.path.join(cadir, 'cert'),
        keybase=os.path.join(cadir, 'key'),
        serial=int.from_bytes(bytes.fromhex('1515ffa740a4bd73f5ba'), 'big')
    )

    nodes = {
        'src': {
            'node_id': 'dtn://src/',
            'modes': {'sign'},
            'serial': int.from_bytes(bytes.fromhex('6ffe89dcb76ed372ea7a'), 'big')
        },
        'dst': {
            'node_id': 'dtn://dst/',
            'modes': {'encrypt'},
            'serial': int.from_bytes(bytes.fromhex('3f240bcda6f7fc3c29de'), 'big')
        },
    }

    for node_name, node_opts in nodes.items():
        node_id = node_opts['node_id']
        modes = node_opts['modes']
        serial = node_opts['serial']

        # Ubuntu common path mounted to /etc/ssl/
        nodedir = os.path.join(args.out_dir, 'nodes', node_name, 'ssl')

        for mode in modes:
            pca.generate_end_entity(
                cafile=None,
                certbase=os.path.join(nodedir, 'certs', f'node-{mode}'),
                keybase=os.path.join(nodedir, 'private', f'node-{mode}'),
                mode=mode,
                serial=serial,
                node_name=node_name,
                node_id=node_id
            )


if __name__ == '__main__':
    sys.exit(main())
