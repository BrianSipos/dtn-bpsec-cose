#!/bin/bash
# Check the PKI structure and consistency using OpenSSL commands

SELFDIR=$(realpath $(dirname "${BASH_SOURCE[0]}"))
ALL_EE_CERTS=$(ls -1 ${SELFDIR}/data/nodes/*/ssl/certs/*.pem)

# CA data
openssl ec -in ${SELFDIR}/data/ca/key.pem
openssl x509 -text -in ${SELFDIR}/data/ca/cert.pem

# EE data
for CERTFILE in ${ALL_EE_CERTS}
do
    echo "${CERTFILE} contains:"
    echo
    openssl x509 -text -in ${CERTFILE}
    echo
done

# self-consistency
openssl verify \
    -attime $(date -d '2025-10-07T00:00:00Z' +'%s') \
    -x509_strict -show_chain \
    -CAfile ${SELFDIR}/data/ca/cert.pem \
    ${ALL_EE_CERTS}
