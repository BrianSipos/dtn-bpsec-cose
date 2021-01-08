#!/bin/bash
# Read stdin and verify it as valid CDDL.
set -e
SELFDIR=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))

OUTFILE=$1
shift
echo "ARGS $@"

rm "${OUTFILE}"

echo "; From stdin:" >${OUTFILE}
cat /dev/stdin >>${OUTFILE}
echo >>${OUTFILE}

for FILEPATH in "$@"; do
    grep "From" ${FILEPATH}
    echo "Adding ${FILEPATH}"

    echo "; From ${FILEPATH}:" >>${OUTFILE}
    cat "${FILEPATH}" >>${OUTFILE}
    echo >>${OUTFILE}
done
