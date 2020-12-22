#!/bin/bash
# Read stdin and verify it as valid CDDL.
set -e
SELFDIR=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))

TMPFILE=$(mktemp --tmpdir XXXXXXXX.cddl)
echo "; From stdin:" >>${TMPFILE}
cat /dev/stdin >>${TMPFILE}
echo >>${TMPFILE}

for FILEPATH in "$@"; do
    echo "; From ${FILEPATH}:" >>${TMPFILE}
    cat "${FILEPATH}" >>${TMPFILE}
    echo >>${TMPFILE}
done

cat "${TMPFILE}"
echo

cddl "${TMPFILE}" generate
