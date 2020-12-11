#!/bin/bash
# Read stdin and verify it as valid CDDL.
set -e
SELFDIR=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))

TMPFILE=$(mktemp --tmpdir XXXXXXXX.cddl)
cat /dev/stdin >>${TMPFILE}
echo >>${TMPFILE}
cat "${SELFDIR}/../bpv7.cddl" "${SELFDIR}/../bpsec.cddl" >>${TMPFILE}

cat "${TMPFILE}"
echo

cddl "${TMPFILE}" generate
