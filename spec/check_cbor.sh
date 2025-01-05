#!/bin/bash
# Read stdin and verify it as valid CBOR against a CDDL schema.
set -e
set -o pipefail

SELFDIR=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))

COMBINED_CDDL=$1

cat | diag2cbor.rb | cddl validate --cddl "${COMBINED_CDDL}" --stdin
