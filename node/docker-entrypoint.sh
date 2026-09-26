#!/bin/sh
# Apply the schema (a no-op after the first run), create a signing key on first start, then serve.
set -eu
: "${POAW_SIGNING_KEY_FILE:=/keys/signing.key}"
export POAW_SIGNING_KEY_FILE
if [ ! -f "$POAW_SIGNING_KEY_FILE" ]; then
  poaw-node keygen "$POAW_SIGNING_KEY_FILE"
  echo "A new receipt-signing key was created at $POAW_SIGNING_KEY_FILE. BACK IT UP: receipts are checked against it." >&2
fi
poaw-node init-db
exec poaw-node serve --host 0.0.0.0 --port 8080
