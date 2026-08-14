#!/bin/bash

# Checks that the GDB scripts embedded by fd_gdb_scripts.S print
# fd_hash_t / fd_pubkey_t / fd_signature_t as base58.

set -u

#shellcheck disable=SC2128
BIN=$(dirname -- "$BASH_SOURCE")/test_gdb_base58

command -v gdb > /dev/null || { echo "SKIP: gdb not installed"; exit 0; }
gdb --batch -nx -ex "python print( 'ok' )" 2>/dev/null | grep -q ok || \
  { echo "SKIP: gdb has no Python support"; exit 0; }

expected=$(cat <<'EOF'
$1 = TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
$2 = 1113ev7KArKmSeNWXoiX44de25oM4BcoUZHC9RfTKL
$3 = 11111111111111111111111111111111
$4 = 66hqP5QbfXgdkSGN7KwA7f7LmgJkwHmuw3awmwMLQ4aWL63AZ8kTidNvLHtJqbeBDfWuRJL9Wn6MmQqH4tBjdS4F
TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
66hqP5QbfXgdkSGN7KwA7f7LmgJkwHmuw3awmwMLQ4aWL63AZ8kTidNvLHtJqbeBDfWuRJL9Wn6MmQqH4tBjdS4F
4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw
EOF
)

actual=$(gdb --batch -nx -iex "set auto-load safe-path /" \
  -ex "p test_pubkey" -ex "p test_hash" -ex "p test_zero" -ex "p test_sig" \
  -ex "b58 &test_pubkey" -ex "b58 test_sig.uc 64" -ex "b58 test_sig.uc + 1" \
  "$BIN" 2>&1)

if [[ "$actual" != "$expected" ]]; then
  diff <( echo "$expected" ) <( echo "$actual" )
  echo FAIL
  exit 1
fi

echo pass
