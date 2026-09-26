#!/bin/bash

# Transpiles an sBPF program to a relocatable object with fd_transpile,
# packs it into libfd_transpiled.a, links the archive into
# test_transpile_link with the system linker using the build's own
# flags, and runs it.  Checks that the object/archive writer produces
# files the toolchain accepts as-is (PIE, RELRO, -z text).
#
# Expects OBJDIR to be set (as by run_script_tests.sh).

set -x

OBJDIR=${OBJDIR:?}
PROG=${PROG:-src/ballet/sbpf/fixtures/spl_p_token.so}

#   .flags:   MACHINE | EXTRAS | CC_ID CC CC_VERSION | CPPFLAGS | CFLAGS
#   .ldflags: LD_ID LD | LDFLAGS | LDFLAGS_EXE | LDFLAGS_SO | LDFLAGS_FUZZ
CC=$(         awk -F'|' '{ print $3 }' "$OBJDIR/.flags" | awk '{ print $2 }')
CPPFLAGS=$(   awk -F'|' '{ print $4 }' "$OBJDIR/.flags"  )
CFLAGS=$(     awk -F'|' '{ print $5 }' "$OBJDIR/.flags"  )
LDFLAGS=$(    awk -F'|' '{ print $2 }' "$OBJDIR/.ldflags")
LDFLAGS_EXE=$(awk -F'|' '{ print $3 }' "$OBJDIR/.ldflags")
CC=${CC:-gcc}
# vendor archives are only part of LDFLAGS on non-lld/mold builds
VENDOR_LIBS=$(for l in fd_blst fd_zstd; do [[ -f "$OBJDIR/lib/lib$l.a" ]] && printf ' -l%s' "$l"; done)

TMP=$(mktemp -d "${TMPDIR:-/tmp}/test_transpile_link.XXXXXX") || exit 1
trap 'rm -rf "$TMP"' EXIT

# 1. sBPF -> relocatable x86 object.  fd_transpile takes the program
#    id from the input file name.

PROG_ID=TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
cp "$PROG" "$TMP/$PROG_ID.so" || exit 1
"$OBJDIR/bin/fd_transpile" --log-path "" "$TMP/$PROG_ID.so" || { echo "FAIL (transpile)"; exit 1; }
[[ -f "$TMP/fd_transpiled_$PROG_ID.o" ]] || { echo "FAIL (object missing)"; exit 1; }

# 2. Archive

"$OBJDIR/bin/fd_transpile" --log-path "" "$TMP" || { echo "FAIL (archive)"; exit 1; }
[[ -f "$TMP/libfd_transpiled.a" && -f "$TMP/fd_transpiled_export.o" ]] || { echo "FAIL (archive files missing)"; exit 1; }

# 3. Link.  The test references fd_transpiled_ext, so the archive
#    member defining it is pulled in; it goes before libfd_flamenco.a
#    so it wins over the weak empty fallback in fd_transpile_ext.o.
#    -z text rejects any text relocation the object might require.

OUT=$OBJDIR/unit-test/test_transpile_link
eval "$CC $CPPFLAGS $CFLAGS \
  -o '$OUT' src/flamenco/vm/transpile/test_transpile_link.c \
  '$TMP/libfd_transpiled.a' \
  -L'$OBJDIR/lib' -lfd_flamenco -lfd_vm -lfd_ballet -lfd_util $VENDOR_LIBS \
  $LDFLAGS $LDFLAGS_EXE -Wl,-z,text" \
  || { echo "FAIL (link)"; exit 1; }

if command -v readelf >/dev/null; then
  readelf -d "$OUT" | grep -q TEXTREL && { echo "FAIL (TEXTREL)"; exit 1; }
fi

# 4. Run

"$OUT" --prog "$PROG" --log-path "" || { echo "FAIL (run)"; exit 1; }
echo "pass"
