#!/bin/bash

# Compiles and runs test_tls_openssl, the fd_tls / fd_tlsrec / fd_x509
# interop test against the system OpenSSL.
#
# Expects OBJDIR to be set (as by run_script_tests.sh).

set -x

OBJDIR=${OBJDIR:?}

if ! pkg-config --atleast-version=3.0 libssl 2>/dev/null; then
  echo "skipped: no OpenSSL >=3.0 (libssl pkg-config)"
  exit 0
fi

# Compile and link with exactly the flags the libs were built with, taken
# from the build's flavor stamps.  The struct layouts in the fd headers
# depend on the FD_HAS_* feature macros, and sanitizer builds (asan,
# ubsan) need the matching -fsanitize runtime at link time.
#
#   .flags:   MACHINE | EXTRAS | CC_ID CC CC_VERSION | CPPFLAGS | CFLAGS
#   .ldflags: LD_ID LD | LDFLAGS | LDFLAGS_EXE | LDFLAGS_SO | LDFLAGS_FUZZ
CC=$(      awk -F'|' '{ print $3 }' "$OBJDIR/.flags"   | awk '{ print $2 }')
CPPFLAGS=$(awk -F'|' '{ print $4 }' "$OBJDIR/.flags"  )
CFLAGS=$(  awk -F'|' '{ print $5 }' "$OBJDIR/.flags"  )
LDFLAGS=$( awk -F'|' '{ print $2 }' "$OBJDIR/.ldflags")
LDFLAGS_EXE=$(awk -F'|' '{ print $3 }' "$OBJDIR/.ldflags")
CC=${CC:-gcc}

OUT=$OBJDIR/unit-test/test_tls_openssl
mkdir -p "$(dirname "$OUT")"

# eval: the stamps hold shell-quoted flags (e.g. -DFD_BUILD_INFO=\"...\")
eval "$CC $CPPFLAGS $CFLAGS \
  -o '$OUT' src/waltz/tlsrec/test_tls_openssl.c \
  -L'$OBJDIR/lib' -lfd_waltz -lfd_tls -lfd_ballet -lfd_util \
  $LDFLAGS $LDFLAGS_EXE -lssl -lcrypto" \
  || { echo "FAIL (compile)"; exit 1; }

exec "$OUT"
