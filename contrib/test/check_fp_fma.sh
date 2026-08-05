#!/bin/bash

# check_fp_fma.sh verifies that consensus-critical objects contain no
# floating-point FMA instructions.
#
# Consensus code must reproduce the Agave validator's floating-point
# results bit-for-bit, and rustc never contracts a*b+c expressions
# into single-rounded FMAs.  An FMA instruction in a directory below
# means the compiler contracted an expression or somebody added an
# explicit FMA; if the use is intentional and provably matches Agave,
# add the object to ALLOW_OBJS with a comment.  See
# test_inflation_rate.c.
#
# Fails closed: any object that cannot be disassembled (missing or
# incompatible objdump, unreadable object) is a hard error, so the
# guard can never be silently skipped.
#
# Expects OBJDIR to be set (e.g. build/native/gcc).  OBJDUMP overrides
# the disassembler.

set -uo pipefail
cd "$(dirname "$0")/../.."

OBJDIR="${OBJDIR:?OBJDIR not set}"
OBJDUMP="${OBJDUMP:-objdump}"

if ! command -v "$OBJDUMP" >/dev/null 2>&1; then
  echo "FAIL: objdump ('$OBJDUMP') not found; cannot verify consensus objects"
  exit 1
fi

if [[ ! -d "$OBJDIR/obj" ]]; then
  echo "FAIL: '$OBJDIR/obj' is not a directory; nothing to verify"
  exit 1
fi

# Top-level object directories where FP FMA instructions are allowed:
# non-consensus code (apps, tiles, networking, monitoring, utils).
ALLOW_DIRS="app disco discof discoh util waltz tango wiredancer third_party"

# Specific objects in denied directories with reviewed, intentional
# FMA use.
ALLOW_OBJS=(
)

fail=0
scanned=0
for dir in "$OBJDIR"/obj/*/; do
  [[ -d "$dir" ]] || continue
  top="$(basename "$dir")"
  case " $ALLOW_DIRS " in *" $top "*) continue;; esac

  while IFS= read -r obj; do
    rel="${obj#"$OBJDIR"/obj/}"

    # Tests, benches and fuzz harnesses are dev-only: they never link
    # into the validator and may use FP freely (timing, throughput,
    # deliberate FMA demonstrations).
    case "$(basename "$obj")" in test_*|bench_*|fuzz_*) continue;; esac

    allowed=0
    for a in "${ALLOW_OBJS[@]}"; do
      if [[ "$rel" == "$a" ]]; then allowed=1; break; fi
    done
    [[ $allowed == 1 ]] && continue

    # Fail closed: objdump must exit cleanly and emit its "file
    # format" banner (printed on every successful open, even for
    # data-only objects).  Anything else means the disassembly did
    # not happen and we must not silently pass.
    disasm="$( "$OBJDUMP" -d "$obj" 2>/dev/null )"
    if [[ $? -ne 0 || "$disasm" != *"file format"* ]]; then
      echo "FAIL: could not disassemble $rel; refusing to pass unverified"
      fail=1
      continue
    fi

    scanned=$(( scanned+1 ))

    matches="$( grep -E 'vf(n?)m(add|sub)' <<<"$disasm" )"
    if [[ -n "$matches" ]]; then
      cnt="$( grep -c '' <<<"$matches" )"
      echo "FAIL: $rel contains $cnt floating-point FMA instruction(s)"
      head -4 <<<"$matches"
      fail=1
    fi
  done < <(find "$dir" -name '*.o')
done

if [[ $scanned -eq 0 ]]; then
  echo "FAIL: no consensus objects were scanned under '$OBJDIR/obj'; check the build"
  exit 1
fi

if [[ $fail != 0 ]]; then
  echo ""
  echo "Floating-point FMA instructions found in consensus-critical objects."
  echo "Consensus code must match Agave (rustc) bit-for-bit and rustc never"
  echo "contracts FP expressions.  Break the expression with a volatile"
  echo "intermediate (see validator() in fd_rewards.c); if the use is"
  echo "intentional and matches Agave, allowlist the object in"
  echo "contrib/test/check_fp_fma.sh."
  exit 1
fi

echo "OK: scanned $scanned consensus object(s); no floating-point FMA instructions"
