#!/bin/sh
# Rewrite the production keccak1eo .inc into a proof-only variant by replacing
# each scalar BMI1 'andnl src1, src2, %eax' with the equivalent
# 'movl src1, %eax; notl %eax; andl src2, %eax' triplet.
#
# The substitution is purely textual and intentionally narrow: it matches only
# the exact form used in chi steps (dst is always %eax in keccak1eo).  Any
# other ANDN form would be left untouched and would break the proof.

set -e
case "$#" in 1) ;; *) echo "usage: $0 <inc-file>" >&2; exit 1 ;; esac

cat <<'HDR'
# =============================================================================
# PROOF-ONLY variant of fd_keccak256_keccak1eo.inc.
# =============================================================================
# Generated from the production .inc by replacing each BMI1
#   andnl src1, src2, %eax    (eax = ~src1 & src2, BMI1, 1 op)
# with the equivalent 3-op baseline sequence
#   movl src1, %eax           (eax = src1)
#   notl %eax                 (eax = ~src1)
#   andl src2, %eax           (eax = ~src1 & src2)
# so HOL Light's x86 decoder (which doesn't implement scalar BMI1 ANDN) can
# verify the bytes.  Do NOT use for performance — use the production .inc.
# =============================================================================
HDR

sed -E '
  s/^([[:space:]]*)andnl[[:space:]]+%([a-z0-9]+),[[:space:]]+%([a-z0-9]+),[[:space:]]+%eax([[:space:]].*)?$/\1movl %\3, %eax\n\1notl %eax\n\1andl %\2, %eax/
' "$1"
