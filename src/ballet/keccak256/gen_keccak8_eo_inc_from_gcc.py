#!/usr/bin/env python3
"""Generate fd_keccak256_avx2_keccak8_eo.inc by extracting gcc-15's compiled
asm for fd_k8eo_perm and wrapping it as a GAS macro.

The input .s file is produced by gcc-15.1.0 with -S on the C source; this
script transforms it into a callable macro matching our calling convention:
  \\state in %rdi, \\rc_eo in %rsi.

The original gcc function signature is fd_k8eo_perm(ae, ao, rc_eo) with
ae=%rdi, ao=%rsi, rc_eo=%rdx (System V ABI).  Our macro entry adapts:
  \\state -> %rdi (already, ae base)
  ao = %rdi + 800 -> %rsi
  \\rc_eo -> %rdx
"""

import re
import sys

INPUT  = "/tmp/eo_gcc15.s"
OUTPUT = "src/ballet/keccak256/fd_keccak256_avx2_keccak8_eo.inc"

def main():
    with open(INPUT) as f:
        lines = f.readlines()

    # Find function boundaries.
    start = None
    end   = None
    for i, ln in enumerate(lines):
        if ln.strip() == "fd_k8eo_perm:":
            start = i + 1
        elif start and ln.strip().startswith(".size\tfd_k8eo_perm"):
            end = i
            break
    if start is None or end is None:
        sys.stderr.write("could not locate fd_k8eo_perm in %s\n" % INPUT)
        sys.exit(1)

    body = lines[start:end]

    # Filter and rewrite.
    out = []
    out.append("# Auto-generated from gcc-15.1.0's compiled asm for fd_k8eo_perm.")
    out.append("# Do not edit by hand; rerun gen_keccak8_eo_inc_from_gcc.py.")
    out.append("#")
    out.append("# Macro: _fd_keccak256_avx2_keccak8_eo_f1600_raw \\state \\rc_eo")
    out.append("# Args:  \\state=%rdi (state in EO SoA, 50 ymm = 1600 B), \\rc_eo=%rsi (48 u32)")
    out.append("# Clobbers: ymm0..ymm15, rax, rcx, rdx, rsi, flags, ~1032 B stack scratch")
    out.append("# Caller must save rbp.")
    out.append("")
    out.append(".macro _fd_keccak256_avx2_keccak8_eo_f1600_raw state, rc_eo")
    out.append("   /* C wrapper pins \\state=%rdi (= ae base) and \\rc_eo=%rdx. */")
    out.append("   /* Compute ao = state + 800 in %rsi as gcc's body expects. */")
    out.append("   leaq 800(\\state), %rsi")
    out.append("")
    out.append("   /* === Begin gcc-15 compiled body of fd_k8eo_perm === */")

    for ln in body:
        s = ln.rstrip("\n")
        # Skip CFI directives.
        if ".cfi_" in s:
            continue
        # Skip the LFB/LFE labels.
        if re.match(r"\s*\.LF[BE]\d+", s):
            continue
        # Rename .L2 to a numeric local label (unique per macro instance).
        s = s.replace(".L2:", "9999:")
        s = s.replace(".L2", "9999b")
        # The leave/ret pair at the end: replace ret with nothing (macro continues).
        # Actually we keep `leave` and drop `ret`.
        if s.strip() == "ret":
            continue
        out.append(s)

    out.append("   /* === End gcc-15 compiled body === */")
    out.append(".endm")
    out.append("")

    with open(OUTPUT, "w") as f:
        f.write("\n".join(out))
    sys.stderr.write("wrote %s (%d lines)\n" % (OUTPUT, len(out)))

if __name__ == "__main__":
    main()
