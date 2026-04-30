#!/usr/bin/env python3
"""Generate fd_keccak256_avx512_keccak4a.inc from s2n-bignum's sha3_keccak4_f1600.S.

Mechanical AVX-512 lift of the s2n keccak4 asm: same instruction order,
same register allocation, same stack layout (slots widened from 32 B to 64 B).

Transformations applied per section:

  Boundary 1 (AoS -> SoA, top of function):
    - Loads from %rdi: kept as ymm (only 32 B per state needed).
    - Transpose ops (vpunpckl/h, vperm2i128): kept as ymm.  VEX encoding
      zero-extends the upper 256 bits of each underlying zmm register.
    - Stores to %rsp: ymm -> zmm (vmovdqu -> vmovdqu64), so the full 64 B
      slot is written; the upper 32 B come from the VEX-zeroed upper half.
    - Stack offsets: doubled (slot N moves from 0x20*N to 0x40*N).

  Round body (between Lsha3_keccak4_f1600_loop: and the conditional branch):
    - All %ymm<N> -> %zmm<N>.
    - All vmovdqu -> vmovdqu64 (64 B loads/stores against the wider slots).
    - All %rsp offsets doubled.

  Boundary 2 (SoA -> AoS, bottom of function):
    - Loads from %rsp: kept as ymm (only the lower 256 bits of each slot
      hold useful data; upper 256 are wasted-zero).  Offsets doubled.
    - Transpose ops and stores to %rdi: kept as ymm.

Skipped:
    - CFI directives, Windows ABI conditional, function-symbol directives,
      function entry/exit (no `ret`; no public symbol).  This file emits
      a GAS macro callable from a C inline-asm wrapper.

Stack frame:
    - s2n: `andq $-32, %rsp; sub $0x360, %rsp` (864 B, 32-B aligned).
    - Lift: `andq $-64, %rsp; sub $0x6c0, %rsp` (1728 B, 64-B aligned).

Loop label:
    - s2n uses `Lsha3_keccak4_f1600_loop:`; macro instances would collide on
      named labels, so we use a numeric local label `1:` / `jne 1b`.
"""

import re
import sys
from pathlib import Path

S2N_SRC = Path("/data/ecesena/s2n-bignum/x86_att/sha3/sha3_keccak4_f1600.S")
OUT     = Path(__file__).parent / "fd_keccak256_avx512_keccak4a.inc"

# ---------------------------------------------------------------------------
# helpers

OFFSET_RE = re.compile(r'(-?0x[0-9a-fA-F]+|-?\d+)\(%rsp\)')

def _double_off(m):
    s = m.group(1)
    if s.lower().startswith('0x') or s.lower().startswith('-0x'):
        v = int(s, 16)
    else:
        v = int(s, 10)
    v2 = v * 2
    if v2 == 0:
        return '(%rsp)'
    sign = '-' if v2 < 0 else ''
    return f'{sign}0x{abs(v2):x}(%rsp)'

def double_rsp_offsets(line):
    """Double every `<off>(%rsp)` displacement in `line`."""
    return OFFSET_RE.sub(_double_off, line)

YMM_RE     = re.compile(r'%ymm(\d+)\b')
VMOVDQU_RE = re.compile(r'\bvmovdqu\b')
COMMENT_RE = re.compile(r'\s*//.*$')  # strip C++-style comments (GAS doesn't accept them)

# EVEX-encoded integer ops need a lane-width suffix (q for 64-bit lanes).
# Map VEX legacy mnemonics in the round body to their EVEX zmm equivalents.
EVEX_RENAME = [
    (re.compile(r'\bvpandn\b'), 'vpandnq'),
    (re.compile(r'\bvpxor\b'),  'vpxorq'),
    (re.compile(r'\bvpor\b'),   'vporq'),
    (re.compile(r'\bvpand\b'),  'vpandq'),
]

def strip_comment(line):
    # Preserve trailing newline if present.
    has_nl = line.endswith('\n')
    body = line.rstrip('\n')
    body = COMMENT_RE.sub('', body)
    return body + ('\n' if has_nl else '')

def lift_round_line(line):
    """Round-body lift: ymm->zmm, vmovdqu->vmovdqu64, vp{andn,xor,or,and}->q form,
       double rsp offsets, strip // comments."""
    line = strip_comment(line)
    line = YMM_RE.sub(r'%zmm\1', line)
    line = VMOVDQU_RE.sub('vmovdqu64', line)
    for rx, rep in EVEX_RENAME:
        line = rx.sub(rep, line)
    line = double_rsp_offsets(line)
    return line

# Boundary 1 store: `vmovdqu %ymm<N>, <off>(%rsp)` -> `vmovdqu64 %zmm<N>, <2*off>(%rsp)`
B1_STORE_RE = re.compile(
    r'^(\s*)vmovdqu\s+%ymm(\d+),\s+((?:-?0x[0-9a-fA-F]+|-?\d+)?)\(%rsp\)(.*)$'
)
def lift_boundary1_line(line):
    line = strip_comment(line)
    m = B1_STORE_RE.match(line)
    if m:
        indent, reg, off, rest = m.groups()
        if off == '':
            new_off = '(%rsp)'
        else:
            class _M:
                def group(self, _i): return off
            new_off = _double_off(_M())
        return f'{indent}vmovdqu64 %zmm{reg}, {new_off}{rest}\n'
    return line

def lift_boundary2_line(line):
    """Boundary 2: keep ymm forms, just double rsp offsets in loads."""
    line = strip_comment(line)
    return double_rsp_offsets(line)

# ---------------------------------------------------------------------------
# scrubbing of directives we do NOT want in the macro

SKIP_PREFIXES = (
    'S2N_BN_SYM_', 'S2N_BN_SYMBOL', 'S2N_BN_FUNCTION_TYPE_DIRECTIVE',
    'S2N_BN_SIZE_DIRECTIVE', '_CET_ENDBR',
    '.text', '.balign', '.section', '.cfi_', 'CFI_',
)

def is_skip_directive(line):
    s = line.strip()
    if not s:
        return False  # keep blank lines for readability
    for p in SKIP_PREFIXES:
        if s.startswith(p):
            return True
    return False

def is_in_windows_block_marker(line):
    s = line.strip()
    if s.startswith('#if WINDOWS_ABI'):
        return 'open'
    if s.startswith('#endif'):
        return 'close'
    return None

def is_skip_label_or_misc(line):
    s = line.strip()
    if s.startswith('S2N_BN_SYMBOL(sha3_keccak4_f1600):'):
        return True
    if s == '.text':
        return True
    return False

# ---------------------------------------------------------------------------
# main

def main():
    src = S2N_SRC.read_text().splitlines(keepends=True)
    out = []

    out.append("# =============================================================================\n")
    out.append("# Keccak-f[1600] x4, AVX-512 lift of s2n-bignum sha3_keccak4_f1600\n")
    out.append("# =============================================================================\n")
    out.append("# Generated by gen_keccak4a_inc_from_s2n.py.  Do not edit by hand.\n")
    out.append("#\n")
    out.append("# Mechanical lift:  ymm -> zmm in round body, vmovdqu -> vmovdqu64,\n")
    out.append("# stack offsets doubled (slots widened from 32 B to 64 B).  Boundary\n")
    out.append("# transposes stay ymm-encoded; VEX zero-extension means the upper 256\n")
    out.append("# bits of each underlying zmm stay zero, so the top 4 lanes ride along\n")
    out.append("# as wasted zero work.\n")
    out.append("#\n")
    out.append("# Macro:    _fd_keccak256_avx512_keccak4a_f1600\n")
    out.append("# Inputs:   %rdi  pointer to 4 contiguous Keccak states (100 u64)\n")
    out.append("#           %rsi  pointer to 24-entry Keccak round-constant table\n")
    out.append("# Clobbers: %rax, %rcx, %rsi, %zmm0..%zmm15, ~1728 B stack scratch\n")
    out.append("# -----------------------------------------------------------------------------\n")
    out.append("\n")
    out.append(".macro _fd_keccak256_avx512_keccak4a_f1600\n")
    out.append("\n")
    out.append("    # Save %rsp into %rcx, align to 64 B, allocate 1728 B (0x6c0)\n")
    out.append("    movq    %rsp, %rcx\n")
    out.append("    andq    $0xffffffffffffffc0, %rsp\n")
    out.append("    subq    $0x6c0, %rsp\n")
    out.append("\n")

    # Section state machine
    section = 'prologue'   # prologue -> boundary1 -> round -> boundary2 -> epilogue
    in_windows = False
    saw_initialize_loop_counter = False

    for raw in src:
        line = raw

        # Skip Windows ABI blocks entirely
        marker = is_in_windows_block_marker(line)
        if marker == 'open':
            in_windows = True
            continue
        if in_windows:
            if marker == 'close':
                in_windows = False
            continue

        # Skip noisy directives unconditionally
        if is_skip_directive(line):
            continue
        if is_skip_label_or_misc(line):
            continue

        s = line.strip()

        # -------- section transitions --------
        if section == 'prologue':
            # The s2n prologue ends and boundary1 begins right after the
            # `andq` + `sub` rsp setup.  We provide our own alignment above,
            # so skip s2n's stack setup and CFI noise until the first real
            # boundary1 instruction (the first vmovq from %rdi).
            if 'movq' in s and '%rsp, %rcx' in s:
                continue
            if s.startswith('andq') and '%rsp' in s:
                continue
            if s.startswith('sub') and '%rsp' in s:
                continue
            if s == '':
                continue
            # Section transitions to boundary1 on the first real
            # instruction.  Do NOT transition on '//' comments — the s2n
            # source has a copyright/license comment block at the top of
            # the file long before any instruction.
            if 'vmovdqu' in s or 'vmovq' in s or 'vpinsrq' in s:
                section = 'boundary1'
                # fall through to handle this line in boundary1
            else:
                # Unknown line in prologue zone: skip (drops file-level
                # comments, the #include, S2N_BN_SYMBOL leftover, etc).
                continue

        if section == 'boundary1':
            # Watch for the comment that signals the loop init.
            if '// Initialize the loop counter' in line:
                section = 'loop_setup'
                # don't emit; the loop counter init we emit ourselves
                continue
            # Transform stack stores; pass everything else through.
            out.append(lift_boundary1_line(line))
            continue

        if section == 'loop_setup':
            # In s2n: `movq $0x0, %rax` then `Lsha3_keccak4_f1600_loop:` label.
            # We emit our own counter init + numeric local label.
            if s.startswith('Lsha3_keccak4_f1600_loop:'):
                out.append("    # ---- 24-round loop ----\n")
                out.append("    movq    $0x0, %rax\n")
                out.append("1:\n")
                section = 'round'
                continue
            # Skip movq $0, %rax in s2n form
            continue

        if section == 'round':
            # End of round body: `jne Lsha3_keccak4_f1600_loop`.
            if 'Lsha3_keccak4_f1600_loop' in s and ('jne' in s or 'jnz' in s):
                # Replace with numeric back-jump.
                out.append("    addq    $0x8, %rsi\n")
                out.append("    addq    $0x1, %rax\n")
                out.append("    cmpq    $0x18, %rax\n")
                out.append("    jne     1b\n")
                section = 'boundary2'
                continue
            # Skip the instructions that we just emitted ourselves above
            # (addq $8 %rsi, addq $1 %rax, cmpq $0x18 %rax) -- we emit
            # them once at section end, not here, so drop them to avoid duplication.
            if (s.startswith('addq') and '%rsi' in s and '0x8' in s) \
               or (s.startswith('addq') and '%rax' in s and '0x1' in s) \
               or (s.startswith('cmpq') and '%rax' in s and '0x18' in s):
                continue
            # Lift everything else.
            out.append(lift_round_line(line))
            continue

        if section == 'boundary2':
            # End of body: `movq %rcx, %rsp` resets stack.  Stop here;
            # we'll emit our own restore.
            if 'movq' in s and '%rcx' in s and '%rsp' in s:
                section = 'epilogue'
                continue
            # Skip CFI and the `ret`.
            if s.startswith('CFI_RET') or s == 'ret':
                continue
            out.append(lift_boundary2_line(line))
            continue

        # epilogue: just drop everything
        continue

    out.append("\n")
    out.append("    # Restore %rsp\n")
    out.append("    movq    %rcx, %rsp\n")
    out.append(".endm\n")

    OUT.write_text(''.join(out))
    print(f"wrote {OUT} ({len(out)} lines)")

if __name__ == '__main__':
    main()
