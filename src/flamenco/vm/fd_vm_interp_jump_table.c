  /* interp_jump_table holds the sBPF interpreter jump table.  It is an
     array where each index is an opcode that can be jumped to be
     executed.  Invalid opcodes branch to the sigill label. */
#include "../../ballet/sbpf/fd_sbpf_loader.h"
#define OPCODE(opcode) interp_##opcode

  /* Suppress warnings for intentional designated initializer overrides.
     VERSION_OVERRIDES re-initializes entries from V0_BASE; the last
     value wins per C semantics. */
#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Woverride-init"
#endif

  /* OVERRIDE conditionally sets a single jump table entry based on
     sBPF version, using the FD_VM_SBPF_* feature macros. */
#define OVERRIDE(v, op, cond, ltrue, lfalse) \
    [op] = cond(v) ? (ltrue) : (lfalse)

  /* OVERRIDE_WITH_FALLBACK is like OVERRIDE but when the condition is
     false, it falls back to a second condition before using lfalse.
     This is to avoid last-write-wins clobbering when two mutually
     exclusive features share the same opcode slot. */
#define OVERRIDE_WITH_FALLBACK(v, op, cond1, ltrue1, cond2, ltrue2, lfalse) \
    [op] = cond1(v) ? (ltrue1) : cond2(v) ? (ltrue2) : (lfalse)

  /* V0_BASE: Complete sBPF v0 opcode table.
     This is the base for all versions.  Version-dependent entries
     are overridden by VERSION_OVERRIDES for v1+. */
#define V0_BASE                                                                                                      \
    /* 0x00 */ [0x00]=&&sigill,           [0x01]=&&sigill,         [0x02]=&&sigill,       [0x03]=&&sigill,           \
    /* 0x04 */ [0x04]=&&OPCODE(0x04depr), [0x05]=&&OPCODE(0x05),   [0x06]=&&sigill,       [0x07]=&&OPCODE(0x07),     \
    /* 0x08 */ [0x08]=&&sigill,           [0x09]=&&sigill,         [0x0a]=&&sigill,       [0x0b]=&&sigill,           \
    /* 0x0c */ [0x0c]=&&OPCODE(0x0cdepr), [0x0d]=&&sigill,         [0x0e]=&&sigill,       [0x0f]=&&OPCODE(0x0f),     \
    /* 0x10 */ [0x10]=&&sigill,           [0x11]=&&sigill,         [0x12]=&&sigill,       [0x13]=&&sigill,           \
    /* 0x14 */ [0x14]=&&OPCODE(0x14depr), [0x15]=&&OPCODE(0x15),   [0x16]=&&sigill,       [0x17]=&&OPCODE(0x17depr), \
    /* 0x18 */ [0x18]=&&OPCODE(0x18),     [0x19]=&&sigill,         [0x1a]=&&sigill,       [0x1b]=&&sigill,           \
    /* 0x1c */ [0x1c]=&&OPCODE(0x1cdepr), [0x1d]=&&OPCODE(0x1d),   [0x1e]=&&sigill,       [0x1f]=&&OPCODE(0x1f),     \
    /* 0x20 */ [0x20]=&&sigill,           [0x21]=&&sigill,         [0x22]=&&sigill,       [0x23]=&&sigill,           \
    /* 0x24 */ [0x24]=&&OPCODE(0x24),     [0x25]=&&OPCODE(0x25),   [0x26]=&&sigill,       [0x27]=&&OPCODE(0x27depr), \
    /* 0x28 */ [0x28]=&&sigill,           [0x29]=&&sigill,         [0x2a]=&&sigill,       [0x2b]=&&sigill,           \
    /* 0x2c */ [0x2c]=&&OPCODE(0x2cdepr), [0x2d]=&&OPCODE(0x2d),   [0x2e]=&&sigill,       [0x2f]=&&OPCODE(0x2fdepr), \
    /* 0x30 */ [0x30]=&&sigill,           [0x31]=&&sigill,         [0x32]=&&sigill,       [0x33]=&&sigill,           \
    /* 0x34 */ [0x34]=&&OPCODE(0x34),     [0x35]=&&OPCODE(0x35),   [0x36]=&&sigill,       [0x37]=&&OPCODE(0x37depr), \
    /* 0x38 */ [0x38]=&&sigill,           [0x39]=&&sigill,         [0x3a]=&&sigill,       [0x3b]=&&sigill,           \
    /* 0x3c */ [0x3c]=&&OPCODE(0x3cdepr), [0x3d]=&&OPCODE(0x3d),   [0x3e]=&&sigill,       [0x3f]=&&OPCODE(0x3fdepr), \
    /* 0x40 */ [0x40]=&&sigill,           [0x41]=&&sigill,         [0x42]=&&sigill,       [0x43]=&&sigill,           \
    /* 0x44 */ [0x44]=&&OPCODE(0x44),     [0x45]=&&OPCODE(0x45),   [0x46]=&&sigill,       [0x47]=&&OPCODE(0x47),     \
    /* 0x48 */ [0x48]=&&sigill,           [0x49]=&&sigill,         [0x4a]=&&sigill,       [0x4b]=&&sigill,           \
    /* 0x4c */ [0x4c]=&&OPCODE(0x4c),     [0x4d]=&&OPCODE(0x4d),   [0x4e]=&&sigill,       [0x4f]=&&OPCODE(0x4f),     \
    /* 0x50 */ [0x50]=&&sigill,           [0x51]=&&sigill,         [0x52]=&&sigill,       [0x53]=&&sigill,           \
    /* 0x54 */ [0x54]=&&OPCODE(0x54),     [0x55]=&&OPCODE(0x55),   [0x56]=&&sigill,       [0x57]=&&OPCODE(0x57),     \
    /* 0x58 */ [0x58]=&&sigill,           [0x59]=&&sigill,         [0x5a]=&&sigill,       [0x5b]=&&sigill,           \
    /* 0x5c */ [0x5c]=&&OPCODE(0x5c),     [0x5d]=&&OPCODE(0x5d),   [0x5e]=&&sigill,       [0x5f]=&&OPCODE(0x5f),     \
    /* 0x60 */ [0x60]=&&sigill,           [0x61]=&&OPCODE(0x8c),   [0x62]=&&OPCODE(0x87), [0x63]=&&OPCODE(0x8f),     \
    /* 0x64 */ [0x64]=&&OPCODE(0x64),     [0x65]=&&OPCODE(0x65),   [0x66]=&&sigill,       [0x67]=&&OPCODE(0x67),     \
    /* 0x68 */ [0x68]=&&sigill,           [0x69]=&&OPCODE(0x3c),   [0x6a]=&&OPCODE(0x37), [0x6b]=&&OPCODE(0x3f),     \
    /* 0x6c */ [0x6c]=&&OPCODE(0x6c),     [0x6d]=&&OPCODE(0x6d),   [0x6e]=&&sigill,       [0x6f]=&&OPCODE(0x6f),     \
    /* 0x70 */ [0x70]=&&sigill,           [0x71]=&&OPCODE(0x2c),   [0x72]=&&OPCODE(0x27), [0x73]=&&OPCODE(0x2f),     \
    /* 0x74 */ [0x74]=&&OPCODE(0x74),     [0x75]=&&OPCODE(0x75),   [0x76]=&&sigill,       [0x77]=&&OPCODE(0x77),     \
    /* 0x78 */ [0x78]=&&sigill,           [0x79]=&&OPCODE(0x9c),   [0x7a]=&&OPCODE(0x97), [0x7b]=&&OPCODE(0x9f),     \
    /* 0x7c */ [0x7c]=&&OPCODE(0x7c),     [0x7d]=&&OPCODE(0x7d),   [0x7e]=&&sigill,       [0x7f]=&&OPCODE(0x7f),     \
    /* 0x80 */ [0x80]=&&sigill,           [0x81]=&&sigill,         [0x82]=&&sigill,       [0x83]=&&sigill,           \
    /* 0x84 */ [0x84]=&&OPCODE(0x84),     [0x85]=&&OPCODE(0x85),   [0x86]=&&sigill,       [0x87]=&&OPCODE(0x87depr), \
    /* 0x88 */ [0x88]=&&sigill,           [0x89]=&&sigill,         [0x8a]=&&sigill,       [0x8b]=&&sigill,           \
    /* 0x8c */ [0x8c]=&&sigill,           [0x8d]=&&OPCODE(0x8d),   [0x8e]=&&sigill,       [0x8f]=&&sigill,           \
    /* 0x90 */ [0x90]=&&sigill,           [0x91]=&&sigill,         [0x92]=&&sigill,       [0x93]=&&sigill,           \
    /* 0x94 */ [0x94]=&&OPCODE(0x94),     [0x95]=&&OPCODE(0x95),   [0x96]=&&sigill,       [0x97]=&&OPCODE(0x97depr), \
    /* 0x98 */ [0x98]=&&sigill,           [0x99]=&&sigill,         [0x9a]=&&sigill,       [0x9b]=&&sigill,           \
    /* 0x9c */ [0x9c]=&&OPCODE(0x9cdepr), [0x9d]=&&sigill,         [0x9e]=&&sigill,       [0x9f]=&&OPCODE(0x9fdepr), \
    /* 0xa0 */ [0xa0]=&&sigill,           [0xa1]=&&sigill,         [0xa2]=&&sigill,       [0xa3]=&&sigill,           \
    /* 0xa4 */ [0xa4]=&&OPCODE(0xa4),     [0xa5]=&&OPCODE(0xa5),   [0xa6]=&&sigill,       [0xa7]=&&OPCODE(0xa7),     \
    /* 0xa8 */ [0xa8]=&&sigill,           [0xa9]=&&sigill,         [0xaa]=&&sigill,       [0xab]=&&sigill,           \
    /* 0xac */ [0xac]=&&OPCODE(0xac),     [0xad]=&&OPCODE(0xad),   [0xae]=&&sigill,       [0xaf]=&&OPCODE(0xaf),     \
    /* 0xb0 */ [0xb0]=&&sigill,           [0xb1]=&&sigill,         [0xb2]=&&sigill,       [0xb3]=&&sigill,           \
    /* 0xb4 */ [0xb4]=&&OPCODE(0xb4),     [0xb5]=&&OPCODE(0xb5),   [0xb6]=&&sigill,       [0xb7]=&&OPCODE(0xb7),     \
    /* 0xb8 */ [0xb8]=&&sigill,           [0xb9]=&&sigill,         [0xba]=&&sigill,       [0xbb]=&&sigill,           \
    /* 0xbc */ [0xbc]=&&OPCODE(0xbcdepr), [0xbd]=&&OPCODE(0xbd),   [0xbe]=&&sigill,       [0xbf]=&&OPCODE(0xbf),     \
    /* 0xc0 */ [0xc0]=&&sigill,           [0xc1]=&&sigill,         [0xc2]=&&sigill,       [0xc3]=&&sigill,           \
    /* 0xc4 */ [0xc4]=&&OPCODE(0xc4),     [0xc5]=&&OPCODE(0xc5),   [0xc6]=&&sigill,       [0xc7]=&&OPCODE(0xc7),     \
    /* 0xc8 */ [0xc8]=&&sigill,           [0xc9]=&&sigill,         [0xca]=&&sigill,       [0xcb]=&&sigill,           \
    /* 0xcc */ [0xcc]=&&OPCODE(0xcc),     [0xcd]=&&OPCODE(0xcd),   [0xce]=&&sigill,       [0xcf]=&&OPCODE(0xcf),     \
    /* 0xd0 */ [0xd0]=&&sigill,           [0xd1]=&&sigill,         [0xd2]=&&sigill,       [0xd3]=&&sigill,           \
    /* 0xd4 */ [0xd4]=&&OPCODE(0xd4),     [0xd5]=&&OPCODE(0xd5),   [0xd6]=&&sigill,       [0xd7]=&&sigill,           \
    /* 0xd8 */ [0xd8]=&&sigill,           [0xd9]=&&sigill,         [0xda]=&&sigill,       [0xdb]=&&sigill,           \
    /* 0xdc */ [0xdc]=&&OPCODE(0xdc),     [0xdd]=&&OPCODE(0xdd),   [0xde]=&&sigill,       [0xdf]=&&sigill,           \
    /* 0xe0 */ [0xe0]=&&sigill,           [0xe1]=&&sigill,         [0xe2]=&&sigill,       [0xe3]=&&sigill,           \
    /* 0xe4 */ [0xe4]=&&sigill,           [0xe5]=&&sigill,         [0xe6]=&&sigill,       [0xe7]=&&sigill,           \
    /* 0xe8 */ [0xe8]=&&sigill,           [0xe9]=&&sigill,         [0xea]=&&sigill,       [0xeb]=&&sigill,           \
    /* 0xec */ [0xec]=&&sigill,           [0xed]=&&sigill,         [0xee]=&&sigill,       [0xef]=&&sigill,           \
    /* 0xf0 */ [0xf0]=&&sigill,           [0xf1]=&&sigill,         [0xf2]=&&sigill,       [0xf3]=&&sigill,           \
    /* 0xf4 */ [0xf4]=&&sigill,           [0xf5]=&&sigill,         [0xf6]=&&sigill,       [0xf7]=&&sigill,           \
    /* 0xf8 */ [0xf8]=&&sigill,           [0xf9]=&&sigill,         [0xfa]=&&sigill,       [0xfb]=&&sigill,           \
    /* 0xfc */ [0xfc]=&&sigill,           [0xfd]=&&sigill,         [0xfe]=&&sigill,       [0xff]=&&sigill

  /* VERSION_OVERRIDES: Applies version-dependent opcode overrides
     on top of V0_BASE. */
#define VERSION_OVERRIDES(v)                                                                                           \
                                                                                                                       \
    /* === V1 (SIMD-0166) ============================================= */                                             \
    /* (no opcode changes in V1, only stack frame semantics) */                                                        \
                                                                                                                       \
    /* === V2 (SIMD-0173, SIMD-0174) ================================== */                                             \
                                                                                                                       \
    /* SIMD-0173: disable LDDW, enable HOR64 */                                                                        \
    OVERRIDE(v, 0x18, FD_VM_SBPF_DISABLE_LDDW, &&sigill,       &&OPCODE(0x18)),                                        \
    OVERRIDE(v, 0xf7, FD_VM_SBPF_DISABLE_LDDW, &&OPCODE(0xf7), &&sigill),                                              \
                                                                                                                       \
    /* SIMD-0173: disable LE */                                                                                        \
    OVERRIDE(v, 0xd4, FD_VM_SBPF_DISABLE_LE, &&sigill, &&OPCODE(0xd4)),                                                \
                                                                                                                       \
    /* SIMD-0173: move memory instruction classes */                                                                   \
    OVERRIDE(v, 0x61, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill,       &&OPCODE(0x8c)),                              \
    OVERRIDE(v, 0x62, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill,       &&OPCODE(0x87)),                              \
    OVERRIDE(v, 0x63, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill,       &&OPCODE(0x8f)),                              \
    OVERRIDE(v, 0x8c, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&OPCODE(0x8c), &&sigill),                                    \
    OVERRIDE(v, 0x87, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&OPCODE(0x87), &&OPCODE(0x87depr)),                          \
    OVERRIDE(v, 0x8f, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&OPCODE(0x8f), &&sigill),                                    \
    OVERRIDE(v, 0x69, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill,       &&OPCODE(0x3c)),                              \
    OVERRIDE(v, 0x6a, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill,       &&OPCODE(0x37)),                              \
    OVERRIDE(v, 0x6b, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill,       &&OPCODE(0x3f)),                              \
    OVERRIDE(v, 0x3c, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&OPCODE(0x3c), &&OPCODE(0x3cdepr)),                          \
    OVERRIDE(v, 0x37, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&OPCODE(0x37), &&OPCODE(0x37depr)),                          \
    OVERRIDE(v, 0x3f, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&OPCODE(0x3f), &&OPCODE(0x3fdepr)),                          \
    OVERRIDE(v, 0x71, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill,       &&OPCODE(0x2c)),                              \
    OVERRIDE(v, 0x72, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill,       &&OPCODE(0x27)),                              \
    OVERRIDE(v, 0x73, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill,       &&OPCODE(0x2f)),                              \
    OVERRIDE(v, 0x2c, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&OPCODE(0x2c), &&OPCODE(0x2cdepr)),                          \
    OVERRIDE(v, 0x27, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&OPCODE(0x27), &&OPCODE(0x27depr)),                          \
    OVERRIDE(v, 0x2f, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&OPCODE(0x2f), &&OPCODE(0x2fdepr)),                          \
    OVERRIDE(v, 0x79, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill,       &&OPCODE(0x9c)),                              \
    OVERRIDE(v, 0x7a, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill,       &&OPCODE(0x97)),                              \
    OVERRIDE(v, 0x7b, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill,       &&OPCODE(0x9f)),                              \
    OVERRIDE(v, 0x9c, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&OPCODE(0x9c), &&OPCODE(0x9cdepr)),                          \
    OVERRIDE(v, 0x97, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&OPCODE(0x97), &&OPCODE(0x97depr)),                          \
    OVERRIDE(v, 0x9f, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&OPCODE(0x9f), &&OPCODE(0x9fdepr)),                          \
                                                                                                                       \
    /* SIMD-0174: enable PQR, disable MUL/DIV/MOD (PQR-only, no JMP32 overlap) */                                       \
    OVERRIDE(v, 0x86, FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0x86), &&sigill),                                                \
    OVERRIDE(v, 0x8e, FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0x8e), &&sigill),                                                \
    OVERRIDE(v, 0x96, FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0x96), &&sigill),                                                \
    OVERRIDE(v, 0x9e, FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0x9e), &&sigill),                                                \
    OVERRIDE(v, 0xe6, FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0xe6), &&sigill),                                                \
    OVERRIDE(v, 0xee, FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0xee), &&sigill),                                                \
    OVERRIDE(v, 0xf6, FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0xf6), &&sigill),                                                \
    OVERRIDE(v, 0xfe, FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0xfe), &&sigill),                                                \
    OVERRIDE(v, 0x24, FD_VM_SBPF_ENABLE_PQR, &&sigill, &&OPCODE(0x24)),                                                \
    OVERRIDE(v, 0x34, FD_VM_SBPF_ENABLE_PQR, &&sigill, &&OPCODE(0x34)),                                                \
    OVERRIDE(v, 0x94, FD_VM_SBPF_ENABLE_PQR, &&sigill, &&OPCODE(0x94)),                                                \
                                                                                                                       \
    /* SIMD-0174: disable NEG */                                                                                       \
    OVERRIDE(v, 0x84, FD_VM_SBPF_DISABLE_NEG, &&sigill, &&OPCODE(0x84)),                                               \
                                                                                                                       \
    /* SIMD-0174: explicit sign extension + swap sub reg/imm operands */                                               \
    OVERRIDE(v, 0x04, FD_VM_SBPF_EXPLICIT_SIGN_EXTENSION_OF_RESULTS, &&OPCODE(0x04), &&OPCODE(0x04depr)),              \
    OVERRIDE(v, 0x0c, FD_VM_SBPF_EXPLICIT_SIGN_EXTENSION_OF_RESULTS, &&OPCODE(0x0c), &&OPCODE(0x0cdepr)),              \
    OVERRIDE(v, 0x1c, FD_VM_SBPF_EXPLICIT_SIGN_EXTENSION_OF_RESULTS, &&OPCODE(0x1c), &&OPCODE(0x1cdepr)),              \
    OVERRIDE(v, 0xbc, FD_VM_SBPF_EXPLICIT_SIGN_EXTENSION_OF_RESULTS, &&OPCODE(0xbc), &&OPCODE(0xbcdepr)),              \
    OVERRIDE(v, 0x14, FD_VM_SBPF_SWAP_SUB_REG_IMM_OPERANDS,          &&OPCODE(0x14), &&OPCODE(0x14depr)),              \
    OVERRIDE(v, 0x17, FD_VM_SBPF_SWAP_SUB_REG_IMM_OPERANDS,          &&OPCODE(0x17), &&OPCODE(0x17depr)),              \
                                                                                                                       \
    /* SIMD-0178: Static syscalls */                                                                                   \
    OVERRIDE(v, 0x85, FD_VM_SBPF_STATIC_SYSCALLS, &&OPCODE(0x85_static), &&OPCODE(0x85)),                              \
                                                                                                                       \
    /* SIMD-0174: PQR (SBPF V2) / SIMD-0377: JMP32 (SBPF V3)
       These opcodes conflict in SBPF V2 and SBPF V3, so we use
       OVERRIDE_WITH_FALLBACK to avoid last-write-wins bugs.

       FD_VM_SBPF_ENABLE_JMP32 and FD_VM_SBPF_ENABLE_PQR are mutually
       exclusive - see static asserts below. */                                                                                      \
    OVERRIDE_WITH_FALLBACK(v, 0x36, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0x36_jmp32), FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0x36), &&sigill), \
    OVERRIDE_WITH_FALLBACK(v, 0x3e, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0x3e_jmp32), FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0x3e), &&sigill), \
    OVERRIDE_WITH_FALLBACK(v, 0x46, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0x46_jmp32), FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0x46), &&sigill), \
    OVERRIDE_WITH_FALLBACK(v, 0x4e, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0x4e_jmp32), FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0x4e), &&sigill), \
    OVERRIDE_WITH_FALLBACK(v, 0x56, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0x56_jmp32), FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0x56), &&sigill), \
    OVERRIDE_WITH_FALLBACK(v, 0x5e, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0x5e_jmp32), FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0x5e), &&sigill), \
    OVERRIDE_WITH_FALLBACK(v, 0x66, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0x66_jmp32), FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0x66), &&sigill), \
    OVERRIDE_WITH_FALLBACK(v, 0x6e, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0x6e_jmp32), FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0x6e), &&sigill), \
    OVERRIDE_WITH_FALLBACK(v, 0x76, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0x76_jmp32), FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0x76), &&sigill), \
    OVERRIDE_WITH_FALLBACK(v, 0x7e, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0x7e_jmp32), FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0x7e), &&sigill), \
    OVERRIDE_WITH_FALLBACK(v, 0xb6, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0xb6_jmp32), FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0xb6), &&sigill), \
    OVERRIDE_WITH_FALLBACK(v, 0xbe, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0xbe_jmp32), FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0xbe), &&sigill), \
    OVERRIDE_WITH_FALLBACK(v, 0xc6, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0xc6_jmp32), FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0xc6), &&sigill), \
    OVERRIDE_WITH_FALLBACK(v, 0xce, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0xce_jmp32), FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0xce), &&sigill), \
    OVERRIDE_WITH_FALLBACK(v, 0xd6, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0xd6_jmp32), FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0xd6), &&sigill), \
    OVERRIDE_WITH_FALLBACK(v, 0xde, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0xde_jmp32), FD_VM_SBPF_ENABLE_PQR, &&OPCODE(0xde), &&sigill), \
                                                                                                                                     \
    /* SIMD-0377: JMP32 non-conflicting opcodes */                                                                                   \
    OVERRIDE(v, 0x16, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0x16_jmp32), &&sigill),                                                      \
    OVERRIDE(v, 0x1e, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0x1e_jmp32), &&sigill),                                                      \
    OVERRIDE(v, 0x26, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0x26_jmp32), &&sigill),                                                      \
    OVERRIDE(v, 0x2e, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0x2e_jmp32), &&sigill),                                                      \
    OVERRIDE(v, 0xa6, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0xa6_jmp32), &&sigill),                                                      \
    OVERRIDE(v, 0xae, FD_VM_SBPF_ENABLE_JMP32, &&OPCODE(0xae_jmp32), &&sigill)

  /* PQR and JMP32 need to be mutually exclusive */
  FD_STATIC_ASSERT( !(FD_VM_SBPF_ENABLE_PQR(FD_SBPF_V0) && FD_VM_SBPF_ENABLE_JMP32(FD_SBPF_V0)), pqr_jmp32_v0 );
  FD_STATIC_ASSERT( !(FD_VM_SBPF_ENABLE_PQR(FD_SBPF_V1) && FD_VM_SBPF_ENABLE_JMP32(FD_SBPF_V1)), pqr_jmp32_v1 );
  FD_STATIC_ASSERT( !(FD_VM_SBPF_ENABLE_PQR(FD_SBPF_V2) && FD_VM_SBPF_ENABLE_JMP32(FD_SBPF_V2)), pqr_jmp32_v2 );
  FD_STATIC_ASSERT( !(FD_VM_SBPF_ENABLE_PQR(FD_SBPF_V3) && FD_VM_SBPF_ENABLE_JMP32(FD_SBPF_V3)), pqr_jmp32_v3 );
  FD_STATIC_ASSERT( !(FD_VM_SBPF_ENABLE_PQR(FD_SBPF_V4) && FD_VM_SBPF_ENABLE_JMP32(FD_SBPF_V4)), pqr_jmp32_v4 );

  static void const * const interp_jump_table[ FD_SBPF_VERSION_COUNT ][ 256 ] = {
    [FD_SBPF_V0] = { V0_BASE },
    [FD_SBPF_V1] = { V0_BASE, VERSION_OVERRIDES(FD_SBPF_V1) },
    [FD_SBPF_V2] = { V0_BASE, VERSION_OVERRIDES(FD_SBPF_V2) },
    [FD_SBPF_V3] = { V0_BASE, VERSION_OVERRIDES(FD_SBPF_V3) },
    [FD_SBPF_V4] = { V0_BASE, VERSION_OVERRIDES(FD_SBPF_V4) },
  };

#undef V0_BASE
#undef VERSION_OVERRIDES
#undef OVERRIDE_WITH_FALLBACK
#undef OVERRIDE
#undef OPCODE
