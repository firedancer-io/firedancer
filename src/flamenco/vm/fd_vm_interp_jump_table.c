  /* interp_jump_table holds the sBPF interpreter jump table.  It is an
     array where each index is an opcode that can be jumped to be
     executed.  Invalid opcodes branch to the sigill label. */
#include "../../ballet/sbpf/fd_sbpf_loader.h"
#   define OPCODE(opcode) interp_##opcode
#   define ALL_ILLEGAL(op) [0][op] = &&sigill,     [1][op] = &&sigill,     [2][op] = &&sigill,     [3][op] = &&sigill
#   define ALL_OPCODE( op) [0][op] = &&OPCODE(op), [1][op] = &&OPCODE(op), [2][op] = &&OPCODE(op), [3][op] = &&OPCODE(op)
#   define CONDITIONAL(op, C, ltrue, lfalse) \
                       [0][op] = C(0) ? (ltrue):(lfalse), \
                       [1][op] = C(1) ? (ltrue):(lfalse), \
                       [2][op] = C(2) ? (ltrue):(lfalse), \
                       [3][op] = C(3) ? (ltrue):(lfalse)

  static void const * const interp_jump_table[ FD_SBPF_VERSION_COUNT ][ 256 ] = {
    /* First we start with the opcodes that are the same in all version
       of sBPF.  We leave gaps for the ones that depend on the version
       of sBPF, with the gap numbered based on the order they appear in
       the first table and the order in which they appear in the
       CONDITIONAL list below. If we get it wrong, the compiler will
       complain about initialized fields being overwritten. */

    ALL_ILLEGAL(0x00), ALL_ILLEGAL(0x01), ALL_ILLEGAL(0x02), ALL_ILLEGAL(0x03),
    /*   55 :   0  */  ALL_OPCODE (0x05), ALL_ILLEGAL(0x06), ALL_OPCODE (0x07),
    ALL_ILLEGAL(0x08), ALL_ILLEGAL(0x09), ALL_ILLEGAL(0x0a), ALL_ILLEGAL(0x0b),
    /*   56 :   1  */  ALL_ILLEGAL(0x0d), ALL_ILLEGAL(0x0e), ALL_OPCODE (0x0f),
    ALL_ILLEGAL(0x10), ALL_ILLEGAL(0x11), ALL_ILLEGAL(0x12), ALL_ILLEGAL(0x13),
    /*   59 :   2  */  ALL_OPCODE (0x15), ALL_ILLEGAL(0x16), /*   60 :   3  */
    /*    0 :   4  */  ALL_ILLEGAL(0x19), ALL_ILLEGAL(0x1a), ALL_ILLEGAL(0x1b),
    /*   57 :   5  */  ALL_OPCODE (0x1d), ALL_ILLEGAL(0x1e), ALL_OPCODE (0x1f),
    ALL_ILLEGAL(0x20), ALL_ILLEGAL(0x21), ALL_ILLEGAL(0x22), ALL_ILLEGAL(0x23),
    /*   51 :   6  */  ALL_OPCODE (0x25), ALL_ILLEGAL(0x26), /*   19 :   7  */
    ALL_ILLEGAL(0x28), ALL_ILLEGAL(0x29), ALL_ILLEGAL(0x2a), ALL_ILLEGAL(0x2b),
    /*   18 :   8  */  ALL_OPCODE (0x2d), ALL_ILLEGAL(0x2e), /*   20 :   9  */
    ALL_ILLEGAL(0x30), ALL_ILLEGAL(0x31), ALL_ILLEGAL(0x32), ALL_ILLEGAL(0x33),
    /*   52 :  10  */  ALL_OPCODE (0x35), /*   27 :  11  */  /*   13 :  12  */
    ALL_ILLEGAL(0x38), ALL_ILLEGAL(0x39), ALL_ILLEGAL(0x3a), ALL_ILLEGAL(0x3b),
    /*   12 :  13  */  ALL_OPCODE (0x3d), /*   28 :  14  */  /*   14 :  15  */
    ALL_ILLEGAL(0x40), ALL_ILLEGAL(0x41), ALL_ILLEGAL(0x42), ALL_ILLEGAL(0x43),
    ALL_OPCODE (0x44), ALL_OPCODE (0x45), /*   29 :  16  */  ALL_OPCODE (0x47),
    ALL_ILLEGAL(0x48), ALL_ILLEGAL(0x49), ALL_ILLEGAL(0x4a), ALL_ILLEGAL(0x4b),
    ALL_OPCODE (0x4c), ALL_OPCODE (0x4d), /*   30 :  17  */  ALL_OPCODE (0x4f),
    ALL_ILLEGAL(0x50), ALL_ILLEGAL(0x51), ALL_ILLEGAL(0x52), ALL_ILLEGAL(0x53),
    ALL_OPCODE (0x54), ALL_OPCODE (0x55), /*   31 :  18  */  ALL_OPCODE (0x57),
    ALL_ILLEGAL(0x58), ALL_ILLEGAL(0x59), ALL_ILLEGAL(0x5a), ALL_ILLEGAL(0x5b),
    ALL_OPCODE (0x5c), ALL_OPCODE (0x5d), /*   32 :  19  */  ALL_OPCODE (0x5f),
    ALL_ILLEGAL(0x60), /*    3 :  20  */  /*    4 :  21  */  /*    5 :  22  */
    ALL_OPCODE (0x64), ALL_OPCODE (0x65), /*   33 :  23  */  ALL_OPCODE (0x67),
    ALL_ILLEGAL(0x68), /*    9 :  24  */  /*   10 :  25  */  /*   11 :  26  */
    ALL_OPCODE (0x6c), ALL_OPCODE (0x6d), /*   34 :  27  */  ALL_OPCODE (0x6f),
    ALL_ILLEGAL(0x70), /*   15 :  28  */  /*   16 :  29  */  /*   17 :  30  */
    ALL_OPCODE (0x74), ALL_OPCODE (0x75), /*   35 :  31  */  ALL_OPCODE (0x77),
    ALL_ILLEGAL(0x78), /*   21 :  32  */  /*   22 :  33  */  /*   23 :  34  */
    ALL_OPCODE (0x7c), ALL_OPCODE (0x7d), /*   36 :  35  */  ALL_OPCODE (0x7f),
    ALL_ILLEGAL(0x80), ALL_ILLEGAL(0x81), ALL_ILLEGAL(0x82), ALL_ILLEGAL(0x83),
    /*   54 :  36  */  /*   61 :  37  */  /*   37 :  38  */  /*    7 :  39  */
    ALL_ILLEGAL(0x88), ALL_ILLEGAL(0x89), ALL_ILLEGAL(0x8a), ALL_ILLEGAL(0x8b),
    /*    6 :  40  */  /*   64 :  41  */  /*   38 :  42  */  /*    8 :  43  */
    ALL_ILLEGAL(0x90), ALL_ILLEGAL(0x91), ALL_ILLEGAL(0x92), ALL_ILLEGAL(0x93),
    /*   53 :  44  */  /*   62 :  45  */  /*   39 :  46  */  /*   25 :  47  */
    ALL_ILLEGAL(0x98), ALL_ILLEGAL(0x99), ALL_ILLEGAL(0x9a), ALL_ILLEGAL(0x9b),
    /*   24 :  48  */  /*   63 :  49  */  /*   40 :  50  */  /*   26 :  51  */
    ALL_ILLEGAL(0xa0), ALL_ILLEGAL(0xa1), ALL_ILLEGAL(0xa2), ALL_ILLEGAL(0xa3),
    ALL_OPCODE (0xa4), ALL_OPCODE (0xa5), ALL_ILLEGAL(0xa6), ALL_OPCODE (0xa7),
    ALL_ILLEGAL(0xa8), ALL_ILLEGAL(0xa9), ALL_ILLEGAL(0xaa), ALL_ILLEGAL(0xab),
    ALL_OPCODE (0xac), ALL_OPCODE (0xad), ALL_ILLEGAL(0xae), ALL_OPCODE (0xaf),
    ALL_ILLEGAL(0xb0), ALL_ILLEGAL(0xb1), ALL_ILLEGAL(0xb2), ALL_ILLEGAL(0xb3),
    ALL_OPCODE (0xb4), ALL_OPCODE (0xb5), /*   41 :  52  */  ALL_OPCODE (0xb7),
    ALL_ILLEGAL(0xb8), ALL_ILLEGAL(0xb9), ALL_ILLEGAL(0xba), ALL_ILLEGAL(0xbb),
    /*   58 :  53  */  ALL_OPCODE (0xbd), /*   42 :  54  */  ALL_OPCODE (0xbf),
    ALL_ILLEGAL(0xc0), ALL_ILLEGAL(0xc1), ALL_ILLEGAL(0xc2), ALL_ILLEGAL(0xc3),
    ALL_OPCODE (0xc4), ALL_OPCODE (0xc5), /*   43 :  55  */  ALL_OPCODE (0xc7),
    ALL_ILLEGAL(0xc8), ALL_ILLEGAL(0xc9), ALL_ILLEGAL(0xca), ALL_ILLEGAL(0xcb),
    ALL_OPCODE (0xcc), ALL_OPCODE (0xcd), /*   44 :  56  */  ALL_OPCODE (0xcf),
    ALL_ILLEGAL(0xd0), ALL_ILLEGAL(0xd1), ALL_ILLEGAL(0xd2), ALL_ILLEGAL(0xd3),
    /*    2 :  57  */  ALL_OPCODE (0xd5), /*   45 :  58  */  ALL_ILLEGAL(0xd7),
    ALL_ILLEGAL(0xd8), ALL_ILLEGAL(0xd9), ALL_ILLEGAL(0xda), ALL_ILLEGAL(0xdb),
    ALL_OPCODE (0xdc), ALL_OPCODE (0xdd), /*   46 :  59  */  ALL_ILLEGAL(0xdf),
    ALL_ILLEGAL(0xe0), ALL_ILLEGAL(0xe1), ALL_ILLEGAL(0xe2), ALL_ILLEGAL(0xe3),
    ALL_ILLEGAL(0xe4), ALL_ILLEGAL(0xe5), /*   47 :  60  */  ALL_ILLEGAL(0xe7),
    ALL_ILLEGAL(0xe8), ALL_ILLEGAL(0xe9), ALL_ILLEGAL(0xea), ALL_ILLEGAL(0xeb),
    ALL_ILLEGAL(0xec), ALL_ILLEGAL(0xed), /*   48 :  61  */  ALL_ILLEGAL(0xef),
    ALL_ILLEGAL(0xf0), ALL_ILLEGAL(0xf1), ALL_ILLEGAL(0xf2), ALL_ILLEGAL(0xf3),
    ALL_ILLEGAL(0xf4), ALL_ILLEGAL(0xf5), /*   49 :  62  */  /*    1 :  63  */
    ALL_ILLEGAL(0xf8), ALL_ILLEGAL(0xf9), ALL_ILLEGAL(0xfa), ALL_ILLEGAL(0xfb),
    ALL_ILLEGAL(0xfc), ALL_ILLEGAL(0xfd), /*   50 :  64  */  ALL_ILLEGAL(0xff),


    /* SIMD-0173: LDDW */
    /*  0:  4 */ CONDITIONAL( 0x18, FD_VM_SBPF_ENABLE_LDDW, &&interp_0x18, &&sigill),
    /*  1: 63 */ CONDITIONAL( 0xf7, FD_VM_SBPF_ENABLE_LDDW, &&sigill, &&interp_0xf7),

    /* SIMD-0173: LE */
    /*  2: 57 */ CONDITIONAL( 0xd4, FD_VM_SBPF_ENABLE_LE, &&interp_0xd4, &&sigill),

    /* SIMD-0173: LDXW, STW, STXW */
    /*  3: 20 */ CONDITIONAL( 0x61, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill, &&interp_0x8c),
    /*  4: 21 */ CONDITIONAL( 0x62, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill, &&interp_0x87),
    /*  5: 22 */ CONDITIONAL( 0x63, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill, &&interp_0x8f),
    /*  6: 40 */ CONDITIONAL( 0x8c, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&interp_0x8c, &&sigill),
    /*  7: 39 */ CONDITIONAL( 0x87, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&interp_0x87, &&interp_0x87depr),
    /*  8: 43 */ CONDITIONAL( 0x8f, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&interp_0x8f, &&sigill),

    /* SIMD-0173: LDXH, STH, STXH */
    /*  9: 24 */ CONDITIONAL( 0x69, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill, &&interp_0x3c),
    /* 10: 25 */ CONDITIONAL( 0x6a, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill, &&interp_0x37),
    /* 11: 26 */ CONDITIONAL( 0x6b, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill, &&interp_0x3f),
    /* 12: 13 */ CONDITIONAL( 0x3c, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&interp_0x3c, &&interp_0x3cdepr),
    /* 13: 12 */ CONDITIONAL( 0x37, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&interp_0x37, &&interp_0x37depr),
    /* 14: 15 */ CONDITIONAL( 0x3f, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&interp_0x3f, &&interp_0x3fdepr),

    /* SIMD-0173: LDXB, STB, STXB */
    /* 15: 28 */ CONDITIONAL( 0x71, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill, &&interp_0x2c),
    /* 16: 29 */ CONDITIONAL( 0x72, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill, &&interp_0x27),
    /* 17: 30 */ CONDITIONAL( 0x73, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill, &&interp_0x2f),
    /* 18:  8 */ CONDITIONAL( 0x2c, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&interp_0x2c, &&interp_0x2cdepr),
    /* 19:  7 */ CONDITIONAL( 0x27, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&interp_0x27, &&interp_0x27depr),
    /* 20:  9 */ CONDITIONAL( 0x2f, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&interp_0x2f, &&interp_0x2fdepr),

    /* SIMD-0173: LDXDW, STDW, STXDW */
    /* 21: 32 */ CONDITIONAL( 0x79, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill, &&interp_0x9c),
    /* 22: 33 */ CONDITIONAL( 0x7a, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill, &&interp_0x97),
    /* 23: 34 */ CONDITIONAL( 0x7b, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&sigill, &&interp_0x9f),
    /* 24: 48 */ CONDITIONAL( 0x9c, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&interp_0x9c, &&interp_0x9cdepr),
    /* 25: 47 */ CONDITIONAL( 0x97, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&interp_0x97, &&interp_0x97depr),
    /* 26: 51 */ CONDITIONAL( 0x9f, FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES, &&interp_0x9f, &&interp_0x9fdepr),

    /* SIMD-0174: PQR */
    /* 27: 11 */ CONDITIONAL( 0x36, FD_VM_SBPF_ENABLE_PQR, &&interp_0x36, &&sigill),
    /* 28: 14 */ CONDITIONAL( 0x3e, FD_VM_SBPF_ENABLE_PQR, &&interp_0x3e, &&sigill),
    /* 29: 16 */ CONDITIONAL( 0x46, FD_VM_SBPF_ENABLE_PQR, &&interp_0x46, &&sigill),
    /* 30: 17 */ CONDITIONAL( 0x4e, FD_VM_SBPF_ENABLE_PQR, &&interp_0x4e, &&sigill),
    /* 31: 18 */ CONDITIONAL( 0x56, FD_VM_SBPF_ENABLE_PQR, &&interp_0x56, &&sigill),
    /* 32: 19 */ CONDITIONAL( 0x5e, FD_VM_SBPF_ENABLE_PQR, &&interp_0x5e, &&sigill),
    /* 33: 23 */ CONDITIONAL( 0x66, FD_VM_SBPF_ENABLE_PQR, &&interp_0x66, &&sigill),
    /* 34: 27 */ CONDITIONAL( 0x6e, FD_VM_SBPF_ENABLE_PQR, &&interp_0x6e, &&sigill),
    /* 35: 31 */ CONDITIONAL( 0x76, FD_VM_SBPF_ENABLE_PQR, &&interp_0x76, &&sigill),
    /* 36: 35 */ CONDITIONAL( 0x7e, FD_VM_SBPF_ENABLE_PQR, &&interp_0x7e, &&sigill),
    /* 37: 38 */ CONDITIONAL( 0x86, FD_VM_SBPF_ENABLE_PQR, &&interp_0x86, &&sigill),
    /* 38: 42 */ CONDITIONAL( 0x8e, FD_VM_SBPF_ENABLE_PQR, &&interp_0x8e, &&sigill),
    /* 39: 46 */ CONDITIONAL( 0x96, FD_VM_SBPF_ENABLE_PQR, &&interp_0x96, &&sigill),
    /* 40: 50 */ CONDITIONAL( 0x9e, FD_VM_SBPF_ENABLE_PQR, &&interp_0x9e, &&sigill),
    /* 41: 52 */ CONDITIONAL( 0xb6, FD_VM_SBPF_ENABLE_PQR, &&interp_0xb6, &&sigill),
    /* 42: 54 */ CONDITIONAL( 0xbe, FD_VM_SBPF_ENABLE_PQR, &&interp_0xbe, &&sigill),
    /* 43: 55 */ CONDITIONAL( 0xc6, FD_VM_SBPF_ENABLE_PQR, &&interp_0xc6, &&sigill),
    /* 44: 56 */ CONDITIONAL( 0xce, FD_VM_SBPF_ENABLE_PQR, &&interp_0xce, &&sigill),
    /* 45: 58 */ CONDITIONAL( 0xd6, FD_VM_SBPF_ENABLE_PQR, &&interp_0xd6, &&sigill),
    /* 46: 59 */ CONDITIONAL( 0xde, FD_VM_SBPF_ENABLE_PQR, &&interp_0xde, &&sigill),
    /* 47: 60 */ CONDITIONAL( 0xe6, FD_VM_SBPF_ENABLE_PQR, &&interp_0xe6, &&sigill),
    /* 48: 61 */ CONDITIONAL( 0xee, FD_VM_SBPF_ENABLE_PQR, &&interp_0xee, &&sigill),
    /* 49: 62 */ CONDITIONAL( 0xf6, FD_VM_SBPF_ENABLE_PQR, &&interp_0xf6, &&sigill),
    /* 50: 64 */ CONDITIONAL( 0xfe, FD_VM_SBPF_ENABLE_PQR, &&interp_0xfe, &&sigill),

    /* SIMD-0174: disable MUL, DIV, MOD */
    /* 51:  6 */ CONDITIONAL( 0x24, FD_VM_SBPF_ENABLE_PQR, &&sigill, &&interp_0x24),
    /* 52: 10 */ CONDITIONAL( 0x34, FD_VM_SBPF_ENABLE_PQR, &&sigill, &&interp_0x34),
    /* 53: 44 */ CONDITIONAL( 0x94, FD_VM_SBPF_ENABLE_PQR, &&sigill, &&interp_0x94),

    /* SIMD-0174: NEG */
    /* 54: 36 */ CONDITIONAL( 0x84, FD_VM_SBPF_ENABLE_NEG, &&interp_0x84, &&sigill),

    /* SIMD-0174: Explicit Sign Extension + Register Immediate Subtraction.
       Note: 0x14 is affected by both. */
    /* 55:  0 */ CONDITIONAL( 0x04, FD_VM_SBPF_EXPLICIT_SIGN_EXT, &&interp_0x04, &&interp_0x04depr),
    /* 56:  1 */ CONDITIONAL( 0x0c, FD_VM_SBPF_EXPLICIT_SIGN_EXT, &&interp_0x0c, &&interp_0x0cdepr),
    /* 57:  5 */ CONDITIONAL( 0x1c, FD_VM_SBPF_EXPLICIT_SIGN_EXT, &&interp_0x1c, &&interp_0x1cdepr),
    /* 58: 53 */ CONDITIONAL( 0xbc, FD_VM_SBPF_EXPLICIT_SIGN_EXT, &&interp_0xbc, &&interp_0xbcdepr),
    /* 59:  2 */ CONDITIONAL( 0x14, FD_VM_SBPF_SWAP_SUB_REG_IMM_OPERANDS, &&interp_0x14, &&interp_0x14depr),
    /* 60:  3 */ CONDITIONAL( 0x17, FD_VM_SBPF_SWAP_SUB_REG_IMM_OPERANDS, &&interp_0x17, &&interp_0x17depr),

    /* SIMD-0178: static syscalls */
    /* 61: 37 */ CONDITIONAL( 0x85, FD_VM_SBPF_STATIC_SYSCALLS, &&interp_0x85, &&interp_0x85depr),
    /* 62: 45 */ CONDITIONAL( 0x95, FD_VM_SBPF_STATIC_SYSCALLS, &&interp_0x95, &&interp_0x9d),
    /* 63: 49 */ CONDITIONAL( 0x9d, FD_VM_SBPF_STATIC_SYSCALLS, &&interp_0x9d, &&sigill),

    /* SIMD-0173 + SIMD-0179: CALLX */
    /* 64: 41 */ CONDITIONAL( 0x8d, FD_VM_SBPF_STATIC_SYSCALLS, &&interp_0x8d, &&interp_0x8ddepr),

#   undef ALL_ILLEGAL
#   undef ALL_OPCODE
#   undef CONDITIONAL
#   undef OPCODE
  };
