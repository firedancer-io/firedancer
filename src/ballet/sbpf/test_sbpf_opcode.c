#include "fd_sbpf.h"

#include "../../util/fd_util.h"

/* Opcode ID checks ***************************************************/

/* Load opcodes */

FD_STATIC_ASSERT( 0x71==BPF_OP_LDXB,       opcode );
FD_STATIC_ASSERT( 0x69==BPF_OP_LDXH,       opcode );
FD_STATIC_ASSERT( 0x61==BPF_OP_LDXW,       opcode );
FD_STATIC_ASSERT( 0x79==BPF_OP_LDXDW,      opcode );

/* Store opcodes */

FD_STATIC_ASSERT( 0x72==BPF_OP_STB,        opcode );
FD_STATIC_ASSERT( 0x6a==BPF_OP_STH,        opcode );
FD_STATIC_ASSERT( 0x62==BPF_OP_STW,        opcode );
FD_STATIC_ASSERT( 0x7a==BPF_OP_STDW,       opcode );

FD_STATIC_ASSERT( 0x73==BPF_OP_STXB,       opcode );
FD_STATIC_ASSERT( 0x6b==BPF_OP_STXH,       opcode );
FD_STATIC_ASSERT( 0x63==BPF_OP_STXW,       opcode );
FD_STATIC_ASSERT( 0x7b==BPF_OP_STXDW,      opcode );

/* 32-bit arithmetic opcodes */

FD_STATIC_ASSERT( 0x04==BPF_OP_ADD32_IMM,  opcode );
FD_STATIC_ASSERT( 0x0c==BPF_OP_ADD32_REG,  opcode );
FD_STATIC_ASSERT( 0x14==BPF_OP_SUB32_IMM,  opcode );
FD_STATIC_ASSERT( 0x1c==BPF_OP_SUB32_REG,  opcode );
FD_STATIC_ASSERT( 0x24==BPF_OP_MUL32_IMM,  opcode );
FD_STATIC_ASSERT( 0x2c==BPF_OP_MUL32_REG,  opcode );
FD_STATIC_ASSERT( 0x34==BPF_OP_DIV32_IMM,  opcode );
FD_STATIC_ASSERT( 0x3c==BPF_OP_DIV32_REG,  opcode );
FD_STATIC_ASSERT( 0x44==BPF_OP_OR32_IMM,   opcode );
FD_STATIC_ASSERT( 0x4c==BPF_OP_OR32_REG,   opcode );
FD_STATIC_ASSERT( 0x54==BPF_OP_AND32_IMM,  opcode );
FD_STATIC_ASSERT( 0x5c==BPF_OP_AND32_REG,  opcode );
FD_STATIC_ASSERT( 0x64==BPF_OP_LSH32_IMM,  opcode );
FD_STATIC_ASSERT( 0x6c==BPF_OP_LSH32_REG,  opcode );
FD_STATIC_ASSERT( 0x74==BPF_OP_RSH32_IMM,  opcode );
FD_STATIC_ASSERT( 0x7c==BPF_OP_RSH32_REG,  opcode );
FD_STATIC_ASSERT( 0x84==BPF_OP_NEG32,      opcode );
FD_STATIC_ASSERT( 0x94==BPF_OP_MOD32_IMM,  opcode );
FD_STATIC_ASSERT( 0x9c==BPF_OP_MOD32_REG,  opcode );
FD_STATIC_ASSERT( 0xa4==BPF_OP_XOR32_IMM,  opcode );
FD_STATIC_ASSERT( 0xac==BPF_OP_XOR32_REG,  opcode );
FD_STATIC_ASSERT( 0xb4==BPF_OP_MOV32_IMM,  opcode );
FD_STATIC_ASSERT( 0xbc==BPF_OP_MOV32_REG,  opcode );
FD_STATIC_ASSERT( 0xc4==BPF_OP_ARSH32_IMM, opcode );
FD_STATIC_ASSERT( 0xcc==BPF_OP_ARSH32_REG, opcode );
FD_STATIC_ASSERT( 0xe4==BPF_OP_SDIV32_IMM, opcode );
FD_STATIC_ASSERT( 0xec==BPF_OP_SDIV32_REG, opcode );

/* 64-bit arithmetic opcodes */

FD_STATIC_ASSERT( 0x07==BPF_OP_ADD64_IMM,  opcode );
FD_STATIC_ASSERT( 0x0f==BPF_OP_ADD64_REG,  opcode );
FD_STATIC_ASSERT( 0x17==BPF_OP_SUB64_IMM,  opcode );
FD_STATIC_ASSERT( 0x1f==BPF_OP_SUB64_REG,  opcode );
FD_STATIC_ASSERT( 0x27==BPF_OP_MUL64_IMM,  opcode );
FD_STATIC_ASSERT( 0x2f==BPF_OP_MUL64_REG,  opcode );
FD_STATIC_ASSERT( 0x37==BPF_OP_DIV64_IMM,  opcode );
FD_STATIC_ASSERT( 0x3f==BPF_OP_DIV64_REG,  opcode );
FD_STATIC_ASSERT( 0x47==BPF_OP_OR64_IMM,   opcode );
FD_STATIC_ASSERT( 0x4f==BPF_OP_OR64_REG,   opcode );
FD_STATIC_ASSERT( 0x57==BPF_OP_AND64_IMM,  opcode );
FD_STATIC_ASSERT( 0x5f==BPF_OP_AND64_REG,  opcode );
FD_STATIC_ASSERT( 0x67==BPF_OP_LSH64_IMM,  opcode );
FD_STATIC_ASSERT( 0x6f==BPF_OP_LSH64_REG,  opcode );
FD_STATIC_ASSERT( 0x77==BPF_OP_RSH64_IMM,  opcode );
FD_STATIC_ASSERT( 0x7f==BPF_OP_RSH64_REG,  opcode );
FD_STATIC_ASSERT( 0x87==BPF_OP_NEG64,      opcode );
FD_STATIC_ASSERT( 0x97==BPF_OP_MOD64_IMM,  opcode );
FD_STATIC_ASSERT( 0x9f==BPF_OP_MOD64_REG,  opcode );
FD_STATIC_ASSERT( 0xa7==BPF_OP_XOR64_IMM,  opcode );
FD_STATIC_ASSERT( 0xaf==BPF_OP_XOR64_REG,  opcode );
FD_STATIC_ASSERT( 0xb7==BPF_OP_MOV64_IMM,  opcode );
FD_STATIC_ASSERT( 0xbf==BPF_OP_MOV64_REG,  opcode );
FD_STATIC_ASSERT( 0xc7==BPF_OP_ARSH64_IMM, opcode );
FD_STATIC_ASSERT( 0xcf==BPF_OP_ARSH64_REG, opcode );
FD_STATIC_ASSERT( 0xe7==BPF_OP_SDIV64_IMM, opcode );
FD_STATIC_ASSERT( 0xef==BPF_OP_SDIV64_REG, opcode );

/* Control flow opcodes */

FD_STATIC_ASSERT( 0x05==BPF_OP_JA,         opcode );
FD_STATIC_ASSERT( 0x15==BPF_OP_JEQ_IMM,    opcode );
FD_STATIC_ASSERT( 0x1d==BPF_OP_JEQ_REG,    opcode );
FD_STATIC_ASSERT( 0x25==BPF_OP_JGT_IMM,    opcode );
FD_STATIC_ASSERT( 0x2d==BPF_OP_JGT_REG,    opcode );
FD_STATIC_ASSERT( 0x35==BPF_OP_JGE_IMM,    opcode );
FD_STATIC_ASSERT( 0x3d==BPF_OP_JGE_REG,    opcode );
FD_STATIC_ASSERT( 0x45==BPF_OP_JSET_IMM,   opcode );
FD_STATIC_ASSERT( 0x4d==BPF_OP_JSET_REG,   opcode );
FD_STATIC_ASSERT( 0x55==BPF_OP_JNE_IMM,    opcode );
FD_STATIC_ASSERT( 0x5d==BPF_OP_JNE_REG,    opcode );
FD_STATIC_ASSERT( 0x65==BPF_OP_JSGT_IMM,   opcode );
FD_STATIC_ASSERT( 0x6d==BPF_OP_JSGT_REG,   opcode );
FD_STATIC_ASSERT( 0x75==BPF_OP_JSGE_IMM,   opcode );
FD_STATIC_ASSERT( 0x7d==BPF_OP_JSGE_REG,   opcode );
FD_STATIC_ASSERT( 0xa5==BPF_OP_JLT_IMM,    opcode );
FD_STATIC_ASSERT( 0xad==BPF_OP_JLT_REG,    opcode );
FD_STATIC_ASSERT( 0xb5==BPF_OP_JLE_IMM,    opcode );
FD_STATIC_ASSERT( 0xbd==BPF_OP_JLE_REG,    opcode );
FD_STATIC_ASSERT( 0xc5==BPF_OP_JSLT_IMM,   opcode );
FD_STATIC_ASSERT( 0xcd==BPF_OP_JSLT_REG,   opcode );
FD_STATIC_ASSERT( 0xd5==BPF_OP_JSLE_IMM,   opcode );
FD_STATIC_ASSERT( 0xdd==BPF_OP_JSLE_REG,   opcode );

/* Function call opcodes */

FD_STATIC_ASSERT( 0x85==BPF_OP_CALL,       opcode );
FD_STATIC_ASSERT( 0x8d==BPF_OP_CALLX,      opcode );
FD_STATIC_ASSERT( 0x95==BPF_OP_EXIT,       opcode );

/* Miscellaneous opcodes */

FD_STATIC_ASSERT( 0x18==BPF_OP_LDDW,       opcode );
FD_STATIC_ASSERT( 0xd4==BPF_OP_LE,         opcode );
FD_STATIC_ASSERT( 0xdc==BPF_OP_BE,         opcode );

/* Runtime checks *****************************************************/

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Add further tests here */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
