#include "fd_sbpf_opcode.h"

#include "../../util/fd_util.h"

/* Opcode ID checks ***************************************************/

/* Load opcodes */

FD_STATIC_ASSERT( 0x71==SBPF_OP_LDXB,       opcode );
FD_STATIC_ASSERT( 0x69==SBPF_OP_LDXH,       opcode );
FD_STATIC_ASSERT( 0x61==SBPF_OP_LDXW,       opcode );
FD_STATIC_ASSERT( 0x79==SBPF_OP_LDXDW,      opcode );

/* Store opcodes */

FD_STATIC_ASSERT( 0x72==SBPF_OP_STB,        opcode );
FD_STATIC_ASSERT( 0x6a==SBPF_OP_STH,        opcode );
FD_STATIC_ASSERT( 0x62==SBPF_OP_STW,        opcode );
FD_STATIC_ASSERT( 0x7a==SBPF_OP_STDW,       opcode );

FD_STATIC_ASSERT( 0x73==SBPF_OP_STXB,       opcode );
FD_STATIC_ASSERT( 0x6b==SBPF_OP_STXH,       opcode );
FD_STATIC_ASSERT( 0x63==SBPF_OP_STXW,       opcode );
FD_STATIC_ASSERT( 0x7b==SBPF_OP_STXDW,      opcode );

/* 32-bit arithmetic opcodes */

FD_STATIC_ASSERT( 0x04==SBPF_OP_ADD32_IMM,  opcode );
FD_STATIC_ASSERT( 0x0c==SBPF_OP_ADD32_REG,  opcode );
FD_STATIC_ASSERT( 0x14==SBPF_OP_SUB32_IMM,  opcode );
FD_STATIC_ASSERT( 0x1c==SBPF_OP_SUB32_REG,  opcode );
FD_STATIC_ASSERT( 0x24==SBPF_OP_MUL32_IMM,  opcode );
FD_STATIC_ASSERT( 0x2c==SBPF_OP_MUL32_REG,  opcode );
FD_STATIC_ASSERT( 0x34==SBPF_OP_DIV32_IMM,  opcode );
FD_STATIC_ASSERT( 0x3c==SBPF_OP_DIV32_REG,  opcode );
FD_STATIC_ASSERT( 0x44==SBPF_OP_OR32_IMM,   opcode );
FD_STATIC_ASSERT( 0x4c==SBPF_OP_OR32_REG,   opcode );
FD_STATIC_ASSERT( 0x54==SBPF_OP_AND32_IMM,  opcode );
FD_STATIC_ASSERT( 0x5c==SBPF_OP_AND32_REG,  opcode );
FD_STATIC_ASSERT( 0x64==SBPF_OP_LSH32_IMM,  opcode );
FD_STATIC_ASSERT( 0x6c==SBPF_OP_LSH32_REG,  opcode );
FD_STATIC_ASSERT( 0x74==SBPF_OP_RSH32_IMM,  opcode );
FD_STATIC_ASSERT( 0x7c==SBPF_OP_RSH32_REG,  opcode );
FD_STATIC_ASSERT( 0x84==SBPF_OP_NEG32,      opcode );
FD_STATIC_ASSERT( 0x94==SBPF_OP_MOD32_IMM,  opcode );
FD_STATIC_ASSERT( 0x9c==SBPF_OP_MOD32_REG,  opcode );
FD_STATIC_ASSERT( 0xa4==SBPF_OP_XOR32_IMM,  opcode );
FD_STATIC_ASSERT( 0xac==SBPF_OP_XOR32_REG,  opcode );
FD_STATIC_ASSERT( 0xb4==SBPF_OP_MOV32_IMM,  opcode );
FD_STATIC_ASSERT( 0xbc==SBPF_OP_MOV32_REG,  opcode );
FD_STATIC_ASSERT( 0xc4==SBPF_OP_ARSH32_IMM, opcode );
FD_STATIC_ASSERT( 0xcc==SBPF_OP_ARSH32_REG, opcode );
FD_STATIC_ASSERT( 0xe4==SBPF_OP_SDIV32_IMM, opcode );
FD_STATIC_ASSERT( 0xec==SBPF_OP_SDIV32_REG, opcode );

/* 64-bit arithmetic opcodes */

FD_STATIC_ASSERT( 0x07==SBPF_OP_ADD64_IMM,  opcode );
FD_STATIC_ASSERT( 0x0f==SBPF_OP_ADD64_REG,  opcode );
FD_STATIC_ASSERT( 0x17==SBPF_OP_SUB64_IMM,  opcode );
FD_STATIC_ASSERT( 0x1f==SBPF_OP_SUB64_REG,  opcode );
FD_STATIC_ASSERT( 0x27==SBPF_OP_MUL64_IMM,  opcode );
FD_STATIC_ASSERT( 0x2f==SBPF_OP_MUL64_REG,  opcode );
FD_STATIC_ASSERT( 0x37==SBPF_OP_DIV64_IMM,  opcode );
FD_STATIC_ASSERT( 0x3f==SBPF_OP_DIV64_REG,  opcode );
FD_STATIC_ASSERT( 0x47==SBPF_OP_OR64_IMM,   opcode );
FD_STATIC_ASSERT( 0x4f==SBPF_OP_OR64_REG,   opcode );
FD_STATIC_ASSERT( 0x57==SBPF_OP_AND64_IMM,  opcode );
FD_STATIC_ASSERT( 0x5f==SBPF_OP_AND64_REG,  opcode );
FD_STATIC_ASSERT( 0x67==SBPF_OP_LSH64_IMM,  opcode );
FD_STATIC_ASSERT( 0x6f==SBPF_OP_LSH64_REG,  opcode );
FD_STATIC_ASSERT( 0x77==SBPF_OP_RSH64_IMM,  opcode );
FD_STATIC_ASSERT( 0x7f==SBPF_OP_RSH64_REG,  opcode );
FD_STATIC_ASSERT( 0x87==SBPF_OP_NEG64,      opcode );
FD_STATIC_ASSERT( 0x97==SBPF_OP_MOD64_IMM,  opcode );
FD_STATIC_ASSERT( 0x9f==SBPF_OP_MOD64_REG,  opcode );
FD_STATIC_ASSERT( 0xa7==SBPF_OP_XOR64_IMM,  opcode );
FD_STATIC_ASSERT( 0xaf==SBPF_OP_XOR64_REG,  opcode );
FD_STATIC_ASSERT( 0xb7==SBPF_OP_MOV64_IMM,  opcode );
FD_STATIC_ASSERT( 0xbf==SBPF_OP_MOV64_REG,  opcode );
FD_STATIC_ASSERT( 0xc7==SBPF_OP_ARSH64_IMM, opcode );
FD_STATIC_ASSERT( 0xcf==SBPF_OP_ARSH64_REG, opcode );
FD_STATIC_ASSERT( 0xe7==SBPF_OP_SDIV64_IMM, opcode );
FD_STATIC_ASSERT( 0xef==SBPF_OP_SDIV64_REG, opcode );

/* Control flow opcodes */

FD_STATIC_ASSERT( 0x05==SBPF_OP_JA,         opcode );
FD_STATIC_ASSERT( 0x15==SBPF_OP_JEQ_IMM,    opcode );
FD_STATIC_ASSERT( 0x1d==SBPF_OP_JEQ_REG,    opcode );
FD_STATIC_ASSERT( 0x25==SBPF_OP_JGT_IMM,    opcode );
FD_STATIC_ASSERT( 0x2d==SBPF_OP_JGT_REG,    opcode );
FD_STATIC_ASSERT( 0x35==SBPF_OP_JGE_IMM,    opcode );
FD_STATIC_ASSERT( 0x3d==SBPF_OP_JGE_REG,    opcode );
FD_STATIC_ASSERT( 0x45==SBPF_OP_JSET_IMM,   opcode );
FD_STATIC_ASSERT( 0x4d==SBPF_OP_JSET_REG,   opcode );
FD_STATIC_ASSERT( 0x55==SBPF_OP_JNE_IMM,    opcode );
FD_STATIC_ASSERT( 0x5d==SBPF_OP_JNE_REG,    opcode );
FD_STATIC_ASSERT( 0x65==SBPF_OP_JSGT_IMM,   opcode );
FD_STATIC_ASSERT( 0x6d==SBPF_OP_JSGT_REG,   opcode );
FD_STATIC_ASSERT( 0x75==SBPF_OP_JSGE_IMM,   opcode );
FD_STATIC_ASSERT( 0x7d==SBPF_OP_JSGE_REG,   opcode );
FD_STATIC_ASSERT( 0xa5==SBPF_OP_JLT_IMM,    opcode );
FD_STATIC_ASSERT( 0xad==SBPF_OP_JLT_REG,    opcode );
FD_STATIC_ASSERT( 0xb5==SBPF_OP_JLE_IMM,    opcode );
FD_STATIC_ASSERT( 0xbd==SBPF_OP_JLE_REG,    opcode );
FD_STATIC_ASSERT( 0xc5==SBPF_OP_JSLT_IMM,   opcode );
FD_STATIC_ASSERT( 0xcd==SBPF_OP_JSLT_REG,   opcode );
FD_STATIC_ASSERT( 0xd5==SBPF_OP_JSLE_IMM,   opcode );
FD_STATIC_ASSERT( 0xdd==SBPF_OP_JSLE_REG,   opcode );

/* Function call opcodes */

FD_STATIC_ASSERT( 0x85==SBPF_OP_CALL,       opcode );
FD_STATIC_ASSERT( 0x8d==SBPF_OP_CALLX,      opcode );
FD_STATIC_ASSERT( 0x95==SBPF_OP_EXIT,       opcode );

/* Miscellaneous opcodes */

FD_STATIC_ASSERT( 0x18==SBPF_OP_LDDW,       opcode );
FD_STATIC_ASSERT( 0xd4==SBPF_OP_LE,         opcode );
FD_STATIC_ASSERT( 0xdc==SBPF_OP_BE,         opcode );

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
