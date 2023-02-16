#ifndef HEADER_fd_src_ballet_sbpf_fd_sbpf_opcode_h
#define HEADER_fd_src_ballet_sbpf_fd_sbpf_opcode_h

/* This header defines the opcodes used in the sBPF (Solana BPF)
   instruction set. The opcode is the first byte of each instruction
   slot. */

/* Opcode encoding helpers ********************************************/

/* SBPF_OPC: Opcode number given the operation class, mode, sub-operation. */
#define SBPF_OPC( class, mode, variant ) (uchar)( (SBPF_CLASS_##class)|(SBPF_##mode)|(SBPF_##variant) )

/* SBPF_CLASS_{...}: Instruction class */
#define SBPF_CLASS_LD     ((uchar)0x00) /* Load                        */
#define SBPF_CLASS_LDX    ((uchar)0x01) /* Load Indexed                */
#define SBPF_CLASS_ST     ((uchar)0x02) /* Store                       */
#define SBPF_CLASS_STX    ((uchar)0x03) /* Store Indexed               */
#define SBPF_CLASS_ALU32  ((uchar)0x04) /* 32-bit integer arithmetic   */
#define SBPF_CLASS_JMP    ((uchar)0x05) /* Control flow                */
#define SBPF_CLASS_ALU64  ((uchar)0x07) /* 64-bit integer arithmetic   */

/* SBPF_SRC_{...}: Source operand mode */
#define SBPF_SRC_IMM      ((uchar)0x00) /* Use immediate field         */
#define SBPF_SRC_REG      ((uchar)0x08) /* Use source register         */

/* SBPF_SZ_{...}: Operand size modifier */
#define SBPF_SZ_UCHAR     ((uchar)0x10)
#define SBPF_SZ_USHORT    ((uchar)0x08)
#define SBPF_SZ_UINT      ((uchar)0x00)
#define SBPF_SZ_ULONG     ((uchar)0x18)

/* SBPF_ADDR_{...}: Addressing mode */
#define SBPF_ADDR_IMM     ((uchar)0x00) /* Use immediate field         */
#define SBPF_ADDR_MEM     ((uchar)0x60) /* Use src+offset fields       */

/* SBPF_ALU_{...}: Integer arithmetic operation identifier */
#define SBPF_ALU_ADD      ((uchar)0x00) /* Add                         */
#define SBPF_ALU_SUB      ((uchar)0x10) /* Subtract                    */
#define SBPF_ALU_MUL      ((uchar)0x20) /* Multiply                    */
#define SBPF_ALU_DIV      ((uchar)0x30) /* Unsigned divide             */
#define SBPF_ALU_OR       ((uchar)0x40) /* Bitwise OR                  */
#define SBPF_ALU_AND      ((uchar)0x50) /* Bitwise AND                 */
#define SBPF_ALU_LSH      ((uchar)0x60) /* Bitwise left shift          */
#define SBPF_ALU_RSH      ((uchar)0x70) /* Bitwise right shift         */
#define SBPF_ALU_NEG      ((uchar)0x80) /* Negate                      */
#define SBPF_ALU_MOD      ((uchar)0x90) /* Modulo                      */
#define SBPF_ALU_XOR      ((uchar)0xa0) /* Bitwise XOR                 */
#define SBPF_ALU_MOV      ((uchar)0xb0) /* Move                        */
#define SBPF_ALU_ARSH     ((uchar)0xc0) /* Arithmetic right shift      */
#define SBPF_ALU_END      ((uchar)0xd0) /* Endianness conversion       */
#define SBPF_ALU_SDIV     ((uchar)0xe0) /* Signed divide               */

/* SBPF_JMP_{...}: Jump condition modes */
#define SBPF_JMP_A        ((uchar)0x00) /* Always                      */
#define SBPF_JMP_EQ       ((uchar)0x10) /* If equal                    */
#define SBPF_JMP_GT       ((uchar)0x20) /* If greater than             */
#define SBPF_JMP_GE       ((uchar)0x30) /* If greater or equal         */
#define SBPF_JMP_SET      ((uchar)0x40) /* If bit set in mask          */
#define SBPF_JMP_NE       ((uchar)0x50) /* If not equal                */
#define SBPF_JMP_SGT      ((uchar)0x60) /* If signed greater than      */
#define SBPF_JMP_SGE      ((uchar)0x70) /* If signed greater or equal  */
#define SBPF_JMP_CALL     ((uchar)0x80) /* Always, function call       */
#define SBPF_JMP_EXIT     ((uchar)0x90) /* Always, function return     */
#define SBPF_JMP_LT       ((uchar)0xa0) /* If less than                */
#define SBPF_JMP_LE       ((uchar)0xb0) /* If less or equal            */
#define SBPF_JMP_SLT      ((uchar)0xc0) /* If signed less than         */
#define SBPF_JMP_SLE      ((uchar)0xd0) /* If signed less or equal     */

/* Load opcodes *******************************************************/

/* SBPF_OP_LDX{B,H,W,DW}: Load GPR from memory and zero upper. */
#define SBPF_OP_LDXB        SBPF_OPC( LDX,   ADDR_MEM, SZ_UCHAR  )
#define SBPF_OP_LDXH        SBPF_OPC( LDX,   ADDR_MEM, SZ_USHORT )
#define SBPF_OP_LDXW        SBPF_OPC( LDX,   ADDR_MEM, SZ_UINT   )
#define SBPF_OP_LDXDW       SBPF_OPC( LDX,   ADDR_MEM, SZ_ULONG  )

/* Store opcodes ******************************************************/

/* SBPF_OP_ST{B,H,W}: Store immediate to memory.

   SBPF_OP_STDW: Store 32-bit immediate and 32-bit zero word to memory. */
#define SBPF_OP_STB         SBPF_OPC( ST,    ADDR_MEM, SZ_UCHAR  )
#define SBPF_OP_STH         SBPF_OPC( ST,    ADDR_MEM, SZ_USHORT )
#define SBPF_OP_STW         SBPF_OPC( ST,    ADDR_MEM, SZ_UINT   )
#define SBPF_OP_STDW        SBPF_OPC( ST,    ADDR_MEM, SZ_ULONG  )

/* SBPF_OP_STX{B,H,W,DW}: Store GPR to memory. */
#define SBPF_OP_STXB        SBPF_OPC( STX,   ADDR_MEM, SZ_UCHAR  )
#define SBPF_OP_STXH        SBPF_OPC( STX,   ADDR_MEM, SZ_USHORT )
#define SBPF_OP_STXW        SBPF_OPC( STX,   ADDR_MEM, SZ_UINT   )
#define SBPF_OP_STXDW       SBPF_OPC( STX,   ADDR_MEM, SZ_ULONG  )

/* 32-bit arithmetic opcodes ******************************************/

/* SBF_OP_{...}32_IMM: Compute binary operation given lower 32 bits of
   dest register and 32-bit immediate, store result into lower 32 bits
   of dest, and zero upper.

   SBF_OP_{...}32_REG: Compute binary operation given lower 32 bits of
   dest and src registers, store result into lower 32 bits of dest, and
   zero upper.

   SBF_OP_{...}32: Compute unary operation on lower 32 bits of dest
   register, store result into lower 32 bits of dest, and zero upper. */
#define SBPF_OP_ADD32_IMM   SBPF_OPC( ALU32, SRC_IMM,  ALU_ADD   )
#define SBPF_OP_ADD32_REG   SBPF_OPC( ALU32, SRC_REG,  ALU_ADD   )
#define SBPF_OP_SUB32_IMM   SBPF_OPC( ALU32, SRC_IMM,  ALU_SUB   )
#define SBPF_OP_SUB32_REG   SBPF_OPC( ALU32, SRC_REG,  ALU_SUB   )
#define SBPF_OP_MUL32_IMM   SBPF_OPC( ALU32, SRC_IMM,  ALU_MUL   )
#define SBPF_OP_MUL32_REG   SBPF_OPC( ALU32, SRC_REG,  ALU_MUL   )
#define SBPF_OP_DIV32_IMM   SBPF_OPC( ALU32, SRC_IMM,  ALU_DIV   )
#define SBPF_OP_DIV32_REG   SBPF_OPC( ALU32, SRC_REG,  ALU_DIV   )
#define SBPF_OP_OR32_IMM    SBPF_OPC( ALU32, SRC_IMM,  ALU_OR    )
#define SBPF_OP_OR32_REG    SBPF_OPC( ALU32, SRC_REG,  ALU_OR    )
#define SBPF_OP_AND32_IMM   SBPF_OPC( ALU32, SRC_IMM,  ALU_AND   )
#define SBPF_OP_AND32_REG   SBPF_OPC( ALU32, SRC_REG,  ALU_AND   )
#define SBPF_OP_LSH32_IMM   SBPF_OPC( ALU32, SRC_IMM,  ALU_LSH   )
#define SBPF_OP_LSH32_REG   SBPF_OPC( ALU32, SRC_REG,  ALU_LSH   )
#define SBPF_OP_RSH32_IMM   SBPF_OPC( ALU32, SRC_IMM,  ALU_RSH   )
#define SBPF_OP_RSH32_REG   SBPF_OPC( ALU32, SRC_REG,  ALU_RSH   )
#define SBPF_OP_NEG32       SBPF_OPC( ALU32, SRC_IMM,  ALU_NEG   )
#define SBPF_OP_MOD32_IMM   SBPF_OPC( ALU32, SRC_IMM,  ALU_MOD   )
#define SBPF_OP_MOD32_REG   SBPF_OPC( ALU32, SRC_REG,  ALU_MOD   )
#define SBPF_OP_XOR32_IMM   SBPF_OPC( ALU32, SRC_IMM,  ALU_XOR   )
#define SBPF_OP_XOR32_REG   SBPF_OPC( ALU32, SRC_REG,  ALU_XOR   )
#define SBPF_OP_MOV32_IMM   SBPF_OPC( ALU32, SRC_IMM,  ALU_MOV   )
#define SBPF_OP_MOV32_REG   SBPF_OPC( ALU32, SRC_REG,  ALU_MOV   )
#define SBPF_OP_ARSH32_IMM  SBPF_OPC( ALU32, SRC_IMM,  ALU_ARSH  )
#define SBPF_OP_ARSH32_REG  SBPF_OPC( ALU32, SRC_REG,  ALU_ARSH  )
#define SBPF_OP_SDIV32_IMM  SBPF_OPC( ALU32, SRC_IMM,  ALU_SDIV  )
#define SBPF_OP_SDIV32_REG  SBPF_OPC( ALU32, SRC_REG,  ALU_SDIV  )

/* 64-bit arithmetic opcodes ******************************************/

/* SBF_OP_{...}64_IMM: Compute binary operation given dest register and
   immediate, and store result into dest.

   SBF_OP_{...}64_REG: Compute binary operation given dest and src
   registers, and store result into dest.

   SBF_OP_{...}64: Compute unary operation given dest register, and
   store result into dest. */
#define SBPF_OP_ADD64_IMM   SBPF_OPC( ALU64, SRC_IMM,  ALU_ADD   )
#define SBPF_OP_ADD64_REG   SBPF_OPC( ALU64, SRC_REG,  ALU_ADD   )
#define SBPF_OP_SUB64_IMM   SBPF_OPC( ALU64, SRC_IMM,  ALU_SUB   )
#define SBPF_OP_SUB64_REG   SBPF_OPC( ALU64, SRC_REG,  ALU_SUB   )
#define SBPF_OP_MUL64_IMM   SBPF_OPC( ALU64, SRC_IMM,  ALU_MUL   )
#define SBPF_OP_MUL64_REG   SBPF_OPC( ALU64, SRC_REG,  ALU_MUL   )
#define SBPF_OP_DIV64_IMM   SBPF_OPC( ALU64, SRC_IMM,  ALU_DIV   )
#define SBPF_OP_DIV64_REG   SBPF_OPC( ALU64, SRC_REG,  ALU_DIV   )
#define SBPF_OP_OR64_IMM    SBPF_OPC( ALU64, SRC_IMM,  ALU_OR    )
#define SBPF_OP_OR64_REG    SBPF_OPC( ALU64, SRC_REG,  ALU_OR    )
#define SBPF_OP_AND64_IMM   SBPF_OPC( ALU64, SRC_IMM,  ALU_AND   )
#define SBPF_OP_AND64_REG   SBPF_OPC( ALU64, SRC_REG,  ALU_AND   )
#define SBPF_OP_LSH64_IMM   SBPF_OPC( ALU64, SRC_IMM,  ALU_LSH   )
#define SBPF_OP_LSH64_REG   SBPF_OPC( ALU64, SRC_REG,  ALU_LSH   )
#define SBPF_OP_RSH64_IMM   SBPF_OPC( ALU64, SRC_IMM,  ALU_RSH   )
#define SBPF_OP_RSH64_REG   SBPF_OPC( ALU64, SRC_REG,  ALU_RSH   )
#define SBPF_OP_NEG64       SBPF_OPC( ALU64, SRC_IMM,  ALU_NEG   )
#define SBPF_OP_MOD64_IMM   SBPF_OPC( ALU64, SRC_IMM,  ALU_MOD   )
#define SBPF_OP_MOD64_REG   SBPF_OPC( ALU64, SRC_REG,  ALU_MOD   )
#define SBPF_OP_XOR64_IMM   SBPF_OPC( ALU64, SRC_IMM,  ALU_XOR   )
#define SBPF_OP_XOR64_REG   SBPF_OPC( ALU64, SRC_REG,  ALU_XOR   )
#define SBPF_OP_MOV64_IMM   SBPF_OPC( ALU64, SRC_IMM,  ALU_MOV   )
#define SBPF_OP_MOV64_REG   SBPF_OPC( ALU64, SRC_REG,  ALU_MOV   )
#define SBPF_OP_ARSH64_IMM  SBPF_OPC( ALU64, SRC_IMM,  ALU_ARSH  )
#define SBPF_OP_ARSH64_REG  SBPF_OPC( ALU64, SRC_REG,  ALU_ARSH  )
#define SBPF_OP_SDIV64_IMM  SBPF_OPC( ALU64, SRC_IMM,  ALU_SDIV  )
#define SBPF_OP_SDIV64_REG  SBPF_OPC( ALU64, SRC_REG,  ALU_SDIV  )

/* Control flow opcodes ***********************************************/

/* SBPF_OP_JA: Jump to other instruction.

   SBPF_OP_J{...}_IMM: Jump if condition given dest and immediate field
   passes.

   SBPF_OP_J{...}_REG: Jump if condition given dest and src registers
   passes. */
#define SBPF_OP_JA          SBPF_OPC( JMP,   SRC_IMM,  JMP_A     )
#define SBPF_OP_JEQ_IMM     SBPF_OPC( JMP,   SRC_IMM,  JMP_EQ    )
#define SBPF_OP_JEQ_REG     SBPF_OPC( JMP,   SRC_REG,  JMP_EQ    )
#define SBPF_OP_JGT_IMM     SBPF_OPC( JMP,   SRC_IMM,  JMP_GT    )
#define SBPF_OP_JGT_REG     SBPF_OPC( JMP,   SRC_REG,  JMP_GT    )
#define SBPF_OP_JGE_IMM     SBPF_OPC( JMP,   SRC_IMM,  JMP_GE    )
#define SBPF_OP_JGE_REG     SBPF_OPC( JMP,   SRC_REG,  JMP_GE    )
#define SBPF_OP_JSET_IMM    SBPF_OPC( JMP,   SRC_IMM,  JMP_SET   )
#define SBPF_OP_JSET_REG    SBPF_OPC( JMP,   SRC_REG,  JMP_SET   )
#define SBPF_OP_JNE_IMM     SBPF_OPC( JMP,   SRC_IMM,  JMP_NE    )
#define SBPF_OP_JNE_REG     SBPF_OPC( JMP,   SRC_REG,  JMP_NE    )
#define SBPF_OP_JSGT_IMM    SBPF_OPC( JMP,   SRC_IMM,  JMP_SGT   )
#define SBPF_OP_JSGT_REG    SBPF_OPC( JMP,   SRC_REG,  JMP_SGT   )
#define SBPF_OP_JSGE_IMM    SBPF_OPC( JMP,   SRC_IMM,  JMP_SGE   )
#define SBPF_OP_JSGE_REG    SBPF_OPC( JMP,   SRC_REG,  JMP_SGE   )
#define SBPF_OP_JLT_IMM     SBPF_OPC( JMP,   SRC_IMM,  JMP_LT    )
#define SBPF_OP_JLT_REG     SBPF_OPC( JMP,   SRC_REG,  JMP_LT    )
#define SBPF_OP_JLE_IMM     SBPF_OPC( JMP,   SRC_IMM,  JMP_LE    )
#define SBPF_OP_JLE_REG     SBPF_OPC( JMP,   SRC_REG,  JMP_LE    )
#define SBPF_OP_JSLT_IMM    SBPF_OPC( JMP,   SRC_IMM,  JMP_SLT   )
#define SBPF_OP_JSLT_REG    SBPF_OPC( JMP,   SRC_REG,  JMP_SLT   )
#define SBPF_OP_JSLE_IMM    SBPF_OPC( JMP,   SRC_IMM,  JMP_SLE   )
#define SBPF_OP_JSLE_REG    SBPF_OPC( JMP,   SRC_REG,  JMP_SLE   )

/* Function call opcodes **********************************************/

#define SBPF_OP_CALL        SBPF_OPC( JMP,   SRC_IMM,  JMP_CALL  )
#define SBPF_OP_CALLX       SBPF_OPC( JMP,   SRC_REG,  JMP_CALL  )
#define SBPF_OP_EXIT        SBPF_OPC( JMP,   SRC_IMM,  JMP_EXIT  )

/* Miscellaneous opcodes **********************************************/

/* SBPF_OP_LDDW: Move 64-bit immediate to GPR. Occupies two slots. */
#define SBPF_OP_LDDW        SBPF_OPC( LD,    SRC_IMM,  SZ_ULONG  )

/* SBPF_OP_LE: Zero upper bits.
   Mask size is specified in the immediate field (16, 32, 64). */
#define SBPF_OP_LE          SBPF_OPC( ALU32, SRC_IMM,  ALU_END   )

/* SBPF_OP_BE: Reverse lower 8-bit groups and zero upper bits.
   Number of bits is specified in the immediate field (16, 32, 64). */
#define SBPF_OP_BE          SBPF_OPC( ALU32, SRC_REG,  ALU_END   )

/* SBPF_OP_NULL: Opcode zero value. Illegal instruction. */
#define SBPF_OP_ZERO        ((uchar)0x00)

#endif /* HEADER_fd_src_ballet_sbpf_fd_sbpf_opcode_h */
