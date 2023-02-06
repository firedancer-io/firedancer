#ifndef HEADER_fd_src_ballet_sbpf_fd_opcode_h
#define HEADER_fd_src_ballet_sbpf_fd_opcode_h

/* This header defines the opcodes used in the sBPF (Solana BPF)
   instruction set. The opcode is the first byte of each instruction
   slot. */

/* Opcode encoding helpers ********************************************/

/* BPF_OPC: Opcode number given the operation class, mode, sub-operation. */
#define BPF_OPC( class, mode, variant ) (uchar)( (BPF_CLASS_##class)|(BPF_##mode)|(BPF_##variant) )

/* BPF_CLASS_{...}: Instruction class */
#define BPF_CLASS_LD     ((uchar)0x00) /* Load                        */
#define BPF_CLASS_LDX    ((uchar)0x01) /* Load Indexed                */
#define BPF_CLASS_ST     ((uchar)0x02) /* Store                       */
#define BPF_CLASS_STX    ((uchar)0x03) /* Store Indexed               */
#define BPF_CLASS_ALU32  ((uchar)0x04) /* 32-bit integer arithmetic   */
#define BPF_CLASS_JMP    ((uchar)0x05) /* Control flow                */
#define BPF_CLASS_ALU64  ((uchar)0x07) /* 64-bit integer arithmetic   */

/* BPF_SRC_{...}: Source operand mode */
#define BPF_SRC_IMM      ((uchar)0x00) /* Use immediate field         */
#define BPF_SRC_REG      ((uchar)0x08) /* Use source register         */

/* BPF_SZ_{...}: Operand size modifier */
#define BPF_SZ_UCHAR     ((uchar)0x10)
#define BPF_SZ_USHORT    ((uchar)0x08)
#define BPF_SZ_UINT      ((uchar)0x00)
#define BPF_SZ_ULONG     ((uchar)0x18)

/* BPF_ADDR_{...}: Addressing mode */
#define BPF_ADDR_IMM     ((uchar)0x00) /* Use immediate field         */
#define BPF_ADDR_MEM     ((uchar)0x60) /* Use src+offset fields       */

/* BPF_ALU_{...}: Integer arithmetic operation identifier */
#define BPF_ALU_ADD      ((uchar)0x00) /* Add                         */
#define BPF_ALU_SUB      ((uchar)0x10) /* Subtract                    */
#define BPF_ALU_MUL      ((uchar)0x20) /* Multiply                    */
#define BPF_ALU_DIV      ((uchar)0x30) /* Unsigned divide             */
#define BPF_ALU_OR       ((uchar)0x40) /* Bitwise OR                  */
#define BPF_ALU_AND      ((uchar)0x50) /* Bitwise AND                 */
#define BPF_ALU_LSH      ((uchar)0x60) /* Bitwise left shift          */
#define BPF_ALU_RSH      ((uchar)0x70) /* Bitwise right shift         */
#define BPF_ALU_NEG      ((uchar)0x80) /* Negate                      */
#define BPF_ALU_MOD      ((uchar)0x90) /* Modulo                      */
#define BPF_ALU_XOR      ((uchar)0xa0) /* Bitwise XOR                 */
#define BPF_ALU_MOV      ((uchar)0xb0) /* Move                        */
#define BPF_ALU_ARSH     ((uchar)0xc0) /* Arithmetic right shift      */
#define BPF_ALU_END      ((uchar)0xd0) /* Endianness conversion       */
#define BPF_ALU_SDIV     ((uchar)0xe0) /* Signed divide               */

/* BPF_JMP_{...}: Jump condition modes */
#define BPF_JMP_A        ((uchar)0x00) /* Always                      */
#define BPF_JMP_EQ       ((uchar)0x10) /* If equal                    */
#define BPF_JMP_GT       ((uchar)0x20) /* If greater than             */
#define BPF_JMP_GE       ((uchar)0x30) /* If greater or equal         */
#define BPF_JMP_SET      ((uchar)0x40) /* If bit set in mask          */
#define BPF_JMP_NE       ((uchar)0x50) /* If not equal                */
#define BPF_JMP_SGT      ((uchar)0x60) /* If signed greater than      */
#define BPF_JMP_SGE      ((uchar)0x70) /* If signed greater or equal  */
#define BPF_JMP_CALL     ((uchar)0x80) /* Always, function call       */
#define BPF_JMP_EXIT     ((uchar)0x90) /* Always, function return     */
#define BPF_JMP_LT       ((uchar)0xa0) /* If less than                */
#define BPF_JMP_LE       ((uchar)0xb0) /* If less or equal            */
#define BPF_JMP_SLT      ((uchar)0xc0) /* If signed less than         */
#define BPF_JMP_SLE      ((uchar)0xd0) /* If signed less or equal     */

/* Load opcodes *******************************************************/

/* BPF_OP_LDX{B,H,W,DW}: Load GPR from memory and zero upper. */
#define BPF_OP_LDXB        BPF_OPC( LDX,   ADDR_MEM, SZ_UCHAR  )
#define BPF_OP_LDXH        BPF_OPC( LDX,   ADDR_MEM, SZ_USHORT )
#define BPF_OP_LDXW        BPF_OPC( LDX,   ADDR_MEM, SZ_UINT   )
#define BPF_OP_LDXDW       BPF_OPC( LDX,   ADDR_MEM, SZ_ULONG  )

/* Store opcodes ******************************************************/

/* BPF_OP_ST{B,H,W}: Store immediate to memory.

   BPF_OP_STDW: Store 32-bit immediate and 32-bit zero word to memory. */
#define BPF_OP_STB         BPF_OPC( ST,    ADDR_MEM, SZ_UCHAR  )
#define BPF_OP_STH         BPF_OPC( ST,    ADDR_MEM, SZ_USHORT )
#define BPF_OP_STW         BPF_OPC( ST,    ADDR_MEM, SZ_UINT   )
#define BPF_OP_STDW        BPF_OPC( ST,    ADDR_MEM, SZ_ULONG  )

/* BPF_OP_STX{B,H,W,DW}: Store GPR to memory. */
#define BPF_OP_STXB        BPF_OPC( STX,   ADDR_MEM, SZ_UCHAR  )
#define BPF_OP_STXH        BPF_OPC( STX,   ADDR_MEM, SZ_USHORT )
#define BPF_OP_STXW        BPF_OPC( STX,   ADDR_MEM, SZ_UINT   )
#define BPF_OP_STXDW       BPF_OPC( STX,   ADDR_MEM, SZ_ULONG  )

/* 32-bit arithmetic opcodes ******************************************/

/* SBF_OP_{...}32_IMM: Compute binary operation given lower 32 bits of
   dest register and 32-bit immediate, store result into lower 32 bits
   of dest, and zero upper.

   SBF_OP_{...}32_REG: Compute binary operation given lower 32 bits of
   dest and src registers, store result into lower 32 bits of dest, and
   zero upper.

   SBF_OP_{...}32: Compute unary operation on lower 32 bits of dest
   register, store result into lower 32 bits of dest, and zero upper. */
#define BPF_OP_ADD32_IMM   BPF_OPC( ALU32, SRC_IMM,  ALU_ADD   )
#define BPF_OP_ADD32_REG   BPF_OPC( ALU32, SRC_REG,  ALU_ADD   )
#define BPF_OP_SUB32_IMM   BPF_OPC( ALU32, SRC_IMM,  ALU_SUB   )
#define BPF_OP_SUB32_REG   BPF_OPC( ALU32, SRC_REG,  ALU_SUB   )
#define BPF_OP_MUL32_IMM   BPF_OPC( ALU32, SRC_IMM,  ALU_MUL   )
#define BPF_OP_MUL32_REG   BPF_OPC( ALU32, SRC_REG,  ALU_MUL   )
#define BPF_OP_DIV32_IMM   BPF_OPC( ALU32, SRC_IMM,  ALU_DIV   )
#define BPF_OP_DIV32_REG   BPF_OPC( ALU32, SRC_REG,  ALU_DIV   )
#define BPF_OP_OR32_IMM    BPF_OPC( ALU32, SRC_IMM,  ALU_OR    )
#define BPF_OP_OR32_REG    BPF_OPC( ALU32, SRC_REG,  ALU_OR    )
#define BPF_OP_AND32_IMM   BPF_OPC( ALU32, SRC_IMM,  ALU_AND   )
#define BPF_OP_AND32_REG   BPF_OPC( ALU32, SRC_REG,  ALU_AND   )
#define BPF_OP_LSH32_IMM   BPF_OPC( ALU32, SRC_IMM,  ALU_LSH   )
#define BPF_OP_LSH32_REG   BPF_OPC( ALU32, SRC_REG,  ALU_LSH   )
#define BPF_OP_RSH32_IMM   BPF_OPC( ALU32, SRC_IMM,  ALU_RSH   )
#define BPF_OP_RSH32_REG   BPF_OPC( ALU32, SRC_REG,  ALU_RSH   )
#define BPF_OP_NEG32       BPF_OPC( ALU32, SRC_IMM,  ALU_NEG   )
#define BPF_OP_MOD32_IMM   BPF_OPC( ALU32, SRC_IMM,  ALU_MOD   )
#define BPF_OP_MOD32_REG   BPF_OPC( ALU32, SRC_REG,  ALU_MOD   )
#define BPF_OP_XOR32_IMM   BPF_OPC( ALU32, SRC_IMM,  ALU_XOR   )
#define BPF_OP_XOR32_REG   BPF_OPC( ALU32, SRC_REG,  ALU_XOR   )
#define BPF_OP_MOV32_IMM   BPF_OPC( ALU32, SRC_IMM,  ALU_MOV   )
#define BPF_OP_MOV32_REG   BPF_OPC( ALU32, SRC_REG,  ALU_MOV   )
#define BPF_OP_ARSH32_IMM  BPF_OPC( ALU32, SRC_IMM,  ALU_ARSH  )
#define BPF_OP_ARSH32_REG  BPF_OPC( ALU32, SRC_REG,  ALU_ARSH  )
#define BPF_OP_SDIV32_IMM  BPF_OPC( ALU32, SRC_IMM,  ALU_SDIV  )
#define BPF_OP_SDIV32_REG  BPF_OPC( ALU32, SRC_REG,  ALU_SDIV  )

/* 64-bit arithmetic opcodes ******************************************/

/* SBF_OP_{...}64_IMM: Compute binary operation given dest register and
   immediate, and store result into dest.

   SBF_OP_{...}64_REG: Compute binary operation given dest and src
   registers, and store result into dest.

   SBF_OP_{...}64: Compute unary operation given dest register, and
   store result into dest. */
#define BPF_OP_ADD64_IMM   BPF_OPC( ALU64, SRC_IMM,  ALU_ADD   )
#define BPF_OP_ADD64_REG   BPF_OPC( ALU64, SRC_REG,  ALU_ADD   )
#define BPF_OP_SUB64_IMM   BPF_OPC( ALU64, SRC_IMM,  ALU_SUB   )
#define BPF_OP_SUB64_REG   BPF_OPC( ALU64, SRC_REG,  ALU_SUB   )
#define BPF_OP_MUL64_IMM   BPF_OPC( ALU64, SRC_IMM,  ALU_MUL   )
#define BPF_OP_MUL64_REG   BPF_OPC( ALU64, SRC_REG,  ALU_MUL   )
#define BPF_OP_DIV64_IMM   BPF_OPC( ALU64, SRC_IMM,  ALU_DIV   )
#define BPF_OP_DIV64_REG   BPF_OPC( ALU64, SRC_REG,  ALU_DIV   )
#define BPF_OP_OR64_IMM    BPF_OPC( ALU64, SRC_IMM,  ALU_OR    )
#define BPF_OP_OR64_REG    BPF_OPC( ALU64, SRC_REG,  ALU_OR    )
#define BPF_OP_AND64_IMM   BPF_OPC( ALU64, SRC_IMM,  ALU_AND   )
#define BPF_OP_AND64_REG   BPF_OPC( ALU64, SRC_REG,  ALU_AND   )
#define BPF_OP_LSH64_IMM   BPF_OPC( ALU64, SRC_IMM,  ALU_LSH   )
#define BPF_OP_LSH64_REG   BPF_OPC( ALU64, SRC_REG,  ALU_LSH   )
#define BPF_OP_RSH64_IMM   BPF_OPC( ALU64, SRC_IMM,  ALU_RSH   )
#define BPF_OP_RSH64_REG   BPF_OPC( ALU64, SRC_REG,  ALU_RSH   )
#define BPF_OP_NEG64       BPF_OPC( ALU64, SRC_IMM,  ALU_NEG   )
#define BPF_OP_MOD64_IMM   BPF_OPC( ALU64, SRC_IMM,  ALU_MOD   )
#define BPF_OP_MOD64_REG   BPF_OPC( ALU64, SRC_REG,  ALU_MOD   )
#define BPF_OP_XOR64_IMM   BPF_OPC( ALU64, SRC_IMM,  ALU_XOR   )
#define BPF_OP_XOR64_REG   BPF_OPC( ALU64, SRC_REG,  ALU_XOR   )
#define BPF_OP_MOV64_IMM   BPF_OPC( ALU64, SRC_IMM,  ALU_MOV   )
#define BPF_OP_MOV64_REG   BPF_OPC( ALU64, SRC_REG,  ALU_MOV   )
#define BPF_OP_ARSH64_IMM  BPF_OPC( ALU64, SRC_IMM,  ALU_ARSH  )
#define BPF_OP_ARSH64_REG  BPF_OPC( ALU64, SRC_REG,  ALU_ARSH  )
#define BPF_OP_SDIV64_IMM  BPF_OPC( ALU64, SRC_IMM,  ALU_SDIV  )
#define BPF_OP_SDIV64_REG  BPF_OPC( ALU64, SRC_REG,  ALU_SDIV  )

/* Control flow opcodes ***********************************************/

/* BPF_OP_JA: Jump to other instruction.

   BPF_OP_J{...}_IMM: Jump if condition given dest and immediate field
   passes.

   BPF_OP_J{...}_REG: Jump if condition given dest and src registers
   passes. */
#define BPF_OP_JA          BPF_OPC( JMP,   SRC_IMM,  JMP_A     )
#define BPF_OP_JEQ_IMM     BPF_OPC( JMP,   SRC_IMM,  JMP_EQ    )
#define BPF_OP_JEQ_REG     BPF_OPC( JMP,   SRC_REG,  JMP_EQ    )
#define BPF_OP_JGT_IMM     BPF_OPC( JMP,   SRC_IMM,  JMP_GT    )
#define BPF_OP_JGT_REG     BPF_OPC( JMP,   SRC_REG,  JMP_GT    )
#define BPF_OP_JGE_IMM     BPF_OPC( JMP,   SRC_IMM,  JMP_GE    )
#define BPF_OP_JGE_REG     BPF_OPC( JMP,   SRC_REG,  JMP_GE    )
#define BPF_OP_JSET_IMM    BPF_OPC( JMP,   SRC_IMM,  JMP_SET   )
#define BPF_OP_JSET_REG    BPF_OPC( JMP,   SRC_REG,  JMP_SET   )
#define BPF_OP_JNE_IMM     BPF_OPC( JMP,   SRC_IMM,  JMP_NE    )
#define BPF_OP_JNE_REG     BPF_OPC( JMP,   SRC_REG,  JMP_NE    )
#define BPF_OP_JSGT_IMM    BPF_OPC( JMP,   SRC_IMM,  JMP_SGT   )
#define BPF_OP_JSGT_REG    BPF_OPC( JMP,   SRC_REG,  JMP_SGT   )
#define BPF_OP_JSGE_IMM    BPF_OPC( JMP,   SRC_IMM,  JMP_SGE   )
#define BPF_OP_JSGE_REG    BPF_OPC( JMP,   SRC_REG,  JMP_SGE   )
#define BPF_OP_JLT_IMM     BPF_OPC( JMP,   SRC_IMM,  JMP_LT    )
#define BPF_OP_JLT_REG     BPF_OPC( JMP,   SRC_REG,  JMP_LT    )
#define BPF_OP_JLE_IMM     BPF_OPC( JMP,   SRC_IMM,  JMP_LE    )
#define BPF_OP_JLE_REG     BPF_OPC( JMP,   SRC_REG,  JMP_LE    )
#define BPF_OP_JSLT_IMM    BPF_OPC( JMP,   SRC_IMM,  JMP_SLT   )
#define BPF_OP_JSLT_REG    BPF_OPC( JMP,   SRC_REG,  JMP_SLT   )
#define BPF_OP_JSLE_IMM    BPF_OPC( JMP,   SRC_IMM,  JMP_SLE   )
#define BPF_OP_JSLE_REG    BPF_OPC( JMP,   SRC_REG,  JMP_SLE   )

/* Function call opcodes **********************************************/

#define BPF_OP_CALL        BPF_OPC( JMP,   SRC_IMM,  JMP_CALL  )
#define BPF_OP_CALLX       BPF_OPC( JMP,   SRC_REG,  JMP_CALL  )
#define BPF_OP_EXIT        BPF_OPC( JMP,   SRC_IMM,  JMP_EXIT  )

/* Miscellaneous opcodes **********************************************/

/* BPF_OP_LDDW: Move 64-bit immediate to GPR. Occupies two slots. */
#define BPF_OP_LDDW        BPF_OPC( LD,    SRC_IMM,  SZ_ULONG  )

/* BPF_OP_LE: Zero upper bits.
   Mask size is specified in the immediate field (16, 32, 64). */
#define BPF_OP_LE          BPF_OPC( ALU32, SRC_IMM,  ALU_END   )

/* BPF_OP_BE: Reverse lower 8-bit groups and zero upper bits.
   Number of bits is specified in the immediate field (16, 32, 64). */
#define BPF_OP_BE          BPF_OPC( ALU32, SRC_REG,  ALU_END   )

/* BPF_OP_NULL: Opcode zero value. Illegal instruction. */
#define BPF_OP_ZERO        ((uchar)0x00)

#endif /* HEADER_fd_src_ballet_sbpf_fd_opcode_h */
