/* This is the BPF interpreter dispatch table.
 * Each instruction is implemented in this table.
 *
 * See `fd_sbpf_interp.c` for usage.
 */

/* 0x00 - 0x0f */
/* 0x00 */ JT_CASE(0x00); // FD_BPF_OP_ADDL_IMM
/* 0x04 */ JT_CASE(0x04) // FD_BPF_OP_ADD_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] + (uint)imm); 
JT_CASE_END
/* 0x05 */ JT_CASE(0x05) // FD_BPF_OP_JA
  pc += instr.offset;
JT_CASE_END
/* 0x07 */ JT_CASE(0x07) // FD_BPF_OP_ADD64_IMM
  register_file[dst_reg] += imm; 
JT_CASE_END
/* 0x0c */ JT_CASE(0x0c) // FD_BPF_OP_ADD_REG
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] + (uint)register_file[src_reg]); 
JT_CASE_END
/* 0x0f */ JT_CASE(0x0f) // FD_BPF_OP_ADD64_REG
  register_file[dst_reg] += register_file[src_reg];
JT_CASE_END

/* 0x10 - 0x1f */
/* 0x14 */ JT_CASE(0x14) // FD_BPF_OP_SUB_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] - (uint)imm); 
JT_CASE_END
/* 0x15 */ JT_CASE(0x15) // FD_BPF_OP_JEQ_IMM
  pc += (register_file[dst_reg] == imm) ? instr.offset : 0;
JT_CASE_END
/* 0x17 */ JT_CASE(0x17) // FD_BPF_OP_SUB64_IMM
  register_file[dst_reg] -= imm;
JT_CASE_END
/* 0x18 */ JT_CASE(0x18) // FD_BPF_OP_LDQ
  register_file[dst_reg] = (ulong)((ulong)imm | ((ulong)ctx->instrs[pc+1].imm << 32));
  pc++;
JT_CASE_END
/* 0x1c */ JT_CASE(0x1c) // FD_BPF_OP_SUB_REG
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] - (uint)register_file[src_reg]); 
JT_CASE_END
/* 0x1d */ JT_CASE(0x1d) // FD_BPF_OP_JEQ_REG
  pc += (register_file[dst_reg] == register_file[src_reg]) ? instr.offset : 0;
JT_CASE_END
/* 0x1f */ JT_CASE(0x1f) // FD_BPF_OP_SUB64_REG
  register_file[dst_reg] -= register_file[src_reg];
JT_CASE_END

/* 0x20 - 0x2f */
/* 0x24 */ JT_CASE(0x24) // FD_BPF_OP_MUL_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] * (uint)imm); 
JT_CASE_END
/* 0x25 */ JT_CASE(0x25) // FD_BPF_OP_JGT_IMM
  pc += (register_file[dst_reg] > imm) ? instr.offset : 0;
JT_CASE_END
/* 0x27 */ JT_CASE(0x27) // FD_BPF_OP_MUL64_IMM
  register_file[dst_reg] *= imm;
JT_CASE_END
/* 0x2c */ JT_CASE(0x2c) // FD_BPF_OP_MUL_REG
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] * (uint)register_file[src_reg]); 
JT_CASE_END
/* 0x2d */ JT_CASE(0x2d) // FD_BPF_OP_JGT_REG
  pc += (register_file[dst_reg] > register_file[src_reg]) ? instr.offset : 0;
JT_CASE_END
/* 0x2f */ JT_CASE(0x2f) // FD_BPF_OP_MUL64_REG
  register_file[dst_reg] *= register_file[src_reg];
JT_CASE_END

/* 0x30 - 0x3f */
/* 0x34 */ JT_CASE(0x34) // FD_BPF_OP_DIV_IMM
  register_file[dst_reg] = imm == 0 ? 0 : (uint)((uint)register_file[dst_reg] / (uint)imm); 
JT_CASE_END
/* 0x35 */ JT_CASE(0x35) // FD_BPF_OP_JGE_IMM
  pc += (register_file[dst_reg] >= imm) ? instr.offset : 0;
JT_CASE_END
/* 0x37 */ JT_CASE(0x37) // FD_BPF_OP_DIV64_IMM 
  register_file[dst_reg] = imm == 0 ? 0 : register_file[dst_reg] / imm;
JT_CASE_END
/* 0x3c */ JT_CASE(0x3c) // FD_BPF_OP_DIV_REG
  register_file[dst_reg] = (uint)register_file[src_reg] == 0 ? 0 : (uint)((uint)register_file[dst_reg] / (uint)register_file[src_reg]); 
JT_CASE_END
/* 0x3d */ JT_CASE(0x3d) // FD_BPF_OP_JGE_REG
  pc += (register_file[dst_reg] >= register_file[src_reg]) ? instr.offset : 0;
JT_CASE_END
/* 0x3f */ JT_CASE(0x3f) // FD_BPF_OP_DIV64_REG
  register_file[dst_reg] = register_file[src_reg] == 0 ? 0 : (register_file[dst_reg] / register_file[src_reg]);
JT_CASE_END

/* 0x40 - 0x4f */
/* 0x44 */ JT_CASE(0x44) // FD_BPF_OP_OR_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] | (uint)imm); 
JT_CASE_END
/* 0x45 */ JT_CASE(0x45) // FD_BPF_OP_JSET_IMM
  pc += (register_file[dst_reg] & imm) ? instr.offset : 0;
JT_CASE_END
/* 0x47 */ JT_CASE(0x47) // FD_BPF_OP_OR64_IMM
  register_file[dst_reg] |= imm;
JT_CASE_END
/* 0x4c */ JT_CASE(0x4c) // FD_BPF_OP_OR_REG
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] | (uint)register_file[src_reg]); 
JT_CASE_END
/* 0x4d */ JT_CASE(0x4d) // FD_BPF_OP_JSET_REG
  pc += (register_file[dst_reg] & register_file[src_reg]) ? instr.offset : 0;
JT_CASE_END
/* 0x4f */ JT_CASE(0x4f) // FD_BPF_OP_OR64_REG
  register_file[dst_reg] |= register_file[src_reg];
JT_CASE_END

/* 0x50 - 0x5f */
/* 0x54 */ JT_CASE(0x54) // FD_BPF_OP_AND_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] & (uint)imm); 
JT_CASE_END
/* 0x55 */ JT_CASE(0x55) // FD_BPF_OP_JNE_IMM
  pc += (register_file[dst_reg] != imm) ? instr.offset : 0;
JT_CASE_END
/* 0x57 */ JT_CASE(0x57) // FD_BPF_OP_AND64_IMM
  register_file[dst_reg] &= imm;
JT_CASE_END
/* 0x5c */ JT_CASE(0x5c) // FD_BPF_OP_AND_REG
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] & (uint)register_file[src_reg]); 
JT_CASE_END
/* 0x5d */ JT_CASE(0x5d) // FD_BPF_OP_JNE_REG
  pc += (register_file[dst_reg] != register_file[src_reg]) ? instr.offset : 0;
JT_CASE_END
/* 0x5f */ JT_CASE(0x5f) // FD_BPF_OP_AND64_REG
  register_file[dst_reg] &= register_file[src_reg];
JT_CASE_END

/* 0x60 - 0x6f */
/* 0x61 */ JT_CASE(0x61) // FD_BPF_OP_LDXW
  ulong * reg_ptr0 = &register_file[dst_reg];
  cond_fault = fd_vm_mem_map_read_uint( ctx, (ulong)((long)register_file[src_reg] + instr.offset), (uint *)reg_ptr0 );
  goto *((cond_fault == 0) ? &&fallthrough_0x61 : &&JT_RET_LOC);
fallthrough_0x61:
JT_CASE_END
/* 0x62 */ JT_CASE(0x62) // FD_BPF_OP_STW
  cond_fault = fd_vm_mem_map_write_uint( ctx, (ulong)((long)register_file[dst_reg] + instr.offset), (uint)imm );
  goto *((cond_fault == 0) ? &&fallthrough_0x62 : &&JT_RET_LOC);
fallthrough_0x62:
JT_CASE_END
/* 0x63 */ JT_CASE(0x63) // FD_BPF_OP_STXW
  cond_fault = fd_vm_mem_map_write_uint( ctx, (ulong)((long)register_file[dst_reg] + instr.offset), (uint)register_file[src_reg]);
  goto *((cond_fault == 0) ? &&fallthrough_0x63 : &&JT_RET_LOC);
fallthrough_0x63:
JT_CASE_END
/* 0x64 */ JT_CASE(0x64) // FD_BPF_OP_LSH_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] << (uint)imm); 
JT_CASE_END
/* 0x65 */ JT_CASE(0x65) // FD_BPF_OP_JSGT_IMM
  pc += ((long)register_file[dst_reg] > (long)imm) ? instr.offset : 0;
JT_CASE_END
/* 0x67 */ JT_CASE(0x67) // FD_BPF_OP_LSH64_IMM
  register_file[dst_reg] <<= imm;
JT_CASE_END
/* 0x69 */ JT_CASE(0x69) // FD_BPF_OP_LDXH
  ulong * reg_ptr1 = &register_file[dst_reg];
  cond_fault = fd_vm_mem_map_read_ushort( ctx, (ulong)((long)register_file[src_reg] + instr.offset), (ushort *)reg_ptr1 );
  goto *((cond_fault == 0) ? &&fallthrough_0x69 : &&JT_RET_LOC);
fallthrough_0x69:
JT_CASE_END
/* 0x6a */ JT_CASE(0x6a) // FD_BPF_OP_STH
  cond_fault = fd_vm_mem_map_write_ushort( ctx, (ulong)((long)register_file[dst_reg] + instr.offset), (ushort)imm );
  goto *((cond_fault == 0) ? &&fallthrough_0x6a : &&JT_RET_LOC);
fallthrough_0x6a:
JT_CASE_END
/* 0x6b */ JT_CASE(0x6b) // FD_BPF_OP_STXH
  cond_fault = fd_vm_mem_map_write_ushort( ctx, (ulong)((long)register_file[dst_reg] + instr.offset), (ushort)register_file[src_reg] );
  goto *((cond_fault == 0) ? &&fallthrough_0x6b : &&JT_RET_LOC);
fallthrough_0x6b:
JT_CASE_END
/* 0x6c */ JT_CASE(0x6c) // FD_BPF_OP_LSH_REG
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] << (uint)register_file[src_reg]); 
JT_CASE_END
/* 0x6d */ JT_CASE(0x6d) // FD_BPF_OP_JSGT_REG
  pc += ((long)register_file[dst_reg] > (long)register_file[src_reg]) ? instr.offset : 0;
JT_CASE_END
/* 0x6f */ JT_CASE(0x6f) // FD_BPF_OP_LSH64_REG
  register_file[dst_reg] <<= register_file[src_reg];
JT_CASE_END

/* 0x70 - 0x7f */
/* 0x71 */ JT_CASE(0x71) // FD_BPF_OP_LDXB
  cond_fault = fd_vm_mem_map_read_uchar( ctx, (ulong)((long)register_file[src_reg] + instr.offset), (uchar *)&register_file[dst_reg] );
  goto *((cond_fault == 0) ? &&fallthrough_0x71 : &&JT_RET_LOC);
fallthrough_0x71:
JT_CASE_END
/* 0x72 */ JT_CASE(0x72) // FD_BPF_OP_STB
  cond_fault = fd_vm_mem_map_write_uchar( ctx, (ulong)((long)register_file[dst_reg] + instr.offset), (uchar)imm );
  goto *((cond_fault == 0) ? &&fallthrough_0x72 : &&JT_RET_LOC);
fallthrough_0x72:
JT_CASE_END
/* 0x73 */ JT_CASE(0x73) // FD_BPF_OP_STXB
  cond_fault = fd_vm_mem_map_write_uchar( ctx, (ulong)((long)register_file[dst_reg] + instr.offset), (uchar)register_file[src_reg] );
  goto *((cond_fault == 0) ? &&fallthrough_0x73 : &&JT_RET_LOC);
fallthrough_0x73:
JT_CASE_END
/* 0x74 */ JT_CASE(0x74) // FD_BPF_OP_RSH_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] >> (uint)imm); 
JT_CASE_END
/* 0x75 */ JT_CASE(0x75) // FD_BPF_OP_JSGE_IMM
  pc += ((long)register_file[dst_reg] >= (long)imm) ? instr.offset : 0;
JT_CASE_END
/* 0x77 */ JT_CASE(0x77) // FD_BPF_OP_RSH64_IMM
  register_file[dst_reg] >>= imm;
JT_CASE_END
/* 0x79 */ JT_CASE(0x79) // FD_BPF_OP_LDXQ
  cond_fault = fd_vm_mem_map_read_ulong( ctx, (ulong)((long)register_file[src_reg] + instr.offset), (ulong *)&register_file[dst_reg] );
  goto *((cond_fault == 0) ? &&fallthrough_0x79 : &&JT_RET_LOC);
fallthrough_0x79:
JT_CASE_END
/* 0x7a */ JT_CASE(0x7a) // FD_BPF_OP_STQ
  cond_fault = fd_vm_mem_map_write_ulong( ctx, (ulong)((long)register_file[dst_reg] + instr.offset), (ulong)imm );
  goto *((cond_fault == 0) ? &&fallthrough_0x7a : &&JT_RET_LOC);
fallthrough_0x7a:
JT_CASE_END
/* 0x7b */ JT_CASE(0x7b) // FD_BPF_OP_STXQ
  cond_fault = fd_vm_mem_map_write_ulong( ctx, (ulong)((long)register_file[dst_reg] + instr.offset), (ulong)register_file[src_reg] );
  goto *((cond_fault == 0) ? &&fallthrough_0x7b : &&JT_RET_LOC);
fallthrough_0x7b:
JT_CASE_END
/* 0x7c */ JT_CASE(0x7c) // FD_BPF_OP_RSH_REG
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] >> (uint)register_file[src_reg]); 
JT_CASE_END
/* 0x7d */ JT_CASE(0x7d) // FD_BPF_OP_JSGE_REG
  pc += ((long)register_file[dst_reg] > (long)register_file[src_reg]) ? instr.offset : 0;
JT_CASE_END
/* 0x7f */ JT_CASE(0x7f) // FD_BPF_OP_RSH64_REG
  register_file[dst_reg] >>= register_file[src_reg];
JT_CASE_END

/* 0x80 - 0x8f */
/* 0x84 */ JT_CASE(0x84) // FD_BPF_OP_NEG
  register_file[dst_reg] = (uint)(~((uint)register_file[dst_reg])); 
JT_CASE_END
/* 0x85 */ JT_CASE(0x85) // FD_BPF_OP_CALL_IMM
  if (imm < ctx->instrs_sz ) {
    cond_fault = 0;
    pc = imm;
  } else {
    fd_vm_sbpf_syscall_map_t * syscall_entry_imm = fd_vm_sbpf_syscall_map_query(&ctx->syscall_map, imm, NULL);
    cond_fault = syscall_entry_imm->syscall_fn_ptr(ctx, register_file[1], register_file[2], register_file[3], register_file[4], register_file[5], &register_file[0]);
  }
  goto *((cond_fault == 0) ? &&fallthrough_0x85 : &&JT_RET_LOC);
fallthrough_0x85:
JT_CASE_END
/* 0x87 */ JT_CASE(0x87) // FD_BPF_OP_NEG64
  register_file[dst_reg] = ~register_file[dst_reg];
JT_CASE_END
/* 0x8d */ JT_CASE(0x8d) // FD_BPF_OP_CALL_REG
  // TODO: fix
  fd_vm_sbpf_syscall_map_t * syscall_entry_reg = fd_vm_sbpf_syscall_map_query(&ctx->syscall_map, register_file[imm], NULL);
  cond_fault = syscall_entry_reg->syscall_fn_ptr(ctx, register_file[1], register_file[2], register_file[3], register_file[4], register_file[5], &register_file[0]);
  goto *((cond_fault == 0) ? &&fallthrough_0x8d : &&JT_RET_LOC);
fallthrough_0x8d:
JT_CASE_END

/* 0x90 - 0x9f */
/* 0x94 */ JT_CASE(0x94) // FD_BPF_OP_MOD_IMM
  register_file[dst_reg] = ((uint)imm==0) ? (uint)register_file[dst_reg] : (uint)((uint)register_file[dst_reg] % (uint)imm); 
JT_CASE_END
/* 0x95 */ JT_CASE(0x95) // FD_BPF_OP_EXIT
  goto JT_RET_LOC;
JT_CASE_END
/* 0x97 */ JT_CASE(0x97) // FD_BPF_OP_MOD64_IMM
  register_file[dst_reg] = (imm==0) ? register_file[dst_reg] : register_file[dst_reg] % imm;
JT_CASE_END
/* 0x9c */ JT_CASE(0x9c) // FD_BPF_OP_MOD_REG
  register_file[dst_reg] = ((uint)register_file[src_reg]==0)
    ? (uint)register_file[dst_reg]
    : (uint)((uint)register_file[dst_reg] % (uint)register_file[src_reg]); 
JT_CASE_END
/* 0x9f */ JT_CASE(0x9f) // FD_BPF_OP_MOD64_REG
  register_file[dst_reg] = (register_file[src_reg]==0) 
    ? register_file[dst_reg]
    : register_file[dst_reg] % register_file[src_reg];
JT_CASE_END

/* 0xa0 - 0xaf */
/* 0xa4 */ JT_CASE(0xa4) // FD_BPF_OP_XOR_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] ^ (uint)imm); 
JT_CASE_END
/* 0xa5 */ JT_CASE(0xa5) // FD_BPF_OP_JLT_IMM
  pc += (register_file[dst_reg] < imm) ? instr.offset : 0;
JT_CASE_END
/* 0xa7 */ JT_CASE(0xa7) // FD_BPF_OP_XOR64_IMM
  register_file[dst_reg] ^= imm;
JT_CASE_END
/* 0xac */ JT_CASE(0xac) // FD_BPF_XOR_REG
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] ^ (uint)register_file[src_reg]); 
JT_CASE_END
/* 0xad */ JT_CASE(0xad) // FD_BPF_OP_JLT_REG
  pc += (register_file[dst_reg] < register_file[src_reg]) ? instr.offset : 0;
JT_CASE_END
/* 0xaf */ JT_CASE(0xaf) // FD_BPF_OP_XOR64_REG
  register_file[dst_reg] ^= register_file[src_reg];
JT_CASE_END

/* 0xb0 - 0xbf */
/* 0xb4 */ JT_CASE(0xb4) // FD_BPF_OP_MOV_IMM
  register_file[dst_reg] = (uint)imm; 
JT_CASE_END
/* 0xb5 */ JT_CASE(0xb5) // FD_BPF_OP_JLE_IMM
  pc += (register_file[dst_reg] <= imm) ? instr.offset : 0;
JT_CASE_END
/* 0xb7 */ JT_CASE(0xb7) // FD_BPF_OP_MOV64_IMM
  register_file[dst_reg] = imm;
JT_CASE_END
/* 0xbc */ JT_CASE(0xbc) // FD_BPF_OP_MOV_REG
  register_file[dst_reg] = (uint)register_file[src_reg];
JT_CASE_END
/* 0xbd */ JT_CASE(0xbd) // FD_BPF_OP_JLE_REG
  pc += (register_file[dst_reg] <= register_file[src_reg]) ? instr.offset : 0;
JT_CASE_END
/* 0xbf */ JT_CASE(0xbf) // FD_BPF_OP_MOV64_REG
  register_file[dst_reg] = register_file[src_reg];
JT_CASE_END

/* 0xc0 - 0xcf */
/* 0xc4 */ JT_CASE(0xc4) // FD_BPF_OP_ARSH_IMM
  register_file[dst_reg] = (uint)((int)register_file[dst_reg] >> (uint)imm); 
JT_CASE_END
/* 0xc5 */ JT_CASE(0xc5) // FD_BPF_OP_JSLT_IMM
  pc += ((long)register_file[dst_reg] < (long)imm) ? instr.offset : 0;
/* 0xc7 */ JT_CASE(0xc7) // FD_BPF_OP_ARSH64_IMM
  register_file[dst_reg] = (ulong)((long)register_file[dst_reg] >> imm);
JT_CASE_END
/* 0xcc */ JT_CASE(0xcc) // FD_BPF_OP_ARSH_REG
  register_file[dst_reg] = (uint)((int)register_file[dst_reg] >> (uint)register_file[src_reg]);
JT_CASE_END
/* 0xcd */ JT_CASE(0xcd) // FD_BPF_OP_JSLT_REG
  pc += ((long)register_file[dst_reg] < (long)register_file[src_reg]) ? instr.offset : 0;
JT_CASE_END
/* 0xcf */ JT_CASE(0xcf) // FD_BPF_OP_ARSH64_REG
  register_file[dst_reg] = (ulong)((long)register_file[dst_reg] >> register_file[src_reg]);
JT_CASE_END

/* 0xd0 - 0xdf */
/* 0xd4 */ JT_CASE(0xd4) // FD_BPF_OP_END_LE
  /* On x86_64, the host is LE already */
/* 0xd5 */ JT_CASE(0xd5) // FD_BPF_OP_JSLE_IMM
  pc += ((long)register_file[dst_reg] <= (long)imm) ? instr.offset : 0;
JT_CASE_END
/* 0xdc */ JT_CASE(0xdc) // FD_BPF_OP_END_BE 
  switch (imm) {
    case 16:
      register_file[dst_reg] = (ushort)fd_ushort_bswap((short)register_file[dst_reg]);
      register_file[dst_reg] &= 0xFFFF;
      break;
    case 32:
      register_file[dst_reg] = (uint)fd_uint_bswap((int)register_file[dst_reg]);
      register_file[dst_reg] &= 0xFFFFFFFF;
      break;
    case 64:
      register_file[dst_reg] = (ulong)fd_ulong_bswap((long)register_file[dst_reg]);
      break;
  }
JT_CASE_END
/* 0xdd */ JT_CASE(0xdd) // FD_BPF_OP_JSLE_REG
  pc += ((long)register_file[dst_reg] <= (long)register_file[src_reg]) ? instr.offset : 0;
JT_CASE_END
