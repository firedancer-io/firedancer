/* 0x00 - 0x0f */
/* 0x00 */ AJT_CASE(0x00) // FD_BPF_OP_ADDL_IMM
/* 0x01 */ AJT_CASE(0x01);
/* 0x02 */ AJT_CASE(0x02);
/* 0x03 */ AJT_CASE(0x03);
/* 0x04 */ AJT_CASE(0x04) // FD_BPF_OP_ADD_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] + (uint)imm); 
/* 0x05 */ AJT_CASE(0x05) // FD_BPF_OP_JA
  pc += instr.offset;
/* 0x06 */ AJT_CASE(0x06);
/* 0x07 */ AJT_CASE(0x07) // FD_BPF_OP_ADD64_IMM
  register_file[dst_reg] += imm; 
/* 0x08 */ AJT_CASE(0x08);
/* 0x09 */ AJT_CASE(0x09);
/* 0x0a */ AJT_CASE(0x0a);
/* 0x0b */ AJT_CASE(0x0b);
/* 0x0c */ AJT_CASE(0x0c) // FD_BPF_OP_ADD_REG
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] + (uint)register_file[src_reg]); 
/* 0x0d */ AJT_CASE(0x0d);
/* 0x0e */ AJT_CASE(0x0e);
/* 0x0f */ AJT_CASE(0x0f) // FD_BPF_OP_ADD64_REG
  register_file[dst_reg] += register_file[src_reg];

/* 0x10 - 0x1f */
/* 0x10 */ AJT_CASE(0x10);
/* 0x11 */ AJT_CASE(0x11);
/* 0x12 */ AJT_CASE(0x12);
/* 0x13 */ AJT_CASE(0x13);
/* 0x14 */ AJT_CASE(0x14) // FD_BPF_OP_SUB_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] - (uint)imm); 
/* 0x15 */ AJT_CASE(0x15) // FD_BPF_OP_JEQ_IMM
  pc += (register_file[dst_reg] == imm) ? instr.offset : 0;
/* 0x16 */ AJT_CASE(0x16);
/* 0x17 */ AJT_CASE(0x17) // FD_BPF_OP_SUB64_IMM
  register_file[dst_reg] -= imm;
/* 0x18 */ AJT_CASE(0x18) // FD_BPF_OP_LDQ
  register_file[dst_reg] = (ulong)((ulong)imm | ((ulong)ctx->instrs[pc+1].imm << 32));
  pc++;
/* 0x19 */ AJT_CASE(0x19);
/* 0x1a */ AJT_CASE(0x1a);
/* 0x1b */ AJT_CASE(0x1b);
/* 0x1c */ AJT_CASE(0x1c) // FD_BPF_OP_SUB_REG
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] + (uint)register_file[src_reg]); 
/* 0x1d */ AJT_CASE(0x1d) // FD_BPF_OP_JEQ_REG
  pc += (register_file[dst_reg] == register_file[src_reg]) ? instr.offset : 0;
/* 0x1e */ AJT_CASE(0x1e);
/* 0x1f */ AJT_CASE(0x1f) // FD_BPF_OP_SUB64_REG
  register_file[dst_reg] += register_file[src_reg];

/* 0x20 - 0x2f */
/* 0x20 */ AJT_CASE(0x20);
/* 0x21 */ AJT_CASE(0x21);
/* 0x22 */ AJT_CASE(0x22);
/* 0x23 */ AJT_CASE(0x23);
/* 0x24 */ AJT_CASE(0x24) // FD_BPF_OP_MUL_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] * (uint)imm); 
/* 0x25 */ AJT_CASE(0x25) // FD_BPF_OP_JGT_IMM
  pc += (register_file[dst_reg] > imm) ? instr.offset : 0;
/* 0x26 */ AJT_CASE(0x26);
/* 0x27 */ AJT_CASE(0x27) // FD_BPF_OP_MUL64_IMM
  register_file[dst_reg] *= imm;
/* 0x28 */ AJT_CASE(0x28);
/* 0x29 */ AJT_CASE(0x29);
/* 0x2a */ AJT_CASE(0x2a);
/* 0x2b */ AJT_CASE(0x2b);
/* 0x2c */ AJT_CASE(0x2c) // FD_BPF_OP_MUL_REG
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] * (uint)register_file[src_reg]); 
/* 0x2d */ AJT_CASE(0x2d) // FD_BPF_OP_JGT_REG
  pc += (register_file[dst_reg] > register_file[src_reg]) ? instr.offset : 0;
/* 0x2e */ AJT_CASE(0x2e);
/* 0x2f */ AJT_CASE(0x2f) // FD_BPF_OP_MUL64_REG
  register_file[dst_reg] *= register_file[src_reg];

/* 0x30 - 0x3f */
/* 0x30 */ AJT_CASE(0x30);
/* 0x31 */ AJT_CASE(0x31);
/* 0x32 */ AJT_CASE(0x32);
/* 0x33 */ AJT_CASE(0x33);
/* 0x34 */ AJT_CASE(0x34) // FD_BPF_OP_DIV_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] / (uint)imm); 
/* 0x35 */ AJT_CASE(0x35) // FD_BPF_OP_JGE_IMM
  pc += (register_file[dst_reg] >= imm) ? instr.offset : 0;
/* 0x36 */ AJT_CASE(0x36);
/* 0x37 */ AJT_CASE(0x37) // FD_BPF_OP_DIV64_IMM 
  register_file[dst_reg] /= imm;
/* 0x38 */ AJT_CASE(0x38);
/* 0x39 */ AJT_CASE(0x39);
/* 0x3a */ AJT_CASE(0x3a);
/* 0x3b */ AJT_CASE(0x3b);
/* 0x3c */ AJT_CASE(0x3c) // FD_BPF_OP_DIV_REG
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] / (uint)register_file[src_reg]); 
/* 0x3d */ AJT_CASE(0x3d) // FD_BPF_OP_JGE_REG
  pc += (register_file[dst_reg] >= register_file[src_reg]) ? instr.offset : 0;
/* 0x3e */ AJT_CASE(0x3e);
/* 0x3f */ AJT_CASE(0x3f) // FD_BPF_OP_DIV64_REG
  register_file[dst_reg] /= register_file[src_reg];

/* 0x40 - 0x4f */
/* 0x40 */ AJT_CASE(0x40);
/* 0x41 */ AJT_CASE(0x41);
/* 0x42 */ AJT_CASE(0x42);
/* 0x43 */ AJT_CASE(0x43);
/* 0x44 */ AJT_CASE(0x44) // FD_BPF_OP_OR_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] | (uint)imm); 
/* 0x45 */ AJT_CASE(0x45) // FD_BPF_OP_JSET_IMM
  pc += (register_file[dst_reg] & imm) ? instr.offset : 0;
/* 0x46 */ AJT_CASE(0x46);
/* 0x47 */ AJT_CASE(0x47) // FD_BPF_OP_OR64_IMM
  register_file[dst_reg] |= imm;
/* 0x48 */ AJT_CASE(0x48);
/* 0x49 */ AJT_CASE(0x49);
/* 0x4a */ AJT_CASE(0x4a);
/* 0x4b */ AJT_CASE(0x4b);
/* 0x4c */ AJT_CASE(0x4c) // FD_BPF_OP_OR_REG
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] | (uint)register_file[src_reg]); 
/* 0x4d */ AJT_CASE(0x4d) // FD_BPF_OP_JSET_REG
  pc += (register_file[dst_reg] & register_file[src_reg]) ? instr.offset : 0;
/* 0x4e */ AJT_CASE(0x4e);
/* 0x4f */ AJT_CASE(0x4f) // FD_BPF_OP_OR64_REG
  register_file[dst_reg] |= register_file[src_reg];

/* 0x50 - 0x5f */
/* 0x50 */ AJT_CASE(0x50);
/* 0x51 */ AJT_CASE(0x51);
/* 0x52 */ AJT_CASE(0x52);
/* 0x53 */ AJT_CASE(0x53);
/* 0x54 */ AJT_CASE(0x54) // FD_BPF_OP_AND_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] & (uint)imm); 
/* 0x55 */ AJT_CASE(0x55) // FD_BPF_OP_JNE_IMM
  pc += (register_file[dst_reg] != imm) ? instr.offset : 0;
/* 0x56 */ AJT_CASE(0x56);
/* 0x57 */ AJT_CASE(0x57) // FD_BPF_OP_AND64_IMM
  register_file[dst_reg] &= imm;
/* 0x58 */ AJT_CASE(0x58);
/* 0x59 */ AJT_CASE(0x59);
/* 0x5a */ AJT_CASE(0x5a);
/* 0x5b */ AJT_CASE(0x5b);
/* 0x5c */ AJT_CASE(0x5c) // FD_BPF_OP_AND_RED
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] & (uint)register_file[src_reg]); 
/* 0x5d */ AJT_CASE(0x5d) // FD_BPF_OP_JNE_REG
  pc += (register_file[dst_reg] != register_file[src_reg]) ? instr.offset : 0;
/* 0x5e */ AJT_CASE(0x5e);
/* 0x5f */ AJT_CASE(0x5f) // FD_BPF_OP_AND64_REG
  register_file[dst_reg] &= register_file[src_reg];

/* 0x60 - 0x6f */
/* 0x60 */ AJT_CASE(0x60);
/* 0x61 */ AJT_CASE(0x61) // FD_BPF_OP_LDXW
  ulong * reg_ptr0 = &register_file[dst_reg];
  cond_fault = fd_vm_mem_map_read_uint( ctx, (ulong)((long)register_file[src_reg] + instr.offset), (uint *)reg_ptr0 );
/* 0x62 */ AJT_CASE(0x62) // FD_BPF_OP_STW
  cond_fault = fd_vm_mem_map_write_uint( ctx, (ulong)((long)register_file[dst_reg] + instr.offset), (uint)imm );
/* 0x63 */ AJT_CASE(0x63) // FD_BPF_OP_STXW
  cond_fault = fd_vm_mem_map_write_uint( ctx, (ulong)((long)register_file[dst_reg] + instr.offset), (uint)register_file[src_reg]);
/* 0x64 */ AJT_CASE(0x64) // FD_BPF_OP_LSH_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] << (uint)imm); 
/* 0x65 */ AJT_CASE(0x65) // FD_BPF_OP_JSGT_IMM
  pc += ((long)register_file[dst_reg] > (long)imm) ? instr.offset : 0;
/* 0x66 */ AJT_CASE(0x66);
/* 0x67 */ AJT_CASE(0x67) // FD_BPF_OP_LSH64_IMM
  register_file[dst_reg] <<= imm;
/* 0x68 */ AJT_CASE(0x68);
/* 0x69 */ AJT_CASE(0x69) // FD_BPF_OP_LDXH
  ulong * reg_ptr1 = &register_file[dst_reg];
  cond_fault = fd_vm_mem_map_read_ushort( ctx, (ulong)((long)register_file[src_reg] + instr.offset), (ushort *)reg_ptr1 );
/* 0x6a */ AJT_CASE(0x6a) // FD_BPF_OP_STH
  cond_fault = fd_vm_mem_map_write_ushort( ctx, (ulong)((long)register_file[dst_reg] + instr.offset), (ushort)imm );
/* 0x6b */ AJT_CASE(0x6b) // FD_BPF_OP_STXH
  cond_fault = fd_vm_mem_map_write_ushort( ctx, (ulong)((long)register_file[dst_reg] + instr.offset), (ushort)register_file[src_reg] );
/* 0x6c */ AJT_CASE(0x6c) // FD_BPF_OP_LSH_REG
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] << (uint)register_file[src_reg]); 
/* 0x6d */ AJT_CASE(0x6d) // FD_BPF_OP_JSGT_REG
  pc += ((long)register_file[dst_reg] > (long)register_file[src_reg]) ? instr.offset : 0;
/* 0x6e */ AJT_CASE(0x6e);
/* 0x6f */ AJT_CASE(0x6f) // FD_BPF_OP_LSH64_REG
  register_file[dst_reg] <<= register_file[src_reg];

/* 0x70 - 0x7f */
/* 0x70 */ AJT_CASE(0x70);
/* 0x71 */ AJT_CASE(0x71) // FD_BPF_OP_LDXB
  cond_fault = fd_vm_mem_map_read_uchar( ctx, (ulong)((long)register_file[src_reg] + instr.offset), (uchar *)&register_file[dst_reg] );
/* 0x72 */ AJT_CASE(0x72) // FD_BPF_OP_STB
  cond_fault = fd_vm_mem_map_write_uchar( ctx, (ulong)((long)register_file[dst_reg] + instr.offset), (uchar)imm );
/* 0x73 */ AJT_CASE(0x73) // FD_BPF_OP_STXB
  cond_fault = fd_vm_mem_map_write_uchar( ctx, (ulong)((long)register_file[dst_reg] + instr.offset), (uchar)register_file[src_reg] );
/* 0x74 */ AJT_CASE(0x74) // FD_BPF_OP_RSH_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] >> (uint)imm); 
/* 0x75 */ AJT_CASE(0x75) // FD_BPF_OP_JSGE_IMM
  pc += ((long)register_file[dst_reg] >= (long)imm) ? instr.offset : 0;
/* 0x76 */ AJT_CASE(0x76);
/* 0x77 */ AJT_CASE(0x77) // FD_BPF_OP_RSH64_IMM
  register_file[dst_reg] >>= imm;
/* 0x78 */ AJT_CASE(0x78);
/* 0x79 */ AJT_CASE(0x79) // FD_BPF_OP_LDXQ
  cond_fault = fd_vm_mem_map_read_ulong( ctx, (ulong)((long)register_file[src_reg] + instr.offset), (ulong *)&register_file[dst_reg] );
/* 0x7a */ AJT_CASE(0x7a) // FD_BPF_OP_STQ
  cond_fault = fd_vm_mem_map_write_ulong( ctx, (ulong)((long)register_file[dst_reg] + instr.offset), (ulong)imm );
/* 0x7b */ AJT_CASE(0x7b) // FD_BPF_OP_STXQ
  cond_fault = fd_vm_mem_map_write_ulong( ctx, (ulong)((long)register_file[dst_reg] + instr.offset), (ulong)register_file[src_reg] );
/* 0x7c */ AJT_CASE(0x7c) // FD_BPF_OP_RSH_REG
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] >> (uint)register_file[src_reg]); 
/* 0x7d */ AJT_CASE(0x7d) // FD_BPF_OP_JSGE_REG
  pc += ((long)register_file[dst_reg] > (long)register_file[src_reg]) ? instr.offset : 0;
/* 0x7e */ AJT_CASE(0x7e);
/* 0x7f */ AJT_CASE(0x7f) // FD_BPF_OP_RSH64_REG
  register_file[dst_reg] >>= register_file[src_reg];

/* 0x80 - 0x8f */
/* 0x80 */ AJT_CASE(0x80);
/* 0x81 */ AJT_CASE(0x81);
/* 0x82 */ AJT_CASE(0x82);
/* 0x83 */ AJT_CASE(0x83);
/* 0x84 */ AJT_CASE(0x84) // FD_BPF_OP_NEG
  register_file[dst_reg] = (uint)(~((uint)register_file[dst_reg])); 
/* 0x85 */ AJT_CASE(0x85);
/* 0x86 */ AJT_CASE(0x86);
/* 0x87 */ AJT_CASE(0x87) // FD_BPF_OP_NEG64
  register_file[dst_reg] = ~register_file[dst_reg];
/* 0x88 */ AJT_CASE(0x88);
/* 0x89 */ AJT_CASE(0x89);
/* 0x8a */ AJT_CASE(0x8a);
/* 0x8b */ AJT_CASE(0x8b);
/* 0x8c */ AJT_CASE(0x8c);
/* 0x8d */ AJT_CASE(0x8d);
/* 0x8e */ AJT_CASE(0x8e);
/* 0x8f */ AJT_CASE(0x8f);

/* 0x90 - 0x9f */
/* 0x90 */ AJT_CASE(0x90);
/* 0x91 */ AJT_CASE(0x91);
/* 0x92 */ AJT_CASE(0x92);
/* 0x93 */ AJT_CASE(0x93);
/* 0x94 */ AJT_CASE(0x94) // FD_BPF_OP_MOD_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] % (uint)imm); 
/* 0x95 */ AJT_CASE(0x95);
  cond_exit = 1;
/* 0x96 */ AJT_CASE(0x96);
/* 0x97 */ AJT_CASE(0x97) // FD_BPF_OP_MOD64_IMM
  register_file[dst_reg] %= imm;
/* 0x98 */ AJT_CASE(0x98);
/* 0x99 */ AJT_CASE(0x99);
/* 0x9a */ AJT_CASE(0x9a);
/* 0x9b */ AJT_CASE(0x9b);
/* 0x9c */ AJT_CASE(0x9c) // FD_BPF_OP_MOD_REG
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] % (uint)register_file[src_reg]); 
/* 0x9d */ AJT_CASE(0x9d);
/* 0x9e */ AJT_CASE(0x9e);
/* 0x9f */ AJT_CASE(0x9f) // FD_BPF_OP_MOD64_REG
  register_file[dst_reg] %= register_file[src_reg];

/* 0xa0 - 0xaf */
/* 0xa0 */ AJT_CASE(0xa0);
/* 0xa1 */ AJT_CASE(0xa1);
/* 0xa2 */ AJT_CASE(0xa2);
/* 0xa3 */ AJT_CASE(0xa3);
/* 0xa4 */ AJT_CASE(0xa4) // FD_BPF_OP_XOR_IMM
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] ^ (uint)imm); 
/* 0xa5 */ AJT_CASE(0xa5) // FD_BPF_OP_JLT_IMM
  pc += (register_file[dst_reg] < imm) ? instr.offset : 0;
/* 0xa6 */ AJT_CASE(0xa6);
/* 0xa7 */ AJT_CASE(0xa7) // FD_BPF_OP_XOR64_IMM
  register_file[dst_reg] ^= imm;
/* 0xa8 */ AJT_CASE(0xa8);
/* 0xa9 */ AJT_CASE(0xa9);
/* 0xaa */ AJT_CASE(0xaa);
/* 0xab */ AJT_CASE(0xab);
/* 0xac */ AJT_CASE(0xac) // FD_BPF_XOR_REG
  register_file[dst_reg] = (uint)((uint)register_file[dst_reg] ^ (uint)register_file[src_reg]); 
/* 0xad */ AJT_CASE(0xad) // FD_BPF_OP_JLT_REG
  pc += (register_file[dst_reg] < register_file[src_reg]) ? instr.offset : 0;
/* 0xae */ AJT_CASE(0xae);
/* 0xaf */ AJT_CASE(0xaf) // FD_BPF_OP_XOR64_REG
  register_file[dst_reg] ^= register_file[src_reg];

/* 0xb0 - 0xbf */
/* 0xb0 */ AJT_CASE(0xb0);
/* 0xb1 */ AJT_CASE(0xb1);
/* 0xb2 */ AJT_CASE(0xb2);
/* 0xb3 */ AJT_CASE(0xb3);
/* 0xb4 */ AJT_CASE(0xb4) // FD_BPF_OP_MOV_IMM
  register_file[dst_reg] = (uint)imm; 
/* 0xb5 */ AJT_CASE(0xb5) // FD_BPF_OP_JLE_IMM
  pc += (register_file[dst_reg] <= imm) ? instr.offset : 0;
/* 0xb6 */ AJT_CASE(0xb6);
/* 0xb7 */ AJT_CASE(0xb7) // FD_BPF_OP_MOV64_IMM
  register_file[dst_reg] = imm;
/* 0xb8 */ AJT_CASE(0xb8);
/* 0xb9 */ AJT_CASE(0xb9);
/* 0xba */ AJT_CASE(0xba);
/* 0xbb */ AJT_CASE(0xbb);
/* 0xbc */ AJT_CASE(0xbc) // FD_BPF_OP_MOV_REG
  register_file[dst_reg] = (uint)register_file[src_reg];
/* 0xbd */ AJT_CASE(0xbd) // FD_BPF_OP_JLE_REG
  pc += (register_file[dst_reg] <= register_file[src_reg]) ? instr.offset : 0;
/* 0xbe */ AJT_CASE(0xbe);
/* 0xbf */ AJT_CASE(0xbf) // FD_BPF_OP_MOV64_REG
  register_file[dst_reg] = register_file[src_reg];

/* 0xc0 - 0xcf */
/* 0xc0 */ AJT_CASE(0xc0);
/* 0xc1 */ AJT_CASE(0xc1);
/* 0xc2 */ AJT_CASE(0xc2);
/* 0xc3 */ AJT_CASE(0xc3);
/* 0xc4 */ AJT_CASE(0xc4) // FD_BPF_OP_ARSH_IMM
  register_file[dst_reg] = (uint)((int)register_file[dst_reg] >> (uint)imm); 
/* 0xc5 */ AJT_CASE(0xc5) // FD_BPF_OP_JSLT_IMM
  pc += ((long)register_file[dst_reg] < (long)imm) ? instr.offset : 0;
/* 0xc6 */ AJT_CASE(0xc6);
/* 0xc7 */ AJT_CASE(0xc7) // FD_BPF_OP_ARSH64_IMM
  register_file[dst_reg] = (ulong)((long)register_file[dst_reg] >> imm);
/* 0xc8 */ AJT_CASE(0xc8);
/* 0xc9 */ AJT_CASE(0xc9);
/* 0xca */ AJT_CASE(0xca);
/* 0xcb */ AJT_CASE(0xcb);
/* 0xcc */ AJT_CASE(0xcc) // FD_BPF_OP_ARSH_REG
  register_file[dst_reg] = (uint)((int)register_file[dst_reg] >> (uint)register_file[src_reg]);
/* 0xcd */ AJT_CASE(0xcd) // FD_BPF_OP_JSLT_REG
  pc += ((long)register_file[dst_reg] < (long)register_file[src_reg]) ? instr.offset : 0;
/* 0xce */ AJT_CASE(0xce);
/* 0xcf */ AJT_CASE(0xcf) // FD_BPF_OP_ARSH64_REG
  register_file[dst_reg] = (ulong)((long)register_file[dst_reg] >> register_file[src_reg]);

/* 0xd0 - 0xdf */
/* 0xd0 */ AJT_CASE(0xd0);
/* 0xd1 */ AJT_CASE(0xd1);
/* 0xd2 */ AJT_CASE(0xd2);
/* 0xd3 */ AJT_CASE(0xd3);
/* 0xd4 */ AJT_CASE(0xd4) // FD_BPF_OP_LE
  /* On x86_64, the host is LE already */
/* 0xd5 */ AJT_CASE(0xd5) // FD_BPF_OP_JSLE_IMM
  pc += ((long)register_file[dst_reg] <= (long)imm) ? instr.offset : 0;
/* 0xd6 */ AJT_CASE(0xd6);
/* 0xd7 */ AJT_CASE(0xd7);
/* 0xd8 */ AJT_CASE(0xd8);
/* 0xd9 */ AJT_CASE(0xd9);
/* 0xda */ AJT_CASE(0xda);
/* 0xdb */ AJT_CASE(0xdb);
/* 0xdc */ AJT_CASE(0xdc) // FD_BPF_OP_BE 
  switch (imm) {
    case 16:
      uchar tmp = ((uchar *)&register_file[dst_reg])[0];
      ((uchar *)&register_file[dst_reg])[0] = ((uchar *)&register_file[dst_reg])[1];
      ((uchar *)&register_file[dst_reg])[1] = tmp;
      
      break;
    case 32:
      register_file[dst_reg] = (uint)_bswap((int)register_file[dst_reg]);
      break;
    case 64:
      register_file[dst_reg] = (ulong)_bswap64((long)register_file[dst_reg]);
      break;
  }
/* 0xdd */ AJT_CASE(0xdd) // FD_BPF_OP_JSLE_REG
  pc += ((long)register_file[dst_reg] <= (long)register_file[src_reg]) ? instr.offset : 0;
/* 0xde */ AJT_CASE(0xde);
/* 0xdf */ AJT_CASE(0xdf);

/* 0xe0 - 0xef */
/* 0xe0 */ AJT_CASE(0xe0);
/* 0xe1 */ AJT_CASE(0xe1);
/* 0xe2 */ AJT_CASE(0xe2);
/* 0xe3 */ AJT_CASE(0xe3);
/* 0xe4 */ AJT_CASE(0xe4);
/* 0xe5 */ AJT_CASE(0xe5);
/* 0xe6 */ AJT_CASE(0xe6);
/* 0xe7 */ AJT_CASE(0xe7);
/* 0xe8 */ AJT_CASE(0xe8);
/* 0xe9 */ AJT_CASE(0xe9);
/* 0xea */ AJT_CASE(0xea);
/* 0xeb */ AJT_CASE(0xeb);
/* 0xec */ AJT_CASE(0xec);
/* 0xed */ AJT_CASE(0xed);
/* 0xee */ AJT_CASE(0xee);
/* 0xef */ AJT_CASE(0xef);

/* 0xf0 - 0xff */
/* 0xf0 */ AJT_CASE(0xf0);
/* 0xf1 */ AJT_CASE(0xf1);
/* 0xf2 */ AJT_CASE(0xf2);
/* 0xf3 */ AJT_CASE(0xf3);
/* 0xf4 */ AJT_CASE(0xf4);
/* 0xf5 */ AJT_CASE(0xf5);
/* 0xf6 */ AJT_CASE(0xf6);
/* 0xf7 */ AJT_CASE(0xf7);
/* 0xf8 */ AJT_CASE(0xf8);
/* 0xf9 */ AJT_CASE(0xf9);
/* 0xfa */ AJT_CASE(0xfa);
/* 0xfb */ AJT_CASE(0xfb);
/* 0xfc */ AJT_CASE(0xfc);
/* 0xfd */ AJT_CASE(0xfd);
/* 0xfe */ AJT_CASE(0xfe);
/* 0xff */ AJT_CASE(0xff);
