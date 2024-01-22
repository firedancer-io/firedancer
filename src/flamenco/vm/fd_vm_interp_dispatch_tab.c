/* This is the BPF interpreter dispatch table.
 * Each instruction is implemented in this table.
 *
 * See `fd_vm_interp.c` for usage.
 */

#ifdef __GNUC__
#ifndef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#endif

#define BRANCH_PRE_CODE \
{ \
  long insns = pc-start_pc + 1; \
  // FD_LOG_WARNING(("Q %ld %ld %ld", pc, start_pc, insns));

#define BRANCH_POST_CODE \
  instr = ctx->instrs[++pc]; \
  ic += (ulong)insns; \
  start_pc = pc; \
  due_insn_cnt += (ulong)insns - skipped_insns; \
  skipped_insns = 0; \
  if ( FD_UNLIKELY( due_insn_cnt >= previous_instruction_meter ) ) { \
    goto interp_fault; \
  } \
  goto *(locs[instr.opcode.raw]); \
}

#define INSTR_POST_CODE \
  instr = ctx->instrs[++pc]; \
  goto *(locs[instr.opcode.raw]);

/* 0x00 - 0x0f */
/* 0x00 */ JT_CASE(0x00); // FD_BPF_OP_ADDL_IMM
/* 0x04 */ JT_CASE(0x04) // FD_BPF_OP_ADD_IMM
  register_file[instr.dst_reg] = (uint)((uint)register_file[instr.dst_reg] + (uint)instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0x05 */ JT_CASE(0x05) // FD_BPF_OP_JA
BRANCH_PRE_CODE
  pc += instr.offset;
BRANCH_POST_CODE
JT_CASE_END
/* 0x07 */ JT_CASE(0x07) // FD_BPF_OP_ADD64_IMM
  register_file[instr.dst_reg] = (ulong)((long)register_file[instr.dst_reg] + (int)instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0x0c */ JT_CASE(0x0c) // FD_BPF_OP_ADD_REG
  register_file[instr.dst_reg] = (uint)((uint)register_file[instr.dst_reg] + (uint)register_file[instr.src_reg]);
INSTR_POST_CODE
JT_CASE_END
/* 0x0f */ JT_CASE(0x0f) // FD_BPF_OP_ADD64_REG
  register_file[instr.dst_reg] += register_file[instr.src_reg];
INSTR_POST_CODE
JT_CASE_END

/* 0x10 - 0x1f */
/* 0x14 */ JT_CASE(0x14) // FD_BPF_OP_SUB_IMM
  register_file[instr.dst_reg] = (uint)((uint)register_file[instr.dst_reg] - (uint)instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0x15 */ JT_CASE(0x15) // FD_BPF_OP_JEQ_IMM
BRANCH_PRE_CODE
  pc += ((long)register_file[instr.dst_reg] == (int)instr.imm) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0x17 */ JT_CASE(0x17) // FD_BPF_OP_SUB64_IMM
  register_file[instr.dst_reg] = (ulong)((long)register_file[instr.dst_reg] - (int)instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0x18 */ JT_CASE(0x18) // FD_BPF_OP_LDQ
  register_file[instr.dst_reg] = (ulong)((ulong)instr.imm | ((ulong)ctx->instrs[pc+1].imm << 32));
  pc++;
  skipped_insns++;
INSTR_POST_CODE
JT_CASE_END
/* 0x1c */ JT_CASE(0x1c) // FD_BPF_OP_SUB_REG
  register_file[instr.dst_reg] = (uint)((uint)register_file[instr.dst_reg] - (uint)register_file[instr.src_reg]);
INSTR_POST_CODE
JT_CASE_END
/* 0x1d */ JT_CASE(0x1d) // FD_BPF_OP_JEQ_REG
BRANCH_PRE_CODE
  pc += (register_file[instr.dst_reg] == register_file[instr.src_reg]) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0x1f */ JT_CASE(0x1f) // FD_BPF_OP_SUB64_REG
  register_file[instr.dst_reg] -= register_file[instr.src_reg];
INSTR_POST_CODE
JT_CASE_END

/* 0x20 - 0x2f */
/* 0x24 */ JT_CASE(0x24) // FD_BPF_OP_MUL_IMM
  register_file[instr.dst_reg] = (uint)((uint)register_file[instr.dst_reg] * (uint)instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0x25 */ JT_CASE(0x25) // FD_BPF_OP_JGT_IMM
BRANCH_PRE_CODE
  pc += (register_file[instr.dst_reg] > (ulong)(long)(int)instr.imm) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0x27 */ JT_CASE(0x27) // FD_BPF_OP_MUL64_IMM
  register_file[instr.dst_reg] = (ulong)((long)register_file[instr.dst_reg] * (int)instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0x2c */ JT_CASE(0x2c) // FD_BPF_OP_MUL_REG
  register_file[instr.dst_reg] = (uint)((uint)register_file[instr.dst_reg] * (uint)register_file[instr.src_reg]);
INSTR_POST_CODE
JT_CASE_END
/* 0x2d */ JT_CASE(0x2d) // FD_BPF_OP_JGT_REG
BRANCH_PRE_CODE
  pc += (register_file[instr.dst_reg] > register_file[instr.src_reg]) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0x2f */ JT_CASE(0x2f) // FD_BPF_OP_MUL64_REG
  register_file[instr.dst_reg] *= register_file[instr.src_reg];
INSTR_POST_CODE
JT_CASE_END

/* 0x30 - 0x3f */
/* 0x34 */ JT_CASE(0x34) // FD_BPF_OP_DIV_IMM
  register_file[instr.dst_reg] = instr.imm == 0 ? 0 : (uint)((uint)register_file[instr.dst_reg] / (uint)instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0x35 */ JT_CASE(0x35) // FD_BPF_OP_JGE_IMM
BRANCH_PRE_CODE
  pc += (register_file[instr.dst_reg] >= instr.imm) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0x37 */ JT_CASE(0x37) // FD_BPF_OP_DIV64_IMM
  // TODO: pretty sure that this instr is checked to be non-zero imm at valiation-time. 
  register_file[instr.dst_reg] = instr.imm == 0 ? 0UL : (ulong)((ulong)register_file[instr.dst_reg] / (ulong)instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0x3c */ JT_CASE(0x3c) // FD_BPF_OP_DIV_REG
  register_file[instr.dst_reg] = (uint)register_file[instr.src_reg] == 0 ? 0 : (uint)((uint)register_file[instr.dst_reg] / (uint)register_file[instr.src_reg]);
INSTR_POST_CODE
JT_CASE_END
/* 0x3d */ JT_CASE(0x3d) // FD_BPF_OP_JGE_REG
BRANCH_PRE_CODE
  pc += (register_file[instr.dst_reg] >= register_file[instr.src_reg]) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0x3f */ JT_CASE(0x3f) // FD_BPF_OP_DIV64_REG
  register_file[instr.dst_reg] = register_file[instr.src_reg] == 0 ? 0 : (register_file[instr.dst_reg] / register_file[instr.src_reg]);
INSTR_POST_CODE
JT_CASE_END

/* 0x40 - 0x4f */
/* 0x44 */ JT_CASE(0x44) // FD_BPF_OP_OR_IMM
  register_file[instr.dst_reg] = (uint)((uint)register_file[instr.dst_reg] | (uint)instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0x45 */ JT_CASE(0x45) // FD_BPF_OP_JSET_IMM
BRANCH_PRE_CODE
  pc += (register_file[instr.dst_reg] & instr.imm) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0x47 */ JT_CASE(0x47) // FD_BPF_OP_OR64_IMM
  register_file[instr.dst_reg] = (ulong)((long)register_file[instr.dst_reg] | (int)instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0x4c */ JT_CASE(0x4c) // FD_BPF_OP_OR_REG
  register_file[instr.dst_reg] = (uint)((uint)register_file[instr.dst_reg] | (uint)register_file[instr.src_reg]);
INSTR_POST_CODE
JT_CASE_END
/* 0x4d */ JT_CASE(0x4d) // FD_BPF_OP_JSET_REG
BRANCH_PRE_CODE
  pc += (register_file[instr.dst_reg] & register_file[instr.src_reg]) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0x4f */ JT_CASE(0x4f) // FD_BPF_OP_OR64_REG
  register_file[instr.dst_reg] |= register_file[instr.src_reg];
INSTR_POST_CODE
JT_CASE_END

/* 0x50 - 0x5f */
/* 0x54 */ JT_CASE(0x54) // FD_BPF_OP_AND_IMM
  register_file[instr.dst_reg] = (uint)((uint)register_file[instr.dst_reg] & (uint)instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0x55 */ JT_CASE(0x55) // FD_BPF_OP_JNE_IMM
BRANCH_PRE_CODE
  pc += ((long)register_file[instr.dst_reg] != (int)instr.imm) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0x57 */ JT_CASE(0x57) // FD_BPF_OP_AND64_IMM
  register_file[instr.dst_reg] = (ulong)((long)register_file[instr.dst_reg] & (int)instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0x5c */ JT_CASE(0x5c) // FD_BPF_OP_AND_REG
  register_file[instr.dst_reg] = (uint)((uint)register_file[instr.dst_reg] & (uint)register_file[instr.src_reg]);
INSTR_POST_CODE
JT_CASE_END
/* 0x5d */ JT_CASE(0x5d) // FD_BPF_OP_JNE_REG
BRANCH_PRE_CODE
  pc += (register_file[instr.dst_reg] != register_file[instr.src_reg]) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0x5f */ JT_CASE(0x5f) // FD_BPF_OP_AND64_REG
  register_file[instr.dst_reg] &= register_file[instr.src_reg];
INSTR_POST_CODE
JT_CASE_END

/* 0x60 - 0x6f */
/* 0x61 */ JT_CASE(0x61) // FD_BPF_OP_LDXW
  cond_fault = fd_vm_mem_map_read_uint( ctx, (ulong)((long)register_file[instr.src_reg] + instr.offset), &register_file[instr.dst_reg] );
  goto *((cond_fault == 0) ? &&fallthrough_0x61 : &&JT_RET_LOC);
fallthrough_0x61:
INSTR_POST_CODE
JT_CASE_END
/* 0x62 */ JT_CASE(0x62) // FD_BPF_OP_STW
  cond_fault = fd_vm_mem_map_write_uint( ctx, (ulong)((long)register_file[instr.dst_reg] + instr.offset), (uint)instr.imm );
  goto *((cond_fault == 0) ? &&fallthrough_0x62 : &&JT_RET_LOC);
fallthrough_0x62:
INSTR_POST_CODE
JT_CASE_END
/* 0x63 */ JT_CASE(0x63) // FD_BPF_OP_STXW
  cond_fault = fd_vm_mem_map_write_uint( ctx, (ulong)((long)register_file[instr.dst_reg] + instr.offset), (uint)register_file[instr.src_reg]);
  goto *((cond_fault == 0) ? &&fallthrough_0x63 : &&JT_RET_LOC);
fallthrough_0x63:
INSTR_POST_CODE
JT_CASE_END
/* 0x64 */ JT_CASE(0x64) // FD_BPF_OP_LSH_IMM
  register_file[instr.dst_reg] = (uint)((uint)register_file[instr.dst_reg] << (uint)instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0x65 */ JT_CASE(0x65) // FD_BPF_OP_JSGT_IMM
BRANCH_PRE_CODE
  pc += ((long)register_file[instr.dst_reg] > (int)instr.imm) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0x67 */ JT_CASE(0x67) // FD_BPF_OP_LSH64_IMM
  register_file[instr.dst_reg] <<= instr.imm;
INSTR_POST_CODE
JT_CASE_END
/* 0x69 */ JT_CASE(0x69) // FD_BPF_OP_LDXH
  cond_fault = fd_vm_mem_map_read_ushort( ctx, (ulong)((long)register_file[instr.src_reg] + instr.offset), &register_file[instr.dst_reg] );
  goto *((cond_fault == 0) ? &&fallthrough_0x69 : &&JT_RET_LOC);
fallthrough_0x69:
INSTR_POST_CODE
JT_CASE_END
/* 0x6a */ JT_CASE(0x6a) // FD_BPF_OP_STH
  cond_fault = fd_vm_mem_map_write_ushort( ctx, (ulong)((long)register_file[instr.dst_reg] + instr.offset), (ushort)instr.imm );
  goto *((cond_fault == 0) ? &&fallthrough_0x6a : &&JT_RET_LOC);
fallthrough_0x6a:
INSTR_POST_CODE
JT_CASE_END
/* 0x6b */ JT_CASE(0x6b) // FD_BPF_OP_STXH
  cond_fault = fd_vm_mem_map_write_ushort( ctx, (ulong)((long)register_file[instr.dst_reg] + instr.offset), (ushort)register_file[instr.src_reg] );
  goto *((cond_fault == 0) ? &&fallthrough_0x6b : &&JT_RET_LOC);
fallthrough_0x6b:
INSTR_POST_CODE
JT_CASE_END
/* 0x6c */ JT_CASE(0x6c) // FD_BPF_OP_LSH_REG
  register_file[instr.dst_reg] = (uint)((uint)register_file[instr.dst_reg] << (uint)register_file[instr.src_reg]);
INSTR_POST_CODE
JT_CASE_END
/* 0x6d */ JT_CASE(0x6d) // FD_BPF_OP_JSGT_REG
BRANCH_PRE_CODE
  pc += ((long)register_file[instr.dst_reg] > (long)register_file[instr.src_reg]) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0x6f */ JT_CASE(0x6f) // FD_BPF_OP_LSH64_REG
  register_file[instr.dst_reg] <<= register_file[instr.src_reg];
INSTR_POST_CODE
JT_CASE_END

/* 0x70 - 0x7f */
/* 0x71 */ JT_CASE(0x71) // FD_BPF_OP_LDXB
  cond_fault = fd_vm_mem_map_read_uchar( ctx, (ulong)((long)register_file[instr.src_reg] + instr.offset), &register_file[instr.dst_reg] );
  goto *((cond_fault == 0) ? &&fallthrough_0x71 : &&JT_RET_LOC);
fallthrough_0x71:
INSTR_POST_CODE
JT_CASE_END
/* 0x72 */ JT_CASE(0x72) // FD_BPF_OP_STB
  cond_fault = fd_vm_mem_map_write_uchar( ctx, (ulong)((long)register_file[instr.dst_reg] + instr.offset), (uchar)instr.imm );
  goto *((cond_fault == 0) ? &&fallthrough_0x72 : &&JT_RET_LOC);
fallthrough_0x72:
INSTR_POST_CODE
JT_CASE_END
/* 0x73 */ JT_CASE(0x73) // FD_BPF_OP_STXB
  cond_fault = fd_vm_mem_map_write_uchar( ctx, (ulong)((long)register_file[instr.dst_reg] + instr.offset), (uchar)register_file[instr.src_reg] );
  goto *((cond_fault == 0) ? &&fallthrough_0x73 : &&JT_RET_LOC);
fallthrough_0x73:
INSTR_POST_CODE
JT_CASE_END
/* 0x74 */ JT_CASE(0x74) // FD_BPF_OP_RSH_IMM
  register_file[instr.dst_reg] = (uint)((uint)register_file[instr.dst_reg] >> (uint)instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0x75 */ JT_CASE(0x75) // FD_BPF_OP_JSGE_IMM
BRANCH_PRE_CODE
  pc += ((long)register_file[instr.dst_reg] >= (long)instr.imm) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0x77 */ JT_CASE(0x77) // FD_BPF_OP_RSH64_IMM
  register_file[instr.dst_reg] >>= instr.imm;
INSTR_POST_CODE
JT_CASE_END
/* 0x79 */ JT_CASE(0x79) // FD_BPF_OP_LDXQ
  cond_fault = fd_vm_mem_map_read_ulong( ctx, (ulong)((long)register_file[instr.src_reg] + instr.offset), (ulong *)&register_file[instr.dst_reg] );
  goto *((cond_fault == 0) ? &&fallthrough_0x79 : &&JT_RET_LOC);
fallthrough_0x79:
INSTR_POST_CODE
JT_CASE_END
/* 0x7a */ JT_CASE(0x7a) // FD_BPF_OP_STQ
  cond_fault = fd_vm_mem_map_write_ulong( ctx, (ulong)((long)register_file[instr.dst_reg] + instr.offset), (ulong)instr.imm );
  goto *((cond_fault == 0) ? &&fallthrough_0x7a : &&JT_RET_LOC);
fallthrough_0x7a:
INSTR_POST_CODE
JT_CASE_END
/* 0x7b */ JT_CASE(0x7b) // FD_BPF_OP_STXQ
  cond_fault = fd_vm_mem_map_write_ulong( ctx, (ulong)((long)register_file[instr.dst_reg] + instr.offset), (ulong)register_file[instr.src_reg] );
  goto *((cond_fault == 0) ? &&fallthrough_0x7b : &&JT_RET_LOC);
fallthrough_0x7b:
INSTR_POST_CODE
JT_CASE_END
/* 0x7c */ JT_CASE(0x7c) // FD_BPF_OP_RSH_REG
  register_file[instr.dst_reg] = (uint)((uint)register_file[instr.dst_reg] >> (uint)register_file[instr.src_reg]);
INSTR_POST_CODE
JT_CASE_END
/* 0x7d */ JT_CASE(0x7d) // FD_BPF_OP_JSGE_REG
BRANCH_PRE_CODE
  pc += ((long)register_file[instr.dst_reg] >= (long)register_file[instr.src_reg]) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0x7f */ JT_CASE(0x7f) // FD_BPF_OP_RSH64_REG
  register_file[instr.dst_reg] >>= register_file[instr.src_reg];
INSTR_POST_CODE
JT_CASE_END

/* 0x80 - 0x8f */
/* 0x84 */ JT_CASE(0x84) // FD_BPF_OP_NEG
  register_file[instr.dst_reg] = (uint)(-((int)register_file[instr.dst_reg]));
INSTR_POST_CODE
JT_CASE_END
/* 0x85 */ JT_CASE(0x85) // FD_BPF_OP_CALL_IMM
BRANCH_PRE_CODE
  if ( (ulong)(pc + (int)instr.imm + 1L) < ctx->instrs_sz ) {
    register_file[10] += 0x2000;
    cond_fault = 0;
    fd_vm_stack_push( &ctx->stack, (ulong)pc, &register_file[6] );
    // printf("QQQ: %lu\n", instr.imm);
    pc += (int)instr.imm;
  } else {
    compute_meter = fd_ulong_sat_sub(compute_meter, due_insn_cnt);
    ctx->compute_meter = compute_meter;
    due_insn_cnt = 0;
    ctx->due_insn_cnt = 0;
    fd_sbpf_syscalls_t * syscall_entry_imm = fd_sbpf_syscalls_query( ctx->syscall_map, instr.imm, NULL );
    if( syscall_entry_imm==NULL ) {
      fd_sbpf_calldests_t * calldest_entry_imm = fd_sbpf_calldests_query( ctx->local_call_map, instr.imm, NULL );
      if( calldest_entry_imm!=NULL ) {
        // FIXME: DO STACK STUFF correctly: move this r10 manipulation in the fd_vm_stack_t or on success.
        register_file[10] += 0x2000;
        // FIXME: stack overflow fault.
        fd_vm_stack_push( &ctx->stack, (ulong)pc, &register_file[6] );
        pc = (long)(calldest_entry_imm->pc-1);
      } else {
        // TODO: real error for nonexistent func
        cond_fault = 1;
      }
    } else {
      ctx->compute_meter = compute_meter;
      cond_fault = ((fd_vm_syscall_fn_ptr_t)( syscall_entry_imm->func_ptr ))(ctx, register_file[1], register_file[2], register_file[3], register_file[4], register_file[5], &register_file[0]);
      compute_meter = ctx->compute_meter;
    }
    previous_instruction_meter = compute_meter;
    ctx->previous_instruction_meter = previous_instruction_meter;
  }
  goto *((cond_fault == 0) ? &&fallthrough_0x85 : &&JT_RET_LOC);
fallthrough_0x85:
BRANCH_POST_CODE
JT_CASE_END
/* 0x87 */ JT_CASE(0x87) // FD_BPF_OP_NEG64
  register_file[instr.dst_reg] = (ulong)(-(long)register_file[instr.dst_reg]);
INSTR_POST_CODE
JT_CASE_END
/* 0x8d */ JT_CASE(0x8d)  // FD_BPF_OP_CALL_REG
BRANCH_PRE_CODE
{
  /* Check if we are in the read only region */
  ulong call_addr = register_file[instr.imm];
  ulong mem_region = call_addr & FD_VM_MEM_MAP_REGION_MASK;
  if( mem_region==FD_VM_MEM_MAP_PROGRAM_REGION_START ) {
    // FIXME: check alignment
    // FIXME: check for run into other region.
    ulong start_addr = call_addr & FD_VM_MEM_MAP_REGION_SZ;
    // FIXME: DO STACK STUFF correctly: move this r10 manipulation in the fd_vm_stack_t or on success.
    register_file[10] += 0x2000;
    // FIXME: stack overflow fault.
    cond_fault = fd_vm_stack_push( &ctx->stack, (ulong)pc, &register_file[6] );
    pc = (long)((start_addr / 8UL)-1);
    pc -= (long)ctx->instrs_offset;
  } else {
    fd_sbpf_syscalls_t * syscall_entry_reg = fd_sbpf_syscalls_query( ctx->syscall_map, (uint)register_file[instr.imm], NULL );
    if( syscall_entry_reg==NULL ) {
      fd_sbpf_calldests_t * calldest_entry_reg = fd_sbpf_calldests_query( ctx->local_call_map, (uint)register_file[instr.imm], NULL );
      if( calldest_entry_reg!=NULL ) {
        // FIXME: DO STACK STUFF correctly: move this r10 manipulation in the fd_vm_stack_t or on success.
        register_file[10] += 0x2000;
        // FIXME: stack overflow fault.
        cond_fault = fd_vm_stack_push( &ctx->stack, (ulong)pc, &register_file[6] );
        pc = (long)(calldest_entry_reg->pc-1);
      } else {
        // TODO: real error for nonexistent func
        cond_fault = 1;
      }
    } else {
      due_insn_cnt = fd_ulong_sat_add(due_insn_cnt, 1UL);
      cond_fault = ((fd_vm_syscall_fn_ptr_t)( syscall_entry_reg->func_ptr ))(ctx, register_file[2], register_file[2], register_file[3], register_file[4], register_file[5], &register_file[0]);
    }
  }
  goto *((cond_fault == 0) ? &&fallthrough_0x8d : &&JT_RET_LOC);
}
fallthrough_0x8d:
BRANCH_POST_CODE
JT_CASE_END

/* 0x90 - 0x9f */
/* 0x94 */ JT_CASE(0x94) // FD_BPF_OP_MOD_IMM
  register_file[instr.dst_reg] = ((uint)instr.imm==0) ? (uint)register_file[instr.dst_reg] : (uint)((uint)register_file[instr.dst_reg] % (uint)instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0x95 */ JT_CASE(0x95) // FD_BPF_OP_EXIT
BRANCH_PRE_CODE
  register_file[10] -= 0x2000;
  // FIXME: stack underflow fault.
  if( ctx->stack.frames_used==0 ) {
    if (due_insn_cnt > previous_instruction_meter) {
      goto interp_fault;
    }
    goto JT_RET_LOC;
  }
  fd_vm_stack_pop( &ctx->stack, (ulong *)&pc, &register_file[6] );
BRANCH_POST_CODE
JT_CASE_END
/* 0x97 */ JT_CASE(0x97) // FD_BPF_OP_MOD64_IMM
  register_file[instr.dst_reg] = (instr.imm==0) ? register_file[instr.dst_reg] : register_file[instr.dst_reg] % instr.imm;
INSTR_POST_CODE
JT_CASE_END
/* 0x9c */ JT_CASE(0x9c) // FD_BPF_OP_MOD_REG
  register_file[instr.dst_reg] = ((uint)register_file[instr.src_reg]==0)
    ? (uint)register_file[instr.dst_reg]
    : (uint)((uint)register_file[instr.dst_reg] % (uint)register_file[instr.src_reg]);
INSTR_POST_CODE
JT_CASE_END
/* 0x9f */ JT_CASE(0x9f) // FD_BPF_OP_MOD64_REG
  register_file[instr.dst_reg] = (register_file[instr.src_reg]==0)
    ? register_file[instr.dst_reg]
    : register_file[instr.dst_reg] % register_file[instr.src_reg];
INSTR_POST_CODE
JT_CASE_END

/* 0xa0 - 0xaf */
/* 0xa4 */ JT_CASE(0xa4) // FD_BPF_OP_XOR_IMM
  register_file[instr.dst_reg] = (uint)((uint)register_file[instr.dst_reg] ^ (uint)instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0xa5 */ JT_CASE(0xa5) // FD_BPF_OP_JLT_IMM
BRANCH_PRE_CODE
  pc += (register_file[instr.dst_reg] < instr.imm) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0xa7 */ JT_CASE(0xa7) // FD_BPF_OP_XOR64_IMM
  *(long *)&register_file[instr.dst_reg] ^= (int)instr.imm;
INSTR_POST_CODE
JT_CASE_END
/* 0xac */ JT_CASE(0xac) // FD_BPF_XOR_REG
  register_file[instr.dst_reg] = (uint)((uint)register_file[instr.dst_reg] ^ (uint)register_file[instr.src_reg]);
INSTR_POST_CODE
JT_CASE_END
/* 0xad */ JT_CASE(0xad) // FD_BPF_OP_JLT_REG
BRANCH_PRE_CODE
  pc += (register_file[instr.dst_reg] < register_file[instr.src_reg]) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0xaf */ JT_CASE(0xaf) // FD_BPF_OP_XOR64_REG
  register_file[instr.dst_reg] ^= register_file[instr.src_reg];
INSTR_POST_CODE
JT_CASE_END

/* 0xb0 - 0xbf */
/* 0xb4 */ JT_CASE(0xb4) // FD_BPF_OP_MOV_IMM
  register_file[instr.dst_reg] = (uint)instr.imm;
INSTR_POST_CODE
JT_CASE_END
/* 0xb5 */ JT_CASE(0xb5) // FD_BPF_OP_JLE_IMM
BRANCH_PRE_CODE
  pc += (register_file[instr.dst_reg] <= instr.imm) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0xb7 */ JT_CASE(0xb7) // FD_BPF_OP_MOV64_IMM
  *(long *)&register_file[instr.dst_reg] = (int)instr.imm;
INSTR_POST_CODE
JT_CASE_END
/* 0xbc */ JT_CASE(0xbc) // FD_BPF_OP_MOV_REG
  register_file[instr.dst_reg] = (uint)register_file[instr.src_reg];
INSTR_POST_CODE
JT_CASE_END
/* 0xbd */ JT_CASE(0xbd) // FD_BPF_OP_JLE_REG
BRANCH_PRE_CODE
  pc += (register_file[instr.dst_reg] <= register_file[instr.src_reg]) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0xbf */ JT_CASE(0xbf) // FD_BPF_OP_MOV64_REG
  register_file[instr.dst_reg] = register_file[instr.src_reg];
INSTR_POST_CODE
JT_CASE_END

/* 0xc0 - 0xcf */
/* 0xc4 */ JT_CASE(0xc4) // FD_BPF_OP_ARSH_IMM
  register_file[instr.dst_reg] = (uint)((int)register_file[instr.dst_reg] >> (uint)instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0xc5 */ JT_CASE(0xc5) // FD_BPF_OP_JSLT_IMM
BRANCH_PRE_CODE
  pc += ((long)register_file[instr.dst_reg] < (long)instr.imm) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0xc7 */ JT_CASE(0xc7) // FD_BPF_OP_ARSH64_IMM
  register_file[instr.dst_reg] = (ulong)((long)register_file[instr.dst_reg] >> instr.imm);
INSTR_POST_CODE
JT_CASE_END
/* 0xcc */ JT_CASE(0xcc) // FD_BPF_OP_ARSH_REG
  register_file[instr.dst_reg] = (uint)((int)register_file[instr.dst_reg] >> (uint)register_file[instr.src_reg]);
INSTR_POST_CODE
JT_CASE_END
/* 0xcd */ JT_CASE(0xcd) // FD_BPF_OP_JSLT_REG
BRANCH_PRE_CODE
  pc += ((long)register_file[instr.dst_reg] < (long)register_file[instr.src_reg]) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0xcf */ JT_CASE(0xcf) // FD_BPF_OP_ARSH64_REG
  register_file[instr.dst_reg] = (ulong)((long)register_file[instr.dst_reg] >> register_file[instr.src_reg]);
INSTR_POST_CODE
JT_CASE_END

/* 0xd0 - 0xdf */
/* 0xd4 */ JT_CASE(0xd4) // FD_BPF_OP_END_LE
  /* On x86_64, the host is LE already */
INSTR_POST_CODE
JT_CASE_END
/* 0xd5 */ JT_CASE(0xd5) // FD_BPF_OP_JSLE_IMM
BRANCH_PRE_CODE
  pc += ((long)register_file[instr.dst_reg] <= (long)instr.imm) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
/* 0xdc */ JT_CASE(0xdc) // FD_BPF_OP_END_BE
  switch (instr.imm) {
    case 16:
      register_file[instr.dst_reg] = (ushort)fd_ushort_bswap((ushort)register_file[instr.dst_reg]);
      register_file[instr.dst_reg] &= 0xFFFF;
      break;
    case 32:
      register_file[instr.dst_reg] = (uint)fd_uint_bswap((uint)register_file[instr.dst_reg]);
      register_file[instr.dst_reg] &= 0xFFFFFFFF;
      break;
    case 64:
      register_file[instr.dst_reg] = (ulong)fd_ulong_bswap((ulong)register_file[instr.dst_reg]);
      break;
  }
INSTR_POST_CODE
JT_CASE_END
/* 0xdd */ JT_CASE(0xdd) // FD_BPF_OP_JSLE_REG
BRANCH_PRE_CODE
  pc += ((long)register_file[instr.dst_reg] <= (long)register_file[instr.src_reg]) ? instr.offset : 0;
BRANCH_POST_CODE
JT_CASE_END
 
#ifdef __GNUC__
#ifndef __clang__
#pragma GCC diagnostic pop
#endif
#endif