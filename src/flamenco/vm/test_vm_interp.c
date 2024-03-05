#include "fd_vm_interp.h"
#include "syscall/fd_vm_syscall.h" /* FIXME: HMMM ... MAYBE INTERP AND SYSCALLS SHOULD BE COMBINED */

#define FD_MAX_COMPUTE_UNIT_LIMIT (1400000)     /* Max compute unit limit */

static int
accumulator_syscall( FD_PARAM_UNUSED void *  _ctx,
                     /**/            ulong   arg0,
                     /**/            ulong   arg1,
                     /**/            ulong   arg2,
                     /**/            ulong   arg3,
                     /**/            ulong   arg4,
                     /**/            ulong * ret ) {
  *ret = arg0 + arg1 + arg2 + arg3 + arg4;
  return 0;
}

static void
test_program_success( char *            test_case_name,
                      ulong             expected_result,
                      ulong             instrs_sz,
                      fd_sbpf_instr_t * instrs ) {
//FD_LOG_NOTICE(( "Test program: %s", test_case_name ));

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( aligned_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint()) );
  FD_TEST( syscalls );

  fd_vm_syscall_register( syscalls, "accumulator", accumulator_syscall );

  fd_vm_exec_context_t ctx = {
    .entrypoint = 0,
    .program_counter = 0,
    .instruction_counter = 0,
    .instrs = instrs,
    .instrs_sz = instrs_sz,
    .syscall_map = syscalls,
    .compute_meter = FD_MAX_COMPUTE_UNIT_LIMIT,
    .due_insn_cnt = 0,
    .previous_instruction_meter = FD_MAX_COMPUTE_UNIT_LIMIT,
    .heap_sz = FD_VM_DEFAULT_HEAP_SZ,
    .alloc               = { {.offset = 0} }
  };

  ulong validation_res = fd_vm_context_validate( &ctx );
  if (validation_res != 0) {
    FD_LOG_WARNING(( "VAL_RES: %lu", validation_res ));
  }
  FD_TEST( validation_res==FD_VM_SBPF_VALIDATE_SUCCESS );

  long dt = -fd_log_wallclock();
  fd_vm_interp_instrs( &ctx );
  dt += fd_log_wallclock();

  free( syscalls );
  if (expected_result != ctx.register_file[0]) {
    // FD_LOG_WARNING(( "RET: %lu 0x%lx", ctx.register_file[0], ctx.register_file[0] ));
    // FD_LOG_WARNING(( "PC: %lu 0x%lx", ctx.program_counter, ctx.program_counter ));
    // FD_LOG_WARNING(( "Cond fault: %d", ctx.cond_fault));
    // FD_LOG_WARNING(( "IC: %lu 0x%lx", ctx.instruction_counter, ctx.instruction_counter));
  }
  FD_TEST( ctx.register_file[0]==expected_result );
//FD_LOG_NOTICE(( "Instr counter: %lu", ctx.instruction_counter ));
  FD_LOG_NOTICE(( "%-20s %11li ns", test_case_name, dt ));
//FD_LOG_NOTICE(( "Time/Instr: %f ns", (double)dt / (double)ctx.instruction_counter ));
//FD_LOG_NOTICE(( "Mega Instr/Sec: %f", 1000.0 * ((double)ctx.instruction_counter / (double) dt)));
}

#define TEST_PROGRAM_SUCCESS(test_case_name, expected_result, instrs_sz, ...) { \
  fd_sbpf_instr_t instrs_var[instrs_sz] = { __VA_ARGS__ }; \
  test_program_success(test_case_name, expected_result, instrs_sz, instrs_var); \
}

static void
generate_random_alu_instrs( fd_rng_t * rng, fd_sbpf_instr_t * instrs, ulong instrs_sz ) {
  uchar opcodes[25] = {
    FD_SBPF_OP_ADD_IMM,
    FD_SBPF_OP_ADD_REG,
    FD_SBPF_OP_SUB_IMM,
    FD_SBPF_OP_SUB_REG,
    FD_SBPF_OP_MUL_IMM,
    FD_SBPF_OP_MUL_REG,
    FD_SBPF_OP_DIV_IMM,
    FD_SBPF_OP_DIV_REG,
    FD_SBPF_OP_OR_IMM,
    FD_SBPF_OP_OR_REG,
    FD_SBPF_OP_AND_IMM,
    FD_SBPF_OP_AND_REG,
    FD_SBPF_OP_LSH_IMM,
    FD_SBPF_OP_LSH_REG,
    FD_SBPF_OP_RSH_IMM,
    FD_SBPF_OP_RSH_REG,
    FD_SBPF_OP_NEG,
    FD_SBPF_OP_MOD_IMM,
    FD_SBPF_OP_MOD_REG,
    FD_SBPF_OP_XOR_IMM,
    FD_SBPF_OP_XOR_REG,
    FD_SBPF_OP_MOV_IMM,
    FD_SBPF_OP_MOV_REG,
    FD_SBPF_OP_ARSH_IMM,
    FD_SBPF_OP_ARSH_REG,
  };

  for( ulong i = 0; i < instrs_sz-1; i++ ) {
    fd_sbpf_instr_t * instr = &instrs[i];
    instr->opcode.raw = opcodes[fd_rng_ulong_roll(rng, 25)];
    instr->dst_reg = (1+fd_rng_uchar_roll(rng, 9)) & 0xFUL;
    instr->src_reg = (1+fd_rng_uchar_roll(rng, 9)) & 0xFUL;
    instr->offset = 0;
    instr->imm = fd_rng_uint_roll(rng, 1024*1024);
  }
  instrs[instrs_sz-1].opcode.raw = FD_SBPF_OP_EXIT;
}

static void
generate_random_alu64_instrs( fd_rng_t * rng, fd_sbpf_instr_t * instrs, ulong instrs_sz ) {
  uchar opcodes[25] = {
    FD_SBPF_OP_ADD64_IMM,
    FD_SBPF_OP_ADD64_REG,
    FD_SBPF_OP_SUB64_IMM,
    FD_SBPF_OP_SUB64_REG,
    FD_SBPF_OP_MUL64_IMM,
    FD_SBPF_OP_MUL64_REG,
    FD_SBPF_OP_DIV64_IMM,
    FD_SBPF_OP_DIV64_REG,
    FD_SBPF_OP_OR64_IMM,
    FD_SBPF_OP_OR64_REG,
    FD_SBPF_OP_AND64_IMM,
    FD_SBPF_OP_AND64_REG,
    FD_SBPF_OP_LSH64_IMM,
    FD_SBPF_OP_LSH64_REG,
    FD_SBPF_OP_RSH64_IMM,
    FD_SBPF_OP_RSH64_REG,
    FD_SBPF_OP_NEG64,
    FD_SBPF_OP_MOD64_IMM,
    FD_SBPF_OP_MOD64_REG,
    FD_SBPF_OP_XOR64_IMM,
    FD_SBPF_OP_XOR64_REG,
    FD_SBPF_OP_MOV64_IMM,
    FD_SBPF_OP_MOV64_REG,
    FD_SBPF_OP_ARSH64_IMM,
    FD_SBPF_OP_ARSH64_REG,
  };

  for( ulong i = 0; i < instrs_sz-1; i++ ) {
    fd_sbpf_instr_t * instr = &instrs[i];
    instr->opcode.raw = opcodes[fd_rng_ulong_roll(rng, 25)];
    instr->dst_reg = (1+fd_rng_uchar_roll(rng, 9)) & 0xFUL;
    instr->src_reg = (1+fd_rng_uchar_roll(rng, 9)) & 0xFUL;
    instr->offset = 0;
    instr->imm = fd_rng_uint_roll(rng, 1024*1024);
  }
  instrs[instrs_sz-1].opcode.raw = FD_SBPF_OP_EXIT;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  TEST_PROGRAM_SUCCESS("add", 0x3, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_ADD_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_ADD_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("add64", 0x3, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_ADD64_IMM, FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_ADD64_REG, FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("alu-arith", 0x2a, 19,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R3,  0,      0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R4,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R5,  0,      0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R6,  0,      0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R7,  0,      0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R8,  0,      0, 8),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R9,  0,      0, 9),

    FD_SBPF_INSTR(FD_SBPF_OP_ADD_IMM,   FD_SBPF_R0,  0,      0, 23),
    FD_SBPF_INSTR(FD_SBPF_OP_ADD_REG,   FD_SBPF_R0,  FD_SBPF_R7,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_SUB_IMM,   FD_SBPF_R0,  0,      0, 13),
    FD_SBPF_INSTR(FD_SBPF_OP_SUB_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_MUL_IMM,   FD_SBPF_R0,  0,      0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MUL_REG,   FD_SBPF_R0,  FD_SBPF_R3,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_DIV_IMM,   FD_SBPF_R0,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV_REG,   FD_SBPF_R0,  FD_SBPF_R4,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("alu-bitwise", 0x11, 21,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R3,  0,      0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R4,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R5,  0,      0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R6,  0,      0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R7,  0,      0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R8,  0,      0, 8),

    FD_SBPF_INSTR(FD_SBPF_OP_OR_REG,    FD_SBPF_R0,  FD_SBPF_R5,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_OR_IMM,    FD_SBPF_R0,  0,      0, 0xa0),

    FD_SBPF_INSTR(FD_SBPF_OP_AND_IMM,   FD_SBPF_R0,  0,      0, 0xa3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R9,  0,      0, 0x91),
    FD_SBPF_INSTR(FD_SBPF_OP_AND_REG,   FD_SBPF_R0,  FD_SBPF_R9,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_LSH_IMM,   FD_SBPF_R0,  0,      0, 22),
    FD_SBPF_INSTR(FD_SBPF_OP_LSH_REG,   FD_SBPF_R0,  FD_SBPF_R8,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_RSH_IMM,   FD_SBPF_R0,  0,      0, 19),
    FD_SBPF_INSTR(FD_SBPF_OP_RSH_REG,   FD_SBPF_R0,  FD_SBPF_R7,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_XOR_IMM,   FD_SBPF_R0,  0,      0, 0x03),
    FD_SBPF_INSTR(FD_SBPF_OP_XOR_REG,   FD_SBPF_R0,  FD_SBPF_R2,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("alu64-arith", 0x2a, 19,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R1,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R2,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R3,  0,      0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R4,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R5,  0,      0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R6,  0,      0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R7,  0,      0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R8,  0,      0, 8),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R9,  0,      0, 9),

    FD_SBPF_INSTR(FD_SBPF_OP_ADD64_IMM,   FD_SBPF_R0,  0,           0, 23),
    FD_SBPF_INSTR(FD_SBPF_OP_ADD64_REG,   FD_SBPF_R0,  FD_SBPF_R7,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_SUB64_IMM,   FD_SBPF_R0,  0,           0, 13),
    FD_SBPF_INSTR(FD_SBPF_OP_SUB64_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_MUL64_IMM,   FD_SBPF_R0,  0,           0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MUL64_REG,   FD_SBPF_R0,  FD_SBPF_R3,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_DIV64_IMM,   FD_SBPF_R0,  0,           0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV64_REG,   FD_SBPF_R0,  FD_SBPF_R4,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("alu64-bitwise", 0x811, 21,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R1,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R2,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R3,  0,      0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R4,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R5,  0,      0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R6,  0,      0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R7,  0,      0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R8,  0,      0, 8),

    FD_SBPF_INSTR(FD_SBPF_OP_OR64_REG,    FD_SBPF_R0,  FD_SBPF_R5,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_OR64_IMM,    FD_SBPF_R0,  0,      0, 0xa0),

    FD_SBPF_INSTR(FD_SBPF_OP_AND64_IMM,   FD_SBPF_R0,  0,      0, 0xa3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,   FD_SBPF_R9,  0,      0, 0x91),
    FD_SBPF_INSTR(FD_SBPF_OP_AND64_REG,   FD_SBPF_R0,  FD_SBPF_R9,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_LSH64_IMM,   FD_SBPF_R0,  0,      0, 22),
    FD_SBPF_INSTR(FD_SBPF_OP_LSH64_REG,   FD_SBPF_R0,  FD_SBPF_R8,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_RSH64_IMM,   FD_SBPF_R0,  0,      0, 19),
    FD_SBPF_INSTR(FD_SBPF_OP_RSH64_REG,   FD_SBPF_R0,  FD_SBPF_R7,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_XOR64_IMM,   FD_SBPF_R0,  0,      0, 0x03),
    FD_SBPF_INSTR(FD_SBPF_OP_XOR64_REG,   FD_SBPF_R0,  FD_SBPF_R2,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("arsh-reg", 0xffff8000, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0xf8),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 16),
    FD_SBPF_INSTR(FD_SBPF_OP_LSH_IMM,   FD_SBPF_R0,  0,      0, 28),
    FD_SBPF_INSTR(FD_SBPF_OP_ARSH_REG,  FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("arsh", 0xffff8000, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0xf8),
    FD_SBPF_INSTR(FD_SBPF_OP_LSH_IMM,   FD_SBPF_R0,  0,      0, 28),
    FD_SBPF_INSTR(FD_SBPF_OP_ARSH_IMM,  FD_SBPF_R0,  0,      0, 16),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("arsh-high-shift", 0x4, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0x8),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_ARSH_REG,  FD_SBPF_R0,  FD_SBPF_R1,  0, 16),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("arsh64", 0xfffffffffffffff8, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,     FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_LSH64_IMM,   FD_SBPF_R0,  0,      0, 63),
    FD_SBPF_INSTR(FD_SBPF_OP_ARSH64_IMM,  FD_SBPF_R0,  0,      0, 55),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,     FD_SBPF_R1,  0,      0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_ARSH64_REG,  FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,        0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("be16-high", 0x1122, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0x44332211),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x88776655),
    FD_SBPF_INSTR(FD_SBPF_OP_END_BE,    FD_SBPF_R0,  0,      0, 16),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("be16", 0x1122, 3,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0x00002211),
    FD_SBPF_INSTR(FD_SBPF_OP_END_BE,    FD_SBPF_R0,  0,      0, 16),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("be32-high", 0x11223344, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0x44332211),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x88776655),
    FD_SBPF_INSTR(FD_SBPF_OP_END_BE,    FD_SBPF_R0,  0,      0, 32),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("be32", 0x11223344, 3,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0x44332211),
    FD_SBPF_INSTR(FD_SBPF_OP_END_BE,    FD_SBPF_R0,  0,      0, 32),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("be64", 0x1122334455667788, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0x44332211),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x88776655),
    FD_SBPF_INSTR(FD_SBPF_OP_END_BE,    FD_SBPF_R0,  0,      0, 64),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div-by-zero-imm", 0x0, 3,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div-by-zero-reg", 0x0, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div-high-divisor", 0x3, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 12),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x4),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div-imm", 0x3, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0xc),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV_IMM,   FD_SBPF_R0,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div-reg", 0x3, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0xc),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div64-by-zero-imm", 0x0, 3,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV64_IMM, FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div64-by-zero-reg", 0x0, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV64_REG, FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div64-high-divisor", 0x15555555, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 12),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x4),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV64_REG, FD_SBPF_R1,  FD_SBPF_R0,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div64-imm", 0x40000003, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0xc),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV64_IMM, FD_SBPF_R0,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div64-reg", 0x40000003, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0xc),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV64_REG, FD_SBPF_R1,  FD_SBPF_R0,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod-by-zero-imm", 0x1, 3,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOD_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod-by-zero-reg", 0x1, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOD_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod-high-divisor", 0x0, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 12),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x4),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOD_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod-imm", 0x0, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0xc),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOD_IMM,   FD_SBPF_R0,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod-reg", 0x0, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0xc),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOD_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod64-by-zero-imm", 0x1, 3,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOD64_IMM, FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod64-by-zero-reg", 0x1, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOD64_REG, FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod64-high-divisor", 0x8, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 12),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x4),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOD64_REG, FD_SBPF_R1,  FD_SBPF_R0,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod64-imm", 0x0, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0xc),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOD64_IMM, FD_SBPF_R0,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod64-reg", 0x0, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0xc),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOD64_REG, FD_SBPF_R1,  FD_SBPF_R0,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_REG,   FD_SBPF_R0,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("early-exit", 0x3, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("exit-not-last", 0x0, 1,
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("exit", 0x0, 2,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("ja", 0x1, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_JA,        0,      0,     +1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jeq-imm", 0x1, 8,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 0xa),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ_IMM,   FD_SBPF_R1,  0,     +4, 0xb),

    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 0xb),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ_IMM,   FD_SBPF_R1,  0,     +1, 0xb),

    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jeq-reg", 0x1, 9,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 0xa),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 0xb),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ_REG,   FD_SBPF_R1,  FD_SBPF_R2, +4, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 0xb),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ_REG,   FD_SBPF_R1,  FD_SBPF_R2, +1, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jge-imm", 0x1, 8,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 4),

    FD_SBPF_INSTR(FD_SBPF_OP_JGE_IMM,   FD_SBPF_R1,  0,     +2, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE_IMM,   FD_SBPF_R1,  0,     +1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE_IMM,   FD_SBPF_R1,  0,     +1, 4),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jge-reg", 0x1, 11,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R3,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R4,  0,      0, 5),

    FD_SBPF_INSTR(FD_SBPF_OP_JGE_REG,   FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE_REG,   FD_SBPF_R1,  FD_SBPF_R4, +1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE_REG,   FD_SBPF_R1,  FD_SBPF_R3, +1, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jgt-imm", 0x1, 8,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 5),

    FD_SBPF_INSTR(FD_SBPF_OP_JGT_IMM,   FD_SBPF_R1,  0,     +2, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT_IMM,   FD_SBPF_R1,  0,     +1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT_IMM,   FD_SBPF_R1,  0,     +1, 4),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jgt-reg", 0x1, 10,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R3,  0,      0, 4),

    FD_SBPF_INSTR(FD_SBPF_OP_JGT_REG,   FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT_REG,   FD_SBPF_R1,  FD_SBPF_R1, +1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT_REG,   FD_SBPF_R1,  FD_SBPF_R3, +1, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jle-imm", 0x1, 8,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 7),

    FD_SBPF_INSTR(FD_SBPF_OP_JLE_IMM,   FD_SBPF_R1,  0,     +2, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_JLE_IMM,   FD_SBPF_R1,  0,     +2, 8),
    FD_SBPF_INSTR(FD_SBPF_OP_JLE_IMM,   FD_SBPF_R1,  0,     +1, 4),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jle-reg", 0x1, 11,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 10),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R3,  0,      0, 11),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R4,  0,      0, 5),

    FD_SBPF_INSTR(FD_SBPF_OP_JLE_REG,   FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JLE_REG,   FD_SBPF_R1,  FD_SBPF_R4, +1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JLE_REG,   FD_SBPF_R1,  FD_SBPF_R3, +1, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jlt-imm", 0x1, 8,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 7),

    FD_SBPF_INSTR(FD_SBPF_OP_JLT_IMM,   FD_SBPF_R1,  0,     +2, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT_IMM,   FD_SBPF_R1,  0,     +2, 8),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT_IMM,   FD_SBPF_R1,  0,     +1, 4),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jlt-reg", 0x1, 11,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 10),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R3,  0,      0, 11),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R4,  0,      0, 5),

    FD_SBPF_INSTR(FD_SBPF_OP_JLT_REG,   FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT_REG,   FD_SBPF_R1,  FD_SBPF_R4, +1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT_REG,   FD_SBPF_R1,  FD_SBPF_R3, +1, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jne-imm", 0x1, 8,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 7),

    FD_SBPF_INSTR(FD_SBPF_OP_JNE_IMM,   FD_SBPF_R1,  0,     +2, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE_IMM,   FD_SBPF_R1,  0,     +2, 10),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE_IMM,   FD_SBPF_R1,  0,     +1, 7),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jne-reg", 0x1, 11,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 10),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 10),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R3,  0,      0, 24),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R4,  0,      0, 10),

    FD_SBPF_INSTR(FD_SBPF_OP_JNE_REG,   FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE_REG,   FD_SBPF_R1,  FD_SBPF_R4, +1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE_REG,   FD_SBPF_R1,  FD_SBPF_R3, +1, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jset-imm", 0x1, 8,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 0x8),

    FD_SBPF_INSTR(FD_SBPF_OP_JSET_IMM,   FD_SBPF_R1,  0,     +2, 0x7),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET_IMM,   FD_SBPF_R1,  0,     +2, 0x9),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET_IMM,   FD_SBPF_R1,  0,     +1, 0x10),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jset-reg", 0x1, 11,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R1,  0,      0, 0x8),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 0x7),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R3,  0,      0, 0x9),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R4,  0,      0, 0x0),

    FD_SBPF_INSTR(FD_SBPF_OP_JSET_REG,   FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET_REG,   FD_SBPF_R1,  FD_SBPF_R4, +1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET_REG,   FD_SBPF_R1,  FD_SBPF_R3, +1, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R0,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("ldq", 0x1122334455667788, 3,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R0,  0,      0, 0x55667788),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x11223344),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("stb-heap", 0x11, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_SBPF_INSTR(FD_SBPF_OP_STB,       FD_SBPF_R1,  0,     +2, 0x11),
    FD_SBPF_INSTR(FD_SBPF_OP_LDXB,      FD_SBPF_R0,  FD_SBPF_R1, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("sth-heap", 0x1122, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_SBPF_INSTR(FD_SBPF_OP_STH,       FD_SBPF_R1,  0,     +2, 0x1122),
    FD_SBPF_INSTR(FD_SBPF_OP_LDXH,      FD_SBPF_R0,  FD_SBPF_R1, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("stw-heap", 0x11223344, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_SBPF_INSTR(FD_SBPF_OP_STW,       FD_SBPF_R1,  0,     +2, 0x11223344),
    FD_SBPF_INSTR(FD_SBPF_OP_LDXW,      FD_SBPF_R0,  FD_SBPF_R1, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  // TODO: check that we zero upper 32 bits
  TEST_PROGRAM_SUCCESS("stq-heap", 0x11223344, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_SBPF_INSTR(FD_SBPF_OP_STDW,      FD_SBPF_R1,  0,     +2, 0x11223344),
    FD_SBPF_INSTR(FD_SBPF_OP_LDXDW,     FD_SBPF_R0,  FD_SBPF_R1, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("stxb-heap", 0x11, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 0x11),
    FD_SBPF_INSTR(FD_SBPF_OP_STXB,      FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_LDXB,      FD_SBPF_R0,  FD_SBPF_R1, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("stxh-heap", 0x1122, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 0x1122),
    FD_SBPF_INSTR(FD_SBPF_OP_STXH,      FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_LDXH,      FD_SBPF_R0,  FD_SBPF_R1, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("stxw-heap", 0x11223344, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV_IMM,   FD_SBPF_R2,  0,      0, 0x11223344),
    FD_SBPF_INSTR(FD_SBPF_OP_STXW,      FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_LDXW,      FD_SBPF_R0,  FD_SBPF_R1, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("stxq-heap", 0x1122334455667788, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R2,  0,      0, 0x55667788),
    FD_SBPF_INSTR(FD_SBPF_OP_ADDL_IMM,  0,      0,      0, 0x11223344),
    FD_SBPF_INSTR(FD_SBPF_OP_STXDW,     FD_SBPF_R1,  FD_SBPF_R2, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_LDXDW,     FD_SBPF_R0,  FD_SBPF_R1, +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("prime", 0x1, 16,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1,  0,      0, 10007),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0,  0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2,  0,      0, 0x2),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT_IMM,   FD_SBPF_R1,  0,     +4, 0x2),

    FD_SBPF_INSTR(FD_SBPF_OP_JA,        0,      0,    +10, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_ADD64_IMM, FD_SBPF_R2,  0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0,  0,      0, 0x1),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE_REG,   FD_SBPF_R2,  FD_SBPF_R1, +7, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_REG, FD_SBPF_R3,  FD_SBPF_R1,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_DIV64_REG, FD_SBPF_R3,  FD_SBPF_R2,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MUL64_REG, FD_SBPF_R3,  FD_SBPF_R2,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_REG, FD_SBPF_R4,  FD_SBPF_R1,  0, 0),

    FD_SBPF_INSTR(FD_SBPF_OP_SUB64_REG, FD_SBPF_R4,  FD_SBPF_R3,  0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0,  0,      0, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE_IMM,   FD_SBPF_R4,  0,    -10, 0x0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("call", 15, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R3,  0,      0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R4,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R5,  0,      0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,      0,      0,      0, 0x7e6bb1fb),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  ulong instrs_sz = 128*1024*1024;
  fd_sbpf_instr_t * instrs = malloc( sizeof(fd_sbpf_instr_t) * instrs_sz );

  generate_random_alu_instrs( rng, instrs, instrs_sz );
  test_program_success("alu_bench", 0x0, instrs_sz, instrs);

  generate_random_alu64_instrs( rng, instrs, instrs_sz );
  test_program_success("alu64_bench", 0x0, instrs_sz, instrs);

  instrs_sz = 1024;
  generate_random_alu_instrs( rng, instrs, instrs_sz );
  test_program_success("alu_bench_short", 0x0, instrs_sz, instrs);

  generate_random_alu64_instrs( rng, instrs, instrs_sz );
  test_program_success("alu64_bench_short", 0x0, instrs_sz, instrs);

  free( instrs );

  FD_LOG_NOTICE(( "pass" ));
  fd_rng_delete( fd_rng_leave( rng ) );
  fd_halt();
  return 0;
}
