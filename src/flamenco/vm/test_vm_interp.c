#include "fd_vm_private.h"

static int
accumulator_syscall( FD_PARAM_UNUSED void *  _vm,
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
test_program_success( char *               test_case_name,
                      ulong                expected_result,
                      ulong const *        text,
                      ulong                text_cnt,
                      fd_sbpf_syscalls_t * syscalls ) {
//FD_LOG_NOTICE(( "Test program: %s", test_case_name ));

  fd_vm_t vm = {
    .instr_ctx = NULL, /* FIXME: HMMM */
    .heap_max  = FD_VM_HEAP_DEFAULT,
    .entry_cu  = FD_VM_COMPUTE_UNIT_LIMIT,
    .rodata    = (uchar *)text,
    .rodata_sz = 8UL*text_cnt,
    .text      = text,
    .text_cnt  = text_cnt,
    .text_off  = 0,
    .entry_pc  = 0,
    .calldests = NULL,     /* FIXME: HMMM */
    .syscalls  = syscalls,
    .input     = NULL,
    .input_sz  = 0,
    .trace     = NULL
  };

  /* FIXME: GROSS */
  vm.pc        = vm.entry_pc;
  vm.ic        = 0UL;
  vm.cu        = vm.entry_cu;
  vm.frame_cnt = 0UL;
  vm.heap_sz   = 0UL;
  vm.log_sz    = 0UL;
  fd_vm_mem_cfg( &vm );

  int err = fd_vm_validate( &vm );
  if( FD_UNLIKELY( err ) ) FD_LOG_WARNING(( "validation failed: %i-%s", err, fd_vm_strerror( err ) ));

  long dt = -fd_log_wallclock();
  err = fd_vm_exec( &vm );
  dt += fd_log_wallclock();

  if( FD_UNLIKELY( vm.reg[0]!=expected_result ) ) {
    FD_LOG_WARNING(( "Interp err: %i (%s)",   err,       fd_vm_strerror( err ) ));
    FD_LOG_WARNING(( "RET:        %lu 0x%lx", vm.reg[0], vm.reg[0]             ));
    FD_LOG_WARNING(( "PC:         %lu 0x%lx", vm.pc,     vm.pc                 ));
    FD_LOG_WARNING(( "IC:         %lu 0x%lx", vm.ic,     vm.ic                 ));
  }
//FD_LOG_NOTICE(( "Instr counter: %lu", vm.ic ));
  FD_TEST( vm.reg[0]==expected_result );
  FD_LOG_NOTICE(( "%-20s %11li ns", test_case_name, dt ));
//FD_LOG_NOTICE(( "Time/Instr: %f ns", (double)dt / (double)vm.ic ));
//FD_LOG_NOTICE(( "Mega Instr/Sec: %f", 1000.0 * ((double)vm.ic / (double) dt)));
}

static void
generate_random_alu_instrs( fd_rng_t * rng,
                            ulong *    text,
                            ulong      text_cnt ) {
  static uchar const opcodes[25] = {
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

  if( FD_UNLIKELY( !text_cnt ) ) return;

  fd_sbpf_instr_t instr;
  for( ulong i=0UL; i<text_cnt-1UL; i++ ) {
    instr.opcode.raw = opcodes[fd_rng_ulong_roll(rng, 25)];
    instr.dst_reg    = (1+fd_rng_uchar_roll(rng, 9)) & 0xFUL;
    instr.src_reg    = (1+fd_rng_uchar_roll(rng, 9)) & 0xFUL;
    instr.offset     = 0;
    instr.imm        = fd_rng_uint_roll(rng, 1024*1024);
    text[i] = fd_sbpf_ulong( instr );
  }
  instr.opcode.raw = FD_SBPF_OP_EXIT;
  text[text_cnt-1UL] = fd_sbpf_ulong( instr );
}

static void
generate_random_alu64_instrs( fd_rng_t * rng,
                              ulong *    text,
                              ulong      text_cnt ) {

  static uchar const opcodes[25] = {
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

  if( FD_UNLIKELY( !text_cnt ) ) return;

  fd_sbpf_instr_t instr;
  for( ulong i=0UL; i<text_cnt-1UL; i++ ) {
    instr.opcode.raw = opcodes[fd_rng_ulong_roll(rng, 25)];
    instr.dst_reg    = (1+fd_rng_uchar_roll(rng, 9)) & 0xFUL;
    instr.src_reg    = (1+fd_rng_uchar_roll(rng, 9)) & 0xFUL;
    instr.offset     = 0;
    instr.imm        = fd_rng_uint_roll( rng, 1024*1024 );
  }
  instr.opcode.raw = FD_SBPF_OP_EXIT;
  text[text_cnt-1UL] = fd_sbpf_ulong( instr );
}

static fd_sbpf_syscalls_t _syscalls[ FD_SBPF_SYSCALLS_SLOT_CNT ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( _syscalls ) ); FD_TEST( syscalls );

  FD_TEST( fd_vm_syscall_register( syscalls, "accumulator", accumulator_syscall )==FD_VM_SUCCESS );

# define TEST_PROGRAM_SUCCESS( test_case_name, expected_result, text_cnt, ... ) do { \
    fd_sbpf_instr_t _text[ text_cnt ] = { __VA_ARGS__ };                             \
    test_program_success( (test_case_name), (expected_result), (ulong const *)fd_type_pun( _text ), text_cnt, syscalls ); /* FIXME: GROSS */ \
  } while(0)

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

  ulong   text_cnt = 128*1024*1024;
  ulong * text     = (ulong *)malloc( sizeof(ulong)*text_cnt ); /* FIXME: gross */

  generate_random_alu_instrs( rng, text, text_cnt );
  test_program_success( "alu_bench", 0x0, text, text_cnt, syscalls );

  generate_random_alu64_instrs( rng, text, text_cnt );
  test_program_success( "alu64_bench", 0x0, text, text_cnt, syscalls );

  text_cnt = 1024UL;
  generate_random_alu_instrs( rng, text, text_cnt );
  test_program_success( "alu_bench_short", 0x0, text, text_cnt, syscalls );

  generate_random_alu64_instrs( rng, text, text_cnt );
  test_program_success( "alu64_bench_short", 0x0, text, text_cnt, syscalls );

  free( text );

  fd_sbpf_syscalls_delete( fd_sbpf_syscalls_leave( syscalls ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_rng_delete( fd_rng_leave( rng ) );
  fd_halt();
  return 0;
}
