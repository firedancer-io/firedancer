#include "fd_vm.h"
#include "fd_opcodes.h"
#include "fd_sbpf_interp.h"
#include "../util/fd_util.h"

static void
test_program_success( char *                test_case_name,
                      ulong                 expected_result,
                      ulong                 instrs_sz,
                      fd_vm_sbpf_instr_t *  instrs ) {
  FD_LOG_NOTICE(( "Test program: %s", test_case_name ));

  fd_vm_sbpf_exec_context_t ctx = {
    .entrypoint = 0,
    .num_ext_funcs = 0,
    .instrs = instrs,
    .instrs_sz = instrs_sz,
  };

  ulong validation_res = fd_vm_sbpf_interp_validate( &ctx ); 
  if (validation_res != 0) {
    FD_LOG_WARNING(( "VAL_RES: %lu, %x", validation_res, FD_BPF_OP_DIV64_REG  ));
  }
  FD_TEST( validation_res==FD_VM_SBPF_VALIDATE_SUCCESS );

  fd_vm_sbpf_interp_instrs( &ctx );
  if (expected_result != ctx.register_file[0]) {
    FD_LOG_WARNING(( "RET: %lu 0x%lx", ctx.register_file[0], ctx.register_file[0] ));
  }
  FD_TEST( ctx.register_file[0]==expected_result );

  /*
  for( ulong i = 0; i < 11; i++ ) {
    FD_LOG_WARNING(( "REG %lu: %lu", i, ctx.register_file[i] ));
  }
  */
}

#define TEST_PROGRAM_SUCCESS(test_case_name, expected_result, instrs_sz, ...) { \
  fd_vm_sbpf_instr_t instrs_var[instrs_sz] = { __VA_ARGS__ }; \
  test_program_success(test_case_name, expected_result, instrs_sz, instrs_var); \
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  TEST_PROGRAM_SUCCESS("add", 0x3, 5,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 2),
    FD_BPF_INSTR(FD_BPF_OP_ADD_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_ADD_REG,   FD_R0,  FD_R1,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("add64", 0x3, 5,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 2),
    FD_BPF_INSTR(FD_BPF_OP_ADD64_IMM, FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_ADD64_REG, FD_R0,  FD_R1,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("alu-arith", 0x2a, 19,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R2,  0,      0, 2),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R3,  0,      0, 3),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R4,  0,      0, 4),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R5,  0,      0, 5),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R6,  0,      0, 6),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R7,  0,      0, 7),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R8,  0,      0, 8),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R9,  0,      0, 9),

    FD_BPF_INSTR(FD_BPF_OP_ADD_IMM,   FD_R0,  0,      0, 23),
    FD_BPF_INSTR(FD_BPF_OP_ADD_REG,   FD_R0,  FD_R7,  0, 0),

    FD_BPF_INSTR(FD_BPF_OP_SUB_IMM,   FD_R0,  0,      0, 13),
    FD_BPF_INSTR(FD_BPF_OP_SUB_REG,   FD_R0,  FD_R1,  0, 0),

    FD_BPF_INSTR(FD_BPF_OP_MUL_IMM,   FD_R0,  0,      0, 7),
    FD_BPF_INSTR(FD_BPF_OP_MUL_REG,   FD_R0,  FD_R3,  0, 0),
    
    FD_BPF_INSTR(FD_BPF_OP_DIV_IMM,   FD_R0,  0,      0, 2),
    FD_BPF_INSTR(FD_BPF_OP_DIV_REG,   FD_R0,  FD_R4,  0, 0),
    
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("alu-bitwise", 0x11, 21,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R2,  0,      0, 2),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R3,  0,      0, 3),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R4,  0,      0, 4),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R5,  0,      0, 5),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R6,  0,      0, 6),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R7,  0,      0, 7),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R8,  0,      0, 8),

    FD_BPF_INSTR(FD_BPF_OP_OR_REG,    FD_R0,  FD_R5,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_OR_IMM,    FD_R0,  0,      0, 0xa0),

    FD_BPF_INSTR(FD_BPF_OP_AND_IMM,   FD_R0,  0,      0, 0xa3),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R9,  0,      0, 0x91),
    FD_BPF_INSTR(FD_BPF_OP_AND_REG,   FD_R0,  FD_R9,  0, 0),

    FD_BPF_INSTR(FD_BPF_OP_LSH_IMM,   FD_R0,  0,      0, 22),
    FD_BPF_INSTR(FD_BPF_OP_LSH_REG,   FD_R0,  FD_R8,  0, 0),
    
    FD_BPF_INSTR(FD_BPF_OP_RSH_IMM,   FD_R0,  0,      0, 19),
    FD_BPF_INSTR(FD_BPF_OP_RSH_REG,   FD_R0,  FD_R7,  0, 0),
    
    FD_BPF_INSTR(FD_BPF_OP_XOR_IMM,   FD_R0,  0,      0, 0x03),
    FD_BPF_INSTR(FD_BPF_OP_XOR_REG,   FD_R0,  FD_R2,  0, 0),
    
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("alu64-arith", 0x2a, 19,
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R1,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R2,  0,      0, 2),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R3,  0,      0, 3),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R4,  0,      0, 4),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R5,  0,      0, 5),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R6,  0,      0, 6),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R7,  0,      0, 7),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R8,  0,      0, 8),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R9,  0,      0, 9),

    FD_BPF_INSTR(FD_BPF_OP_ADD64_IMM,   FD_R0,  0,      0, 23),
    FD_BPF_INSTR(FD_BPF_OP_ADD64_REG,   FD_R0,  FD_R7,  0, 0),

    FD_BPF_INSTR(FD_BPF_OP_SUB64_IMM,   FD_R0,  0,      0, 13),
    FD_BPF_INSTR(FD_BPF_OP_SUB64_REG,   FD_R0,  FD_R1,  0, 0),

    FD_BPF_INSTR(FD_BPF_OP_MUL64_IMM,   FD_R0,  0,      0, 7),
    FD_BPF_INSTR(FD_BPF_OP_MUL64_REG,   FD_R0,  FD_R3,  0, 0),
    
    FD_BPF_INSTR(FD_BPF_OP_DIV64_IMM,   FD_R0,  0,      0, 2),
    FD_BPF_INSTR(FD_BPF_OP_DIV64_REG,   FD_R0,  FD_R4,  0, 0),
    
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("alu64-bitwise", 0x811, 21,
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R1,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R2,  0,      0, 2),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R3,  0,      0, 3),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R4,  0,      0, 4),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R5,  0,      0, 5),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R6,  0,      0, 6),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R7,  0,      0, 7),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R8,  0,      0, 8),

    FD_BPF_INSTR(FD_BPF_OP_OR64_REG,    FD_R0,  FD_R5,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_OR64_IMM,    FD_R0,  0,      0, 0xa0),

    FD_BPF_INSTR(FD_BPF_OP_AND64_IMM,   FD_R0,  0,      0, 0xa3),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM,   FD_R9,  0,      0, 0x91),
    FD_BPF_INSTR(FD_BPF_OP_AND64_REG,   FD_R0,  FD_R9,  0, 0),

    FD_BPF_INSTR(FD_BPF_OP_LSH64_IMM,   FD_R0,  0,      0, 22),
    FD_BPF_INSTR(FD_BPF_OP_LSH64_REG,   FD_R0,  FD_R8,  0, 0),
    
    FD_BPF_INSTR(FD_BPF_OP_RSH64_IMM,   FD_R0,  0,      0, 19),
    FD_BPF_INSTR(FD_BPF_OP_RSH64_REG,   FD_R0,  FD_R7,  0, 0),
    
    FD_BPF_INSTR(FD_BPF_OP_XOR64_IMM,   FD_R0,  0,      0, 0x03),
    FD_BPF_INSTR(FD_BPF_OP_XOR64_REG,   FD_R0,  FD_R2,  0, 0),
    
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("arsh-reg", 0xffff8000, 5,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0xf8),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 16),
    FD_BPF_INSTR(FD_BPF_OP_LSH_IMM,   FD_R0,  0,      0, 28),
    FD_BPF_INSTR(FD_BPF_OP_ARSH_REG,  FD_R0,  FD_R1,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("arsh", 0xffff8000, 4,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0xf8),
    FD_BPF_INSTR(FD_BPF_OP_LSH_IMM,   FD_R0,  0,      0, 28),
    FD_BPF_INSTR(FD_BPF_OP_ARSH_IMM,  FD_R0,  0,      0, 16),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("arsh-high-shift", 0x4, 5,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0x8),
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R1,  0,      0, 0x1),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_BPF_INSTR(FD_BPF_OP_ARSH_REG,  FD_R0,  FD_R1,  0, 16),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("arsh64", 0xfffffffffffffff8, 6,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,     FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_LSH64_IMM,   FD_R0,  0,      0, 63),
    FD_BPF_INSTR(FD_BPF_OP_ARSH64_IMM,  FD_R0,  0,      0, 55),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,     FD_R1,  0,      0, 5),
    FD_BPF_INSTR(FD_BPF_OP_ARSH64_REG,  FD_R0,  FD_R1,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,        0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("be16-high", 0x1122, 4,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R0,  0,      0, 0x44332211),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x88776655),
    FD_BPF_INSTR(FD_BPF_OP_END_BE,    FD_R0,  0,      0, 16),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("be16", 0x1122, 3,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0x00002211),
    FD_BPF_INSTR(FD_BPF_OP_END_BE,    FD_R0,  0,      0, 16),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("be32-high", 0x11223344, 4,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R0,  0,      0, 0x44332211),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x88776655),
    FD_BPF_INSTR(FD_BPF_OP_END_BE,    FD_R0,  0,      0, 32),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("be32", 0x11223344, 3,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0x44332211),
    FD_BPF_INSTR(FD_BPF_OP_END_BE,    FD_R0,  0,      0, 32),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("be64", 0x1122334455667788, 4,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R0,  0,      0, 0x44332211),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x88776655),
    FD_BPF_INSTR(FD_BPF_OP_END_BE,    FD_R0,  0,      0, 64),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div-by-zero-imm", 0x0, 3,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_DIV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("div-by-zero-reg", 0x0, 4,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_DIV_REG,   FD_R0,  FD_R1,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div-high-divisor", 0x3, 5,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 12),
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R1,  0,      0, 0x4),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_BPF_INSTR(FD_BPF_OP_DIV_REG,   FD_R0,  FD_R1,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("div-imm", 0x3, 4,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R0,  0,      0, 0xc),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_BPF_INSTR(FD_BPF_OP_DIV_IMM,   FD_R0,  0,      0, 4),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div-reg", 0x3, 5,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R0,  0,      0, 0xc),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 4),
    FD_BPF_INSTR(FD_BPF_OP_DIV_REG,   FD_R0,  FD_R1,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("div64-by-zero-imm", 0x0, 3,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_DIV64_IMM, FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("div64-by-zero-reg", 0x0, 4,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_DIV64_REG, FD_R0,  FD_R1,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div64-high-divisor", 0x15555555, 6,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 12),
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R1,  0,      0, 0x4),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_BPF_INSTR(FD_BPF_OP_DIV64_REG, FD_R1,  FD_R0,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_REG,   FD_R0,  FD_R1,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("div64-imm", 0x40000003, 4,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R0,  0,      0, 0xc),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_BPF_INSTR(FD_BPF_OP_DIV64_IMM, FD_R0,  0,      0, 4),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("div64-reg", 0x40000003, 6,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R1,  0,      0, 0xc),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 4),
    FD_BPF_INSTR(FD_BPF_OP_DIV64_REG, FD_R1,  FD_R0,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_REG,   FD_R0,  FD_R1,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("early-exit", 0x3, 4,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 3),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 4),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("exit-not-last", 0x0, 1,
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("exit", 0x0, 2,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  fd_halt();
  return 0;
}

