#include "fd_vm.h"
#include "fd_opcodes.h"
#include "fd_sbpf_interp.h"
#include "../util/fd_util.h"
#include "../ballet/base58/fd_base58.h"
#include <string.h>
#include <stdio.h>
#include <immintrin.h>

static ulong accumulator_syscall(FD_FN_UNUSED fd_vm_sbpf_exec_context_t * ctx, ulong arg0, ulong arg1, ulong arg2, ulong arg3, ulong arg4, ulong * ret) {
  *ret = arg0 + arg1 + arg2 + arg3 + arg4; 
  return 0;
}

static void
test_program_success( char *                test_case_name,
                      ulong                 expected_result,
                      ulong                 instrs_sz,
                      fd_vm_sbpf_instr_t *  instrs ) {
  FD_LOG_NOTICE(( "Test program: %s", test_case_name ));

  fd_vm_sbpf_exec_context_t ctx = {
    .entrypoint = 0,
    .program_counter = 0,
    .instruction_counter = 0,
    .instrs = instrs,
    .instrs_sz = instrs_sz,
  };

  fd_vm_sbpf_interp_register_syscall( &ctx, "accumulator", accumulator_syscall );

  ulong validation_res = fd_vm_sbpf_interp_validate( &ctx ); 
  if (validation_res != 0) {
    FD_LOG_WARNING(( "VAL_RES: %lu", validation_res ));
  }
  FD_TEST( validation_res==FD_VM_SBPF_VALIDATE_SUCCESS );

  long dt = -fd_log_wallclock();
  fd_vm_sbpf_interp_instrs( &ctx );
  dt += fd_log_wallclock(); 
  if (expected_result != ctx.register_file[0]) {
    FD_LOG_WARNING(( "RET: %lu 0x%lx", ctx.register_file[0], ctx.register_file[0] ));
    FD_LOG_WARNING(( "PC: %lu 0x%lx", ctx.program_counter, ctx.program_counter ));
    FD_LOG_WARNING(( "x: %lu 0x%x", ctx.program_counter, FD_BPF_OP_JLE_IMM ));
  }
  FD_TEST( ctx.register_file[0]==expected_result );
  FD_LOG_NOTICE(( "Instr counter: %lu", ctx.instruction_counter ));
  FD_LOG_NOTICE(( "Time: %ldns", dt ));
  FD_LOG_NOTICE(( "Time/Instr: %f ns", (double)dt / (double)ctx.instruction_counter ));
  FD_LOG_NOTICE(( "Mega Instr/Sec: %f", 1000.0 * ((double)ctx.instruction_counter / (double) dt)));
}

#define TEST_PROGRAM_SUCCESS(test_case_name, expected_result, instrs_sz, ...) { \
  fd_vm_sbpf_instr_t instrs_var[instrs_sz] = { __VA_ARGS__ }; \
  test_program_success(test_case_name, expected_result, instrs_sz, instrs_var); \
}

static void
test_input_params_diff( fd_vm_sbpf_exec_params_t * params, 
                        uchar const * expected_bytes, 
                        ulong expected_bytes_len ) {
  ulong buf_size = 65536;
  uchar buf[buf_size];
  
  ulong len = fd_vm_serialize_input_params( params, buf, buf_size );
  ulong min_len = (len < expected_bytes_len) ? len : expected_bytes_len;

  if( len != expected_bytes_len ) { 
    FD_LOG_WARNING(( "Mismatch in bytes content of params: actual: %lu, expected: %lu", 
          len, expected_bytes_len ));
  }

  for( ulong i = 0; i < min_len; i++ ) {
    if( buf[i] != expected_bytes[i] ) {
      FD_LOG_WARNING(( "Input parameters differ at byte %lu: actual: %x, expected: %x", i, buf[i], 
            expected_bytes[i] ));
      FD_TEST( buf[i] == expected_bytes[i] );
    }
  }
  
  FD_TEST( len == expected_bytes_len );
}

static void
generate_random_alu_instrs( fd_rng_t * rng, fd_vm_sbpf_instr_t * instrs, ulong instrs_sz ) {
  uchar opcodes[25] = {
    FD_BPF_OP_ADD_IMM,
    FD_BPF_OP_ADD_REG,
    FD_BPF_OP_SUB_IMM,
    FD_BPF_OP_SUB_REG,
    FD_BPF_OP_MUL_IMM,
    FD_BPF_OP_MUL_REG,
    FD_BPF_OP_DIV_IMM,
    FD_BPF_OP_DIV_REG,
    FD_BPF_OP_OR_IMM,
    FD_BPF_OP_OR_REG,
    FD_BPF_OP_AND_IMM,
    FD_BPF_OP_AND_REG,
    FD_BPF_OP_LSH_IMM,
    FD_BPF_OP_LSH_REG,
    FD_BPF_OP_RSH_IMM,
    FD_BPF_OP_RSH_REG,
    FD_BPF_OP_NEG,
    FD_BPF_OP_MOD_IMM,
    FD_BPF_OP_MOD_REG,
    FD_BPF_OP_XOR_IMM,
    FD_BPF_OP_XOR_REG,
    FD_BPF_OP_MOV_IMM,
    FD_BPF_OP_MOV_REG,
    FD_BPF_OP_ARSH_IMM,
    FD_BPF_OP_ARSH_REG,
  };
  
  for( ulong i = 0; i < instrs_sz-1; i++ ) {
    fd_vm_sbpf_instr_t * instr = &instrs[i];
    instr->opcode.raw = opcodes[fd_rng_ulong_roll(rng, 25)];
    instr->dst_reg = 1+fd_rng_uchar_roll(rng, 9);
    instr->src_reg = 1+fd_rng_uchar_roll(rng, 9);
    instr->offset = 0;
    instr->imm = fd_rng_uint_roll(rng, 1024*1024);
  }
  instrs[instrs_sz-1].opcode.raw = FD_BPF_OP_EXIT;
}

static void
generate_random_alu64_instrs( fd_rng_t * rng, fd_vm_sbpf_instr_t * instrs, ulong instrs_sz ) {
  uchar opcodes[25] = {
    FD_BPF_OP_ADD64_IMM,
    FD_BPF_OP_ADD64_REG,
    FD_BPF_OP_SUB64_IMM,
    FD_BPF_OP_SUB64_REG,
    FD_BPF_OP_MUL64_IMM,
    FD_BPF_OP_MUL64_REG,
    FD_BPF_OP_DIV64_IMM,
    FD_BPF_OP_DIV64_REG,
    FD_BPF_OP_OR64_IMM,
    FD_BPF_OP_OR64_REG,
    FD_BPF_OP_AND64_IMM,
    FD_BPF_OP_AND64_REG,
    FD_BPF_OP_LSH64_IMM,
    FD_BPF_OP_LSH64_REG,
    FD_BPF_OP_RSH64_IMM,
    FD_BPF_OP_RSH64_REG,
    FD_BPF_OP_NEG64,
    FD_BPF_OP_MOD64_IMM,
    FD_BPF_OP_MOD64_REG,
    FD_BPF_OP_XOR64_IMM,
    FD_BPF_OP_XOR64_REG,
    FD_BPF_OP_MOV64_IMM,
    FD_BPF_OP_MOV64_REG,
    FD_BPF_OP_ARSH64_IMM,
    FD_BPF_OP_ARSH64_REG,
  };
  
  for( ulong i = 0; i < instrs_sz-1; i++ ) {
    fd_vm_sbpf_instr_t * instr = &instrs[i];
    instr->opcode.raw = opcodes[fd_rng_ulong_roll(rng, 25)];
    instr->dst_reg = 1+fd_rng_uchar_roll(rng, 9);
    instr->src_reg = 1+fd_rng_uchar_roll(rng, 9);
    instr->offset = 0;
    instr->imm = fd_rng_uint_roll(rng, 1024*1024);
  }
  instrs[instrs_sz-1].opcode.raw = FD_BPF_OP_EXIT;
}

FD_IMPORT_BINARY( input_param_1, "src/vm/test_input_param_1.bin" );

static void
test_input_params_1() {
  ulong expected_bytes_len = 641;
  uchar const * expected_bytes = input_param_1;

  fd_vm_sbpf_exec_account_info_t account_infos[8];
  memset(account_infos, 0, sizeof(account_infos));

  {
    fd_vm_sbpf_exec_account_info_t * account_info = &account_infos[0];
    fd_base58_decode_32( "6pQhYqaECP9Sa4oaXss2fLYRVVs7cFcWQHZbwHMbjgfp", account_info->pubkey );
    fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111", account_info->owner );
    account_info->is_signer = 0;
    account_info->is_writable = 0;
    account_info->is_executable = 0;
    account_info->lamports = 1;
    account_info->rent_epoch = 100;

    account_info->data_len = 5;
    uchar account_data[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    account_info->data = malloc(5);
    fd_memcpy( account_info->data, account_data, 5);
  }
  
  {
    fd_vm_sbpf_exec_account_info_t * account_info = &account_infos[1];
    account_info->is_duplicate = 1;
    account_info->index_of_origin = 0;
  }

  {
    fd_vm_sbpf_exec_account_info_t * account_info = &account_infos[2];
    fd_base58_decode_32( "5dw2RiM3VcYYwQbvif2wvtUNPHX5j6RKfg7E7nwcjuEj", account_info->pubkey );
    fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111", account_info->owner );
    account_info->is_signer = 0;
    account_info->is_writable = 0;
    account_info->is_executable = 1;
    account_info->lamports = 2;
    account_info->rent_epoch = 200;

    account_info->data_len = 9;
    uchar account_data[] = { 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13 };
    account_info->data = malloc(9);
    fd_memcpy( account_info->data, account_data, 9);
  }
  
  {
    fd_vm_sbpf_exec_account_info_t * account_info = &account_infos[3];
    fd_base58_decode_32( "CjBG1SGWx3CqVmhQwfdi8WBs2Vrj6G3q9pDDhpwdbUtj", account_info->pubkey );
    fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111", account_info->owner );
    account_info->is_signer = 0;
    account_info->is_writable = 0;
    account_info->is_executable = 0;
    account_info->lamports = 3;
    account_info->rent_epoch = 3100;

    account_info->data_len = 0;
    uchar account_data[] = {};
    account_info->data = malloc(0);
    fd_memcpy( account_info->data, account_data, 0);
  }
  
  {
    fd_vm_sbpf_exec_account_info_t * account_info = &account_infos[4];
    fd_base58_decode_32( "GzsgerRWY6RmZAqHQvzsA9jdMgevzaDXu9fb3CHe3nks", account_info->pubkey );
    fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111", account_info->owner );
    account_info->is_signer = 0;
    account_info->is_writable = 1;
    account_info->is_executable = 0;
    account_info->lamports = 4;
    account_info->rent_epoch = 100;

    account_info->data_len = 5;
    uchar account_data[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    account_info->data = malloc(5);
    fd_memcpy( account_info->data, account_data, 5);
  }
  
  {
    fd_vm_sbpf_exec_account_info_t * account_info = &account_infos[5];
    account_info->is_duplicate = 1;
    account_info->index_of_origin = 4;
  }
  
  {
    fd_vm_sbpf_exec_account_info_t * account_info = &account_infos[6];
    fd_base58_decode_32( "5oNfRTeEezVxgjNe8b1hnJsr8wiAkhYYUDty7zLxKANL", account_info->pubkey );
    fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111", account_info->owner );
    account_info->is_signer = 0;
    account_info->is_writable = 1;
    account_info->is_executable = 1;
    account_info->lamports = 5;
    account_info->rent_epoch = 200;

    account_info->data_len = 9;
    uchar account_data[] = { 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13 };
    account_info->data = malloc(9);
    fd_memcpy( account_info->data, account_data, 9);
  }
  
  {
    fd_vm_sbpf_exec_account_info_t * account_info = &account_infos[7];
    fd_base58_decode_32( "4RZb6jbUTRRtZcGFb3Wrqehdjz69NX8xsUY7i5upps6u", account_info->pubkey );
    fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111", account_info->owner );
    account_info->is_signer = 0;
    account_info->is_writable = 1;
    account_info->is_executable = 0;
    account_info->lamports = 6;
    account_info->rent_epoch = 3100;

    account_info->data_len = 0;
    uchar account_data[] = {};
    account_info->data = malloc(0);
    fd_memcpy( account_info->data, account_data, 0);
  }

  fd_pubkey_t program_id;
  fd_base58_decode_32( "AZBkttuNfLzUaSNUK77Q6rJRENDo3UFztiKY7AhEjzMP", program_id);
  fd_vm_sbpf_exec_params_t params = {
    .accounts = account_infos,
    .accounts_len = 8,
    .data_len = 11,
    .program_id = &program_id
  };

  uchar data[11] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b };
  params.data = data;

  test_input_params_diff( &params, expected_bytes, expected_bytes_len );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_input_params_1();

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

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
  
  TEST_PROGRAM_SUCCESS("mod-by-zero-imm", 0x1, 3,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_MOD_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("mod-by-zero-reg", 0x1, 4,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOD_REG,   FD_R0,  FD_R1,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod-high-divisor", 0x0, 5,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 12),
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R1,  0,      0, 0x4),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_BPF_INSTR(FD_BPF_OP_MOD_REG,   FD_R0,  FD_R1,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("mod-imm", 0x0, 4,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R0,  0,      0, 0xc),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_BPF_INSTR(FD_BPF_OP_MOD_IMM,   FD_R0,  0,      0, 4),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod-reg", 0x0, 5,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R0,  0,      0, 0xc),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 4),
    FD_BPF_INSTR(FD_BPF_OP_MOD_REG,   FD_R0,  FD_R1,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("mod64-by-zero-imm", 0x1, 3,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_MOD64_IMM, FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("mod64-by-zero-reg", 0x1, 4,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOD64_REG, FD_R0,  FD_R1,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod64-high-divisor", 0x8, 6,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 12),
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R1,  0,      0, 0x4),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_BPF_INSTR(FD_BPF_OP_MOD64_REG, FD_R1,  FD_R0,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_REG,   FD_R0,  FD_R1,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("mod64-imm", 0x0, 4,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R0,  0,      0, 0xc),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_BPF_INSTR(FD_BPF_OP_MOD64_IMM, FD_R0,  0,      0, 4),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("mod64-reg", 0x0, 6,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R1,  0,      0, 0xc),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x1),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 4),
    FD_BPF_INSTR(FD_BPF_OP_MOD64_REG, FD_R1,  FD_R0,  0, 0),
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

  TEST_PROGRAM_SUCCESS("ja", 0x1, 4,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_JA,        0,      0,     +1, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 2),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("jeq-imm", 0x1, 8,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 0xa),
    FD_BPF_INSTR(FD_BPF_OP_JEQ_IMM,   FD_R1,  0,     +4, 0xb),

    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 0xb),
    FD_BPF_INSTR(FD_BPF_OP_JEQ_IMM,   FD_R1,  0,     +1, 0xb),

    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 2),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jeq-reg", 0x1, 9,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 0xa),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R2,  0,      0, 0xb),
    FD_BPF_INSTR(FD_BPF_OP_JEQ_REG,   FD_R1,  FD_R2, +4, 0),

    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 0xb),
    FD_BPF_INSTR(FD_BPF_OP_JEQ_REG,   FD_R1,  FD_R2, +1, 0),

    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 2),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("jge-imm", 0x1, 8,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 4),
    
    FD_BPF_INSTR(FD_BPF_OP_JGE_IMM,   FD_R1,  0,     +2, 6),
    FD_BPF_INSTR(FD_BPF_OP_JGE_IMM,   FD_R1,  0,     +1, 5),
    FD_BPF_INSTR(FD_BPF_OP_JGE_IMM,   FD_R1,  0,     +1, 4),

    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("jge-reg", 0x1, 11,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 4),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R2,  0,      0, 6),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R3,  0,      0, 4),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R4,  0,      0, 5),
    
    FD_BPF_INSTR(FD_BPF_OP_JGE_REG,   FD_R1,  FD_R2, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_JGE_REG,   FD_R1,  FD_R4, +1, 0),
    FD_BPF_INSTR(FD_BPF_OP_JGE_REG,   FD_R1,  FD_R3, +1, 0),

    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jgt-imm", 0x1, 8,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 5),
    
    FD_BPF_INSTR(FD_BPF_OP_JGT_IMM,   FD_R1,  0,     +2, 6),
    FD_BPF_INSTR(FD_BPF_OP_JGT_IMM,   FD_R1,  0,     +1, 5),
    FD_BPF_INSTR(FD_BPF_OP_JGT_IMM,   FD_R1,  0,     +1, 4),

    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("jgt-reg", 0x1, 10,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 5),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R2,  0,      0, 6),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R3,  0,      0, 4),
    
    FD_BPF_INSTR(FD_BPF_OP_JGT_REG,   FD_R1,  FD_R2, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_JGT_REG,   FD_R1,  FD_R1, +1, 0),
    FD_BPF_INSTR(FD_BPF_OP_JGT_REG,   FD_R1,  FD_R3, +1, 0),

    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("jle-imm", 0x1, 8,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 7),
    
    FD_BPF_INSTR(FD_BPF_OP_JLE_IMM,   FD_R1,  0,     +2, 6),
    FD_BPF_INSTR(FD_BPF_OP_JLE_IMM,   FD_R1,  0,     +2, 8),
    FD_BPF_INSTR(FD_BPF_OP_JLE_IMM,   FD_R1,  0,     +1, 4),

    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("jle-reg", 0x1, 11,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 10),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R2,  0,      0, 7),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R3,  0,      0, 11),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R4,  0,      0, 5),
    
    FD_BPF_INSTR(FD_BPF_OP_JLE_REG,   FD_R1,  FD_R2, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_JLE_REG,   FD_R1,  FD_R4, +1, 0),
    FD_BPF_INSTR(FD_BPF_OP_JLE_REG,   FD_R1,  FD_R3, +1, 0),

    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("jlt-imm", 0x1, 8,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 7),
    
    FD_BPF_INSTR(FD_BPF_OP_JLT_IMM,   FD_R1,  0,     +2, 6),
    FD_BPF_INSTR(FD_BPF_OP_JLT_IMM,   FD_R1,  0,     +2, 8),
    FD_BPF_INSTR(FD_BPF_OP_JLT_IMM,   FD_R1,  0,     +1, 4),

    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("jlt-reg", 0x1, 11,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 10),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R2,  0,      0, 7),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R3,  0,      0, 11),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R4,  0,      0, 5),
    
    FD_BPF_INSTR(FD_BPF_OP_JLT_REG,   FD_R1,  FD_R2, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_JLT_REG,   FD_R1,  FD_R4, +1, 0),
    FD_BPF_INSTR(FD_BPF_OP_JLT_REG,   FD_R1,  FD_R3, +1, 0),

    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("jne-imm", 0x1, 8,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 7),
    
    FD_BPF_INSTR(FD_BPF_OP_JNE_IMM,   FD_R1,  0,     +2, 7),
    FD_BPF_INSTR(FD_BPF_OP_JNE_IMM,   FD_R1,  0,     +2, 10),
    FD_BPF_INSTR(FD_BPF_OP_JNE_IMM,   FD_R1,  0,     +1, 7),

    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("jne-reg", 0x1, 11,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 10),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R2,  0,      0, 10),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R3,  0,      0, 24),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R4,  0,      0, 10),
    
    FD_BPF_INSTR(FD_BPF_OP_JNE_REG,   FD_R1,  FD_R2, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_JNE_REG,   FD_R1,  FD_R4, +1, 0),
    FD_BPF_INSTR(FD_BPF_OP_JNE_REG,   FD_R1,  FD_R3, +1, 0),

    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("jset-imm", 0x1, 8,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 0x8),
    
    FD_BPF_INSTR(FD_BPF_OP_JSET_IMM,   FD_R1,  0,     +2, 0x7),
    FD_BPF_INSTR(FD_BPF_OP_JSET_IMM,   FD_R1,  0,     +2, 0x9),
    FD_BPF_INSTR(FD_BPF_OP_JSET_IMM,   FD_R1,  0,     +1, 0x10),

    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("jset-reg", 0x1, 11,
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R1,  0,      0, 0x8),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R2,  0,      0, 0x7),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R3,  0,      0, 0x9),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R4,  0,      0, 0x0),
    
    FD_BPF_INSTR(FD_BPF_OP_JSET_REG,   FD_R1,  FD_R2, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_JSET_REG,   FD_R1,  FD_R4, +1, 0),
    FD_BPF_INSTR(FD_BPF_OP_JSET_REG,   FD_R1,  FD_R3, +1, 0),

    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R0,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("ldq", 0x1122334455667788, 3,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R0,  0,      0, 0x55667788),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x11223344),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("stb-heap", 0x11, 5,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R1,  0,      0, 0x0),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_BPF_INSTR(FD_BPF_OP_STB,       FD_R1,  0,     +2, 0x11),
    FD_BPF_INSTR(FD_BPF_OP_LDXB,      FD_R0,  FD_R1, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("sth-heap", 0x1122, 5,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R1,  0,      0, 0x0),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_BPF_INSTR(FD_BPF_OP_STH,       FD_R1,  0,     +2, 0x1122),
    FD_BPF_INSTR(FD_BPF_OP_LDXH,      FD_R0,  FD_R1, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("stw-heap", 0x11223344, 5,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R1,  0,      0, 0x0),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_BPF_INSTR(FD_BPF_OP_STW,       FD_R1,  0,     +2, 0x11223344),
    FD_BPF_INSTR(FD_BPF_OP_LDXW,      FD_R0,  FD_R1, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  // TODO: check that we zero upper 32 bits
  TEST_PROGRAM_SUCCESS("stq-heap", 0x11223344, 5,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R1,  0,      0, 0x0),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_BPF_INSTR(FD_BPF_OP_STQ,       FD_R1,  0,     +2, 0x11223344),
    FD_BPF_INSTR(FD_BPF_OP_LDXQ,      FD_R0,  FD_R1, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("stxb-heap", 0x11, 6,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R1,  0,      0, 0x0),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R2,  0,      0, 0x11),
    FD_BPF_INSTR(FD_BPF_OP_STXB,      FD_R1,  FD_R2, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_LDXB,      FD_R0,  FD_R1, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("stxh-heap", 0x1122, 6,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R1,  0,      0, 0x0),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R2,  0,      0, 0x1122),
    FD_BPF_INSTR(FD_BPF_OP_STXH,      FD_R1,  FD_R2, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_LDXH,      FD_R0,  FD_R1, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("stxw-heap", 0x11223344, 6,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R1,  0,      0, 0x0),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_BPF_INSTR(FD_BPF_OP_MOV_IMM,   FD_R2,  0,      0, 0x11223344),
    FD_BPF_INSTR(FD_BPF_OP_STXW,      FD_R1,  FD_R2, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_LDXW,      FD_R0,  FD_R1, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("stxq-heap", 0x1122334455667788, 7,
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R1,  0,      0, 0x0),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x3),
    FD_BPF_INSTR(FD_BPF_OP_LDQ,       FD_R2,  0,      0, 0x55667788),
    FD_BPF_INSTR(FD_BPF_OP_ADDL_IMM,  0,      0,      0, 0x11223344),
    FD_BPF_INSTR(FD_BPF_OP_STXQ,      FD_R1,  FD_R2, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_LDXQ,      FD_R0,  FD_R1, +2, 0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  TEST_PROGRAM_SUCCESS("prime", 0x1, 16,
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM, FD_R1,  0,      0, 100000007),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM, FD_R0,  0,      0, 0x1),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM, FD_R2,  0,      0, 0x2),
    FD_BPF_INSTR(FD_BPF_OP_JGT_IMM,   FD_R1,  0,     +4, 0x2),
    
    FD_BPF_INSTR(FD_BPF_OP_JA,        0,      0,    +10, 0),
    FD_BPF_INSTR(FD_BPF_OP_ADD64_IMM, FD_R2,  0,      0, 0x1),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM, FD_R0,  0,      0, 0x1),
    FD_BPF_INSTR(FD_BPF_OP_JGE_REG,   FD_R2,  FD_R1, +7, 0),
    
    FD_BPF_INSTR(FD_BPF_OP_MOV64_REG, FD_R3,  FD_R1,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_DIV64_REG, FD_R3,  FD_R2,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MUL64_REG, FD_R3,  FD_R2,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_REG, FD_R4,  FD_R1,  0, 0),

    FD_BPF_INSTR(FD_BPF_OP_SUB64_REG, FD_R4,  FD_R3,  0, 0),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM, FD_R0,  0,      0, 0x0),
    FD_BPF_INSTR(FD_BPF_OP_JNE_IMM,   FD_R4,  0,    -10, 0x0),
    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );
  
  TEST_PROGRAM_SUCCESS("call", 15, 7,
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM, FD_R1,  0,      0, 1),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM, FD_R2,  0,      0, 2),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM, FD_R3,  0,      0, 3),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM, FD_R4,  0,      0, 4),
    FD_BPF_INSTR(FD_BPF_OP_MOV64_IMM, FD_R5,  0,      0, 5),
    FD_BPF_INSTR(FD_BPF_OP_CALL_IMM,      0,      0,      0, 0x7e6bb1fb),

    FD_BPF_INSTR(FD_BPF_OP_EXIT,      0,      0,      0, 0),
  );

  ulong instrs_sz = 128*1024*1024;
  fd_vm_sbpf_instr_t * instrs = malloc( sizeof(fd_vm_sbpf_instr_t) * instrs_sz );

  generate_random_alu_instrs( rng, instrs, instrs_sz );
  test_program_success("alu_bench", 0x0, instrs_sz, instrs);

  generate_random_alu64_instrs( rng, instrs, instrs_sz );
  test_program_success("alu64_bench", 0x0, instrs_sz, instrs);
  
  instrs_sz = 1024;
  generate_random_alu_instrs( rng, instrs, instrs_sz );
  test_program_success("alu_bench_short", 0x0, instrs_sz, instrs);

  generate_random_alu64_instrs( rng, instrs, instrs_sz );
  test_program_success("alu64_bench_short", 0x0, instrs_sz, instrs);
  
  fd_rng_delete( fd_rng_leave( rng ) );

  fd_halt();
  return 0;
}
