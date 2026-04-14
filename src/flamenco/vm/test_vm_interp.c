#include "fd_vm.h"
#include "fd_vm_base.h"
#include "fd_vm_private.h"
#include "test_vm_util.h"
#include "../runtime/fd_bank.h"
#include "../../ballet/sbpf/fd_sbpf_instr.h"
#include "../../ballet/sbpf/fd_sbpf_opcodes.h"
#include "../../ballet/murmur3/fd_murmur3.h"
#include <stdlib.h>  /* malloc */

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
test_program_exec( char *                test_case_name,
                      ulong                 expected_result,
                      int                   expected_err,
                      ulong                 sbpf_version,
                      ulong const *         text,
                      ulong                 text_cnt,
                      fd_sbpf_syscalls_t *  syscalls,
                      fd_exec_instr_ctx_t * instr_ctx ) {

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );

  int vm_ok = !!fd_vm_init(
      /* vm                                     */ vm,
      /* instr_ctx                              */ instr_ctx,
      /* heap_max                               */ FD_VM_HEAP_DEFAULT,
      /* entry_cu                               */ FD_VM_COMPUTE_UNIT_LIMIT,
      /* rodata                                 */ (uchar *)text,
      /* rodata_sz                              */ 8UL*text_cnt,
      /* text                                   */ text,
      /* text_cnt                               */ text_cnt,
      /* text_off                               */ 0UL,
      /* text_sz                                */ 8UL*text_cnt,
      /* entry_pc                               */ 0UL,
      /* calldests                              */ NULL,
      /* sbpf_version                           */ sbpf_version,
      /* syscalls                               */ syscalls,
      /* trace                                  */ NULL,
      /* sha                                    */ sha,
      /* mem_regions                            */ NULL,
      /* mem_regions_cnt                        */ 0UL,
      /* mem_regions_accs                       */ NULL,
      /* is_deprecated                          */ 0,
      /* direct mapping                         */ FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, account_data_direct_mapping ),
      /* syscall_parameter_address_restrictions */ FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, syscall_parameter_address_restrictions ),
      /* virtual_address_space_adjustments      */ FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, virtual_address_space_adjustments ),
      /* dump_syscall_to_pb                     */ 0,
      /* r2_initial_value                       */ 0UL
  );
  FD_TEST( vm_ok );

  /* FIXME: GROSS */
  vm->pc        = vm->entry_pc;
  vm->ic        = 0UL;
  vm->cu        = vm->entry_cu;
  vm->frame_cnt = 0UL;
  vm->heap_sz   = 0UL;
  fd_vm_mem_cfg( vm );

  int err = fd_vm_validate( vm );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "validation failed: %i-%s", err, fd_vm_strerror( err ) ));

  long dt = -fd_log_wallclock();
  err = fd_vm_exec( vm );
  dt += fd_log_wallclock();

  if( expected_err!=FD_VM_SUCCESS ) {
    if( FD_UNLIKELY( err!=expected_err ) ) {
      FD_LOG_WARNING(( "Expected err %i (%s), got %i (%s)",
                       expected_err, fd_vm_strerror( expected_err ),
                       err,          fd_vm_strerror( err ) ));
    }
    FD_TEST( err==expected_err );
    test_vm_clear_txn_ctx_err( instr_ctx->txn_out );
  } else {
    if( FD_UNLIKELY( vm->reg[0]!=expected_result ) ) {
      FD_LOG_WARNING(( "Interp err: %i (%s)",   err,        fd_vm_strerror( err ) ));
      FD_LOG_WARNING(( "RET:        %lu 0x%lx", vm->reg[0], vm->reg[0]            ));
      FD_LOG_WARNING(( "PC:         %lu 0x%lx", vm->pc,     vm->pc                ));
      FD_LOG_WARNING(( "IC:         %lu 0x%lx", vm->ic,     vm->ic                ));
    }
    FD_TEST( vm->reg[0]==expected_result );
  }

//FD_LOG_NOTICE(( "Instr counter: %lu", vm.ic ));
  FD_LOG_NOTICE(( "%-20s %11li ns", test_case_name, dt ));
//FD_LOG_NOTICE(( "Time/Instr: %f ns", (double)dt / (double)vm.ic ));
//FD_LOG_NOTICE(( "Mega Instr/Sec: %f", 1000.0 * ((double)vm.ic / (double) dt)));
}


static int
test_vm_validate( ulong                 sbpf_version,
                       ulong const *         text,
                       ulong                 text_cnt,
                       fd_sbpf_syscalls_t *  syscalls,
                       fd_exec_instr_ctx_t * instr_ctx ) {
  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );
  int ok = !!fd_vm_init(
      vm, instr_ctx, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
      (uchar *)text, 8UL*text_cnt, text, text_cnt, 0UL, 8UL*text_cnt,
      0UL, NULL, sbpf_version, syscalls, NULL, sha, NULL, 0UL, NULL, 0,
      FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, account_data_direct_mapping ),
      FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, syscall_parameter_address_restrictions ),
      FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, virtual_address_space_adjustments ),
      0, 0UL );
  FD_TEST( ok );
  vm->pc        = vm->entry_pc;
  vm->ic        = 0UL;
  vm->cu        = vm->entry_cu;
  vm->frame_cnt = 0UL;
  vm->heap_sz   = 0UL;
  fd_vm_mem_cfg( vm );
  return fd_vm_validate( vm );
}

static void
test_stack_configuration( fd_sbpf_syscalls_t *  syscalls,
                          fd_exec_instr_ctx_t * instr_ctx ) {
  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  ulong text[] = { fd_vm_instr( FD_SBPF_OP_EXIT, 0, 0, 0, 0 ) };

  ulong versions[]    = { FD_SBPF_V0, FD_SBPF_V1, FD_SBPF_V2, FD_SBPF_V3 };
  ulong expected_sz[] = { FD_VM_STACK_FRAME_SZ, 0UL, 0UL, FD_VM_STACK_FRAME_SZ };
  ulong expected_ct[] = { 2UL, 0UL, 0UL, 1UL };

  for( ulong i=0; i<4; i++ ) {
    FD_TEST( fd_vm_init( vm, instr_ctx, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
        (uchar *)text, 8UL, text, 1UL, 0UL, 8UL, 0UL, NULL,
        versions[i], syscalls, NULL, sha, NULL, 0UL, NULL, 0,
        FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, account_data_direct_mapping ),
        FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, syscall_parameter_address_restrictions ),
        FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, virtual_address_space_adjustments ),
        0, 0UL ) );
    FD_TEST( vm->stack_frame_sz==expected_sz[i] );
    FD_TEST( vm->stack_push_frame_count==expected_ct[i] );
  }

  FD_LOG_NOTICE(( "%-20s PASS", "stack-frame-cfg" ));
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
    switch( instr.opcode.raw ) {
    case 0x34:  /* FD_SBPF_OP_DIV_IMM */
    case 0x94:  /* FD_SBPF_OP_MOD_IMM */
      instr.imm = fd_uint_max( instr.imm, 1 );
      break;
    case 0x64:  /* FD_SBPF_OP_LSH_IMM */
    case 0x74:  /* FD_SBPF_OP_RSH_IMM */
    case 0xc4:  /* FD_SBPF_OP_ARSH_IMM */
      instr.imm &= 31;
      break;
    }
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
    switch( instr.opcode.raw ) {
    case 0x37:  /* FD_SBPF_OP_DIV64_IMM */
    case 0x97:  /* FD_SBPF_OP_MOD64_IMM */
      instr.imm = fd_uint_max( instr.imm, 1 );
      break;
    case 0x67:  /* FD_SBPF_OP_LSH_IMM */
    case 0x77:  /* FD_SBPF_OP_RSH_IMM */
    case 0xc7:  /* FD_SBPF_OP_ARSH_IMM */
      instr.imm &= 31;
      break;
    }
    text[i] = fd_sbpf_ulong( instr );
  }
  instr.opcode.raw = FD_SBPF_OP_EXIT;
  text[text_cnt-1UL] = fd_sbpf_ulong( instr );
}

/* test_0cu_exit ensures that the VM correctly exits the root frame if
   the CU count after the final exit instruction reaches zero. */

static void
test_0cu_exit( fd_runtime_t * runtime ) {

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );

  ulong const text[3] = {
    fd_vm_instr( FD_SBPF_OP_XOR64_REG, 0, 0, 0, 0 ),
    fd_vm_instr( FD_SBPF_OP_XOR64_REG, 0, 0, 0, 0 ),
    fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0, 0, 0 )
  };
  ulong text_cnt = 3UL;

  fd_exec_instr_ctx_t instr_ctx[1];
  fd_bank_t           bank[1];
  fd_txn_out_t        txn_out[1];
  test_vm_minimal_exec_instr_ctx( instr_ctx, runtime, bank, txn_out );

  /* Ensure the VM exits with success if the CU count after the final
     exit instruction reaches zero. */

  int vm_ok = !!fd_vm_init(
      /* vm                                     */ vm,
      /* instr_ctx                              */ instr_ctx,
      /* heap_max                               */ FD_VM_HEAP_DEFAULT,
      /* entry_cu                               */ text_cnt,
      /* rodata                                 */ (uchar *)text,
      /* rodata_sz                              */ 8UL*text_cnt,
      /* text                                   */ text,
      /* text_cnt                               */ text_cnt,
      /* text_off                               */ 0UL,
      /* text_sz                                */ 8UL*text_cnt,
      /* entry_pc                               */ 0UL,
      /* calldests                              */ NULL,
      /* sbpf_version                           */ TEST_VM_DEFAULT_SBPF_VERSION,
      /* syscalls                               */ NULL,
      /* trace                                  */ NULL,
      /* sha                                    */ sha,
      /* mem_regions                            */ NULL,
      /* mem_regions_cnt                        */ 0UL,
      /* mem_regions_accs                       */ NULL,
      /* is_deprecated                          */ 0,
      /* direct mapping                         */ FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, account_data_direct_mapping ),
      /* syscall_parameter_address_restrictions */ FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, syscall_parameter_address_restrictions ),
      /* virtual_address_space_adjustments      */ FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, virtual_address_space_adjustments ),
      /* dump_syscall_to_pb                     */ 0,
      /* r2_initial_value                       */ 0UL
  );
  FD_TEST( vm_ok );

  FD_TEST( fd_vm_validate( vm )==FD_VM_SUCCESS );
  FD_TEST( fd_vm_exec    ( vm )==FD_VM_SUCCESS );
  FD_TEST( vm->cu == 0UL );

  /* Ensure the VM exits with failure if CUs are exhausted. */

  vm_ok = !!fd_vm_init(
      /* vm                                     */ vm,
      /* instr_ctx                              */ instr_ctx,
      /* heap_max                               */ FD_VM_HEAP_DEFAULT,
      /* entry_cu                               */ text_cnt - 1UL,
      /* rodata                                 */ (uchar *)text,
      /* rodata_sz                              */ 8UL*text_cnt,
      /* text                                   */ text,
      /* text_cnt                               */ text_cnt,
      /* text_off                               */ 0UL,
      /* text_sz                                */ 8UL*text_cnt,
      /* entry_pc                               */ 0UL,
      /* calldests                              */ NULL,
      /* sbpf_version                           */ TEST_VM_DEFAULT_SBPF_VERSION,
      /* syscalls                               */ NULL,
      /* trace                                  */ NULL,
      /* sha                                    */ sha,
      /* mem_regions                            */ NULL,
      /* mem_regions_cnt                        */ 0UL,
      /* mem_regions_accs                       */ NULL,
      /* is_deprecated                          */ 0,
      /* direct mapping                         */ FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, account_data_direct_mapping ),
      /* syscall_parameter_address_restrictions */ FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, syscall_parameter_address_restrictions ),
      /* virtual_address_space_adjustments      */ FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, virtual_address_space_adjustments ),
      /* dump_syscall_to_pb                     */ 0,
      /* r2_initial_value                       */ 0UL
  );
  FD_TEST( vm_ok );

  FD_TEST( fd_vm_validate( vm )==FD_VM_SUCCESS );
  FD_TEST( fd_vm_exec    ( vm )==FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS );

  fd_vm_delete( fd_vm_leave( vm ) );
  fd_sha256_delete( fd_sha256_leave( sha ) );
}


static void
test_mem_ld_bench( fd_runtime_t *        runtime,
                   fd_sbpf_syscalls_t *  syscalls ) {

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );

  fd_exec_instr_ctx_t instr_ctx[1];
  fd_bank_t           bank[1];
  fd_txn_out_t        txn_out[1];
  test_vm_minimal_exec_instr_ctx( instr_ctx, runtime, bank, txn_out );

  ulong input_sz = 32768UL;
  uchar * input_buf = (uchar *)malloc( input_sz );
  FD_TEST( input_buf );
  memset( input_buf, 0x42, input_sz );

  fd_vm_input_region_t input_region;
  memset( &input_region, 0, sizeof(input_region) );
  input_region.vaddr_offset           = 0UL;
  input_region.haddr                  = (ulong)input_buf;
  input_region.region_sz              = (uint)input_sz;
  input_region.address_space_reserved = input_sz;
  input_region.is_writable            = 0;

  ulong load_cnt = 1024UL * 1024UL;
  ulong text_cnt = 2UL + load_cnt + 1UL;
  ulong * text   = (ulong *)malloc( sizeof(ulong) * text_cnt );
  FD_TEST( text );

  /* LDDW r1, 0x400000000 (input region base vaddr) */
  text[0] = fd_vm_instr( 0x18, 1, 0, 0, 0 );
  text[1] = fd_vm_instr( 0,    0, 0, 0, 4 );

  for( ulong i = 0; i < load_cnt; i++ ) {
    short off = (short)((i * 8UL) % (input_sz - 8UL));
    text[2 + i] = fd_vm_instr( 0x79, 0, 1, off, 0 );
  }
  text[text_cnt - 1] = fd_vm_instr( FD_SBPF_OP_EXIT, 0, 0, 0, 0 );

  int vm_ok = !!fd_vm_init(
      vm, instr_ctx, FD_VM_HEAP_DEFAULT, text_cnt + 10UL,
      (uchar *)text, 8UL*text_cnt, text, text_cnt, 0UL, 8UL*text_cnt,
      0UL, NULL, FD_SBPF_V0, syscalls, NULL, sha,
      &input_region, 1UL, NULL, 0,
      FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, account_data_direct_mapping ),
      FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, syscall_parameter_address_restrictions ),
      FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, virtual_address_space_adjustments ),
      0, 0UL );
  FD_TEST( vm_ok );

  vm->pc        = vm->entry_pc;
  vm->ic        = 0UL;
  vm->cu        = vm->entry_cu;
  vm->frame_cnt = 0UL;
  vm->heap_sz   = 0UL;
  fd_vm_mem_cfg( vm );

  FD_TEST( fd_vm_validate( vm )==FD_VM_SUCCESS );

  long dt = -fd_log_wallclock();
  int err = fd_vm_exec( vm );
  dt += fd_log_wallclock();

  FD_TEST( err==FD_VM_SUCCESS );
  FD_LOG_NOTICE(( "%-20s %11li ns (%.1f ns/load, %lu loads)",
    "mem_ld_bench", dt, (double)dt / (double)load_cnt, load_cnt ));

  free( text );
  free( input_buf );
  fd_vm_delete( fd_vm_leave( vm ) );
  fd_sha256_delete( fd_sha256_leave( sha ) );
}



static void
test_branch_bench( fd_runtime_t *       runtime,
                   fd_sbpf_syscalls_t * syscalls ) {
  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_exec_instr_ctx_t instr_ctx[1];
  fd_bank_t           bank[1];
  fd_txn_out_t        txn_out[1];
  test_vm_minimal_exec_instr_ctx( instr_ctx, runtime, bank, txn_out );

  /* Branch-heavy program: tight loop of JNE (taken) + ADD.
     Pattern: add64_imm r0, 1 ; jne r0, LIMIT.
     Every 2 instructions hits BRANCH_BEGIN/BRANCH_END. */

  ulong loop_iters = 1UL << 20;
  ulong text_cnt = 2UL + 1UL; /* add + jne + exit */
  ulong * text = (ulong *)malloc( sizeof(ulong) * text_cnt );
  FD_TEST( text );

  text[0] = fd_vm_instr( FD_SBPF_OP_ADD64_IMM, 0, 0, 0, 1 );
  text[1] = fd_vm_instr( FD_SBPF_OP_JNE_IMM, 0, 0, (short)(-2), (uint)loop_iters );
  text[2] = fd_vm_instr( FD_SBPF_OP_EXIT, 0, 0, 0, 0 );

  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );

  int vm_ok = !!fd_vm_init(
      vm, instr_ctx, FD_VM_HEAP_DEFAULT, 4UL * loop_iters,
      (uchar *)text, 8UL*text_cnt, text, text_cnt, 0UL, 8UL*text_cnt,
      0UL, NULL, FD_SBPF_V0, syscalls, NULL, sha,
      NULL, 0UL, NULL, 0,
      FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, account_data_direct_mapping ),
      FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, syscall_parameter_address_restrictions ),
      FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, virtual_address_space_adjustments ),
      0, 0UL );
  FD_TEST( vm_ok );
  vm->pc = vm->entry_pc; vm->ic = 0UL; vm->cu = vm->entry_cu;
  vm->frame_cnt = 0UL; vm->heap_sz = 0UL;
  fd_vm_mem_cfg( vm );
  FD_TEST( fd_vm_validate( vm )==FD_VM_SUCCESS );

  long dt = -fd_log_wallclock();
  int err = fd_vm_exec( vm );
  dt += fd_log_wallclock();

  FD_TEST( err==FD_VM_SUCCESS );
  FD_LOG_NOTICE(( "%-20s %11li ns (%.1f ns/branch, %lu branches)",
    "branch_bench", dt, (double)dt / (double)loop_iters, loop_iters ));

  free( text );
  fd_vm_delete( fd_vm_leave( vm ) );
  fd_sha256_delete( fd_sha256_leave( sha ) );
}


static void
test_lazy_zero_bench( fd_runtime_t *       runtime,
                      fd_sbpf_syscalls_t * syscalls ) {
  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_exec_instr_ctx_t instr_ctx[1];
  fd_bank_t           bank[1];
  fd_txn_out_t        txn_out[1];
  test_vm_minimal_exec_instr_ctx( instr_ctx, runtime, bank, txn_out );

  /* Benchmark 1: fd_vm_new cost (now only zeros config+tail, not stack/heap). */
  {
    ulong const ITERS = 1UL << 14;
    uchar * shmem = (uchar *)aligned_alloc( FD_VM_ALIGN, FD_VM_FOOTPRINT );
    FD_TEST( shmem );

    long dt = -fd_log_wallclock();
    for( ulong i = 0; i < ITERS; i++ ) {
      fd_vm_new( shmem );
      fd_vm_delete( shmem );
      __asm__ volatile( "" ::: "memory" );
    }
    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "%-20s %11li ns (%.0f ns/call, %lu calls)",
      "vm_new_lazy", dt, (double)dt / (double)ITERS, ITERS ));
    free( shmem );
  }

  /* Benchmark 2: program that accesses N distinct stack pages via stores.
     This measures the per-page lazy zeroing overhead (memset 2KB on first access).
     Uses r1 = stack_base, then stores to r1+page_offset for each page.
     r10 in V1 = stack_top (0x200040000), so r10 - FD_VM_STACK_MAX = stack_base. */
  {
    ulong pages_to_touch = 16;
    /* lddw r1,stack_base (2 words) + per-page: stb [r1+off],r0 + add r0,1 + exit */
    ulong text_cnt = 2UL + pages_to_touch * 2UL + 1UL;
    ulong * text = (ulong *)malloc( sizeof(ulong) * text_cnt );
    FD_TEST( text );

    ulong stack_base = FD_VM_MEM_MAP_STACK_REGION_START;
    text[0] = fd_vm_instr( FD_SBPF_OP_LDDW, 2, 0, 0, (uint)(stack_base) );
    text[1] = fd_vm_instr( 0, 0, 0, 0, (uint)(stack_base >> 32) );

    for( ulong p = 0; p < pages_to_touch; p++ ) {
      short off = (short)(p * FD_VM_LAZY_PAGE_SZ);
      text[2 + p*2]     = fd_vm_instr( FD_SBPF_OP_STB, 2, 0, off, 0x42 );
      text[2 + p*2 + 1] = fd_vm_instr( FD_SBPF_OP_ADD64_IMM, 0, 0, 0, 1 );
    }
    text[text_cnt - 1] = fd_vm_instr( FD_SBPF_OP_EXIT, 0, 0, 0, 0 );

    ulong const ITERS = 1UL << 14;
    fd_vm_t _vm[1];
    fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
    FD_TEST( vm );

    long dt = -fd_log_wallclock();
    for( ulong i = 0; i < ITERS; i++ ) {
      int vm_ok = !!fd_vm_init(
          vm, instr_ctx, FD_VM_HEAP_DEFAULT, 10UL * text_cnt,
          (uchar *)text, 8UL*text_cnt, text, text_cnt, 0UL, 8UL*text_cnt,
          0UL, NULL, FD_SBPF_V1, syscalls, NULL, sha,
          NULL, 0UL, NULL, 0,
          FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, account_data_direct_mapping ),
          FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, syscall_parameter_address_restrictions ),
          FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, virtual_address_space_adjustments ),
          0, 0UL );
      FD_TEST( vm_ok );
      int err = fd_vm_exec( vm );
      FD_TEST( err==FD_VM_SUCCESS );
      __asm__ volatile( "" ::: "memory" );
    }
    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "%-20s %11li ns (%.0f ns/call, %lu pages touched)",
      "lazy_16pg_exec", dt, (double)dt / (double)ITERS, pages_to_touch ));

    free( text );
    fd_vm_delete( fd_vm_leave( vm ) );
  }

  /* Benchmark 3: program that writes to heap via stack-relative addressing.
     Touches 4 heap pages to verify heap lazy zeroing works correctly. */
  {
    ulong pages_to_touch = 4;
    ulong text_cnt = 2UL + pages_to_touch * 3UL + 1UL;
    ulong * text = (ulong *)malloc( sizeof(ulong) * text_cnt );
    FD_TEST( text );

    /* r1 = heap base vaddr (0x300000000) */
    text[0] = fd_vm_instr( FD_SBPF_OP_LDDW, 1, 0, 0, (uint)(FD_VM_MEM_MAP_HEAP_REGION_START) );
    text[1] = fd_vm_instr( 0, 0, 0, 0, (uint)(FD_VM_MEM_MAP_HEAP_REGION_START >> 32) );

    for( ulong p = 0; p < pages_to_touch; p++ ) {
      ushort off = (ushort)(p * FD_VM_LAZY_PAGE_SZ);
      text[2 + p*3]     = fd_vm_instr( FD_SBPF_OP_STB, 1, 0, (short)off, 0 );
      /* Load back to verify reads zero (testing lazy zero correctness) */
      text[2 + p*3 + 1] = fd_vm_instr( FD_SBPF_OP_LDXB, 0, 1, (short)(off+1), 0 );
      text[2 + p*3 + 2] = fd_vm_instr( FD_SBPF_OP_ADD64_IMM, 0, 0, 0, 0 );
    }
    text[text_cnt - 1] = fd_vm_instr( FD_SBPF_OP_EXIT, 0, 0, 0, 0 );

    fd_vm_t _vm[1];
    fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
    FD_TEST( vm );

    int vm_ok = !!fd_vm_init(
        vm, instr_ctx, FD_VM_HEAP_DEFAULT, 10UL * text_cnt,
        (uchar *)text, 8UL*text_cnt, text, text_cnt, 0UL, 8UL*text_cnt,
        0UL, NULL, FD_SBPF_V1, syscalls, NULL, sha,
        NULL, 0UL, NULL, 0,
        FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, account_data_direct_mapping ),
        FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, syscall_parameter_address_restrictions ),
        FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, virtual_address_space_adjustments ),
        0, 0UL );
    FD_TEST( vm_ok );
    int err = fd_vm_exec( vm );
    FD_TEST( err==FD_VM_SUCCESS );

    /* Verify correctness: r0 should be 0 (all lazy-zeroed bytes read as 0) */
    FD_TEST( vm->reg[0] == 0UL );

    FD_LOG_NOTICE(( "%-20s PASS (heap lazy zero correctness)", "lazy_heap_check" ));

    free( text );
    fd_vm_delete( fd_vm_leave( vm ) );
  }

  /* Benchmark 4: Stack correctness with lazy zeroing.
     Write to one stack page, then read from a DIFFERENT (untouched) page.
     The untouched page must read zero due to lazy zeroing. */
  {
    ulong text_cnt = 4;
    ulong * text = (ulong *)malloc( sizeof(ulong) * text_cnt );
    FD_TEST( text );

    /* Write 0x42 to stack page 0 (near top of stack: r10 - small offset) */
    text[0] = fd_vm_instr( FD_SBPF_OP_STB, 10, 0, (short)(-1), 0x42 );
    /* Read from a different stack page (r10 - 4096, which is 2 pages away) */
    text[1] = fd_vm_instr( FD_SBPF_OP_LDXB, 0, 10, (short)(-4096), 0 );
    /* r0 should be 0 if lazy zeroing works */
    text[2] = fd_vm_instr( FD_SBPF_OP_ADD64_IMM, 0, 0, 0, 0 );
    text[3] = fd_vm_instr( FD_SBPF_OP_EXIT, 0, 0, 0, 0 );

    fd_vm_t _vm[1];
    fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
    FD_TEST( vm );

    int vm_ok = !!fd_vm_init(
        vm, instr_ctx, FD_VM_HEAP_DEFAULT, 100UL,
        (uchar *)text, 8UL*text_cnt, text, text_cnt, 0UL, 8UL*text_cnt,
        0UL, NULL, FD_SBPF_V1, syscalls, NULL, sha,
        NULL, 0UL, NULL, 0,
        FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, account_data_direct_mapping ),
        FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, syscall_parameter_address_restrictions ),
        FD_FEATURE_ACTIVE_BANK( instr_ctx->bank, virtual_address_space_adjustments ),
        0, 0UL );
    FD_TEST( vm_ok );
    int err = fd_vm_exec( vm );
    FD_TEST( err==FD_VM_SUCCESS );
    FD_TEST( vm->reg[0] == 0UL );

    FD_LOG_NOTICE(( "%-20s PASS (stack lazy zero correctness)", "lazy_stack_check" ));

    free( text );
    fd_vm_delete( fd_vm_leave( vm ) );
  }

  fd_sha256_delete( fd_sha256_leave( sha ) );
}


/* Direct-mapping TLB tests.

   Simulate DM-style fragmented input regions with small token-account-
   sized data (165 bytes) and separate metadata regions.  Three
   scenarios:

   1. dm_contiguous:  Sequential loads within one account's data region.
      Models a p-token transfer reading/writing a single account — the
      TLB should hit ~100% after the first miss.

   2. dm_alternating: Alternating loads between two different account
      data regions.  Every load switches fragment, causing a TLB miss.
      Worst-case for a single-slot TLB under DM.

   3. dm_resize:      Writes past the end of a writable data region
      with VAS enabled, triggering fd_vm_handle_input_mem_region_oob
      to grow region_sz.  Verifies the TLB picks up the new size on
      the next miss.

   All three use the interpreter (fd_vm_exec) so the soft TLB is
   exercised end-to-end. */

/* Token account data size (SPL Token Account layout) */
#define DM_TEST_ACCT_DLEN        (165UL)
/* Per-account metadata serialized before data: 88 bytes (ABI v1) */
#define DM_TEST_META_SZ          (88UL)
/* address_space_reserved = dlen + MAX_PERMITTED_DATA_INCREASE (10 KB) */
#define DM_TEST_ADDR_RESERVED    (DM_TEST_ACCT_DLEN + MAX_PERMITTED_DATA_INCREASE)

/* Build a DM-style input_mem_regions array for N_ACCTS token accounts.
   Layout per account:
     region[2*i]   = metadata region  (DM_TEST_META_SZ bytes, writable)
     region[2*i+1] = data region      (DM_TEST_ACCT_DLEN bytes, writable, haddr -> acct_data_bufs[i])
   vaddr_offsets are contiguous: meta0 | data0 (reserved) | meta1 | data1 (reserved) | ... */

#define DM_TEST_MAX_ACCTS (4)

static void
dm_test_build_regions( fd_vm_input_region_t    regions[ /* 2*n_accts */ ],
                       uchar *                 meta_buf,        /* at least DM_TEST_META_SZ * n_accts */
                       uchar *                 acct_data_bufs[],/* n_accts pointers, each >= DM_TEST_ADDR_RESERVED */
                       fd_vm_acc_region_meta_t arm[],            /* n_accts entries */
                       ulong                   n_accts ) {
  ulong vaddr = 0UL;
  for( ulong i = 0; i < n_accts; i++ ) {
    /* Metadata region */
    regions[2*i].vaddr_offset           = vaddr;
    regions[2*i].haddr                  = (ulong)(meta_buf + i * DM_TEST_META_SZ);
    regions[2*i].region_sz              = (uint)DM_TEST_META_SZ;
    regions[2*i].address_space_reserved = DM_TEST_META_SZ;
    regions[2*i].is_writable            = 1;
    regions[2*i].acc_region_meta_idx    = ULONG_MAX;
    vaddr += DM_TEST_META_SZ;

    /* Data region — haddr points at the account's backing buffer */
    regions[2*i+1].vaddr_offset           = vaddr;
    regions[2*i+1].haddr                  = (ulong)acct_data_bufs[i];
    regions[2*i+1].region_sz              = (uint)DM_TEST_ACCT_DLEN;
    regions[2*i+1].address_space_reserved = DM_TEST_ADDR_RESERVED;
    regions[2*i+1].is_writable            = 1;
    regions[2*i+1].acc_region_meta_idx    = i;
    vaddr += DM_TEST_ADDR_RESERVED;

    arm[i].region_idx        = (uint)(2*i+1);
    arm[i].original_data_len = DM_TEST_ACCT_DLEN;
    arm[i].meta              = NULL;
  }
}

static void
test_dm_tlb( fd_runtime_t *       runtime,
             fd_sbpf_syscalls_t * syscalls ) {

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_exec_instr_ctx_t instr_ctx[1];
  fd_bank_t           bank[1];
  fd_txn_out_t        txn_out[1];
  test_vm_minimal_exec_instr_ctx( instr_ctx, runtime, bank, txn_out );

  /* Backing buffers for 4 token accounts (165 B data + 10 KB realloc headroom). */

  static uchar acct_data_0[ DM_TEST_ADDR_RESERVED ];
  static uchar acct_data_1[ DM_TEST_ADDR_RESERVED ];
  static uchar acct_data_2[ DM_TEST_ADDR_RESERVED ];
  static uchar acct_data_3[ DM_TEST_ADDR_RESERVED ];
  uchar * acct_data_bufs[DM_TEST_MAX_ACCTS] = { acct_data_0, acct_data_1, acct_data_2, acct_data_3 };

  /* Fill each account's data region with a recognizable pattern */
  for( ulong a = 0; a < DM_TEST_MAX_ACCTS; a++ ) {
    memset( acct_data_bufs[a], 0, DM_TEST_ADDR_RESERVED );
    for( ulong j = 0; j < DM_TEST_ACCT_DLEN; j++ ) {
      acct_data_bufs[a][j] = (uchar)((a + 1) * 0x11 + j);
    }
  }

  static uchar meta_buf[ DM_TEST_META_SZ * DM_TEST_MAX_ACCTS ];
  memset( meta_buf, 0xAA, sizeof(meta_buf) );

  /* === Test 1: dm_contiguous ===
     Load 1M times sequentially within account 0's data region.
     Expect ~100% TLB hit rate after the first miss. */
  {
    ulong n_accts = 2;
    fd_vm_input_region_t    regions[ 2 * DM_TEST_MAX_ACCTS ];
    fd_vm_acc_region_meta_t arm[ DM_TEST_MAX_ACCTS ];
    memset( arm, 0, sizeof(arm) );
    dm_test_build_regions( regions, meta_buf, acct_data_bufs, arm, n_accts );

    /* Data region 0 starts at vaddr_offset = DM_TEST_META_SZ within input space.
       Input vaddr = 0x400000000 + DM_TEST_META_SZ + byte_offset */
    ulong data0_input_vaddr = FD_VM_MEM_MAP_INPUT_REGION_START + DM_TEST_META_SZ;

    ulong load_cnt = 1024UL * 1024UL;
    ulong text_cnt = 2UL + load_cnt + 1UL;
    ulong * text   = (ulong *)malloc( sizeof(ulong) * text_cnt );
    FD_TEST( text );

    /* LDDW r1, data0_input_vaddr */
    text[0] = fd_vm_instr( FD_SBPF_OP_LDDW, 1, 0, 0, (uint)(data0_input_vaddr) );
    text[1] = fd_vm_instr( 0, 0, 0, 0, (uint)(data0_input_vaddr >> 32) );

    for( ulong i = 0; i < load_cnt; i++ ) {
      short off = (short)(( i * 8UL ) % (DM_TEST_ACCT_DLEN - 8UL));
      text[2 + i] = fd_vm_instr( FD_SBPF_OP_LDXDW, 0, 1, off, 0 );
    }
    text[text_cnt - 1] = fd_vm_instr( FD_SBPF_OP_EXIT, 0, 0, 0, 0 );

    fd_vm_t _vm[1];
    fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
    FD_TEST( vm );

    int vm_ok = !!fd_vm_init(
        vm, instr_ctx, FD_VM_HEAP_DEFAULT, text_cnt + 10UL,
        (uchar *)text, 8UL*text_cnt, text, text_cnt, 0UL, 8UL*text_cnt,
        0UL, NULL, FD_SBPF_V0, syscalls, NULL, sha,
        regions, (uint)(n_accts * 2), arm, 0,
        1 /* direct_mapping */,
        0 /* syscall_parameter_address_restrictions */,
        0 /* virtual_address_space_adjustments */,
        0, 0UL );
    FD_TEST( vm_ok );
    vm->pc = vm->entry_pc; vm->ic = 0UL; vm->cu = vm->entry_cu;
    vm->frame_cnt = 0UL; vm->heap_sz = 0UL;
    fd_vm_mem_cfg( vm );
    FD_TEST( fd_vm_validate( vm )==FD_VM_SUCCESS );

    long dt = -fd_log_wallclock();
    int err = fd_vm_exec( vm );
    dt += fd_log_wallclock();

    FD_TEST( err==FD_VM_SUCCESS );
    FD_LOG_NOTICE(( "%-20s %11li ns (%.1f ns/load, %lu loads)",
      "dm_contiguous", dt, (double)dt / (double)load_cnt, load_cnt ));

    free( text );
    fd_vm_delete( fd_vm_leave( vm ) );
  }

  /* === Test 2: dm_alternating ===
     Alternate loads between account 0 and account 1 data regions.
     Every load misses the single-slot TLB (worst case). */
  {
    ulong n_accts = 2;
    fd_vm_input_region_t    regions[ 2 * DM_TEST_MAX_ACCTS ];
    fd_vm_acc_region_meta_t arm[ DM_TEST_MAX_ACCTS ];
    memset( arm, 0, sizeof(arm) );
    dm_test_build_regions( regions, meta_buf, acct_data_bufs, arm, n_accts );

    ulong data0_input_vaddr = FD_VM_MEM_MAP_INPUT_REGION_START + DM_TEST_META_SZ;
    ulong data1_input_vaddr = FD_VM_MEM_MAP_INPUT_REGION_START
                            + DM_TEST_META_SZ + DM_TEST_ADDR_RESERVED
                            + DM_TEST_META_SZ;

    /* Program:
       LDDW r1, data0_vaddr    (2 words)
       LDDW r2, data1_vaddr    (2 words)
       loop body (2 instrs per iter): ldxdw r0,[r1+off] ; ldxdw r0,[r2+off]
       exit */
    ulong load_pairs = 512UL * 1024UL;
    ulong text_cnt   = 4UL + load_pairs * 2UL + 1UL;
    ulong * text     = (ulong *)malloc( sizeof(ulong) * text_cnt );
    FD_TEST( text );

    text[0] = fd_vm_instr( FD_SBPF_OP_LDDW, 1, 0, 0, (uint)(data0_input_vaddr) );
    text[1] = fd_vm_instr( 0, 0, 0, 0, (uint)(data0_input_vaddr >> 32) );
    text[2] = fd_vm_instr( FD_SBPF_OP_LDDW, 2, 0, 0, (uint)(data1_input_vaddr) );
    text[3] = fd_vm_instr( 0, 0, 0, 0, (uint)(data1_input_vaddr >> 32) );

    for( ulong i = 0; i < load_pairs; i++ ) {
      short off = (short)(( i * 8UL ) % (DM_TEST_ACCT_DLEN - 8UL));
      text[4 + i*2]     = fd_vm_instr( FD_SBPF_OP_LDXDW, 0, 1, off, 0 );
      text[4 + i*2 + 1] = fd_vm_instr( FD_SBPF_OP_LDXDW, 0, 2, off, 0 );
    }
    text[text_cnt - 1] = fd_vm_instr( FD_SBPF_OP_EXIT, 0, 0, 0, 0 );

    fd_vm_t _vm[1];
    fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
    FD_TEST( vm );

    int vm_ok = !!fd_vm_init(
        vm, instr_ctx, FD_VM_HEAP_DEFAULT, text_cnt + 10UL,
        (uchar *)text, 8UL*text_cnt, text, text_cnt, 0UL, 8UL*text_cnt,
        0UL, NULL, FD_SBPF_V0, syscalls, NULL, sha,
        regions, (uint)(n_accts * 2), arm, 0,
        1 /* direct_mapping */,
        0 /* syscall_parameter_address_restrictions */,
        0 /* virtual_address_space_adjustments */,
        0, 0UL );
    FD_TEST( vm_ok );
    vm->pc = vm->entry_pc; vm->ic = 0UL; vm->cu = vm->entry_cu;
    vm->frame_cnt = 0UL; vm->heap_sz = 0UL;
    fd_vm_mem_cfg( vm );
    FD_TEST( fd_vm_validate( vm )==FD_VM_SUCCESS );

    long dt = -fd_log_wallclock();
    int err = fd_vm_exec( vm );
    dt += fd_log_wallclock();

    ulong total_loads = load_pairs * 2UL;
    FD_TEST( err==FD_VM_SUCCESS );
    FD_LOG_NOTICE(( "%-20s %11li ns (%.1f ns/load, %lu loads)",
      "dm_alternating", dt, (double)dt / (double)total_loads, total_loads ));

    free( text );
    fd_vm_delete( fd_vm_leave( vm ) );
  }

  /* === Test 3: dm_resize ===
     With VAS + DM, write past the current region_sz to trigger
     fd_vm_handle_input_mem_region_oob, which grows region_sz.
     Then read back to verify the TLB picks up the new size.

     The account data region starts with region_sz = DM_TEST_ACCT_DLEN
     (165 B) and address_space_reserved = DM_TEST_ADDR_RESERVED (~10 KB).
     We write at offset 200 (past 165), triggering resize, then read
     it back and verify. */
  {
    ulong n_accts = 1;
    fd_vm_input_region_t    regions[ 2 * DM_TEST_MAX_ACCTS ];
    fd_vm_acc_region_meta_t arm[ DM_TEST_MAX_ACCTS ];
    memset( arm, 0, sizeof(arm) );
    dm_test_build_regions( regions, meta_buf, acct_data_bufs, arm, n_accts );

    /* We need a real fd_account_meta_t for the resize path to call
       fd_account_meta_resize on.  Place it at the start of the data buffer. */
    static uchar resize_acct_buf[ sizeof(fd_account_meta_t) + DM_TEST_ADDR_RESERVED ]
      __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
    memset( resize_acct_buf, 0, sizeof(resize_acct_buf) );
    fd_account_meta_t * resize_meta = (fd_account_meta_t *)resize_acct_buf;
    resize_meta->dlen = (uint)DM_TEST_ACCT_DLEN;

    uchar * resize_data = resize_acct_buf + sizeof(fd_account_meta_t);
    for( ulong j = 0; j < DM_TEST_ACCT_DLEN; j++ ) resize_data[j] = (uchar)(0x11 + j);

    /* Point the data region haddr at resize_data (past the meta header) */
    regions[1].haddr = (ulong)resize_data;
    arm[0].meta = resize_meta;

    ulong data0_input_vaddr = FD_VM_MEM_MAP_INPUT_REGION_START + DM_TEST_META_SZ;

    /* Program:
       LDDW r1, data0_input_vaddr   (2 words)
       MOV64_IMM r3, 0xBE           (marker byte value)
       STB [r1+200], r3             (write at offset 200 — past region_sz=165, triggers resize)
       LDXB r0, [r1+200]            (read back — should get 0xBE)
       EXIT */
    ulong text_cnt = 6UL;
    ulong * text = (ulong *)malloc( sizeof(ulong) * text_cnt );
    FD_TEST( text );

    text[0] = fd_vm_instr( FD_SBPF_OP_LDDW, 1, 0, 0, (uint)(data0_input_vaddr) );
    text[1] = fd_vm_instr( 0, 0, 0, 0, (uint)(data0_input_vaddr >> 32) );
    text[2] = fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 3, 0, 0, 0xBE );
    text[3] = fd_vm_instr( FD_SBPF_OP_STXB, 1, 3, 200, 0 );
    text[4] = fd_vm_instr( FD_SBPF_OP_LDXB, 0, 1, 200, 0 );
    text[5] = fd_vm_instr( FD_SBPF_OP_EXIT, 0, 0, 0, 0 );

    fd_vm_t _vm[1];
    fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
    FD_TEST( vm );

    int vm_ok = !!fd_vm_init(
        vm, instr_ctx, FD_VM_HEAP_DEFAULT, 100UL,
        (uchar *)text, 8UL*text_cnt, text, text_cnt, 0UL, 8UL*text_cnt,
        0UL, NULL, FD_SBPF_V0, syscalls, NULL, sha,
        regions, (uint)(n_accts * 2), arm, 0,
        1 /* direct_mapping */,
        0 /* syscall_parameter_address_restrictions */,
        1 /* virtual_address_space_adjustments */,
        0, 0UL );
    FD_TEST( vm_ok );
    vm->pc = vm->entry_pc; vm->ic = 0UL; vm->cu = vm->entry_cu;
    vm->frame_cnt = 0UL; vm->heap_sz = 0UL;
    fd_vm_mem_cfg( vm );
    FD_TEST( fd_vm_validate( vm )==FD_VM_SUCCESS );

    int err = fd_vm_exec( vm );
    FD_TEST( err==FD_VM_SUCCESS );

    /* Verify: r0 should hold 0xBE (the byte we wrote past the original region_sz) */
    FD_TEST( vm->reg[0] == 0xBEUL );

    /* Verify: region_sz was grown past the original 165 */
    FD_TEST( regions[1].region_sz > DM_TEST_ACCT_DLEN );

    FD_LOG_NOTICE(( "%-20s PASS (region grew from %lu to %u, read back 0x%lx)",
      "dm_resize", DM_TEST_ACCT_DLEN, regions[1].region_sz, vm->reg[0] ));

    free( text );
    fd_vm_delete( fd_vm_leave( vm ) );
  }

  fd_sha256_delete( fd_sha256_leave( sha ) );
}


/* Direct translation microbenchmark: isolates fd_vm_mem_haddr vs
   fd_vm_mem_haddr_with_tlb cost for DM-style fragmented input regions
   by calling them directly in a loop (no interpreter overhead). */

static void
test_dm_translate_bench( fd_runtime_t *       runtime,
                         fd_sbpf_syscalls_t * syscalls ) {
  (void)syscalls;

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  fd_exec_instr_ctx_t instr_ctx[1];
  fd_bank_t           bank[1];
  fd_txn_out_t        txn_out[1];
  test_vm_minimal_exec_instr_ctx( instr_ctx, runtime, bank, txn_out );

  static uchar acct_data_0[ DM_TEST_ADDR_RESERVED ];
  static uchar acct_data_1[ DM_TEST_ADDR_RESERVED ];
  uchar * acct_data_bufs[DM_TEST_MAX_ACCTS] = { acct_data_0, acct_data_1, NULL, NULL };
  static uchar meta_buf[ DM_TEST_META_SZ * DM_TEST_MAX_ACCTS ];
  memset( meta_buf, 0xAA, sizeof(meta_buf) );
  memset( acct_data_0, 0x11, DM_TEST_ACCT_DLEN );
  memset( acct_data_1, 0x22, DM_TEST_ACCT_DLEN );

  ulong n_accts = 2;
  fd_vm_input_region_t    regions[ 2 * DM_TEST_MAX_ACCTS ];
  fd_vm_acc_region_meta_t arm[ DM_TEST_MAX_ACCTS ];
  memset( arm, 0, sizeof(arm) );
  dm_test_build_regions( regions, meta_buf, acct_data_bufs, arm, n_accts );

  /* vaddrs for byte 0 of each data region */
  ulong vaddr0 = FD_VM_MEM_MAP_INPUT_REGION_START + DM_TEST_META_SZ;
  ulong vaddr1 = FD_VM_MEM_MAP_INPUT_REGION_START
               + DM_TEST_META_SZ + DM_TEST_ADDR_RESERVED
               + DM_TEST_META_SZ;

  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );

  ulong dummy_text[2] = { fd_vm_instr( FD_SBPF_OP_EXIT, 0, 0, 0, 0 ), 0 };
  int vm_ok = !!fd_vm_init(
      vm, instr_ctx, FD_VM_HEAP_DEFAULT, 100UL,
      (uchar *)dummy_text, 8UL, dummy_text, 1UL, 0UL, 8UL,
      0UL, NULL, FD_SBPF_V0, syscalls, NULL, sha,
      regions, (uint)(n_accts * 2), arm, 0,
      1 /* direct_mapping */, 0, 0, 0, 0UL );
  FD_TEST( vm_ok );
  vm->pc = 0; vm->ic = 0; vm->cu = 100; vm->frame_cnt = 0; vm->heap_sz = 0;
  fd_vm_mem_cfg( vm );

  ulong const N = 1UL << 20;

  /* --- Bench 1: fd_vm_mem_haddr alternating (no TLB, DM baseline) --- */
  {
    ulong haddr;
    volatile ulong sink = 0;
    long dt = -fd_log_wallclock();
    for( ulong i = 0; i < N; i++ ) {
      ulong vaddr = (i & 1) ? vaddr1 : vaddr0;
      haddr = fd_vm_mem_haddr( vm, vaddr, 8UL, vm->region_haddr, vm->region_ld_sz, 0, 0UL );
      sink += haddr;
    }
    dt += fd_log_wallclock();
    (void)sink;
    FD_LOG_NOTICE(( "%-20s %11li ns (%.1f ns/xlat, %lu xlats)",
      "dm_raw_alt", dt, (double)dt / (double)N, N ));
  }

  /* --- Bench 2: fd_vm_mem_haddr contiguous (no TLB, DM baseline) --- */
  {
    ulong haddr;
    volatile ulong sink = 0;
    long dt = -fd_log_wallclock();
    for( ulong i = 0; i < N; i++ ) {
      haddr = fd_vm_mem_haddr( vm, vaddr0, 8UL, vm->region_haddr, vm->region_ld_sz, 0, 0UL );
      sink += haddr;
    }
    dt += fd_log_wallclock();
    (void)sink;
    FD_LOG_NOTICE(( "%-20s %11li ns (%.1f ns/xlat, %lu xlats)",
      "dm_raw_contig", dt, (double)dt / (double)N, N ));
  }

  /* --- Bench 3: fd_vm_mem_haddr_with_tlb alternating (100% miss) --- */
  {
    ulong tlb_ld_haddr_base = 0, tlb_ld_vaddr_lo = 0, tlb_ld_vaddr_hi = 0;
    ulong haddr;
    volatile ulong sink = 0;
    long dt = -fd_log_wallclock();
    for( ulong i = 0; i < N; i++ ) {
      ulong vaddr = (i & 1) ? vaddr1 : vaddr0;
      haddr = fd_vm_mem_haddr_with_tlb( vm, vaddr, 8UL, vm->region_haddr, vm->region_ld_sz, 0, 0UL,
        &tlb_ld_haddr_base, &tlb_ld_vaddr_lo, &tlb_ld_vaddr_hi, 0 );
      sink += haddr;
    }
    dt += fd_log_wallclock();
    (void)sink;
    FD_LOG_NOTICE(( "%-20s %11li ns (%.1f ns/xlat, %lu xlats)",
      "dm_tlb_alt", dt, (double)dt / (double)N, N ));
  }

  /* --- Bench 4: fd_vm_mem_haddr_with_tlb contiguous (100% hit after 1st) --- */
  {
    ulong tlb_ld_haddr_base = 0, tlb_ld_vaddr_lo = 0, tlb_ld_vaddr_hi = 0;
    ulong haddr;
    volatile ulong sink = 0;
    long dt = -fd_log_wallclock();
    for( ulong i = 0; i < N; i++ ) {
      haddr = fd_vm_mem_haddr_with_tlb( vm, vaddr0, 8UL, vm->region_haddr, vm->region_ld_sz, 0, 0UL,
        &tlb_ld_haddr_base, &tlb_ld_vaddr_lo, &tlb_ld_vaddr_hi, 0 );
      sink += haddr;
    }
    dt += fd_log_wallclock();
    (void)sink;
    FD_LOG_NOTICE(( "%-20s %11li ns (%.1f ns/xlat, %lu xlats)",
      "dm_tlb_contig", dt, (double)dt / (double)N, N ));
  }

  fd_vm_delete( fd_vm_leave( vm ) );
  fd_sha256_delete( fd_sha256_leave( sha ) );
}

static fd_sbpf_syscalls_t _syscalls[ FD_SBPF_SYSCALLS_SLOT_CNT ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL, NULL            );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 5UL             );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL, 1234UL          );

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  fd_runtime_t * runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), wksp_tag );
  FD_TEST( runtime );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( _syscalls ) ); FD_TEST( syscalls );

  fd_exec_instr_ctx_t instr_ctx[1];
  fd_bank_t           bank[1];
  fd_txn_out_t        txn_out[1];
  test_vm_minimal_exec_instr_ctx( instr_ctx, runtime, bank, txn_out );

  FD_TEST( fd_vm_syscall_register( syscalls, "accumulator", accumulator_syscall )==FD_VM_SUCCESS );

# define TEST_PROGRAM_SUCCESS( test_case_name, expected_result, text_cnt, ... ) do {         \
    ulong _text[ text_cnt ] = { __VA_ARGS__ };                                               \
    test_program_exec( (test_case_name), (expected_result), FD_VM_SUCCESS,                 \
                          TEST_VM_DEFAULT_SBPF_VERSION, _text, (text_cnt), syscalls, instr_ctx ); \
  } while(0)

# define TEST_V3_SUCCESS( test_case_name, expected_result, text_cnt, ... ) do { \
    ulong _text[ text_cnt ] = { __VA_ARGS__ };                                  \
    test_program_exec( (test_case_name), (expected_result), FD_VM_SUCCESS,    \
                          FD_SBPF_V3, _text, (text_cnt), syscalls, instr_ctx ); \
  } while(0)

# define TEST_V3_ERROR( test_case_name, expected_err, text_cnt, ... ) do {    \
    ulong _text[ text_cnt ] = { __VA_ARGS__ };                                \
    test_program_exec( (test_case_name), 0UL, (expected_err),              \
                          FD_SBPF_V3, _text, (text_cnt), syscalls, instr_ctx ); \
  } while(0)

# define FD_SBPF_INSTR(op, dst, src, off, val) (fd_vm_instr( op, dst, src, off, val ))

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

  TEST_PROGRAM_SUCCESS("alu-arith", 0x150, 17,
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

    /* Divide by zero faults */
    //FD_SBPF_INSTR(FD_SBPF_OP_DIV_IMM,   FD_SBPF_R0,  0,      0, 2),
    //FD_SBPF_INSTR(FD_SBPF_OP_DIV_REG,   FD_SBPF_R0,  FD_SBPF_R4,  0, 0),

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

  TEST_PROGRAM_SUCCESS("syscall", 15, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R3,  0,      0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R4,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R5,  0,      0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,      0,      0,      0, fd_murmur3_32( "accumulator", 11UL, 0U ) ),

    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,      0,      0, 0),
  );

  /* SIMD-0178: Static syscalls (SBPF V3+) */

  TEST_V3_SUCCESS("static-syscall", 15, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1,  0,      0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2,  0,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R3,  0,      0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R4,  0,      0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R5,  0,      0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,           0,      0, fd_murmur3_32( "accumulator", 11UL, 0U ) ),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,           0,      0, 0),
  );

  TEST_V3_SUCCESS("static-syscall-args", 150, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1,  0,      0, 10),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2,  0,      0, 20),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R3,  0,      0, 30),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R4,  0,      0, 40),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R5,  0,      0, 50),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,           0,      0, fd_murmur3_32( "accumulator", 11UL, 0U ) ),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,           0,      0, 0),
  );

  TEST_V3_SUCCESS("static-call-fwd", 42, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,           1,   0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,           0,   0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0,  0,   0, 42),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,           0,   0, 0),
  );

  TEST_V3_SUCCESS("static-call-bwd", 99, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_JA,        0,          0,     +2, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,      0, 99),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          1,      0, (uint)(int)-3),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,      0, 0),
  );

  TEST_V3_SUCCESS("static-call-boundary", 55, 5,
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          1,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,      0, 55),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,      0, 0),
  );

  TEST_V3_SUCCESS("static-call-nested", 42, 8,
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          1,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          1,      0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,      0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,      0, 42),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,      0, 0),
  );

  TEST_V3_SUCCESS("static-call-then-external-syscall", 100, 11,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R6, 0,           0, 100),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          1,           0, 7),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_REG, FD_SBPF_R1, FD_SBPF_R6, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,           0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R3, 0,           0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R4, 0,           0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R5, 0,           0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          0,           0, fd_murmur3_32( "accumulator", 11UL, 0U ) ),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,           0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,           0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,           0, 0),
  );

  TEST_V3_ERROR("static-syscall-external-missing", FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION, 2,
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM, 0, 0, 0, 0xDEADBEEF),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,     0, 0, 0, 0),
  );

  TEST_V3_ERROR("static-syscall-external-zero", FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION, 2,
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM, 0, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,     0, 0, 0, 0),
  );

  TEST_V3_ERROR("static-call-oob-hi", FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION, 3,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          1, 0, 100),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  TEST_V3_ERROR("static-call-oob-lo", FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION, 3,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          1, 0, (uint)(int)-10),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  TEST_V3_ERROR("static-call-oob-eq", FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION, 4,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM,  0,          1, 0, 2), /* target=4==text_cnt */
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  TEST_V3_ERROR("static-bad-src-2", FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION, 2,
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM, 0, 2, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,     0, 0, 0, 0),
  );

  TEST_V3_ERROR("static-bad-src-9", FD_VM_ERR_EBPF_UNSUPPORTED_INSTRUCTION, 2,
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM, 0, 9, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,     0, 0, 0, 0),
  );

  TEST_V3_ERROR("static-stack-ovflw", FD_VM_ERR_EBPF_CALL_DEPTH_EXCEEDED, 2,
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_IMM, 0, 1, 0, (uint)(int)-1), /* self-call (target=0) */
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,     0, 0, 0, 0),
  );

  /* SIMD-0377: JMP32 (SBPF V3+)
     Branch taken -> r0=2, not taken -> r0=1. */

  /* JEQ32 */

  TEST_V3_SUCCESS("jeq32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jeq32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_IMM, FD_SBPF_R1, 0, 1, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jeq32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jeq32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );

  /* JGT32 */

  TEST_V3_SUCCESS("jgt32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jgt32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jgt32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jgt32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );

  /* JGE32 */

  TEST_V3_SUCCESS("jge32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jge32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jge32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jge32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );

  /* JSET32 */

  TEST_V3_SUCCESS("jset32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET32_IMM, FD_SBPF_R1, 0, 1, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jset32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET32_IMM, FD_SBPF_R1, 0, 1, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jset32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, 3),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jset32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );

  /* JNE32 */

  TEST_V3_SUCCESS("jne32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE32_IMM, FD_SBPF_R1, 0, 1, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jne32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jne32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jne32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );

  /* JSGT32 */

  TEST_V3_SUCCESS("jsgt32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsgt32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsgt32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jsgt32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );

  /* JSGE32 */

  TEST_V3_SUCCESS("jsge32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGE32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsge32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGE32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsge32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jsge32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );

  /* JLT32 */

  TEST_V3_SUCCESS("jlt32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jlt32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jlt32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 4),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jlt32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );

  /* JLE32 */

  TEST_V3_SUCCESS("jle32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JLE32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jle32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_JLE32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jle32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JLE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jle32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0,          0, 6),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_JLE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );

  /* JSLT32 */

  TEST_V3_SUCCESS("jslt32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLT32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jslt32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLT32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jslt32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLT32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jslt32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLT32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );

  /* JSLE32 */

  TEST_V3_SUCCESS("jsle32-imm-taken", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLE32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsle32-imm-ntaken", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLE32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsle32-reg-taken", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );
  TEST_V3_SUCCESS("jsle32-reg-ntaken", 1, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );

  /* JMP32 32-bit truncation: upper 32 bits should be ignored */
  TEST_V3_SUCCESS("jeq32-trunc-imm", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1, 0, 0, 5),
    FD_SBPF_INSTR(0,                     0,          0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_IMM, FD_SBPF_R1, 0, 1, 5),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jeq32-trunc-reg", 2, 9,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1, 0,          0, 5),
    FD_SBPF_INSTR(0,                     0,          0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R2, 0,          0, 5),
    FD_SBPF_INSTR(0,                     0,          0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );

  TEST_V3_SUCCESS("jne32-trunc-reg", 1, 9,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1, 0,          0, 0x42),
    FD_SBPF_INSTR(0,                     0,          0,          0, 0xDEAD),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R2, 0,          0, 0x42),
    FD_SBPF_INSTR(0,                     0,          0,          0, 0xBEEF),
    FD_SBPF_INSTR(FD_SBPF_OP_JNE32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0,          0, 0),
  );

  TEST_V3_SUCCESS("jeq32-hi-set-lo0", 2, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(0,                     0,          0, 0, 0xFFFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  /* JMP32 signed vs unsigned cross-boundary edge cases */
  TEST_V3_SUCCESS("jgt32-0x80000000", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT32_IMM, FD_SBPF_R1, 0, 1, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsgt32-0x80000000", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_IMM, FD_SBPF_R1, 0, 1, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jgt32-0xffffffff", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsgt32-neg1-vs-0", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jsgt32-max-vs-min", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0x7FFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_IMM, FD_SBPF_R1, 0, 1, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jgt32-max-vs-min", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 0x7FFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_JGT32_IMM, FD_SBPF_R1, 0, 1, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jsgt32-neg2-neg1", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, (uint)(int)-2),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_IMM, FD_SBPF_R1, 0, 1, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jsgt32-neg1-neg2", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGT32_IMM, FD_SBPF_R1, 0, 1, (uint)(int)-2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jsge32-min-vs-max", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_JSGE32_IMM, FD_SBPF_R1, 0, 1, 0x7FFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jge32-min-vs-max", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_JGE32_IMM, FD_SBPF_R1, 0, 1, 0x7FFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jslt32-max-vs-min", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0x7FFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_JSLT32_IMM, FD_SBPF_R1, 0, 1, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );
  TEST_V3_SUCCESS("jlt32-max-vs-min", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 0x7FFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_JLT32_IMM, FD_SBPF_R1, 0, 1, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  /* JSET32 bit-test edge cases */
  TEST_V3_SUCCESS("jset32-no-overlap", 1, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0xAAAAAAAAU),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET32_IMM, FD_SBPF_R1, 0, 1, 0x55555555U),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jset32-all-overlap", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET32_IMM, FD_SBPF_R1, 0, 1, 0xFFFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jset32-high-bit", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R1, 0, 0, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET32_IMM, FD_SBPF_R1, 0, 1, 0x80000000U),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jset32-upper-only", 1, 9,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,       FD_SBPF_R1, 0,          0, 0),
    FD_SBPF_INSTR(0,                      0,          0,          0, 0xFFFF0000U),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,       FD_SBPF_R2, 0,          0, 0),
    FD_SBPF_INSTR(0,                      0,          0,          0, 0xFFFF0000U),
    FD_SBPF_INSTR(FD_SBPF_OP_JSET32_REG, FD_SBPF_R1, FD_SBPF_R2, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM,  FD_SBPF_R0, 0,          0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,       0,          0,          0, 0),
  );

  /* JMP32 boundary values */
  TEST_V3_SUCCESS("jeq32-both-zero", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_IMM, FD_SBPF_R1, 0, 1, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  TEST_V3_SUCCESS("jeq32-both-max", 2, 6,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R1, 0, 0, (uint)(int)-1),
    FD_SBPF_INSTR(FD_SBPF_OP_JEQ32_IMM, FD_SBPF_R1, 0, 1, 0xFFFFFFFFU),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 2),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  /* SIMD-0377: CALLX uses dst register in V3 */

  TEST_V3_SUCCESS("callx-dst-reg", 42, 7,
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_LDDW,      FD_SBPF_R1, 0, 0, 5*8),
    FD_SBPF_INSTR(0,                     0,         0, 0, 1),
    FD_SBPF_INSTR(FD_SBPF_OP_CALL_REG,  FD_SBPF_R1, 0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
    FD_SBPF_INSTR(FD_SBPF_OP_MOV64_IMM, FD_SBPF_R0, 0, 0, 42),
    FD_SBPF_INSTR(FD_SBPF_OP_EXIT,      0,          0, 0, 0),
  );

  /* CALLX validation */
  {
    ulong vtext_callx_inv[] = {
      fd_vm_instr( FD_SBPF_OP_CALL_REG, 10, 0, 0, 0 ),
      fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0, 0, 0 ),
    };
    FD_TEST( test_vm_validate( FD_SBPF_V3, vtext_callx_inv, 2, syscalls, instr_ctx )==FD_VM_ERR_INVALID_REG );
    FD_LOG_NOTICE(( "%-20s PASS", "callx-dst-inv-v3" ));
  }

  {
    ulong vtext_callx_ok[] = {
      fd_vm_instr( FD_SBPF_OP_CALL_REG, 9, 0, 0, 0 ),
      fd_vm_instr( FD_SBPF_OP_EXIT,     0, 0, 0, 0 ),
    };
    FD_TEST( test_vm_validate( FD_SBPF_V3, vtext_callx_ok, 2, syscalls, instr_ctx )==FD_VM_SUCCESS );
    FD_LOG_NOTICE(( "%-20s PASS", "callx-dst-max-v3" ));
  }

  {
    ulong vtext_jmp32[] = {
      fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 0, 0, 0, 0 ),
      fd_vm_instr( FD_SBPF_OP_JEQ32_IMM, 0, 0, 0, 0 ),
      fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0, 0, 0 ),
    };
    FD_TEST( test_vm_validate( FD_SBPF_V0, vtext_jmp32, 3, syscalls, instr_ctx )!=FD_VM_SUCCESS );
    FD_TEST( test_vm_validate( FD_SBPF_V3, vtext_jmp32, 3, syscalls, instr_ctx )==FD_VM_SUCCESS );
    FD_LOG_NOTICE(( "%-20s PASS", "jmp32-vfy-gate" ));
  }

  test_stack_configuration( syscalls, instr_ctx );

  ulong   text_cnt = 128*1024*1024;
  ulong * text     = (ulong *)malloc( sizeof(ulong)*text_cnt ); /* FIXME: gross */

  generate_random_alu_instrs( rng, text, text_cnt );
  test_program_exec( "alu_bench", 0x0, FD_VM_SUCCESS, TEST_VM_DEFAULT_SBPF_VERSION, text, text_cnt, syscalls, instr_ctx );

  generate_random_alu64_instrs( rng, text, text_cnt );
  test_program_exec( "alu64_bench", 0x0, FD_VM_SUCCESS, TEST_VM_DEFAULT_SBPF_VERSION, text, text_cnt, syscalls, instr_ctx );

  text_cnt = 1024UL;
  generate_random_alu_instrs( rng, text, text_cnt );
  test_program_exec( "alu_bench_short", 0x0, FD_VM_SUCCESS, TEST_VM_DEFAULT_SBPF_VERSION, text, text_cnt, syscalls, instr_ctx );

  generate_random_alu64_instrs( rng, text, text_cnt );
  test_program_exec( "alu64_bench_short", 0x0, FD_VM_SUCCESS, TEST_VM_DEFAULT_SBPF_VERSION, text, text_cnt, syscalls, instr_ctx );

  test_0cu_exit( runtime );

  test_mem_ld_bench( runtime, syscalls );
  test_branch_bench( runtime, syscalls );
  test_lazy_zero_bench( runtime, syscalls );
  test_dm_tlb( runtime, syscalls );
  test_dm_translate_bench( runtime, syscalls );


  free( text );

  fd_sbpf_syscalls_delete( fd_sbpf_syscalls_leave( syscalls ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_rng_delete( fd_rng_leave( rng ) );
  fd_halt();
  return 0;
}
