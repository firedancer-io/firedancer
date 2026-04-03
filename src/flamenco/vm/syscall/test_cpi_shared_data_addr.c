/* Unit test for a CPI bug which was reported and fixed

   Scenario:
   - Two accounts share the same data_box_addr
   - The callee grows both accounts
   - The first account's update modifies the shared ref_to_len_in_vm,
     causing the second account's update to skip the resize branch
     (since prev_len == post_len).
   - The second account's update will skip the resize branch,
     causing the serialized_data_len to be stale.
   - This can result in a buffer overflow on the final memcpy.

   Fix:
   - Add a check, which is present in Agave, to ensure that the
     serialized_data_len is not stale.  */

#include "fd_vm_syscall.h"
#include "../test_vm_util.h"
#include "../../runtime/fd_system_ids.h"
#include "../../runtime/tests/fd_svm_mini.h"
#include "../../runtime/tests/fd_svm_elfgen.h"
#include "../../../ballet/sbpf/fd_sbpf_instr.h"
#include "../../../ballet/sbpf/fd_sbpf_opcodes.h"

#define LAMPORTS     1000000UL
#define INIT_DLEN    8UL
#define TARGET_LEN   1000UL

/* ABI v1 per-account serialization layout:
   80 bytes header + 8 byte data_len + data (aligned) + 10240 realloc + 8 rent_epoch */
#define ACCT_META_SZ       88UL  /* offset to account data start */
#define ACCT_DLEN_OFF      (ACCT_META_SZ - sizeof(ulong))  /* offset to data_len field */
#define ACCT_SERIALIZED_SZ (ACCT_META_SZ + fd_ulong_align_up( INIT_DLEN, 8UL ) + 10240UL + 8UL)

static fd_pubkey_t const callee_program_pubkey = {{
  0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
  0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
  0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
  0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
}};

static fd_pubkey_t const acct1_pubkey = {{
  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
}};

static fd_pubkey_t const acct2_pubkey = {{
  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
}};

/* sBPF program that sets account data lengths to TARGET_LEN.
   r1 points to serialized account data on entry. */

static ulong
build_callee_text( ulong * buf ) {
  ulong acct1_dlen_off = 8UL + ACCT_DLEN_OFF;
  ulong acct2_dlen_off = 8UL + ACCT_SERIALIZED_SZ + ACCT_DLEN_OFF;
  FD_TEST( acct2_dlen_off <= SHRT_MAX );
  ulong ic = 0UL;
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode = {.raw=FD_SBPF_OP_MOV64_IMM}, .dst_reg = 2, .imm = (uint)TARGET_LEN } );
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode = {.raw=FD_SBPF_OP_STXDW},     .dst_reg = 1, .src_reg = 2, .offset = (short)acct1_dlen_off } );
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode = {.raw=FD_SBPF_OP_STXDW},     .dst_reg = 1, .src_reg = 2, .offset = (short)acct2_dlen_off } );
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode = {.raw=FD_SBPF_OP_MOV64_IMM}, .dst_reg = 0 } );
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode = {.raw=FD_SBPF_OP_EXIT} } );
  return ic * 8UL;
}

/* Set up a data account meta with the callee as owner */

static fd_account_meta_t *
init_data_meta( uchar * buf, ulong buf_sz ) {
  FD_TEST( buf_sz >= sizeof(fd_account_meta_t) + INIT_DLEN + MAX_PERMITTED_DATA_INCREASE );
  fd_account_meta_t * meta = (fd_account_meta_t *)buf;
  memset( meta, 0, sizeof(fd_account_meta_t) + INIT_DLEN + MAX_PERMITTED_DATA_INCREASE );
  memcpy( meta->owner, &callee_program_pubkey, sizeof(fd_pubkey_t) );
  meta->lamports = LAMPORTS;
  meta->dlen     = (uint)INIT_DLEN;
  return meta;
}

/* Set up the full test environment: bank, accounts, instruction
   context, and VM.  All accounts are registered in accdb. */

static void
test_env_setup( fd_svm_mini_t * mini ) {

  fd_runtime_t * runtime = mini->runtime;
  fd_vm_t *      vm      = mini->vm;

  /* Build callee ELF */
  ulong text_buf[8];
  ulong text_sz = build_callee_text( text_buf );
  ulong elf_sz  = fd_svm_elfgen_sz( text_sz, 0UL );
  uchar elf_buf[2048];
  FD_TEST( elf_sz <= sizeof(elf_buf) );
  fd_svm_elfgen( elf_buf, elf_sz, (uchar const *)text_buf, text_sz, NULL, 0UL );

  /* Reset svm_mini to get a fresh bank */
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong bank_idx = fd_svm_mini_reset( mini, params );
  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );

  fd_features_disable_all( &bank->f.features );
  bank->f.features.loosen_cpi_size_restriction = 0UL;

  /* Set up txn_out with 3 accounts: [0]=program [1]=acct1 [2]=acct2 */
  static fd_txn_out_t txn_out[1];
  memset( txn_out, 0, sizeof(fd_txn_out_t) );
  txn_out->accounts.cnt = 3;

  /* Program account */
  static uchar prog_buf[ sizeof(fd_account_meta_t) + 2048 ] __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
  fd_account_meta_t * prog_meta = (fd_account_meta_t *)prog_buf;
  FD_TEST( sizeof(prog_buf) >= sizeof(fd_account_meta_t) + elf_sz );
  memset( prog_meta, 0, sizeof(fd_account_meta_t) + elf_sz );
  memcpy( prog_meta->owner, &fd_solana_bpf_loader_program_id, sizeof(fd_pubkey_t) );
  prog_meta->executable = 1;
  prog_meta->lamports   = LAMPORTS;
  prog_meta->dlen       = (uint)elf_sz;
  memcpy( (uchar *)prog_meta + sizeof(fd_account_meta_t), elf_buf, elf_sz );
  memcpy( &txn_out->accounts.keys[0], &callee_program_pubkey, sizeof(fd_pubkey_t) );
  fd_accdb_rw_init_nodb( &txn_out->accounts.account[0], &callee_program_pubkey, prog_meta, FD_RUNTIME_ACC_SZ_MAX );

  /* Data accounts */
  static uchar acct1_buf[ sizeof(fd_account_meta_t) + MAX_PERMITTED_DATA_INCREASE + 1024 ] __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
  static uchar acct2_buf[ sizeof(fd_account_meta_t) + MAX_PERMITTED_DATA_INCREASE + 1024 ] __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
  fd_account_meta_t * acct1_meta = init_data_meta( acct1_buf, sizeof(acct1_buf) );
  fd_account_meta_t * acct2_meta = init_data_meta( acct2_buf, sizeof(acct2_buf) );

  memcpy( &txn_out->accounts.keys[1], &acct1_pubkey, sizeof(fd_pubkey_t) );
  fd_accdb_rw_init_nodb( &txn_out->accounts.account[1], &acct1_pubkey, acct1_meta, FD_RUNTIME_ACC_SZ_MAX );
  memcpy( &txn_out->accounts.keys[2], &acct2_pubkey, sizeof(fd_pubkey_t) );
  fd_accdb_rw_init_nodb( &txn_out->accounts.account[2], &acct2_pubkey, acct2_meta, FD_RUNTIME_ACC_SZ_MAX );

  for( uint i=0; i<3; i++ ) fd_svm_mini_put_account_rooted( mini, txn_out->accounts.account[i].ro );

  /* Instruction info */
  fd_instr_info_t * instr = &runtime->instr.trace[0];
  memset( instr, 0, sizeof(fd_instr_info_t) );
  instr->program_id    = 0;
  instr->acct_cnt      = 3;
  instr->accounts[0]   = fd_instruction_account_init( 0, 0, 0, 0, 0 );
  instr->accounts[1]   = fd_instruction_account_init( 1, 1, 1, 1, 1 );
  instr->accounts[2]   = fd_instruction_account_init( 2, 2, 2, 1, 0 );
  instr->starting_lamports_h = 0UL;
  instr->starting_lamports_l = LAMPORTS * 3UL;

  /* Instruction execution context */
  fd_exec_instr_ctx_t * instr_ctx = &runtime->instr.stack[0];
  memset( instr_ctx, 0, sizeof(fd_exec_instr_ctx_t) );
  instr_ctx->instr   = instr;
  instr_ctx->runtime = runtime;
  instr_ctx->txn_out = txn_out;
  instr_ctx->bank    = bank;

  runtime->instr.stack_sz     = 1;
  runtime->instr.trace_length = 1UL;
  runtime->instr.current_idx  = 0;

  /* VM acc_region_metas */
  static fd_vm_acc_region_meta_t arm[3];
  memset( arm, 0, sizeof(arm) );
  arm[0].meta = prog_meta;
  arm[1].meta = acct1_meta;  arm[1].original_data_len = INIT_DLEN;
  arm[2].meta = acct2_meta;  arm[2].original_data_len = INIT_DLEN;

  /* Initialize VM */
  static uchar rodata[100];
  memset( rodata, 0, sizeof(rodata) );
  FD_TEST( fd_vm_init(
    vm, instr_ctx,
    FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
    rodata, sizeof(rodata),
    NULL, 0UL, 0UL, 0UL, 0UL, NULL,
    TEST_VM_DEFAULT_SBPF_VERSION,
    NULL, NULL, mini->sha256, NULL, 0U,
    arm, 0,
    FD_FEATURE_ACTIVE_BANK( bank, account_data_direct_mapping ),
    FD_FEATURE_ACTIVE_BANK( bank, syscall_parameter_address_restrictions ),
    FD_FEATURE_ACTIVE_BANK( bank, virtual_address_space_adjustments ),
    0, 0UL
  ) );

  /* Test writes directly to vm->heap, bypassing VM address translation.
     Mark all pages as initialized so lazy zeroing doesn't clobber them. */
  fd_vm_mark_all_pages_initialized( vm );
}

static void
setup_input_region( fd_vm_t * vm ) {
  static uchar                buf[ 65536 ] __attribute__((aligned(16)));
  static fd_vm_input_region_t regions[1];

  memset( buf, 0, sizeof(buf) );
  *(ulong *)(buf + ACCT_DLEN_OFF) = INIT_DLEN;

  regions[0] = (fd_vm_input_region_t) {
    .haddr                  = (ulong)buf,
    .region_sz              = (uint)sizeof(buf),
    .address_space_reserved = sizeof(buf),
    .is_writable            = 1,
  };

  vm->input_mem_regions     = regions;
  vm->input_mem_regions_cnt = 1;
  vm->region_haddr[4]       = (ulong)buf;
  vm->region_ld_sz[4]       = (uint)sizeof(buf);
  vm->region_st_sz[4]       = (uint)sizeof(buf);
}

/* Rust ABI: two account infos sharing the same data_box_addr.
   This causes ref_to_len_in_vm to be shared between both accounts. */

#define HEAP_VA(off) (FD_VM_MEM_MAP_HEAP_REGION_START + (off))

static void
setup_rust_cpi_memory( fd_vm_t * vm,
                       ulong *   out_instr_va,
                       ulong *   out_acct_infos_va,
                       ulong *   out_num_infos ) {
  ulong h = 0UL;

  fd_vm_rust_instruction_t * instr = (fd_vm_rust_instruction_t *)&vm->heap[h];
  *out_instr_va = HEAP_VA( h );
  h += sizeof(fd_vm_rust_instruction_t);

  ulong acct_metas_off = h;
  fd_vm_rust_account_meta_t * meta0 = (fd_vm_rust_account_meta_t *)&vm->heap[h];
  h += sizeof(fd_vm_rust_account_meta_t);
  fd_vm_rust_account_meta_t * meta1 = (fd_vm_rust_account_meta_t *)&vm->heap[h];
  h += sizeof(fd_vm_rust_account_meta_t);

  memcpy( meta0->pubkey, acct1_pubkey.uc, 32 );  meta0->is_signer = 1;  meta0->is_writable = 1;
  memcpy( meta1->pubkey, acct2_pubkey.uc, 32 );  meta1->is_signer = 0;  meta1->is_writable = 1;

  h = fd_ulong_align_up( h, 8UL );
  ulong pubkey1_off = h; memcpy( &vm->heap[h], acct1_pubkey.uc, 32 ); h += 32;
  ulong pubkey2_off = h; memcpy( &vm->heap[h], acct2_pubkey.uc, 32 ); h += 32;

  h = fd_ulong_align_up( h, 8UL );
  ulong lb1_off = h;
  *(fd_vm_rc_refcell_ref_t *)&vm->heap[h] = (fd_vm_rc_refcell_ref_t){ .strong=1 };
  h += sizeof(fd_vm_rc_refcell_ref_t);
  ulong lb2_off = h;
  *(fd_vm_rc_refcell_ref_t *)&vm->heap[h] = (fd_vm_rc_refcell_ref_t){ .strong=1 };
  h += sizeof(fd_vm_rc_refcell_ref_t);

  /* Single shared data box -- both account infos point here */
  h = fd_ulong_align_up( h, 8UL );
  ulong data_box_off = h;
  *(fd_vm_rc_refcell_vec_t *)&vm->heap[h] = (fd_vm_rc_refcell_vec_t){
    .strong = 1,
    .addr   = FD_VM_MEM_MAP_INPUT_REGION_START + ACCT_META_SZ,
    .len    = INIT_DLEN,
  };
  h += sizeof(fd_vm_rc_refcell_vec_t);

  h = fd_ulong_align_up( h, 8UL );
  ulong lv1_off = h; *(ulong *)&vm->heap[h] = LAMPORTS; h += 8;
  ulong lv2_off = h; *(ulong *)&vm->heap[h] = LAMPORTS; h += 8;

  ((fd_vm_rc_refcell_ref_t *)&vm->heap[lb1_off])->addr = HEAP_VA( lv1_off );
  ((fd_vm_rc_refcell_ref_t *)&vm->heap[lb2_off])->addr = HEAP_VA( lv2_off );

  h = fd_ulong_align_up( h, 8UL );
  ulong owner_off = h;
  memcpy( &vm->heap[h], callee_program_pubkey.uc, 32 ); h += 32;

  h = fd_ulong_align_up( h, 8UL );
  *out_acct_infos_va = HEAP_VA( h );
  *out_num_infos = 2UL;
  ulong db_va = HEAP_VA( data_box_off );

  fd_vm_rust_account_info_t * info0 = (fd_vm_rust_account_info_t *)&vm->heap[h];
  h += sizeof(fd_vm_rust_account_info_t);
  fd_vm_rust_account_info_t * info1 = (fd_vm_rust_account_info_t *)&vm->heap[h];
  h += sizeof(fd_vm_rust_account_info_t);

  *info0 = (fd_vm_rust_account_info_t){
    .pubkey_addr = HEAP_VA( pubkey1_off ), .lamports_box_addr = HEAP_VA( lb1_off ),
    .data_box_addr = db_va, .owner_addr = HEAP_VA( owner_off ),
    .is_signer = 1, .is_writable = 1,
  };
  *info1 = (fd_vm_rust_account_info_t){
    .pubkey_addr = HEAP_VA( pubkey2_off ), .lamports_box_addr = HEAP_VA( lb2_off ),
    .data_box_addr = db_va, .owner_addr = HEAP_VA( owner_off ),
    .is_signer = 0, .is_writable = 1,
  };

  instr->accounts = (fd_vm_rust_vec_t){ .addr = HEAP_VA( acct_metas_off ), .cap = 2, .len = 2 };
  instr->data     = (fd_vm_rust_vec_t){0};
  memcpy( instr->pubkey, callee_program_pubkey.uc, 32 );

  setup_input_region( vm );
}

/* C ABI: two account infos sharing the same data_addr.
   C ABI has separate data_sz fields so the syscall should succeed. */

static void
setup_c_cpi_memory( fd_vm_t * vm,
                    ulong *   out_instr_va,
                    ulong *   out_acct_infos_va,
                    ulong *   out_num_infos ) {
  ulong h = 0UL;

  fd_vm_c_instruction_t * instr = (fd_vm_c_instruction_t *)&vm->heap[h];
  *out_instr_va = HEAP_VA( h );
  h += sizeof(fd_vm_c_instruction_t);

  h = fd_ulong_align_up( h, 8UL );
  ulong metas_off = h;
  fd_vm_c_account_meta_t * meta0 = (fd_vm_c_account_meta_t *)&vm->heap[h]; h += sizeof(*meta0);
  fd_vm_c_account_meta_t * meta1 = (fd_vm_c_account_meta_t *)&vm->heap[h]; h += sizeof(*meta1);

  h = fd_ulong_align_up( h, 8UL );
  ulong prog_off = h; memcpy( &vm->heap[h], callee_program_pubkey.uc, 32 ); h += 32;
  ulong pk1_off  = h; memcpy( &vm->heap[h], acct1_pubkey.uc, 32 );          h += 32;
  ulong pk2_off  = h; memcpy( &vm->heap[h], acct2_pubkey.uc, 32 );          h += 32;

  h = fd_ulong_align_up( h, 8UL );
  ulong lam1_off = h; *(ulong *)&vm->heap[h] = LAMPORTS; h += 8;
  ulong lam2_off = h; *(ulong *)&vm->heap[h] = LAMPORTS; h += 8;

  h = fd_ulong_align_up( h, 8UL );
  ulong owner_off = h;
  memcpy( &vm->heap[h], callee_program_pubkey.uc, 32 ); h += 32;

  meta0->pubkey_addr = HEAP_VA( pk1_off ); meta0->is_signer = 1; meta0->is_writable = 1;
  meta1->pubkey_addr = HEAP_VA( pk2_off ); meta1->is_signer = 0; meta1->is_writable = 1;

  h = fd_ulong_align_up( h, 8UL );
  *out_acct_infos_va = HEAP_VA( h );
  *out_num_infos = 2UL;
  ulong data_va = FD_VM_MEM_MAP_INPUT_REGION_START + ACCT_META_SZ;

  fd_vm_c_account_info_t * info0 = (fd_vm_c_account_info_t *)&vm->heap[h]; h += sizeof(*info0);
  fd_vm_c_account_info_t * info1 = (fd_vm_c_account_info_t *)&vm->heap[h]; h += sizeof(*info1);

  *info0 = (fd_vm_c_account_info_t){
    .pubkey_addr = HEAP_VA( pk1_off ), .lamports_addr = HEAP_VA( lam1_off ),
    .data_sz = INIT_DLEN, .data_addr = data_va, .owner_addr = HEAP_VA( owner_off ),
    .is_signer = 1, .is_writable = 1,
  };
  *info1 = (fd_vm_c_account_info_t){
    .pubkey_addr = HEAP_VA( pk2_off ), .lamports_addr = HEAP_VA( lam2_off ),
    .data_sz = INIT_DLEN, .data_addr = data_va, .owner_addr = HEAP_VA( owner_off ),
    .is_signer = 0, .is_writable = 1,
  };

  instr->program_id_addr = HEAP_VA( prog_off );
  instr->accounts_addr   = HEAP_VA( metas_off );
  instr->accounts_len    = 2;

  setup_input_region( vm );
}

/* Test runner */

typedef void (* cpi_setup_fn_t  )( fd_vm_t *, ulong *, ulong *, ulong * );
typedef int  (* cpi_syscall_fn_t)( void *, ulong, ulong, ulong, ulong, ulong, ulong * );

static void
run_cpi_test( fd_svm_mini_t *   mini,
              char const *      name,
              cpi_setup_fn_t    setup_fn,
              cpi_syscall_fn_t  syscall_fn,
              int               expected_err ) {
  FD_LOG_INFO(( "Running %s", name ));
  test_env_setup( mini );

  ulong instr_va, acct_infos_va, num_infos;
  setup_fn( mini->vm, &instr_va, &acct_infos_va, &num_infos );

  ulong ret = 0UL;
  int err = syscall_fn( mini->vm, instr_va, acct_infos_va, num_infos, 0UL, 0UL, &ret );
  FD_TEST( err == expected_err );
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1]; fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  run_cpi_test( mini, "rust_abi_shared_data_box_addr",
                setup_rust_cpi_memory, fd_vm_syscall_cpi_rust,
                FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL );

  run_cpi_test( mini, "c_abi_shared_data_addr",
                setup_c_cpi_memory, fd_vm_syscall_cpi_c,
                FD_VM_SUCCESS );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
