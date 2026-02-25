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
#include "../../runtime/fd_runtime.h"
#include "../../runtime/fd_bank.h"
#include "../../runtime/fd_system_ids.h"
#include "../../runtime/fd_acc_pool.h"
#include "../../runtime/program/fd_builtin_programs.h"
#include "../../runtime/sysvar/fd_sysvar_clock.h"
#include "../../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../runtime/sysvar/fd_sysvar_rent.h"
#include "../../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../../accdb/fd_accdb_admin_v1.h"
#include "../../accdb/fd_accdb_impl_v1.h"
#include "../../progcache/fd_progcache_admin.h"
#include "../../progcache/fd_progcache_user.h"
#include "../../log_collector/fd_log_collector.h"
#include "../../../ballet/elf/fd_elf64.h"
#include "../../../funk/fd_funk_rec.h"
#include "../../../funk/fd_funk_val.h"

#define TEST_WKSP_TAG 1234UL

#define DATA_PREFIX_SZ 88UL

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

static fd_pubkey_t const fee_payer_pubkey = {{
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
}};

/* sBPF instruction encoding */

#define SBPF_OP_MOV64_IMM 0xB7
#define SBPF_OP_STXDW     0x7B
#define SBPF_OP_EXIT      0x95

static inline void
sbpf_encode( uchar * out, uchar opcode, uchar dst, uchar src, short off, int imm ) {
  out[0] = opcode;
  out[1] = (uchar)((src << 4) | (dst & 0x0F));
  memcpy( out + 2, &off, 2 );
  memcpy( out + 4, &imm, 4 );
}

/* Per-account size in aligned serialization:
   88 bytes metadata + aligned data + 10240 realloc + 8 rent_epoch */
static ulong
compute_acct_serialized_size( ulong init_dlen ) {
  return 88UL + fd_ulong_align_up( init_dlen, 8UL ) + 10240UL + 8UL;
}

static ulong
build_sbpf_instructions( uchar * text_buf,
                         ulong   target_len,
                         ulong   init_dlen,
                         ulong   num_accts ) {
  ulong acct_size = compute_acct_serialized_size( init_dlen );
  ulong ic = 0UL;

  /* data_len offset for account 1: 8 (header) + 80 (metadata prefix) */
  ulong acct1_dlen_off = 88UL;

  sbpf_encode( text_buf + ic*8UL, SBPF_OP_MOV64_IMM, 2, 0, 0, (int)(uint)target_len );
  ic++;

  FD_TEST( acct1_dlen_off <= SHRT_MAX );
  sbpf_encode( text_buf + ic*8UL, SBPF_OP_STXDW, 1, 2, (short)acct1_dlen_off, 0 );
  ic++;

  if( num_accts >= 2UL ) {
    ulong acct2_dlen_off = 8UL + acct_size + 80UL;
    FD_TEST( acct2_dlen_off <= SHRT_MAX );
    sbpf_encode( text_buf + ic*8UL, SBPF_OP_STXDW, 1, 2, (short)acct2_dlen_off, 0 );
    ic++;
  }

  sbpf_encode( text_buf + ic*8UL, SBPF_OP_MOV64_IMM, 0, 0, 0, 0 );
  ic++;
  sbpf_encode( text_buf + ic*8UL, SBPF_OP_EXIT, 0, 0, 0, 0 );
  ic++;

  return ic;
}

/* Build a minimal ELF64 for SBPF V0 containing the given .text.
   Returns total ELF size. */
static ulong
build_elf( uchar * buf,
           ulong   buf_sz,
           uchar * text_data,
           ulong   text_sz ) {
  static const char shstrtab[] = "\0.text\0.shstrtab\0";
  ulong shstrtab_sz = sizeof(shstrtab);

  ulong ehdr_sz = sizeof(fd_elf64_ehdr);
  ulong phdr_sz = sizeof(fd_elf64_phdr);
  ulong shdr_sz = sizeof(fd_elf64_shdr);

  ulong phdr_file_off     = ehdr_sz;
  ulong text_file_off     = fd_ulong_align_up( phdr_file_off + phdr_sz, 8UL );
  ulong shstrtab_file_off = text_file_off + text_sz;
  ulong shdr_file_off     = fd_ulong_align_up( shstrtab_file_off + shstrtab_sz, 8UL );
  ulong total_sz          = shdr_file_off + 3UL * shdr_sz;

  FD_TEST( total_sz <= buf_sz );
  memset( buf, 0, total_sz );

  fd_elf64_ehdr * ehdr = (fd_elf64_ehdr *)buf;
  ehdr->e_ident[0] = 0x7F;
  ehdr->e_ident[1] = 'E';
  ehdr->e_ident[2] = 'L';
  ehdr->e_ident[3] = 'F';
  ehdr->e_ident[4] = FD_ELF_CLASS_64;
  ehdr->e_ident[5] = FD_ELF_DATA_LE;
  ehdr->e_ident[6] = 1;
  ehdr->e_ident[7] = FD_ELF_OSABI_NONE;
  ehdr->e_type      = FD_ELF_ET_DYN;
  ehdr->e_machine   = FD_ELF_EM_BPF;
  ehdr->e_version   = 1;
  ehdr->e_entry     = text_file_off;
  ehdr->e_phoff     = phdr_file_off;
  ehdr->e_shoff     = shdr_file_off;
  ehdr->e_flags     = 0;
  ehdr->e_ehsize    = (ushort)ehdr_sz;
  ehdr->e_phentsize = (ushort)phdr_sz;
  ehdr->e_phnum     = 1;
  ehdr->e_shentsize = (ushort)shdr_sz;
  ehdr->e_shnum     = 3;
  ehdr->e_shstrndx  = 2;

  fd_elf64_phdr * phdr = (fd_elf64_phdr *)(buf + phdr_file_off);
  phdr->p_type   = FD_ELF_PT_LOAD;
  phdr->p_flags  = 5;
  phdr->p_offset = text_file_off;
  phdr->p_vaddr  = text_file_off;
  phdr->p_paddr  = text_file_off;
  phdr->p_filesz = text_sz;
  phdr->p_memsz  = text_sz;
  phdr->p_align  = 8;

  /* Section 1: .text (sh_addr must equal sh_offset for the loader) */
  fd_elf64_shdr * shdr_text = (fd_elf64_shdr *)(buf + shdr_file_off + shdr_sz);
  shdr_text->sh_name      = 1;
  shdr_text->sh_type      = FD_ELF_SHT_PROGBITS;
  shdr_text->sh_flags     = 0x6;
  shdr_text->sh_addr      = text_file_off;
  shdr_text->sh_offset    = text_file_off;
  shdr_text->sh_size      = text_sz;
  shdr_text->sh_addralign = 8;

  /* Section 2: .shstrtab */
  fd_elf64_shdr * shdr_strtab = (fd_elf64_shdr *)(buf + shdr_file_off + 2UL * shdr_sz);
  shdr_strtab->sh_name      = 7;
  shdr_strtab->sh_type      = FD_ELF_SHT_STRTAB;
  shdr_strtab->sh_offset    = shstrtab_file_off;
  shdr_strtab->sh_size      = shstrtab_sz;
  shdr_strtab->sh_addralign = 1;

  memcpy( buf + text_file_off, text_data, text_sz );
  memcpy( buf + shstrtab_file_off, shstrtab, shstrtab_sz );

  return total_sz;
}

struct test_env {
  fd_wksp_t *          wksp;
  void *               funk_mem;
  void *               funk_locks;
  fd_accdb_admin_t     accdb_admin[1];
  fd_accdb_user_t      accdb[1];
  void *               pcache_mem;
  void *               pcache_locks;
  fd_progcache_admin_t progcache_admin[1];
  fd_progcache_t       progcache[1];
  uchar *              progcache_scratch;
  fd_banks_t           banks[1];
  fd_bank_t            bank[1];
  void *               acc_pool_mem;
  fd_acc_pool_t *      acc_pool;
  fd_runtime_t *       runtime;
  fd_funk_txn_xid_t    xid;
  fd_log_collector_t   log_collector[1];
  fd_sha256_t          sha[1];
  fd_vm_t              vm[1];
  fd_exec_instr_ctx_t  instr_ctx[1];
  fd_txn_out_t         txn_out[1];
  fd_instr_info_t      instr[1];
  uchar                rodata[100];
  fd_account_meta_t *  prog_meta;
  fd_account_meta_t *  acct1_meta;
  fd_account_meta_t *  acct2_meta;
  fd_vm_acc_region_meta_t acc_region_metas[3];
};
typedef struct test_env test_env_t;

static void
init_sysvars( test_env_t * env ) {
  fd_rent_t rent = { .lamports_per_uint8_year = 3480UL, .exemption_threshold = 2.0, .burn_percent = 50 };
  fd_bank_rent_set( env->bank, rent );
  fd_sysvar_rent_write( env->bank, env->accdb, &env->xid, NULL, &rent );

  fd_epoch_schedule_t epoch_schedule = {
    .slots_per_epoch             = 432000UL,
    .leader_schedule_slot_offset = 432000UL,
    .warmup                      = 0,
    .first_normal_epoch          = 0UL,
    .first_normal_slot           = 0UL
  };
  fd_bank_epoch_schedule_set( env->bank, epoch_schedule );
  fd_sysvar_epoch_schedule_write( env->bank, env->accdb, &env->xid, NULL, &epoch_schedule );

  fd_sysvar_stake_history_init( env->bank, env->accdb, &env->xid, NULL );
  fd_sysvar_clock_init( env->bank, env->accdb, &env->xid, NULL );
}

static void
init_fee_payer( test_env_t * env ) {
  fd_funk_t * funk = fd_accdb_user_v1_funk( env->accdb );
  fd_funk_rec_key_t rec_key = FD_LOAD( fd_funk_rec_key_t, fee_payer_pubkey.uc );
  fd_funk_rec_prepare_t prepare[1];
  fd_funk_rec_t * rec = fd_funk_rec_prepare( funk, &env->xid, &rec_key, prepare, NULL );
  FD_TEST( rec );

  uchar * rec_data = fd_funk_val_truncate( rec, fd_funk_alloc( funk ), fd_funk_wksp( funk ), 0UL, sizeof(fd_account_meta_t), NULL );
  FD_TEST( rec_data );

  fd_account_meta_t * meta = (fd_account_meta_t *)rec_data;
  fd_account_meta_init( meta );
  meta->lamports = 1000000000UL;

  fd_funk_rec_publish( funk, prepare );
}

static void
create_account_in_accdb( test_env_t *        env,
                         fd_pubkey_t const * pubkey,
                         fd_pubkey_t const * owner,
                         ulong               lamports,
                         uchar const *       data,
                         ulong               dlen,
                         uchar               executable ) {
  fd_funk_t * funk = fd_accdb_user_v1_funk( env->accdb );
  fd_funk_rec_key_t rec_key = FD_LOAD( fd_funk_rec_key_t, pubkey->uc );
  fd_funk_rec_prepare_t prepare[1];
  fd_funk_rec_t * rec = fd_funk_rec_prepare( funk, &env->xid, &rec_key, prepare, NULL );
  FD_TEST( rec );

  ulong total_sz = sizeof(fd_account_meta_t) + dlen;
  uchar * rec_data = fd_funk_val_truncate( rec, fd_funk_alloc( funk ), fd_funk_wksp( funk ), 0UL, total_sz, NULL );
  FD_TEST( rec_data );

  fd_account_meta_t * meta = (fd_account_meta_t *)rec_data;
  fd_account_meta_init( meta );
  meta->lamports   = lamports;
  meta->dlen       = (uint)dlen;
  meta->executable = executable;
  memcpy( meta->owner, owner->uc, sizeof(fd_pubkey_t) );

  if( data ) {
    memcpy( rec_data + sizeof(fd_account_meta_t), data, dlen );
  } else if( dlen > 0UL ) {
    memset( rec_data + sizeof(fd_account_meta_t), 0, dlen );
  }

  fd_funk_rec_publish( funk, prepare );
}

static void
test_env_create( test_env_t * env,
                 fd_wksp_t *  wksp,
                 uchar *      elf_data,
                 ulong        elf_sz,
                 ulong        init_dlen,
                 ulong        num_data_accts ) {
  memset( env, 0, sizeof(test_env_t) );
  env->wksp = wksp;

  ulong funk_seed = 17UL;
  ulong txn_max   = 16UL;
  ulong rec_max   = 1024UL;

  /* Account database */
  env->funk_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_shmem_footprint( txn_max, rec_max ), TEST_WKSP_TAG );
  FD_TEST( env->funk_mem );
  FD_TEST( fd_funk_shmem_new( env->funk_mem, TEST_WKSP_TAG, funk_seed, txn_max, rec_max ) );
  env->funk_locks = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_locks_footprint( txn_max, rec_max ), TEST_WKSP_TAG );
  FD_TEST( env->funk_locks );
  FD_TEST( fd_funk_locks_new( env->funk_locks, txn_max, rec_max ) );
  FD_TEST( fd_accdb_admin_v1_init( env->accdb_admin, env->funk_mem, env->funk_locks ) );
  FD_TEST( fd_accdb_user_v1_init( env->accdb, env->funk_mem, env->funk_locks, txn_max ) );

  /* Program cache */
  env->pcache_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_shmem_footprint( txn_max, rec_max ), TEST_WKSP_TAG );
  FD_TEST( env->pcache_mem );
  FD_TEST( fd_funk_shmem_new( env->pcache_mem, TEST_WKSP_TAG, funk_seed + 1UL, txn_max, rec_max ) );
  env->pcache_locks = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_locks_footprint( txn_max, rec_max ), TEST_WKSP_TAG );
  FD_TEST( env->pcache_locks );
  FD_TEST( fd_funk_locks_new( env->pcache_locks, txn_max, rec_max ) );
  env->progcache_scratch = fd_wksp_alloc_laddr( wksp, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT, TEST_WKSP_TAG );
  FD_TEST( env->progcache_scratch );
  FD_TEST( fd_progcache_join( env->progcache, env->pcache_mem, env->pcache_locks, env->progcache_scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
  FD_TEST( fd_progcache_admin_join( env->progcache_admin, env->pcache_mem, env->pcache_locks ) );

  /* Banks */
  ulong max_total_banks = 1UL;
  ulong max_fork_width  = 1UL;
  fd_banks_data_t * banks_data = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( max_total_banks, max_fork_width ), TEST_WKSP_TAG );
  FD_TEST( banks_data );
  fd_banks_locks_t * banks_locks = fd_wksp_alloc_laddr( wksp, alignof(fd_banks_locks_t), sizeof(fd_banks_locks_t), TEST_WKSP_TAG );
  fd_banks_locks_init( banks_locks );
  FD_TEST( fd_banks_join( env->banks, fd_banks_new( banks_data, max_total_banks, max_fork_width, 0, 8888UL ), banks_locks ) );
  FD_TEST( fd_banks_init_bank( env->bank, env->banks ) );

  /* Account pool */
  ulong acc_pool_cnt = 4UL;
  env->acc_pool_mem = fd_wksp_alloc_laddr( wksp, fd_acc_pool_align(), fd_acc_pool_footprint( acc_pool_cnt ), TEST_WKSP_TAG );
  FD_TEST( env->acc_pool_mem );
  env->acc_pool = fd_acc_pool_join( fd_acc_pool_new( env->acc_pool_mem, acc_pool_cnt ) );
  FD_TEST( env->acc_pool );

  /* Runtime */
  env->runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), TEST_WKSP_TAG );
  FD_TEST( env->runtime );
  memset( env->runtime, 0, sizeof(fd_runtime_t) );

  /* Transaction fork */
  fd_funk_txn_xid_t root[1];
  fd_funk_txn_xid_set_root( root );
  env->xid = (fd_funk_txn_xid_t){ .ul = { 10UL, env->bank->data->idx } };
  fd_accdb_attach_child( env->accdb_admin, root, &env->xid );
  fd_progcache_txn_attach_child( env->progcache_admin, root, &env->xid );

  fd_bank_slot_set( env->bank, 10UL );
  fd_bank_parent_slot_set( env->bank, 9UL );
  fd_bank_epoch_set( env->bank, 0UL );

  env->runtime->accdb        = env->accdb;
  env->runtime->status_cache = NULL;
  env->runtime->progcache    = env->progcache;
  env->runtime->acc_pool     = env->acc_pool;

  fd_log_collector_init( env->log_collector, 0 );
  env->runtime->log.log_collector = env->log_collector;

  /* Features: legacy mode (no direct_mapping, no stricter_abi) */
  fd_features_t * features = fd_bank_features_modify( env->bank );
  fd_features_disable_all( features );
  features->loosen_cpi_size_restriction = 0UL;

  init_sysvars( env );
  fd_builtin_programs_init( env->bank, env->accdb, &env->xid, NULL );
  init_fee_payer( env );

  /* Create accounts in accdb */
  create_account_in_accdb( env, &callee_program_pubkey, &fd_solana_bpf_loader_program_id, 1000000UL, elf_data, elf_sz, 1 );
  create_account_in_accdb( env, &acct1_pubkey, &callee_program_pubkey, 1000000UL, NULL, init_dlen, 0 );
  if( num_data_accts >= 2UL ) {
    create_account_in_accdb( env, &acct2_pubkey, &callee_program_pubkey, 1000000UL, NULL, init_dlen, 0 );
  }

  /* Inject BPF program into progcache */
  {
    ulong inject_sz = sizeof(fd_account_meta_t) + elf_sz;
    uchar * inject_buf = fd_wksp_alloc_laddr( wksp, alignof(fd_account_meta_t), inject_sz, TEST_WKSP_TAG );
    FD_TEST( inject_buf );

    fd_account_meta_t * inject_meta = (fd_account_meta_t *)inject_buf;
    fd_account_meta_init( inject_meta );
    inject_meta->lamports   = 1000000UL;
    inject_meta->dlen       = (uint)elf_sz;
    inject_meta->executable = 1;
    memcpy( inject_meta->owner, fd_solana_bpf_loader_program_id.uc, sizeof(fd_pubkey_t) );
    memcpy( inject_buf + sizeof(fd_account_meta_t), elf_data, elf_sz );

    uchar * scratch = fd_wksp_alloc_laddr( wksp, FD_PROGCACHE_SCRATCH_ALIGN, elf_sz, TEST_WKSP_TAG );
    FD_TEST( scratch );
    fd_progcache_inject_rec( env->progcache_admin,
                             &callee_program_pubkey,
                             inject_meta,
                             features,
                             fd_bank_slot_get( env->bank ),
                             scratch,
                             elf_sz );
    fd_wksp_free_laddr( scratch );
    fd_wksp_free_laddr( inject_buf );
  }

  /* Set up caller VM */
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( env->sha ) );
  FD_TEST( sha );
  fd_vm_t * vm = fd_vm_join( fd_vm_new( env->vm ) );
  FD_TEST( vm );

  test_vm_minimal_exec_instr_ctx( env->instr_ctx, env->runtime, env->bank, env->bank->data, env->banks->locks, env->txn_out );

  features = fd_bank_features_modify( env->bank );
  fd_features_disable_all( features );
  features->loosen_cpi_size_restriction = 0UL;

  /* Transaction accounts:
     [0] callee program  [1] data account 1  [2] data account 2 (optional) */
  ulong total_accts = 1UL + num_data_accts;
  env->txn_out->accounts.cnt = (uint)total_accts;

  memcpy( &env->txn_out->accounts.keys[0], &callee_program_pubkey, sizeof(fd_pubkey_t) );
  env->prog_meta = fd_wksp_alloc_laddr( wksp, alignof(fd_account_meta_t), sizeof(fd_account_meta_t) + elf_sz, TEST_WKSP_TAG );
  FD_TEST( env->prog_meta );
  memset( env->prog_meta, 0, sizeof(fd_account_meta_t) );
  memcpy( env->prog_meta->owner, &fd_solana_bpf_loader_program_id, sizeof(fd_pubkey_t) );
  env->prog_meta->executable = 1;
  env->prog_meta->lamports   = 1000000UL;
  env->prog_meta->dlen       = (uint)elf_sz;
  memcpy( ((uchar *)env->prog_meta) + sizeof(fd_account_meta_t), elf_data, elf_sz );
  env->txn_out->accounts.account[0].meta = env->prog_meta;

  memcpy( &env->txn_out->accounts.keys[1], &acct1_pubkey, sizeof(fd_pubkey_t) );
  env->acct1_meta = fd_wksp_alloc_laddr( wksp, alignof(fd_account_meta_t),
    sizeof(fd_account_meta_t) + init_dlen + MAX_PERMITTED_DATA_INCREASE, TEST_WKSP_TAG );
  FD_TEST( env->acct1_meta );
  memset( env->acct1_meta, 0, sizeof(fd_account_meta_t) + init_dlen + MAX_PERMITTED_DATA_INCREASE );
  memcpy( env->acct1_meta->owner, &callee_program_pubkey, sizeof(fd_pubkey_t) );
  env->acct1_meta->lamports = 1000000UL;
  env->acct1_meta->dlen     = (uint)init_dlen;
  env->txn_out->accounts.account[1].meta = env->acct1_meta;

  if( num_data_accts >= 2UL ) {
    memcpy( &env->txn_out->accounts.keys[2], &acct2_pubkey, sizeof(fd_pubkey_t) );
    env->acct2_meta = fd_wksp_alloc_laddr( wksp, alignof(fd_account_meta_t),
      sizeof(fd_account_meta_t) + init_dlen + MAX_PERMITTED_DATA_INCREASE, TEST_WKSP_TAG );
    FD_TEST( env->acct2_meta );
    memset( env->acct2_meta, 0, sizeof(fd_account_meta_t) + init_dlen + MAX_PERMITTED_DATA_INCREASE );
    memcpy( env->acct2_meta->owner, &callee_program_pubkey, sizeof(fd_pubkey_t) );
    env->acct2_meta->lamports = 1000000UL;
    env->acct2_meta->dlen     = (uint)init_dlen;
    env->txn_out->accounts.account[2].meta = env->acct2_meta;
  }

  env->runtime->accounts.refcnt[0] = 0UL;
  env->runtime->accounts.refcnt[1] = 0UL;
  if( num_data_accts >= 2UL ) env->runtime->accounts.refcnt[2] = 0UL;

  memset( env->instr, 0, sizeof(fd_instr_info_t) );
  env->instr->program_id = 0;
  env->instr->acct_cnt   = (ushort)total_accts;
  env->instr->accounts[0] = fd_instruction_account_init( 0, 0, 0, 0, 0 );
  env->instr->accounts[1] = fd_instruction_account_init( 1, 1, 1, 1, 1 );
  if( num_data_accts >= 2UL ) {
    env->instr->accounts[2] = fd_instruction_account_init( 2, 2, 2, 1, 0 );
  }
  env->instr_ctx->instr = env->instr;

  memset( env->acc_region_metas, 0, sizeof(env->acc_region_metas) );
  env->acc_region_metas[0].region_idx        = 0;
  env->acc_region_metas[0].original_data_len = 0UL;
  env->acc_region_metas[0].meta              = env->prog_meta;
  env->acc_region_metas[1].region_idx        = 0;
  env->acc_region_metas[1].original_data_len = init_dlen;
  env->acc_region_metas[1].meta              = env->acct1_meta;
  if( num_data_accts >= 2UL ) {
    env->acc_region_metas[2].region_idx        = 0;
    env->acc_region_metas[2].original_data_len = init_dlen;
    env->acc_region_metas[2].meta              = env->acct2_meta;
  }

  memset( env->rodata, 0, sizeof(env->rodata) );
  int vm_ok = !!fd_vm_init(
    vm, env->instr_ctx,
    FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
    env->rodata, sizeof(env->rodata),
    NULL, 0UL, 0UL, 0UL, 0UL, NULL,
    TEST_VM_DEFAULT_SBPF_VERSION,
    NULL, NULL, sha, NULL, 0U,
    env->acc_region_metas, 0,
    FD_FEATURE_ACTIVE_BANK( env->bank, account_data_direct_mapping ),
    FD_FEATURE_ACTIVE_BANK( env->bank, stricter_abi_and_runtime_constraints ),
    0, 0UL
  );
  FD_TEST( vm_ok );
}

static void
test_env_destroy( test_env_t * env ) {
  test_vm_clear_txn_ctx_err( env->instr_ctx->txn_out );
  fd_vm_delete( fd_vm_leave( env->vm ) );
  fd_sha256_delete( fd_sha256_leave( env->sha ) );

  fd_wksp_free_laddr( env->prog_meta );
  fd_wksp_free_laddr( env->acct1_meta );
  if( env->acct2_meta ) fd_wksp_free_laddr( env->acct2_meta );

  fd_accdb_cancel( env->accdb_admin, &env->xid );
  fd_progcache_txn_cancel( env->progcache_admin, &env->xid );

  fd_wksp_free_laddr( env->runtime );
  fd_wksp_free_laddr( env->acc_pool_mem );
  fd_wksp_free_laddr( env->banks->data );
  fd_wksp_free_laddr( env->banks->locks );

  fd_progcache_leave( env->progcache, NULL, NULL );
  void * pcache_funk = NULL;
  fd_progcache_admin_leave( env->progcache_admin, &pcache_funk, NULL );
  fd_wksp_free_laddr( fd_funk_delete( pcache_funk ) );
  fd_wksp_free_laddr( env->pcache_locks );
  fd_wksp_free_laddr( env->progcache_scratch );

  void * accdb_shfunk = fd_accdb_admin_v1_funk( env->accdb_admin )->shmem;
  fd_accdb_admin_fini( env->accdb_admin );
  fd_accdb_user_fini( env->accdb );
  fd_wksp_free_laddr( fd_funk_delete( accdb_shfunk ) );
  fd_wksp_free_laddr( env->funk_locks );
}

static void
setup_input_region( fd_vm_t *               vm,
                    uchar *                 buf,
                    ulong                   buf_sz,
                    fd_vm_input_region_t *  regions,
                    ulong                   init_dlen ) {
  memset( buf, 0, buf_sz );
  *(ulong *)(buf + DATA_PREFIX_SZ - sizeof(ulong)) = init_dlen;

  regions[0].vaddr_offset           = 0;
  regions[0].haddr                  = (ulong)buf;
  regions[0].region_sz              = (uint)buf_sz;
  regions[0].address_space_reserved = buf_sz;
  regions[0].is_writable            = 1;
  regions[0].acc_region_meta_idx    = 0;

  vm->input_mem_regions     = regions;
  vm->input_mem_regions_cnt = 1;
  vm->region_haddr[4]       = (ulong)buf;
  vm->region_ld_sz[4]       = (uint)buf_sz;
  vm->region_st_sz[4]       = (uint)buf_sz;
}

/* Rust ABI: two account infos sharing the same data_box_addr.
   This causes ref_to_len_in_vm to be shared between both accounts. */
static void
setup_rust_cpi_memory_shared_data_box( fd_vm_t * vm,
                                       ulong     init_dlen,
                                       ulong *   out_instr_va,
                                       ulong *   out_acct_infos_va,
                                       ulong *   out_num_infos ) {
  ulong heap_off = 0UL;

  fd_vm_rust_instruction_t * instr = (fd_vm_rust_instruction_t *)&vm->heap[heap_off];
  *out_instr_va = FD_VM_MEM_MAP_HEAP_REGION_START + heap_off;
  heap_off += sizeof(fd_vm_rust_instruction_t);

  ulong acct_metas_off = heap_off;
  fd_vm_rust_account_meta_t * meta0 = (fd_vm_rust_account_meta_t *)&vm->heap[heap_off];
  heap_off += sizeof(fd_vm_rust_account_meta_t);
  fd_vm_rust_account_meta_t * meta1 = (fd_vm_rust_account_meta_t *)&vm->heap[heap_off];
  heap_off += sizeof(fd_vm_rust_account_meta_t);

  memcpy( meta0->pubkey, acct1_pubkey.uc, 32 );
  meta0->is_signer   = 1;
  meta0->is_writable = 1;
  memcpy( meta1->pubkey, acct2_pubkey.uc, 32 );
  meta1->is_signer   = 0;
  meta1->is_writable = 1;

  heap_off = fd_ulong_align_up( heap_off, 8UL );
  ulong pubkey1_off = heap_off;
  memcpy( &vm->heap[heap_off], acct1_pubkey.uc, 32 ); heap_off += 32;
  ulong pubkey2_off = heap_off;
  memcpy( &vm->heap[heap_off], acct2_pubkey.uc, 32 ); heap_off += 32;

  heap_off = fd_ulong_align_up( heap_off, 8UL );
  ulong lamports_box1_off = heap_off;
  {
    fd_vm_rc_refcell_ref_t * box = (fd_vm_rc_refcell_ref_t *)&vm->heap[heap_off];
    box->strong = 1; box->weak = 0; box->borrow = 0;
    heap_off += sizeof(fd_vm_rc_refcell_ref_t);
  }
  ulong lamports_box2_off = heap_off;
  {
    fd_vm_rc_refcell_ref_t * box = (fd_vm_rc_refcell_ref_t *)&vm->heap[heap_off];
    box->strong = 1; box->weak = 0; box->borrow = 0;
    heap_off += sizeof(fd_vm_rc_refcell_ref_t);
  }

  /* Single shared data box -- both account infos point here */
  heap_off = fd_ulong_align_up( heap_off, 8UL );
  ulong shared_data_box_off = heap_off;
  {
    fd_vm_rc_refcell_vec_t * box = (fd_vm_rc_refcell_vec_t *)&vm->heap[heap_off];
    box->strong = 1; box->weak = 0; box->borrow = 0;
    heap_off += sizeof(fd_vm_rc_refcell_vec_t);
  }

  heap_off = fd_ulong_align_up( heap_off, 8UL );
  ulong lamports_val1_off = heap_off;
  *(ulong *)&vm->heap[heap_off] = 1000000UL;
  heap_off += sizeof(ulong);
  ulong lamports_val2_off = heap_off;
  *(ulong *)&vm->heap[heap_off] = 1000000UL;
  heap_off += sizeof(ulong);

  ((fd_vm_rc_refcell_ref_t *)&vm->heap[lamports_box1_off])->addr =
    FD_VM_MEM_MAP_HEAP_REGION_START + lamports_val1_off;
  ((fd_vm_rc_refcell_ref_t *)&vm->heap[lamports_box2_off])->addr =
    FD_VM_MEM_MAP_HEAP_REGION_START + lamports_val2_off;

  heap_off = fd_ulong_align_up( heap_off, 8UL );
  ulong owner_off = heap_off;
  memcpy( &vm->heap[heap_off], callee_program_pubkey.uc, 32 );
  heap_off += 32;

  ulong vm_data_vaddr = FD_VM_MEM_MAP_INPUT_REGION_START + DATA_PREFIX_SZ;
  {
    fd_vm_rc_refcell_vec_t * box = (fd_vm_rc_refcell_vec_t *)&vm->heap[shared_data_box_off];
    box->addr = vm_data_vaddr;
    box->len  = init_dlen;
  }

  heap_off = fd_ulong_align_up( heap_off, 8UL );
  ulong acct_infos_off = heap_off;
  *out_acct_infos_va = FD_VM_MEM_MAP_HEAP_REGION_START + acct_infos_off;
  *out_num_infos = 2UL;

  fd_vm_rust_account_info_t * info0 = (fd_vm_rust_account_info_t *)&vm->heap[heap_off];
  heap_off += sizeof(fd_vm_rust_account_info_t);
  fd_vm_rust_account_info_t * info1 = (fd_vm_rust_account_info_t *)&vm->heap[heap_off];
  heap_off += sizeof(fd_vm_rust_account_info_t);

  ulong shared_data_box_va = FD_VM_MEM_MAP_HEAP_REGION_START + shared_data_box_off;

  info0->pubkey_addr       = FD_VM_MEM_MAP_HEAP_REGION_START + pubkey1_off;
  info0->lamports_box_addr = FD_VM_MEM_MAP_HEAP_REGION_START + lamports_box1_off;
  info0->data_box_addr     = shared_data_box_va;
  info0->owner_addr        = FD_VM_MEM_MAP_HEAP_REGION_START + owner_off;
  info0->rent_epoch        = 0;
  info0->is_signer         = 1;
  info0->is_writable       = 1;
  info0->executable        = 0;
  memset( info0->_padding_0, 0, sizeof(info0->_padding_0) );

  info1->pubkey_addr       = FD_VM_MEM_MAP_HEAP_REGION_START + pubkey2_off;
  info1->lamports_box_addr = FD_VM_MEM_MAP_HEAP_REGION_START + lamports_box2_off;
  info1->data_box_addr     = shared_data_box_va; /* same as info0 */
  info1->owner_addr        = FD_VM_MEM_MAP_HEAP_REGION_START + owner_off;
  info1->rent_epoch        = 0;
  info1->is_signer         = 0;
  info1->is_writable       = 1;
  info1->executable        = 0;
  memset( info1->_padding_0, 0, sizeof(info1->_padding_0) );

  instr->accounts.addr = FD_VM_MEM_MAP_HEAP_REGION_START + acct_metas_off;
  instr->accounts.cap  = 2;
  instr->accounts.len  = 2;
  instr->data.addr     = 0;
  instr->data.cap      = 0;
  instr->data.len      = 0;
  memcpy( instr->pubkey, callee_program_pubkey.uc, 32 );

  static uchar                input_buf[ 65536 ] __attribute__((aligned(16)));
  static fd_vm_input_region_t input_regions[1];
  setup_input_region( vm, input_buf, sizeof(input_buf), input_regions, init_dlen );
}

/* C ABI: two account infos sharing the same data_addr.
   Unlike Rust, C ABI derives ref_to_len_in_vm from each struct's own
   data_sz field, so sharing data_addr does not cause the bug. */

static void
setup_c_cpi_memory_shared_data( fd_vm_t * vm,
                                ulong     init_dlen,
                                ulong *   out_instr_va,
                                ulong *   out_acct_infos_va,
                                ulong *   out_num_infos ) {
  ulong heap_off = 0UL;

  fd_vm_c_instruction_t * instr = (fd_vm_c_instruction_t *)&vm->heap[heap_off];
  *out_instr_va = FD_VM_MEM_MAP_HEAP_REGION_START + heap_off;
  heap_off += sizeof(fd_vm_c_instruction_t);

  heap_off = fd_ulong_align_up( heap_off, 8UL );
  ulong acct_metas_off = heap_off;
  fd_vm_c_account_meta_t * meta0 = (fd_vm_c_account_meta_t *)&vm->heap[heap_off];
  heap_off += sizeof(fd_vm_c_account_meta_t);
  fd_vm_c_account_meta_t * meta1 = (fd_vm_c_account_meta_t *)&vm->heap[heap_off];
  heap_off += sizeof(fd_vm_c_account_meta_t);

  heap_off = fd_ulong_align_up( heap_off, 8UL );
  ulong prog_id_off = heap_off;
  memcpy( &vm->heap[heap_off], callee_program_pubkey.uc, 32 ); heap_off += 32;
  ulong pubkey1_off = heap_off;
  memcpy( &vm->heap[heap_off], acct1_pubkey.uc, 32 ); heap_off += 32;
  ulong pubkey2_off = heap_off;
  memcpy( &vm->heap[heap_off], acct2_pubkey.uc, 32 ); heap_off += 32;

  heap_off = fd_ulong_align_up( heap_off, 8UL );
  ulong lamports1_off = heap_off;
  *(ulong *)&vm->heap[heap_off] = 1000000UL; heap_off += sizeof(ulong);
  ulong lamports2_off = heap_off;
  *(ulong *)&vm->heap[heap_off] = 1000000UL; heap_off += sizeof(ulong);

  heap_off = fd_ulong_align_up( heap_off, 8UL );
  ulong owner_off = heap_off;
  memcpy( &vm->heap[heap_off], callee_program_pubkey.uc, 32 ); heap_off += 32;

  meta0->pubkey_addr = FD_VM_MEM_MAP_HEAP_REGION_START + pubkey1_off;
  meta0->is_signer   = 1;
  meta0->is_writable = 1;
  meta1->pubkey_addr = FD_VM_MEM_MAP_HEAP_REGION_START + pubkey2_off;
  meta1->is_signer   = 0;
  meta1->is_writable = 1;

  heap_off = fd_ulong_align_up( heap_off, 8UL );
  ulong acct_infos_off = heap_off;
  *out_acct_infos_va = FD_VM_MEM_MAP_HEAP_REGION_START + acct_infos_off;
  *out_num_infos = 2UL;

  fd_vm_c_account_info_t * info0 = (fd_vm_c_account_info_t *)&vm->heap[heap_off];
  heap_off += sizeof(fd_vm_c_account_info_t);
  fd_vm_c_account_info_t * info1 = (fd_vm_c_account_info_t *)&vm->heap[heap_off];
  heap_off += sizeof(fd_vm_c_account_info_t);

  ulong vm_data_vaddr = FD_VM_MEM_MAP_INPUT_REGION_START + DATA_PREFIX_SZ;

  info0->pubkey_addr   = FD_VM_MEM_MAP_HEAP_REGION_START + pubkey1_off;
  info0->lamports_addr = FD_VM_MEM_MAP_HEAP_REGION_START + lamports1_off;
  info0->data_sz       = init_dlen;
  info0->data_addr     = vm_data_vaddr;
  info0->owner_addr    = FD_VM_MEM_MAP_HEAP_REGION_START + owner_off;
  info0->rent_epoch    = 0;
  info0->is_signer     = 1;
  info0->is_writable   = 1;
  info0->executable    = 0;

  info1->pubkey_addr   = FD_VM_MEM_MAP_HEAP_REGION_START + pubkey2_off;
  info1->lamports_addr = FD_VM_MEM_MAP_HEAP_REGION_START + lamports2_off;
  info1->data_sz       = init_dlen;
  info1->data_addr     = vm_data_vaddr; /* same as info0 */
  info1->owner_addr    = FD_VM_MEM_MAP_HEAP_REGION_START + owner_off;
  info1->rent_epoch    = 0;
  info1->is_signer     = 0;
  info1->is_writable   = 1;
  info1->executable    = 0;

  instr->program_id_addr = FD_VM_MEM_MAP_HEAP_REGION_START + prog_id_off;
  instr->accounts_addr   = FD_VM_MEM_MAP_HEAP_REGION_START + acct_metas_off;
  instr->accounts_len    = 2;
  instr->data_addr       = 0;
  instr->data_len        = 0;

  static uchar                c_input_buf[ 65536 ] __attribute__((aligned(16)));
  static fd_vm_input_region_t c_input_regions[1];
  setup_input_region( vm, c_input_buf, sizeof(c_input_buf), c_input_regions, init_dlen );
}

/* Test runner */

typedef void (* cpi_setup_fn_t  )( fd_vm_t *, ulong, ulong *, ulong *, ulong * );
typedef int  (* cpi_syscall_fn_t)( void *, ulong, ulong, ulong, ulong, ulong, ulong * );

#define INIT_DLEN    8UL
#define TARGET_LEN   1000UL
#define NUM_ACCTS    2UL

static void
run_cpi_test( fd_wksp_t *       wksp,
              char const *      name,
              cpi_setup_fn_t    setup_fn,
              cpi_syscall_fn_t  syscall_fn,
              int               expected_err ) {
  FD_LOG_NOTICE(( "%s ...", name ));

  uchar text_buf[ 64 ];
  ulong instr_cnt = build_sbpf_instructions( text_buf, TARGET_LEN, INIT_DLEN, NUM_ACCTS );

  uchar elf_buf[ 2048 ];
  ulong elf_sz = build_elf( elf_buf, sizeof(elf_buf), text_buf, instr_cnt * 8UL );
  FD_TEST( elf_sz > 0UL );

  test_env_t env[1];
  test_env_create( env, wksp, elf_buf, elf_sz, INIT_DLEN, NUM_ACCTS );

  ulong instr_va, acct_infos_va, num_infos;
  setup_fn( env->vm, INIT_DLEN, &instr_va, &acct_infos_va, &num_infos );

  ulong ret = 0UL;
  int err = syscall_fn( env->vm, instr_va, acct_infos_va, num_infos, 0UL, 0UL, &ret );

  FD_TEST( err == expected_err );
  FD_LOG_NOTICE(( "%s ... PASS", name ));

  test_env_destroy( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx > fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "normal" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1100000UL );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  FD_TEST( page_sz );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* Rust ABI: two account infos sharing the same data_box_addr */
  run_cpi_test( wksp,
                "rust_abi_shared_data_box_addr",
                setup_rust_cpi_memory_shared_data_box,
                fd_vm_syscall_cpi_rust,
                FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL );

  /* C ABI: two account infos sharing the same data_addr.
     C ABI has separate data_sz fields so the syscall should succeed. */
  run_cpi_test( wksp,
                "c_abi_shared_data_addr",
                setup_c_cpi_memory_shared_data,
                fd_vm_syscall_cpi_c,
                FD_VM_SUCCESS );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
