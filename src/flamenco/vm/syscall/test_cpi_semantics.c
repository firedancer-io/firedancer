/* Unit tests for CPI semantics.

   Covers a variety of CPI behaviours, as well as how these differ under
   the direct mapping feature gates:
   - syscall_parameter_address_restrictions
   - virtual_address_space_adjustments
   - account_data_direct_mapping */

#include "fd_vm_syscall.h"
#include "../test_vm_util.h"
#include "../../runtime/fd_system_ids.h"
#include "../../runtime/fd_pubkey_utils.h"
#include "../../runtime/fd_borrowed_account.h"
#include "../../runtime/context/fd_exec_instr_ctx.h"
#include "../../runtime/tests/fd_svm_mini.h"
#include "../../runtime/tests/fd_svm_elfgen.h"
#include "../../../ballet/sbpf/fd_sbpf_instr.h"
#include "../../../ballet/sbpf/fd_sbpf_opcodes.h"

#include <limits.h>

#define LAMPORTS    1000000UL
#define INIT_DLEN   8UL

/* ABI v1 per-account serialization layout (matches test_cpi_shared_data_addr.c):
   80-byte header + 8-byte data_len + data (8-aligned) + 10240 realloc + 8 rent_epoch */
#define ACCT_META_SZ       88UL
#define ACCT_DLEN_OFF      (ACCT_META_SZ - sizeof(ulong))
#define ACCT_SERIALIZED_SZ (ACCT_META_SZ + fd_ulong_align_up( INIT_DLEN, 8UL ) + 10240UL + 8UL)

#define HEAP_VA(off) (FD_VM_MEM_MAP_HEAP_REGION_START + (off))

#define MAX_CFG_ACCTS 8

static fd_pubkey_t const callee_program_pubkey = {{
  0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
  0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA }};

static fd_pubkey_t const acct1_pubkey = {{
  0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
  0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11 }};

/* acct2_pubkey is reserved for multi-account tests */
static fd_pubkey_t const acct2_pubkey = {{
  0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22, 0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
  0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22, 0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22 }};

typedef struct {
  fd_pubkey_t const * pubkey;
  fd_pubkey_t const * owner;
  ulong               lamports;
  ulong               dlen;
  uchar               data_fill;
  uint                executable : 1;
} acct_spec_t;

typedef struct {
  uchar acct_idx;        /* index into cfg->accts[] */
  uchar is_signer  : 1;
  uchar is_writable: 1;  /* outer writability */
} outer_acct_spec_t;

/* signer_seed_group_t: one PDA signer group.  The CPI runtime derives a PDA
   from (seeds[0..num_seeds-1], caller_program_id) and grants signer privilege
   to any account whose pubkey matches. */
typedef struct {
  uchar num_seeds;          /* number of byte-slice seeds for this signer */
  uchar seed_lens[ 8 ];     /* up to 8 seeds, each up to 32 bytes */
  uchar seed_data[ 8 ][ 32 ];
} signer_seed_group_t;

typedef struct {
  uchar acct_idx;                /* index into cfg->accts[] */
  uchar omit             : 1;    /* skip this entry from account_infos */
  uchar bad_key          : 1;    /* corrupt SPAR key check */
  uchar bad_owner        : 1;    /* corrupt SPAR owner check */
  uchar bad_lamports     : 1;    /* corrupt SPAR lamports check */
  uchar bad_data         : 1;    /* corrupt SPAR data check */
  uchar dlen_override_set: 1;    /* if 1, write claimed_data_len_override; else write real dlen */
  ulong claimed_data_len_override;
} info_spec_t;

typedef struct cpi_test_cfg cpi_test_cfg_t;
typedef void (*pre_cpi_hook_t)( cpi_test_cfg_t const * cfg );

struct cpi_test_cfg {
  /* Feature gates */
  int spar, vasa, dm;
  int is_deprecated;

  /* Callee program text (built via build_*_text helpers) */
  ulong text_buf[ 64 ];
  ulong text_sz;

  /* Accounts known to the env */
  acct_spec_t       accts[ MAX_CFG_ACCTS ]; ulong n_accts;

  /* Outer instruction's account list */
  outer_acct_spec_t outer[ MAX_CFG_ACCTS ]; ulong n_outer;

  /* CPI instruction account metas */
  info_spec_t       infos[ MAX_CFG_ACCTS ]; ulong n_infos;
  uchar             cpi_meta_writable[ MAX_CFG_ACCTS ];
  uchar             cpi_meta_signer  [ MAX_CFG_ACCTS ];

  /* Optional hook: mutate input_buf after env_build but before the CPI
     syscall.  NULL = no mutation. */
  pre_cpi_hook_t    pre_cpi_hook;

  /* PDA signer seed groups (signers_seeds argument).  n_signers=0 means no
     signer seeds (the default, equivalent to signers_seeds_len=0).  Each
     entry describes one PDA signer group; the runtime derives a PDA from
     (seed_data[0..num_seeds-1], caller_program_id) and grants signer
     privilege to matching accounts. */
  signer_seed_group_t signers[ 4 ];
  ulong               n_signers;

  /* Out: filled in by rust_cpi_build / c_cpi_build to expose the heap byte
     offset of the per-info data_len field that ref_to_len_in_vm reads/writes
     during update_caller_acc. */
  ulong               data_len_haddr_off[ MAX_CFG_ACCTS ];
};

static ulong
build_noop_text( ulong * buf ) {
  ulong ic = 0UL;
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode = {.raw=FD_SBPF_OP_MOV64_IMM}, .dst_reg = 0 } );
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode = {.raw=FD_SBPF_OP_EXIT} } );
  return ic * 8UL;
}

static ulong
build_set_data_len_text( ulong * buf, ulong acct_idx_in_input, ulong new_len ) {
  ulong dlen_off = 8UL + acct_idx_in_input * ACCT_SERIALIZED_SZ + ACCT_DLEN_OFF;
  FD_TEST( dlen_off <= SHRT_MAX );
  ulong ic = 0UL;
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode={.raw=FD_SBPF_OP_MOV64_IMM}, .dst_reg=2, .imm=(uint)new_len } );
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode={.raw=FD_SBPF_OP_STXDW},     .dst_reg=1, .src_reg=2, .offset=(short)dlen_off } );
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode={.raw=FD_SBPF_OP_MOV64_IMM}, .dst_reg=0 } );
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode={.raw=FD_SBPF_OP_EXIT} } );
  return ic * 8UL;
}

static ulong
build_write_data_text( ulong * buf, ulong acct_idx_in_input, uchar pat, ulong cnt ) {
  ulong data_off = 8UL + acct_idx_in_input * ACCT_SERIALIZED_SZ + ACCT_META_SZ;
  FD_TEST( data_off + cnt <= SHRT_MAX );
  FD_TEST( cnt <= 16UL ); /* keep unrolled small */
  ulong ic = 0UL;
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode={.raw=FD_SBPF_OP_MOV64_IMM}, .dst_reg=2, .imm=pat } );
  for( ulong i=0UL; i<cnt; i++ ) {
    buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode={.raw=FD_SBPF_OP_STXB}, .dst_reg=1, .src_reg=2, .offset=(short)(data_off+i) } );
  }
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode={.raw=FD_SBPF_OP_MOV64_IMM}, .dst_reg=0 } );
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode={.raw=FD_SBPF_OP_EXIT} } );
  return ic * 8UL;
}

static ulong
build_grow_then_write_text( ulong * buf, ulong acct_idx_in_input, ulong new_dlen, uchar pat, ulong cnt ) {
  ulong dlen_off = 8UL + acct_idx_in_input * ACCT_SERIALIZED_SZ + ACCT_DLEN_OFF;
  ulong data_off = 8UL + acct_idx_in_input * ACCT_SERIALIZED_SZ + ACCT_META_SZ;
  FD_TEST( data_off + cnt <= SHRT_MAX );
  FD_TEST( cnt <= 16UL );
  ulong ic = 0UL;
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode={.raw=FD_SBPF_OP_MOV64_IMM}, .dst_reg=2, .imm=(uint)new_dlen } );
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode={.raw=FD_SBPF_OP_STXDW},     .dst_reg=1, .src_reg=2, .offset=(short)dlen_off } );
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode={.raw=FD_SBPF_OP_MOV64_IMM}, .dst_reg=2, .imm=pat } );
  for( ulong i=0UL; i<cnt; i++ ) {
    buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode={.raw=FD_SBPF_OP_STXB}, .dst_reg=1, .src_reg=2, .offset=(short)(data_off+i) } );
  }
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode={.raw=FD_SBPF_OP_MOV64_IMM}, .dst_reg=0 } );
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode={.raw=FD_SBPF_OP_EXIT} } );
  return ic * 8UL;
}

/* Returns a non-zero error code from the callee.  Used for testing CPI
   error propagation. */
static ulong
build_error_return_text( ulong * buf, ulong err_code ) {
  ulong ic = 0UL;
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode={.raw=FD_SBPF_OP_MOV64_IMM}, .dst_reg=0, .imm=(uint)err_code } );
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode={.raw=FD_SBPF_OP_EXIT} } );
  return ic * 8UL;
}

#define ACCT_BUF_SZ (sizeof(fd_account_meta_t) + MAX_PERMITTED_DATA_INCREASE + 1024)

static uchar prog_buf [ sizeof(fd_account_meta_t) + 4096 ] __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
static uchar acct_buf [ MAX_CFG_ACCTS ][ ACCT_BUF_SZ ]    __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));

static fd_account_meta_t *
init_data_meta_from_spec( uchar *             buf,
                          ulong               buf_sz,
                          acct_spec_t const * spec ) {
  FD_TEST( buf_sz >= sizeof(fd_account_meta_t) + spec->dlen );
  fd_account_meta_t * meta = (fd_account_meta_t *)buf;
  ulong total = sizeof(fd_account_meta_t) + spec->dlen + MAX_PERMITTED_DATA_INCREASE;
  if( total > buf_sz ) total = buf_sz;
  memset( meta, 0, total );
  memcpy( meta->owner, spec->owner, sizeof(fd_pubkey_t) );
  meta->lamports   = spec->lamports;
  meta->dlen       = (uint)spec->dlen;
  meta->executable = (uchar)spec->executable;
  if( spec->dlen ) {
    memset( (uchar *)meta + sizeof(fd_account_meta_t), spec->data_fill, spec->dlen );
  }
  return meta;
}

static fd_account_meta_t * g_acct_metas[ MAX_CFG_ACCTS ];

static void
env_build( fd_svm_mini_t *        mini,
           cpi_test_cfg_t const * cfg ) {
  FD_TEST( cfg->n_accts >= 1UL && cfg->n_accts <= MAX_CFG_ACCTS );

  fd_runtime_t * runtime = mini->runtime;
  fd_vm_t *      vm      = mini->vm;

  /* Build callee ELF */
  ulong elf_sz = fd_svm_elfgen_sz( cfg->text_sz, 0UL );
  static uchar elf_buf[ 4096 ];
  FD_TEST( elf_sz <= sizeof(elf_buf) );
  fd_svm_elfgen( elf_buf, elf_sz, (uchar const *)cfg->text_buf, cfg->text_sz, NULL, 0UL );

  /* Reset svm_mini */
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong bank_idx = fd_svm_mini_reset( mini, params );
  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );

  fd_features_disable_all( &bank->f.features );
  bank->f.features.loosen_cpi_size_restriction = 0UL;
  /* Activate per-cfg feature gates by setting their slot to 0 (always-on). */
  if( cfg->spar ) bank->f.features.syscall_parameter_address_restrictions = 0UL;
  if( cfg->vasa ) bank->f.features.virtual_address_space_adjustments      = 0UL;
  if( cfg->dm   ) bank->f.features.account_data_direct_mapping            = 0UL;

  /* Build txn_out: index 0 is the program; indices 1.. are the cfg accounts */
  static fd_txn_out_t txn_out[1];
  memset( txn_out, 0, sizeof(fd_txn_out_t) );
  ulong txn_acc_cnt = 1UL + cfg->n_accts;
  FD_TEST( txn_acc_cnt <= FD_TXN_ACCT_ADDR_MAX );
  txn_out->accounts.cnt = (ushort)txn_acc_cnt;

  /* Program account at index 0 */
  fd_account_meta_t * prog_meta = (fd_account_meta_t *)prog_buf;
  FD_TEST( sizeof(prog_buf) >= sizeof(fd_account_meta_t) + elf_sz );
  memset( prog_meta, 0, sizeof(prog_buf) );
  memcpy( prog_meta->owner, &fd_solana_bpf_loader_program_id, sizeof(fd_pubkey_t) );
  prog_meta->executable = 1;
  prog_meta->lamports   = LAMPORTS;
  prog_meta->dlen       = (uint)elf_sz;
  memcpy( (uchar *)prog_meta + sizeof(fd_account_meta_t), elf_buf, elf_sz );
  memcpy( &txn_out->accounts.keys[0], &callee_program_pubkey, sizeof(fd_pubkey_t) );
  fd_accdb_rw_init_nodb( &txn_out->accounts.account[0], &callee_program_pubkey,
                         prog_meta, FD_RUNTIME_ACC_SZ_MAX );

  /* Data accounts at indices 1..n_accts */
  for( ulong i=0UL; i<cfg->n_accts; i++ ) {
    g_acct_metas[i] = init_data_meta_from_spec( acct_buf[i], sizeof(acct_buf[i]), &cfg->accts[i] );
    memcpy( &txn_out->accounts.keys[1UL+i], cfg->accts[i].pubkey, sizeof(fd_pubkey_t) );
    fd_accdb_rw_init_nodb( &txn_out->accounts.account[1UL+i],
                           cfg->accts[i].pubkey,
                           g_acct_metas[i],
                           FD_RUNTIME_ACC_SZ_MAX );
  }
  for( ulong i=0UL; i<txn_acc_cnt; i++ ) {
    fd_svm_mini_put_account_rooted( mini, txn_out->accounts.account[i].ro );
  }

  fd_instr_info_t * instr = &runtime->instr.trace[0];
  memset( instr, 0, sizeof(fd_instr_info_t) );
  instr->program_id = 0;
  ulong outer_acct_total = 1UL + cfg->n_outer;
  FD_TEST( outer_acct_total <= FD_INSTR_ACCT_MAX );
  instr->acct_cnt = (ushort)outer_acct_total;

  uchar acc_idx_seen[ FD_TXN_ACCT_ADDR_MAX ] = {0};
  fd_instr_info_setup_instr_account( instr, acc_idx_seen, 0, 0, 0, 0, 0 );

  ulong start_lamp_lo = LAMPORTS;
  for( ulong i=0UL; i<cfg->n_outer; i++ ) {
    ushort outer_pos = (ushort)(1UL + i);
    /* txn_idx reflects the true txn position of this account (1 + acct_idx),
       enabling duplicate detection when two slots share the same acct_idx. */
    ushort txn_idx = (ushort)(1UL + cfg->outer[i].acct_idx);
    fd_instr_info_setup_instr_account( instr, acc_idx_seen,
        txn_idx, outer_pos, outer_pos,
        cfg->outer[i].is_writable,
        cfg->outer[i].is_signer );
    /* Only count unique accounts in lamport sum (skip duplicates). */
    if( !instr->is_duplicate[ outer_pos ] ) {
      start_lamp_lo += cfg->accts[ cfg->outer[i].acct_idx ].lamports;
    }
  }
  instr->starting_lamports_h = 0UL;
  instr->starting_lamports_l = start_lamp_lo;

  /* Instr exec ctx */
  fd_exec_instr_ctx_t * instr_ctx = &runtime->instr.stack[0];
  memset( instr_ctx, 0, sizeof(fd_exec_instr_ctx_t) );
  instr_ctx->instr   = instr;
  instr_ctx->runtime = runtime;
  instr_ctx->txn_out = txn_out;
  instr_ctx->bank    = bank;
  runtime->instr.stack_sz     = 1;
  runtime->instr.trace_length = 1UL;
  runtime->instr.current_idx  = 0;

  static fd_vm_acc_region_meta_t arm[ MAX_CFG_ACCTS + 1UL ];
  memset( arm, 0, sizeof(arm) );
  for( ulong i=0UL; i<cfg->n_outer; i++ ) {
    ulong block = i*ACCT_SERIALIZED_SZ;
    arm[ 1UL + i ].meta              = g_acct_metas[ cfg->outer[i].acct_idx ];
    arm[ 1UL + i ].original_data_len = cfg->accts[ cfg->outer[i].acct_idx ].dlen;
    arm[ 1UL + i ].vm_key_addr       = FD_VM_MEM_MAP_INPUT_REGION_START + block + 8UL;
    arm[ 1UL + i ].vm_owner_addr     = FD_VM_MEM_MAP_INPUT_REGION_START + block + 40UL;
    arm[ 1UL + i ].vm_lamports_addr  = FD_VM_MEM_MAP_INPUT_REGION_START + block + 72UL;
    arm[ 1UL + i ].vm_data_addr      = FD_VM_MEM_MAP_INPUT_REGION_START + block + ACCT_META_SZ;
  }

  static uchar rodata[ 100 ];
  memset( rodata, 0, sizeof(rodata) );
  FD_TEST( fd_vm_init(
    vm, instr_ctx,
    FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
    rodata, sizeof(rodata),
    NULL, 0UL, 0UL, 0UL, 0UL, NULL,
    TEST_VM_DEFAULT_SBPF_VERSION,
    NULL, NULL, mini->sha256, NULL, 0U,
    arm, (uchar)cfg->is_deprecated,
    FD_FEATURE_ACTIVE_BANK( bank, account_data_direct_mapping ),
    FD_FEATURE_ACTIVE_BANK( bank, syscall_parameter_address_restrictions ),
    FD_FEATURE_ACTIVE_BANK( bank, virtual_address_space_adjustments ),
    0, 0UL
  ) );
}

static uchar                input_buf [ 131072 ] __attribute__((aligned(16)));
static fd_vm_input_region_t input_regs[ MAX_CFG_ACCTS + 2 ];

/* Canonical-offset helpers: vaddrs for a given outer-instr account index `i`,
   matching the layout env_build wrote into acc_region_metas. */
static inline ulong canonical_key_vaddr     ( ulong i ) { return FD_VM_MEM_MAP_INPUT_REGION_START + i*ACCT_SERIALIZED_SZ +  8UL; }
static inline ulong canonical_owner_vaddr   ( ulong i ) { return FD_VM_MEM_MAP_INPUT_REGION_START + i*ACCT_SERIALIZED_SZ + 40UL; }
static inline ulong canonical_lamports_vaddr( ulong i ) { return FD_VM_MEM_MAP_INPUT_REGION_START + i*ACCT_SERIALIZED_SZ + 72UL; }
static inline ulong canonical_data_vaddr    ( ulong i ) { return FD_VM_MEM_MAP_INPUT_REGION_START + i*ACCT_SERIALIZED_SZ + ACCT_META_SZ; }

static inline ulong canonical_key_off     ( ulong i ) { return i*ACCT_SERIALIZED_SZ +  8UL; }
static inline ulong canonical_owner_off   ( ulong i ) { return i*ACCT_SERIALIZED_SZ + 40UL; }
static inline ulong canonical_lamports_off( ulong i ) { return i*ACCT_SERIALIZED_SZ + 72UL; }
static inline ulong canonical_dlen_off    ( ulong i ) { return i*ACCT_SERIALIZED_SZ + ACCT_DLEN_OFF; }
static inline ulong canonical_data_off    ( ulong i ) { return i*ACCT_SERIALIZED_SZ + ACCT_META_SZ; }

static void
setup_input_region_for_cfg( fd_vm_t * vm, cpi_test_cfg_t const * cfg ) {
  memset( input_buf, 0, sizeof(input_buf) );

  /* Per outer account, write the canonical pubkey/owner/lamports/dlen bytes
     into input_buf so the SPAR pointer-equality checks find consistent data. */
  for( ulong i=0UL; i<cfg->n_outer; i++ ) {
    acct_spec_t const * spec = &cfg->accts[ cfg->outer[i].acct_idx ];
    memcpy( input_buf + canonical_key_off  ( i ), spec->pubkey, 32 );
    memcpy( input_buf + canonical_owner_off( i ), spec->owner,  32 );
    *(ulong *)( input_buf + canonical_lamports_off( i ) ) = spec->lamports;
    /* dlen: use info override if the explicit flag is set, else the real dlen */
    ulong stored_len = spec->dlen;
    if( i < cfg->n_infos && cfg->infos[i].dlen_override_set ) {
      stored_len = cfg->infos[i].claimed_data_len_override;
    }
    *(ulong *)( input_buf + canonical_dlen_off( i ) ) = stored_len;
    /* data: copy the real bytes too so callee reads see them */
    if( spec->dlen ) {
      memset( input_buf + canonical_data_off( i ), spec->data_fill, spec->dlen );
    }
  }

  /* Initialize all region slots to the same backing buffer.  The runtime
     under VASA writes to input_mem_regions[ region_idx + 1 ] for per-account
     region updates; sharing the buffer is harmless because each slot has
     independent {region_sz, is_writable} fields. */
  for( ulong i=0UL; i<sizeof(input_regs)/sizeof(input_regs[0]); i++ ) {
    input_regs[i] = (fd_vm_input_region_t){
      .haddr                  = (ulong)input_buf,
      .region_sz              = (uint)sizeof(input_buf),
      .address_space_reserved = sizeof(input_buf),
      .is_writable            = 1,
    };
  }
  vm->input_mem_regions     = input_regs;
  vm->input_mem_regions_cnt = (uint)( sizeof(input_regs)/sizeof(input_regs[0]) );
  vm->region_haddr[4]       = (ulong)input_buf;
  vm->region_ld_sz[4]       = (uint)sizeof(input_buf);
  vm->region_st_sz[4]       = (uint)sizeof(input_buf);
}

/* -------------------------------------------------------------------------- *
 * Rust ABI CPI memory builder                                                *
 * -------------------------------------------------------------------------- */

static void
rust_cpi_build( fd_vm_t *              vm,
                cpi_test_cfg_t const * cfg,
                ulong *                out_instr_va,
                ulong *                out_acct_infos_va,
                ulong *                out_num_infos ) {
  ulong h = 0UL;

  /* Instruction header */
  fd_vm_rust_instruction_t * instr = (fd_vm_rust_instruction_t *)&vm->heap[h];
  *out_instr_va = HEAP_VA( h );
  h += sizeof(fd_vm_rust_instruction_t);

  /* Account metas (CPI side) */
  h = fd_ulong_align_up( h, 8UL );
  ulong metas_off = h;
  for( ulong i=0UL; i<cfg->n_infos; i++ ) {
    fd_vm_rust_account_meta_t * m = (fd_vm_rust_account_meta_t *)&vm->heap[h];
    h += sizeof(fd_vm_rust_account_meta_t);
    memcpy( m->pubkey, cfg->accts[ cfg->infos[i].acct_idx ].pubkey, 32 );
    m->is_signer   = cfg->cpi_meta_signer  [i];
    m->is_writable = cfg->cpi_meta_writable[i];
  }

  /* Per-info: lamports box and data box live in the heap (the user-allocated
     Rc<RefCell<...>> structures), but their `addr` payloads point at the
     canonical input-region vaddrs.  Pubkey and owner addrs are direct
     pointers into the input region (no Rc wrapper). */
  h = fd_ulong_align_up( h, 8UL );
  ulong lb_off[ MAX_CFG_ACCTS ];
  for( ulong i=0UL; i<cfg->n_infos; i++ ) {
    lb_off[i] = h;
    /* fd_vm_rc_refcell_ref_t = {strong, weak, borrow, addr}; payload (addr)
       lives at offset offsetof(fd_vm_rc_refcell_t, payload) = 24.  The macro
       LAMPORTS_VADDR reads `addr` at that payload offset. */
    *(fd_vm_rc_refcell_ref_t *)&vm->heap[h] = (fd_vm_rc_refcell_ref_t){
      .strong = 1,
      .addr   = canonical_lamports_vaddr( i ),
    };
    h += sizeof(fd_vm_rc_refcell_ref_t);
  }

  h = fd_ulong_align_up( h, 8UL );
  ulong db_off[ MAX_CFG_ACCTS ];
  for( ulong i=0UL; i<cfg->n_infos; i++ ) {
    db_off[i] = h;
    /* If dlen_override_set, write the lie into the RefCell vec's len field —
       this is what ref_to_len_in_vm reads for the Rust ABI (data_len_vaddr =
       data_box_addr + 24 + 8 = the `len` field of fd_vm_rc_refcell_vec_t). */
    ulong dlen = cfg->accts[ cfg->infos[i].acct_idx ].dlen;
    if( cfg->infos[i].dlen_override_set ) dlen = cfg->infos[i].claimed_data_len_override;
    *(fd_vm_rc_refcell_vec_t *)&vm->heap[h] = (fd_vm_rc_refcell_vec_t){
      .strong = 1,
      .addr   = canonical_data_vaddr( i ),
      .len    = dlen,
    };
    /* Expose the heap offset of the `len` field for tests that need to
       inspect post-CPI. */
    ((cpi_test_cfg_t *)cfg)->data_len_haddr_off[i] = h + offsetof(fd_vm_rc_refcell_vec_t, len);
    h += sizeof(fd_vm_rc_refcell_vec_t);
  }

  /* Account infos array */
  h = fd_ulong_align_up( h, 8UL );
  *out_acct_infos_va = HEAP_VA( h );
  ulong included = 0UL;
  for( ulong i=0UL; i<cfg->n_infos; i++ ) {
    if( cfg->infos[i].omit ) continue;
    fd_vm_rust_account_info_t * info = (fd_vm_rust_account_info_t *)&vm->heap[h];
    h += sizeof(fd_vm_rust_account_info_t);
    *info = (fd_vm_rust_account_info_t){
      .pubkey_addr       = canonical_key_vaddr  ( i ),
      .lamports_box_addr = HEAP_VA( lb_off[i] ),
      .data_box_addr     = HEAP_VA( db_off[i] ),
      .owner_addr        = canonical_owner_vaddr( i ),
      .is_signer         = cfg->cpi_meta_signer  [i],
      .is_writable       = cfg->cpi_meta_writable[i],
    };
    /* SPAR-corruption switches: nudge to a still-8-byte-aligned but wrong
       address.  +1 would break alignment on the Rc dereference and trigger
       a VM error before the SPAR equality check fires. */
    if( cfg->infos[i].bad_key      ) info->pubkey_addr       += 8UL;
    if( cfg->infos[i].bad_owner    ) info->owner_addr        += 8UL;
    if( cfg->infos[i].bad_lamports ) info->lamports_box_addr += 8UL;
    if( cfg->infos[i].bad_data     ) info->data_box_addr     += 8UL;
    included++;
  }
  *out_num_infos = included;

  instr->accounts = (fd_vm_rust_vec_t){ .addr = HEAP_VA( metas_off ), .cap = cfg->n_infos, .len = cfg->n_infos };
  ulong data_off = fd_ulong_align_up( h, 8UL );
  vm->heap[ data_off ] = 0;
  instr->data     = (fd_vm_rust_vec_t){ .addr = HEAP_VA( data_off ), .cap = 1, .len = 1 };
  memcpy( instr->pubkey, callee_program_pubkey.uc, 32 );

  setup_input_region_for_cfg( vm, cfg );
}

/* -------------------------------------------------------------------------- *
 * C ABI CPI memory builder                                                   *
 * -------------------------------------------------------------------------- */

static void
c_cpi_build( fd_vm_t *              vm,
             cpi_test_cfg_t const * cfg,
             ulong *                out_instr_va,
             ulong *                out_acct_infos_va,
             ulong *                out_num_infos ) {
  ulong h = 0UL;

  fd_vm_c_instruction_t * instr = (fd_vm_c_instruction_t *)&vm->heap[h];
  *out_instr_va = HEAP_VA( h );
  h += sizeof(fd_vm_c_instruction_t);

  h = fd_ulong_align_up( h, 8UL );
  ulong metas_off = h;
  ulong meta_pubkey_off[ MAX_CFG_ACCTS ];
  for( ulong i=0UL; i<cfg->n_infos; i++ ) {
    fd_vm_c_account_meta_t * m = (fd_vm_c_account_meta_t *)&vm->heap[h];
    h += sizeof(fd_vm_c_account_meta_t);
    /* For C ABI we still need a pubkey to point at */
    meta_pubkey_off[i] = 0UL; /* filled in below */
    (void)m;
  }

  h = fd_ulong_align_up( h, 8UL );
  ulong prog_off = h;
  memcpy( &vm->heap[h], callee_program_pubkey.uc, 32 ); h += 32;

  /* Fill in the meta pubkey_addr to point at the canonical input-region
     pubkey vaddr (same as the SPAR check expects). */
  for( ulong i=0UL; i<cfg->n_infos; i++ ) {
    fd_vm_c_account_meta_t * m = (fd_vm_c_account_meta_t *)( vm->heap + metas_off
        + i*sizeof(fd_vm_c_account_meta_t) );
    m->pubkey_addr = canonical_key_vaddr( i );
    m->is_signer   = cfg->cpi_meta_signer  [i];
    m->is_writable = cfg->cpi_meta_writable[i];
    meta_pubkey_off[i] = 0UL; (void)meta_pubkey_off;
  }
  (void)meta_pubkey_off;

  /* Account infos array.  All field addrs point into the canonical input-region
     layout (matching env_build's acc_region_metas). */
  h = fd_ulong_align_up( h, 8UL );
  *out_acct_infos_va = HEAP_VA( h );
  ulong included = 0UL;
  for( ulong i=0UL; i<cfg->n_infos; i++ ) {
    if( cfg->infos[i].omit ) continue;
    fd_vm_c_account_info_t * info = (fd_vm_c_account_info_t *)&vm->heap[h];
    /* Expose the heap offset of the data_sz field for tests that need to
       inspect post-CPI. */
    ((cpi_test_cfg_t *)cfg)->data_len_haddr_off[i] = h + offsetof(fd_vm_c_account_info_t, data_sz);
    h += sizeof(fd_vm_c_account_info_t);
    /* If dlen_override_set, write the lie into info->data_sz — this is what
       ref_to_len_in_vm reads for the C ABI (data_len_vaddr resolves to the
       vaddr of info->data_sz). */
    ulong dlen = cfg->accts[ cfg->infos[i].acct_idx ].dlen;
    if( cfg->infos[i].dlen_override_set ) dlen = cfg->infos[i].claimed_data_len_override;
    *info = (fd_vm_c_account_info_t){
      .pubkey_addr   = canonical_key_vaddr     ( i ),
      .lamports_addr = canonical_lamports_vaddr( i ),
      .data_sz       = dlen,
      .data_addr     = canonical_data_vaddr    ( i ),
      .owner_addr    = canonical_owner_vaddr   ( i ),
      .is_signer     = cfg->cpi_meta_signer  [i],
      .is_writable   = cfg->cpi_meta_writable[i],
    };
    /* +8 (still aligned, but wrong) — see Rust ABI counterpart for rationale. */
    if( cfg->infos[i].bad_key      ) info->pubkey_addr   += 8UL;
    if( cfg->infos[i].bad_owner    ) info->owner_addr    += 8UL;
    if( cfg->infos[i].bad_lamports ) info->lamports_addr += 8UL;
    if( cfg->infos[i].bad_data     ) info->data_addr     += 8UL;
    included++;
  }
  *out_num_infos = included;

  instr->program_id_addr = HEAP_VA( prog_off );
  instr->accounts_addr   = HEAP_VA( metas_off );
  instr->accounts_len    = cfg->n_infos;
  ulong data_off = fd_ulong_align_up( h, 8UL );
  vm->heap[ data_off ] = 0;
  instr->data_addr       = HEAP_VA( data_off );
  instr->data_len        = 1UL;

  setup_input_region_for_cfg( vm, cfg );
}

/* -------------------------------------------------------------------------- *
 * Test runners                                                               *
 * -------------------------------------------------------------------------- */

typedef int (* cpi_syscall_fn_t)( void *, ulong, ulong, ulong, ulong, ulong, ulong * );

/* build_signers_in_heap: lay out the signers_seeds argument in vm->heap
   starting at `*h_inout` (heap byte offset), and return the vm vaddr of
   the outer slice.  Returns 0 if n_signers==0 (no signers).

   Memory layout (all 8-byte aligned):

     outer_array[n_signers]    : fd_vm_vec_t  — outer level
     per_signer[i][num_seeds]  : fd_vm_vec_t  — mid level (seeds list)
     seed_bytes[i][j][len]     : uchar[]      — leaf level (actual bytes)

   The signers_seeds_va argument to the CPI syscall must point at the outer
   array and signers_seeds_cnt = n_signers. */
static ulong
build_signers_in_heap( fd_vm_t *              vm,
                       cpi_test_cfg_t const * cfg,
                       ulong *                h_inout,
                       ulong *                out_cnt ) {
  *out_cnt = cfg->n_signers;
  if( cfg->n_signers == 0UL ) return 0UL;

  ulong h = *h_inout;
  h = fd_ulong_align_up( h, 8UL );

  /* Allocate the outer slice (n_signers fd_vm_vec_t entries). */
  ulong outer_off = h;
  h += cfg->n_signers * FD_VM_VEC_SIZE;

  /* For each signer group, allocate its per-seed slice and then each seed. */
  for( ulong i=0UL; i<cfg->n_signers; i++ ) {
    signer_seed_group_t const * sg = &cfg->signers[i];
    h = fd_ulong_align_up( h, 8UL );
    ulong mid_off = h;
    h += sg->num_seeds * FD_VM_VEC_SIZE;

    /* Fill in the outer entry: addr = mid slice vaddr, len = num_seeds. */
    fd_vm_vec_t * outer = (fd_vm_vec_t *)( vm->heap + outer_off + i*FD_VM_VEC_SIZE );
    outer->addr = HEAP_VA( mid_off );
    outer->len  = sg->num_seeds;

    /* Allocate and fill each seed's bytes, fill in the mid entry. */
    for( ulong j=0UL; j<sg->num_seeds; j++ ) {
      h = fd_ulong_align_up( h, 1UL );
      ulong seed_off = h;
      ulong seed_len = sg->seed_lens[j];
      memcpy( vm->heap + seed_off, sg->seed_data[j], seed_len );
      h += seed_len;

      fd_vm_vec_t * mid = (fd_vm_vec_t *)( vm->heap + mid_off + j*FD_VM_VEC_SIZE );
      mid->addr = HEAP_VA( seed_off );
      mid->len  = seed_len;
    }
  }

  *h_inout = h;
  return HEAP_VA( outer_off );
}

static int
run_one( fd_svm_mini_t *  mini,
         cpi_test_cfg_t * cfg,
         int              rust_abi ) {
  env_build( mini, cfg );

  ulong instr_va, infos_va, n_infos;
  if( rust_abi ) rust_cpi_build( mini->vm, cfg, &instr_va, &infos_va, &n_infos );
  else           c_cpi_build   ( mini->vm, cfg, &instr_va, &infos_va, &n_infos );

  fd_vm_t * vm      = mini->vm;
  ulong signers_h   = 4096UL;
  ulong signers_cnt = 0UL;
  ulong signers_va  = build_signers_in_heap( vm, cfg, &signers_h, &signers_cnt );

  if( cfg->pre_cpi_hook ) cfg->pre_cpi_hook( cfg );

  cpi_syscall_fn_t fn = rust_abi ? fd_vm_syscall_cpi_rust : fd_vm_syscall_cpi_c;
  ulong ret = 0UL;
  return fn( mini->vm, instr_va, infos_va, n_infos, signers_va, signers_cnt, &ret );
}

static void
run_matrix( fd_svm_mini_t *  mini,
            cpi_test_cfg_t * cfg,
            char const *     name,
            int              expected_err[4][2][2] ) {
  static int const combo_spar[4] = { 0, 1, 1, 1 };
  static int const combo_vasa[4] = { 0, 0, 1, 1 };
  static int const combo_dm  [4] = { 0, 0, 0, 1 };
  for( int c=0; c<4; c++ ) {
    for( int dep=0; dep<2; dep++ ) {
      for( int abi=0; abi<2; abi++ ) {
        cfg->spar          = combo_spar[c];
        cfg->vasa          = combo_vasa[c];
        cfg->dm            = combo_dm  [c];
        cfg->is_deprecated = dep;
        int want = expected_err[c][dep][abi];
        if( want == INT_MIN ) continue;  /* skip this cell */
        int got = run_one( mini, cfg, /*rust_abi=*/!abi );
        if( FD_UNLIKELY( got != want ) ) {
          fd_txn_out_t * txo = mini->vm->instr_ctx->txn_out;
          FD_LOG_ERR(( "%s: combo=%d dep=%d abi=%s expected=%d got=%d "
                       "(txn.err.exec_err=%d idx=%d)",
                       name, c, dep, abi==0 ? "rust" : "c", want, got,
                       txo->err.exec_err, txo->err.exec_err_idx ));
        }
      }
    }
  }
}

/* Fill expected_err[4][2][2] with a single value across every cell. */
static void
expect_all( int e[4][2][2], int err ) {
  for( int c=0; c<4; c++ ) for( int d=0; d<2; d++ ) for( int a=0; a<2; a++ )
    e[c][d][a] = err;
}

/* Fill expected_err with `combo0` for combo 0 and `combo123` for combos 1-3. */
static void
expect_combo0_vs_rest( int e[4][2][2], int combo0, int combo123 ) {
  for( int d=0; d<2; d++ ) for( int a=0; a<2; a++ ) {
    e[0][d][a] = combo0;
    e[1][d][a] = combo123;
    e[2][d][a] = combo123;
    e[3][d][a] = combo123;
  }
}

/* Initialize a single-account writable cfg: one acct (acct1, owned by callee
   program, INIT_DLEN), one outer slot (writable), one CPI info, CPI writable.
   Tests start from this and override what they need. */
static void
simple_writable_cfg( cpi_test_cfg_t * cfg ) {
  memset( cfg, 0, sizeof(*cfg) );
  cfg->text_sz = build_noop_text( cfg->text_buf );
  cfg->n_accts = 1;
  cfg->accts[0] = (acct_spec_t){
    .pubkey = &acct1_pubkey, .owner = &callee_program_pubkey,
    .lamports = LAMPORTS, .dlen = INIT_DLEN };
  cfg->n_outer = 1;
  cfg->outer[0] = (outer_acct_spec_t){ .acct_idx=0, .is_writable=1 };
  cfg->n_infos = 1;
  cfg->infos[0] = (info_spec_t){ .acct_idx=0 };
  cfg->cpi_meta_writable[0] = 1;
}

/* Pre-CPI hooks: run after env_build / setup_input_region but before the CPI
   syscall fires.  Use to mutate the serialized input region (lamports, owner,
   data_len) so that update_callee_acc sees the mutated values. */

static void
hook_lamports_plus1000( cpi_test_cfg_t const * cfg ) {
  (void)cfg;
  *(ulong *)( input_buf + canonical_lamports_off( 0UL ) ) = LAMPORTS + 1000UL;
}

static void
hook_owner_system_program( cpi_test_cfg_t const * cfg ) {
  (void)cfg;
  memcpy( input_buf + canonical_owner_off( 0UL ),
          fd_solana_system_program_id.uc, 32 );
}

static void
hook_owner_same( cpi_test_cfg_t const * cfg ) {
  (void)cfg;
  memcpy( input_buf + canonical_owner_off( 0UL ),
          callee_program_pubkey.uc, 32 );
}

static void
hook_dlen_to_100( cpi_test_cfg_t const * cfg ) {
  (void)cfg;
  *(ulong *)( input_buf + canonical_dlen_off( 0UL ) ) = 100UL;
}

static void
hook_lamports_uint64_max( cpi_test_cfg_t const * cfg ) {
  (void)cfg;
  *(ulong *)( input_buf + canonical_lamports_off( 0UL ) ) = ULONG_MAX;
}

static void
hook_lamports_zero( cpi_test_cfg_t const * cfg ) {
  (void)cfg;
  *(ulong *)( input_buf + canonical_lamports_off( 0UL ) ) = 0UL;
}

/* Mutates BOTH lamports (LAMPORTS+500) and owner (system program). */
static void
hook_lamports_and_owner( cpi_test_cfg_t const * cfg ) {
  (void)cfg;
  *(ulong *)( input_buf + canonical_lamports_off( 0UL ) ) = LAMPORTS + 500UL;
  memcpy( input_buf + canonical_owner_off( 0UL ),
          fd_solana_system_program_id.uc, 32 );
}

static void
hook_lamports_plus777( cpi_test_cfg_t const * cfg ) {
  (void)cfg;
  *(ulong *)( input_buf + canonical_lamports_off( 0UL ) ) = LAMPORTS + 777UL;
}

/* Extra pubkeys for multi-account tests (acct3..acct7, alt owner). */
static fd_pubkey_t const acct3_pubkey = {{
  0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33, 0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
  0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33, 0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33 }};
static fd_pubkey_t const acct4_pubkey = {{
  0x44,0x44,0x44,0x44,0x44,0x44,0x44,0x44, 0x44,0x44,0x44,0x44,0x44,0x44,0x44,0x44,
  0x44,0x44,0x44,0x44,0x44,0x44,0x44,0x44, 0x44,0x44,0x44,0x44,0x44,0x44,0x44,0x44 }};
static fd_pubkey_t const acct5_pubkey = {{
  0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55, 0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
  0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55, 0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55 }};
static fd_pubkey_t const acct6_pubkey = {{
  0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66, 0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
  0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66, 0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66 }};
static fd_pubkey_t const acct7_pubkey = {{
  0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77, 0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,
  0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77, 0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77 }};

static fd_pubkey_t const acct1_alt_owner = {{
  0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC, 0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
  0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC, 0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC }};

static void
hook_owner_alt( cpi_test_cfg_t const * cfg ) {
  (void)cfg;
  memcpy( input_buf + canonical_owner_off( 0UL ), acct1_alt_owner.uc, 32 );
}

/* build_burn_cus_text: callee that issues `n_movs` MOV64_IMM then EXIT.
   Each MOV consumes 1 CU under the canonical sBPF model. */
static ulong
build_burn_cus_text( ulong * buf, ulong n_movs ) {
  if( n_movs > 60UL ) n_movs = 60UL;  /* text_buf cap */
  ulong ic = 0UL;
  for( ulong i=0UL; i<n_movs; i++ ) {
    buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){
      .opcode={.raw=FD_SBPF_OP_MOV64_IMM}, .dst_reg=2, .imm=(uint)i } );
  }
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){
    .opcode={.raw=FD_SBPF_OP_MOV64_IMM}, .dst_reg=0 } );
  buf[ic++] = fd_sbpf_ulong( (fd_sbpf_instr_t){ .opcode={.raw=FD_SBPF_OP_EXIT} } );
  return ic * 8UL;
}

/* Find the smallest bump such that PDA(callee_program, [seed, bump]) is
   off-curve.  Iterates bump 255..1 and writes the result into *out_pda. */
static void
find_pda_two_seeds( uchar const * seed, ulong seed_len, fd_pubkey_t * out_pda, uchar * out_bump ) {
  uchar bump = 0;
  uchar const * sa[2] = { seed, &bump };
  ulong         sl[2] = { seed_len, 1UL };
  uint custom_err = UINT_MAX;
  for( ulong i=0UL; i<255UL; i++ ) {
    bump = (uchar)(255UL - i);
    sa[1] = &bump;
    int rc = fd_pubkey_derive_pda( &callee_program_pubkey, 2UL, sa, sl,
                                   NULL, out_pda, &custom_err );
    if( rc == FD_PUBKEY_SUCCESS ) { *out_bump = bump; return; }
    if( custom_err != FD_PUBKEY_ERR_INVALID_SEEDS ) {
      FD_LOG_ERR(( "find_pda: derive error %d custom=%u", rc, custom_err ));
    }
  }
  FD_LOG_ERR(( "find_pda: failed to find off-curve PDA" ));
}

/* -------------------------------------------------------------------------- *
 * ===== Privilege checks =====                                               *
 * -------------------------------------------------------------------------- */

static void
test_escalation_writable( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->outer[0].is_writable = 0;  /* outer readonly, CPI tries writable -> escalation */

  int e[4][2][2]; expect_all( e, FD_EXECUTOR_INSTR_ERR_PRIVILEGE_ESCALATION );
  run_matrix( mini, cfg, "test_escalation_writable", e );
}

static void
test_signer_demotion( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->outer[0].is_signer = 1;
  /* CPI signer stays 0: legitimate demotion */

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_signer_demotion", e );
}

static void
test_cpi_demotion_input_region_not_clobbered( fd_svm_mini_t * mini ) {
  /* Outer-writable, CPI-readonly (legitimate demotion).  Smoke check that
     the exit-side data update gate is correctly off (per the bug-fix). */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->accts[0].data_fill = 0xAA;
  cfg->cpi_meta_writable[0] = 0;

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_cpi_demotion_input_region_not_clobbered", e );
}

static void
test_missing_account( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->infos[0].omit = 1;  /* excluded from the user-facing account_infos */

  int e[4][2][2]; expect_all( e, FD_EXECUTOR_INSTR_ERR_MISSING_ACC );
  run_matrix( mini, cfg, "test_missing_account", e );
}

static void
test_duplicate_accounts( fd_svm_mini_t * mini ) {
  /* Two outer slots and two CPI infos at the same acct_idx; OR-merge of
     duplicate slots gives effective writability=1. */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->n_outer = 2;
  cfg->outer[1] = (outer_acct_spec_t){ .acct_idx=0, .is_writable=1 };
  cfg->n_infos = 2;
  cfg->infos[1] = (info_spec_t){ .acct_idx=0 };
  cfg->cpi_meta_writable[1] = 1;

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_duplicate_accounts", e );
}

static void
test_executable_account( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->n_accts = 2;
  cfg->accts[1] = (acct_spec_t){
    .pubkey = &acct2_pubkey, .owner = &fd_solana_bpf_loader_program_id,
    .lamports = LAMPORTS, .dlen = INIT_DLEN, .executable = 1 };
  cfg->n_outer = 2;
  cfg->outer[1] = (outer_acct_spec_t){ .acct_idx=1, .is_writable=0 };
  cfg->n_infos = 2;
  cfg->infos[1] = (info_spec_t){ .acct_idx=1 };
  cfg->cpi_meta_writable[1] = 0;

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_executable_account", e );
}

static void
test_cpi_dup_writable_or_merge( fd_svm_mini_t * mini ) {
  /* Two slots at same pubkey, one writable one readonly.  OR-merge to writable. */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->n_outer = 2;
  cfg->outer[1] = (outer_acct_spec_t){ .acct_idx=0, .is_writable=0 };
  cfg->n_infos = 2;
  cfg->infos[1] = (info_spec_t){ .acct_idx=0 };
  cfg->cpi_meta_writable[1] = 0;

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_cpi_dup_writable_or_merge", e );
}

static void
test_cpi_dup_signer_or_merge( fd_svm_mini_t * mini ) {
  /* Two slots at same pubkey, signer OR-merge.  Outer signer=1 so no escalation. */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->cpi_meta_writable[0] = 0;
  cfg->cpi_meta_signer[0]   = 1;
  cfg->outer[0].is_writable = 0;
  cfg->outer[0].is_signer   = 1;
  cfg->n_outer = 2;
  cfg->outer[1] = (outer_acct_spec_t){ .acct_idx=0, .is_signer=1, .is_writable=0 };
  cfg->n_infos = 2;
  cfg->infos[1] = (info_spec_t){ .acct_idx=0 };
  cfg->cpi_meta_writable[1] = 0;
  cfg->cpi_meta_signer  [1] = 0;

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_cpi_dup_signer_or_merge", e );
}

static void
test_empty_data_account( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->accts[0].dlen = 0UL;

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_empty_data_account", e );
}

static void
test_max_data_length( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->accts[0].dlen      = 1024UL;
  cfg->accts[0].data_fill = 0x55;

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_max_data_length", e );
}

static void
test_zero_account_cpi( fd_svm_mini_t * mini ) {
  /* env_build needs n_accts>=1; just don't reference it from outer/infos. */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->n_outer = 0;
  cfg->n_infos = 0;
  cfg->cpi_meta_writable[0] = 0;

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_zero_account_cpi", e );
}

static void
test_zero_data_cpi( fd_svm_mini_t * mini ) {
  /* data_len=0 is the default in both ABI builders. */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_zero_data_cpi", e );
}

/* Pubkey set used by tests 45 and 88 (7 distinct accounts at the harness cap). */
static fd_pubkey_t const * const seven_pks[7] = {
  &acct1_pubkey, &acct2_pubkey,
  &acct3_pubkey, &acct4_pubkey, &acct5_pubkey, &acct6_pubkey, &acct7_pubkey };

static void
test_max_instruction_accounts_at_limit( fd_svm_mini_t * mini ) {
  /* 7 distinct writable accounts -- at MAX_CFG_ACCTS-1 (the framework cap). */
  cpi_test_cfg_t cfg[1]; memset( cfg, 0, sizeof(*cfg) );
  cfg->text_sz = build_noop_text( cfg->text_buf );
  ulong const N = 7UL;
  FD_TEST( N+1 <= MAX_CFG_ACCTS );
  cfg->n_accts = N; cfg->n_outer = N; cfg->n_infos = N;
  for( ulong i=0UL; i<N; i++ ) {
    cfg->accts[i] = (acct_spec_t){
      .pubkey = seven_pks[i], .owner = &callee_program_pubkey,
      .lamports = LAMPORTS, .dlen = INIT_DLEN, .data_fill = (uchar)(0xA0|(uchar)i) };
    cfg->outer[i] = (outer_acct_spec_t){ .acct_idx=(uchar)i, .is_writable=1 };
    cfg->infos[i] = (info_spec_t){ .acct_idx=(uchar)i };
    cfg->cpi_meta_writable[i] = 1;
  }

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_max_instruction_accounts_at_limit", e );
}

static void
test_exceed_max_account_infos( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );

  env_build( mini, cfg );
  fd_vm_t * vm = mini->vm;
  ulong instr_va, infos_va, n_infos;
  rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
  ulong ret = 0UL;
  int got = fd_vm_syscall_cpi_rust( vm, instr_va, infos_va, 129UL, 0UL, 0UL, &ret );
  FD_TEST( got == FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNT_INFOS_EXCEEDED );

  env_build( mini, cfg );
  c_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
  got = fd_vm_syscall_cpi_c( vm, instr_va, infos_va, 129UL, 0UL, 0UL, &ret );
  FD_TEST( got == FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNT_INFOS_EXCEEDED );
}

static void
test_account_infos_at_max_limit( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; memset( cfg, 0, sizeof(*cfg) );
  cfg->text_sz = build_noop_text( cfg->text_buf );
  ulong const N = 7UL;
  cfg->n_accts = N; cfg->n_outer = N; cfg->n_infos = N;
  for( ulong i=0UL; i<N; i++ ) {
    cfg->accts[i] = (acct_spec_t){
      .pubkey = seven_pks[i], .owner = &callee_program_pubkey,
      .lamports = LAMPORTS, .dlen = INIT_DLEN, .data_fill = (uchar)(0xB0|(uchar)i) };
    cfg->outer[i] = (outer_acct_spec_t){ .acct_idx=(uchar)i, .is_writable=1 };
    cfg->infos[i] = (info_spec_t){ .acct_idx=(uchar)i };
    cfg->cpi_meta_writable[i] = 1;
  }

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_account_infos_at_max_limit", e );
}

static void
test_exceed_max_instruction_accounts( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );

  env_build( mini, cfg );
  fd_vm_t * vm = mini->vm;
  ulong instr_va, infos_va, n_infos;
  rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
  ((fd_vm_rust_instruction_t *)vm->heap)->accounts.len = 256UL;
  ulong ret = 0UL;
  int got = fd_vm_syscall_cpi_rust( vm, instr_va, infos_va, n_infos, 0UL, 0UL, &ret );
  FD_TEST( got == FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNTS_EXCEEDED );

  env_build( mini, cfg );
  c_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
  ((fd_vm_c_instruction_t *)vm->heap)->accounts_len = 256UL;
  got = fd_vm_syscall_cpi_c( vm, instr_va, infos_va, n_infos, 0UL, 0UL, &ret );
  FD_TEST( got == FD_VM_SYSCALL_ERR_MAX_INSTRUCTION_ACCOUNTS_EXCEEDED );
}

static void
test_carrier_overflow_max_instruction_accounts( fd_svm_mini_t * mini ) {
  ulong const N = MAX_CFG_ACCTS - 1UL;
  static fd_pubkey_t extra_pks[ MAX_CFG_ACCTS - 1UL ];
  for( ulong i=0UL; i<N; i++ ) memset( &extra_pks[i], 0x30 + (uchar)i, sizeof(fd_pubkey_t) );

  cpi_test_cfg_t cfg[1]; memset( cfg, 0, sizeof(*cfg) );
  cfg->text_sz = build_noop_text( cfg->text_buf );
  cfg->n_accts = N; cfg->n_outer = N; cfg->n_infos = N;
  for( ulong i=0UL; i<N; i++ ) {
    cfg->accts[i] = (acct_spec_t){
      .pubkey = &extra_pks[i], .owner = &callee_program_pubkey,
      .lamports = LAMPORTS, .dlen = INIT_DLEN, .data_fill = (uchar)(0xA0 + i) };
    cfg->outer[i] = (outer_acct_spec_t){ .acct_idx=(uchar)i, .is_writable=1 };
    cfg->infos[i] = (info_spec_t){ .acct_idx=(uchar)i };
    cfg->cpi_meta_writable[i] = 1;
  }

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_carrier_overflow_max_instruction_accounts", e );
}

static void
test_mixed_carrier( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->accts[0].data_fill = 0x11;
  cfg->n_accts = 2;
  cfg->accts[1] = (acct_spec_t){
    .pubkey = &acct2_pubkey, .owner = &fd_solana_bpf_loader_program_id,
    .lamports = LAMPORTS, .dlen = INIT_DLEN, .data_fill = 0x22, .executable = 1 };
  cfg->n_outer = 2;
  cfg->outer[1] = (outer_acct_spec_t){ .acct_idx=1, .is_writable=0 };
  cfg->n_infos = 2;
  cfg->infos[1] = (info_spec_t){ .acct_idx=1 };
  cfg->cpi_meta_writable[1] = 0;

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_mixed_carrier", e );
}

static void
test_spar_bad_owner( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->infos[0].bad_owner = 1;

  int e[4][2][2];
  expect_combo0_vs_rest( e, FD_VM_SUCCESS, FD_VM_SYSCALL_ERR_INVALID_POINTER );
  run_matrix( mini, cfg, "test_spar_bad_owner", e );
}

static void
test_spar_bad_lamports( fd_svm_mini_t * mini ) {
  /* combo 0 is unspecified: bad_lamports nudges the Rc address; the
     dereference at the wrong vaddr produces unpredictable downstream errors. */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->infos[0].bad_lamports = 1;

  int e[4][2][2];
  expect_combo0_vs_rest( e, INT_MIN, FD_VM_SYSCALL_ERR_INVALID_POINTER );
  run_matrix( mini, cfg, "test_spar_bad_lamports", e );
}

static void
test_spar_bad_data( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->infos[0].bad_data = 1;

  /* combo 0 Rust: Rc dereference at shifted heap address yields garbage; skip.
     combo 0 C   : data_addr direct shift still maps; empirically SUCCESS. */
  int e[4][2][2];
  for(int d=0;d<2;d++) {
    e[0][d][0] = INT_MIN;
    e[0][d][1] = FD_VM_SUCCESS;
    for(int c=1;c<4;c++) for(int a=0;a<2;a++) e[c][d][a] = FD_VM_SYSCALL_ERR_INVALID_POINTER;
  }
  run_matrix( mini, cfg, "test_spar_bad_data", e );
}

static void
test_account_infos_array_in_input_region( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );

  static int const cs[4] = { 0, 1, 1, 1 };
  static int const cv[4] = { 0, 0, 1, 1 };
  static int const cd[4] = { 0, 0, 0, 1 };

  for( int c=0; c<4; c++ ) {
    for( int dep=0; dep<2; dep++ ) {
      for( int abi=0; abi<2; abi++ ) {
        cfg->spar=cs[c]; cfg->vasa=cv[c]; cfg->dm=cd[c]; cfg->is_deprecated=dep;
        env_build( mini, cfg );
        fd_vm_t * vm = mini->vm;

        ulong instr_va, dummy_infos, n_infos;
        if( abi==0 ) rust_cpi_build( vm, cfg, &instr_va, &dummy_infos, &n_infos );
        else         c_cpi_build   ( vm, cfg, &instr_va, &dummy_infos, &n_infos );

        ulong infos_va = FD_VM_MEM_MAP_INPUT_REGION_START;
        ulong ret = 0UL;
        cpi_syscall_fn_t fn = (abi==0) ? fd_vm_syscall_cpi_rust : fd_vm_syscall_cpi_c;
        int got = fn( vm, instr_va, infos_va, 1UL, 0UL, 0UL, &ret );

        if( cs[c] ) {
          FD_TEST( got == FD_VM_SYSCALL_ERR_INVALID_POINTER );
        } else {
          /* SPAR off: AccountInfo struct at input_buf[0] has pubkey_addr=0,
             dereferences unmapped vaddr 0 -> SEGFAULT. */
          FD_TEST( got == FD_VM_SYSCALL_ERR_SEGFAULT );
        }
      }
    }
  }
}

static void
test_account_info_struct_in_input_region( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );

  static int const cs[4] = { 0, 1, 1, 1 };
  static int const cv[4] = { 0, 0, 1, 1 };
  static int const cd[4] = { 0, 0, 0, 1 };

  for( int c=0; c<4; c++ ) {
    for( int dep=0; dep<2; dep++ ) {
      cfg->spar=cs[c]; cfg->vasa=cv[c]; cfg->dm=cd[c]; cfg->is_deprecated=dep;
      env_build( mini, cfg );
      fd_vm_t * vm = mini->vm;

      ulong instr_va, infos_va, n_infos;
      rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );

      fd_vm_rust_account_info_t * info = (fd_vm_rust_account_info_t *)( vm->heap + (infos_va - HEAP_VA(0)) );
      info->lamports_box_addr = FD_VM_MEM_MAP_INPUT_REGION_START;

      ulong ret = 0UL;
      int got = fd_vm_syscall_cpi_rust( vm, instr_va, infos_va, 1UL, 0UL, 0UL, &ret );
      if( cs[c] ) FD_TEST( got == FD_VM_SYSCALL_ERR_INVALID_POINTER );
      else        (void)got;  /* implementation-specific */
    }
  }
}

static void
test_data_refcell_vec_in_input_region( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );

  static int const cs[4] = { 0, 1, 1, 1 };
  static int const cv[4] = { 0, 0, 1, 1 };
  static int const cd[4] = { 0, 0, 0, 1 };

  for( int c=0; c<4; c++ ) {
    for( int dep=0; dep<2; dep++ ) {
      cfg->spar=cs[c]; cfg->vasa=cv[c]; cfg->dm=cd[c]; cfg->is_deprecated=dep;
      env_build( mini, cfg );
      fd_vm_t * vm = mini->vm;

      ulong instr_va, infos_va, n_infos;
      rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );

      fd_vm_rust_account_info_t * info = (fd_vm_rust_account_info_t *)( vm->heap + (infos_va - HEAP_VA(0)) );
      info->data_box_addr = FD_VM_MEM_MAP_INPUT_REGION_START;

      ulong ret = 0UL;
      int got = fd_vm_syscall_cpi_rust( vm, instr_va, infos_va, 1UL, 0UL, 0UL, &ret );
      if( cs[c] ) FD_TEST( got == FD_VM_SYSCALL_ERR_INVALID_POINTER );
      else        (void)got;
    }
  }
}

static void
test_data_in_rodata_under_no_spar( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );

  static int const cs[4] = { 0, 1, 1, 1 };
  static int const cv[4] = { 0, 0, 1, 1 };
  static int const cd[4] = { 0, 0, 0, 1 };

  for( int c=0; c<4; c++ ) {
    for( int dep=0; dep<2; dep++ ) {
      for( int abi=0; abi<2; abi++ ) {
        cfg->spar=cs[c]; cfg->vasa=cv[c]; cfg->dm=cd[c]; cfg->is_deprecated=dep;
        env_build( mini, cfg );
        fd_vm_t * vm = mini->vm;

        ulong instr_va, infos_va, n_infos;
        if( abi==0 ) rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
        else         c_cpi_build   ( vm, cfg, &instr_va, &infos_va, &n_infos );

        if( abi==0 ) {
          fd_vm_rust_account_info_t * info = (fd_vm_rust_account_info_t *)( vm->heap + (infos_va - HEAP_VA(0)) );
          fd_vm_rc_refcell_vec_t * vec = (fd_vm_rc_refcell_vec_t *)( vm->heap + (info->data_box_addr - HEAP_VA(0)) );
          vec->addr = FD_VM_MEM_MAP_RODATA_REGION_START;
        } else {
          fd_vm_c_account_info_t * info = (fd_vm_c_account_info_t *)( vm->heap + (infos_va - HEAP_VA(0)) );
          info->data_addr = FD_VM_MEM_MAP_RODATA_REGION_START;
        }

        ulong ret = 0UL;
        cpi_syscall_fn_t fn = (abi==0) ? fd_vm_syscall_cpi_rust : fd_vm_syscall_cpi_c;
        int got = fn( vm, instr_va, infos_va, 1UL, 0UL, 0UL, &ret );
        if( cs[c] ) FD_TEST( got == FD_VM_SYSCALL_ERR_INVALID_POINTER );
        else        FD_TEST( got != FD_VM_SUCCESS );
      }
    }
  }
}

static void
test_caller_lamports_box_in_rodata_under_no_spar( fd_svm_mini_t * mini ) {
  for( int abi=0; abi<2; abi++ ) {
    cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
    cfg->spar=0; cfg->vasa=0; cfg->dm=0;

    env_build( mini, cfg );
    fd_vm_t * vm = mini->vm;
    ulong instr_va, infos_va, n_infos;
    if( abi==0 ) rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
    else         c_cpi_build   ( vm, cfg, &instr_va, &infos_va, &n_infos );

    if( abi==0 ) {
      fd_vm_rust_account_info_t * info = (fd_vm_rust_account_info_t *)
        ( vm->heap + (infos_va - HEAP_VA(0)) );
      fd_vm_rc_refcell_ref_t * rc = (fd_vm_rc_refcell_ref_t *)
        ( vm->heap + (info->lamports_box_addr - HEAP_VA(0)) );
      rc->addr = FD_VM_MEM_MAP_RODATA_REGION_START;
    } else {
      fd_vm_c_account_info_t * info = (fd_vm_c_account_info_t *)
        ( vm->heap + (infos_va - HEAP_VA(0)) );
      info->lamports_addr = FD_VM_MEM_MAP_RODATA_REGION_START;
    }

    cpi_syscall_fn_t fn = (abi==0) ? fd_vm_syscall_cpi_rust : fd_vm_syscall_cpi_c;
    ulong ret = 0UL;
    int got = fn( vm, instr_va, infos_va, 1UL, 0UL, 0UL, &ret );
    (void)got;
  }
}

static void
test_length_grow_propagation( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_set_data_len_text( cfg->text_buf, 0UL, 100UL );
  cfg->accts[0].data_fill = 0xAA;

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_VM_SUCCESS );
  FD_TEST( g_acct_metas[0]->dlen == 100UL );
  FD_TEST( *(ulong *)( input_buf + canonical_dlen_off( 0UL ) ) == 100UL );

  /* SPAR+deprecated: address_space_reserved = orig_data_len = 8; post=100 -> INVALID_REALLOC. */
  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  for( int c=1;c<4;c++) for( int a=0;a<2;a++) e[c][1][a] = FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
  run_matrix( mini, cfg, "test_length_grow_propagation", e );
}

static void
test_length_shrink_propagation( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_set_data_len_text( cfg->text_buf, 0UL, 4UL );
  cfg->accts[0].dlen      = 16UL;
  cfg->accts[0].data_fill = 0xBB;

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_VM_SUCCESS );
  FD_TEST( g_acct_metas[0]->dlen == 4UL );
  FD_TEST( *(ulong *)( input_buf + canonical_dlen_off( 0UL ) ) == 4UL );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_length_shrink_propagation", e );
}

static void
test_lamports_change( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->pre_cpi_hook = hook_lamports_plus1000;

  /* set_lamports succeeds, then fd_instr_stack_push detects lamport sum
     imbalance (no balancing subtract) -> UNBALANCED_INSTR. */
  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR );
  FD_TEST( g_acct_metas[0]->lamports == LAMPORTS + 1000UL );

  int e[4][2][2]; expect_all( e, FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR );
  run_matrix( mini, cfg, "test_lamports_change", e );
}

static void
test_owner_change( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->pre_cpi_hook = hook_owner_system_program;

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_VM_SUCCESS );
  FD_TEST( !memcmp( g_acct_metas[0]->owner, fd_solana_system_program_id.uc, 32 ) );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_owner_change", e );
}

static void
test_region_size_update_under_vasa( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_set_data_len_text( cfg->text_buf, 0UL, 100UL );

  static int const cs[4] = { 0, 1, 1, 1 };
  static int const cv[4] = { 0, 0, 1, 1 };
  static int const cd[4] = { 0, 0, 0, 1 };

  for( int c=0; c<4; c++ ) {
    for( int dep=0; dep<2; dep++ ) {
      for( int abi=0; abi<2; abi++ ) {
        cfg->spar=cs[c]; cfg->vasa=cv[c]; cfg->dm=cd[c]; cfg->is_deprecated=dep;
        int err = run_one( mini, cfg, /*rust_abi=*/!abi );
        if( cfg->spar && dep ) {
          FD_TEST( err == FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC );
          continue;
        }
        FD_TEST( err == FD_VM_SUCCESS );
        FD_TEST( *(ulong *)( input_buf + canonical_dlen_off( 0UL ) ) == 100UL );
      }
    }
  }
}

static void
test_region_size_shrink_under_vasa( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_set_data_len_text( cfg->text_buf, 0UL, 16UL );
  cfg->accts[0].dlen      = 64UL;
  cfg->accts[0].data_fill = 0xCC;

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_VM_SUCCESS );
  FD_TEST( g_acct_metas[0]->dlen == 16UL );
  FD_TEST( *(ulong *)( input_buf + canonical_dlen_off( 0UL ) ) == 16UL );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_region_size_shrink_under_vasa", e );
}

static void
test_region_size_unchanged_when_callee_no_modify( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->accts[0].dlen      = 32UL;
  cfg->accts[0].data_fill = 0x55;

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_VM_SUCCESS );
  FD_TEST( g_acct_metas[0]->dlen == 32UL );
  FD_TEST( *(ulong *)( input_buf + canonical_dlen_off( 0UL ) ) == 32UL );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_region_size_unchanged_when_callee_no_modify", e );
}

static void
test_lamports_noop( fd_svm_mini_t * mini ) {
  /* No hook: lamports already match -> early-out in update_callee_acc. */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_lamports_noop", e );
}

static void
test_owner_noop( fd_svm_mini_t * mini ) {
  /* Hook writes the SAME owner -> memcmp at cpi_common.c:215 skips set_owner. */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->pre_cpi_hook = hook_owner_same;

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_owner_noop", e );
}

static void
test_data_noop( fd_svm_mini_t * mini ) {
  /* Data bytes match (both zero) -> set_data_from_slice no-change path. */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_data_noop", e );
}

static void
test_lamports_change_readonly( fd_svm_mini_t * mini ) {
  /* update_callee_acc borrows under OUTER instr_ctx (outer-writable), so
     set_lamports succeeds; lamport conservation then trips UNBALANCED_INSTR. */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->cpi_meta_writable[0] = 0;
  cfg->pre_cpi_hook = hook_lamports_plus1000;

  int e[4][2][2]; expect_all( e, FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR );
  run_matrix( mini, cfg, "test_lamports_change_readonly", e );
}

static void
test_owner_change_readonly( fd_svm_mini_t * mini ) {
  /* Same as test_lamports_change_readonly but no lamport delta -> SUCCESS. */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->cpi_meta_writable[0] = 0;
  cfg->pre_cpi_hook = hook_owner_system_program;

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_owner_change_readonly", e );
}

static void
test_owner_change_to_system_program( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->pre_cpi_hook = hook_owner_system_program;

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_owner_change_to_system_program", e );
}

static void
test_lamports_uint64_max( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->pre_cpi_hook = hook_lamports_uint64_max;

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR );
  FD_TEST( g_acct_metas[0]->lamports == ULONG_MAX );

  int e[4][2][2]; expect_all( e, FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR );
  run_matrix( mini, cfg, "test_lamports_uint64_max", e );
}

static void
test_lamports_drain_to_zero( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->pre_cpi_hook = hook_lamports_zero;

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR );
  FD_TEST( g_acct_metas[0]->lamports == 0UL );

  int e[4][2][2]; expect_all( e, FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR );
  run_matrix( mini, cfg, "test_lamports_drain_to_zero", e );
}

static void
test_multi_field_update_in_cpi( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->pre_cpi_hook = hook_lamports_and_owner;

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR );
  FD_TEST( g_acct_metas[0]->lamports == LAMPORTS + 500UL );
  FD_TEST( !memcmp( g_acct_metas[0]->owner, fd_solana_system_program_id.uc, 32 ) );

  int e[4][2][2]; expect_all( e, FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR );
  run_matrix( mini, cfg, "test_multi_field_update_in_cpi", e );
}

static void
test_owner_change_last_ordering( fd_svm_mini_t * mini ) {
  /* New owner must differ from callee_program_pubkey to keep the executor
     lookup (which keys on callee at txn idx 0) intact. */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->pre_cpi_hook = hook_owner_alt;

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_VM_SUCCESS );
  FD_TEST( !memcmp( g_acct_metas[0]->owner, acct1_alt_owner.uc, 32 ) );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_owner_change_last_ordering", e );
}

/* The executable byte is NOT a field copied by update_callee_acc (which only
   propagates lamports, owner, data).  Smoke-asserts the carrier never carries it. */
static void
test_executable_flag_immutable_via_cpi( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_VM_SUCCESS );
  FD_TEST( g_acct_metas[0]->executable == 0 );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_executable_flag_immutable_via_cpi", e );
}

static void
test_caller_view_propagated_via_update_callee_acc( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->pre_cpi_hook = hook_lamports_plus777;

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR );
  FD_TEST( g_acct_metas[0]->lamports == LAMPORTS + 777UL );

  int e[4][2][2]; expect_all( e, FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR );
  run_matrix( mini, cfg, "test_caller_view_propagated_via_update_callee_acc", e );
}

static void
test_realloc_cap_exact_boundary( fd_svm_mini_t * mini ) {
  ulong const EXACT = INIT_DLEN + MAX_PERMITTED_DATA_INCREASE;
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_set_data_len_text( cfg->text_buf, 0UL, EXACT );

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_VM_SUCCESS );
  FD_TEST( g_acct_metas[0]->dlen == EXACT );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  for(int c=1;c<4;c++) for(int a=0;a<2;a++) e[c][1][a] = FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
  run_matrix( mini, cfg, "test_realloc_cap_exact_boundary", e );
}

static void
test_realloc_to_exact_cap( fd_svm_mini_t * mini ) {
  ulong const EXACT = INIT_DLEN + MAX_PERMITTED_DATA_INCREASE;
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_set_data_len_text( cfg->text_buf, 0UL, EXACT );

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_VM_SUCCESS );
  FD_TEST( g_acct_metas[0]->dlen == EXACT );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  for(int c=1;c<4;c++) for(int a=0;a<2;a++) e[c][1][a] = FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
  run_matrix( mini, cfg, "test_realloc_to_exact_cap", e );
}

static void
test_realloc_cap_exceeded( fd_svm_mini_t * mini ) {
  ulong const OVER = INIT_DLEN + MAX_PERMITTED_DATA_INCREASE + 1UL;
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_set_data_len_text( cfg->text_buf, 0UL, OVER );

  int e[4][2][2]; expect_all( e, FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC );
  run_matrix( mini, cfg, "test_realloc_cap_exceeded", e );
}

static void
test_callee_modifies_outer_readonly( fd_svm_mini_t * mini ) {
  /* Outer + CPI both readonly; callee writes 1 byte -> READONLY_DATA_MODIFIED. */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_write_data_text( cfg->text_buf, 0UL, 0xBB, 1UL );
  cfg->accts[0].data_fill = 0xAA;
  cfg->outer[0].is_writable = 0;
  cfg->cpi_meta_writable[0] = 0;

  int e[4][2][2]; expect_all( e, FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED );
  run_matrix( mini, cfg, "test_callee_modifies_outer_readonly", e );
}

static void
test_empty_grown_to_nonzero( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_set_data_len_text( cfg->text_buf, 0UL, 64UL );
  cfg->accts[0].dlen = 0UL;

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_VM_SUCCESS );
  FD_TEST( g_acct_metas[0]->dlen == 64UL );
  FD_TEST( *(ulong *)( input_buf + canonical_dlen_off( 0UL ) ) == 64UL );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  for(int c=1;c<4;c++) for(int a=0;a<2;a++) e[c][1][a] = FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
  run_matrix( mini, cfg, "test_empty_grown_to_nonzero", e );
}

static void
test_already_at_max_grow_attempt( fd_svm_mini_t * mini ) {
  /* dlen=4096; grow by MAX+1.  BPF-loader serialization rejects pre-update_caller. */
  ulong const INIT_42 = 4096UL;
  ulong const OVER    = INIT_42 + MAX_PERMITTED_DATA_INCREASE + 1UL;
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_set_data_len_text( cfg->text_buf, 0UL, OVER );
  cfg->accts[0].dlen = INIT_42;

  int e[4][2][2]; expect_all( e, FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC );
  run_matrix( mini, cfg, "test_already_at_max_grow_attempt", e );
}

static void
test_callee_writes_within_data( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_write_data_text( cfg->text_buf, 0UL, 0xAB, 8UL );
  cfg->accts[0].dlen = 16UL;

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_VM_SUCCESS );
  uchar * d = (uchar *)g_acct_metas[0] + sizeof(fd_account_meta_t);
  for( ulong i=0UL; i<8UL; i++ ) FD_TEST( d[i] == 0xAB );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_callee_writes_within_data", e );
}

static void
test_callee_writes_past_dlen( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_grow_then_write_text( cfg->text_buf, 0UL, 16UL, 0xCC, 12UL );
  cfg->accts[0].dlen = 4UL;

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_VM_SUCCESS );
  FD_TEST( g_acct_metas[0]->dlen == 16UL );
  uchar * d = (uchar *)g_acct_metas[0] + sizeof(fd_account_meta_t);
  for( ulong i=0UL; i<12UL; i++ ) FD_TEST( d[i] == 0xCC );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  for(int c=1;c<4;c++) for(int a=0;a<2;a++) e[c][1][a] = FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
  run_matrix( mini, cfg, "test_callee_writes_past_dlen", e );
}

static void
test_growth_budget_exhausted( fd_svm_mini_t * mini ) {
  /* dlen=4 + MAX equals the allowed growth (delta == MAX, not strictly greater). */
  ulong const INIT_75 = 4UL;
  ulong const EXACT   = INIT_75 + MAX_PERMITTED_DATA_INCREASE;
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_set_data_len_text( cfg->text_buf, 0UL, EXACT );
  cfg->accts[0].dlen = INIT_75;

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_VM_SUCCESS );
  FD_TEST( g_acct_metas[0]->dlen == EXACT );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  for(int c=1;c<4;c++) for(int a=0;a<2;a++) e[c][1][a] = FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
  run_matrix( mini, cfg, "test_growth_budget_exhausted", e );
}

static void
test_multi_account_realloc_within_budget( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  /* Callee grows acct[1] (idx 1 in callee's serialized input) to 100. */
  cfg->text_sz = build_set_data_len_text( cfg->text_buf, 1UL, 100UL );
  cfg->accts[0].data_fill = 0x11;
  cfg->n_accts = 2;
  cfg->accts[1] = (acct_spec_t){
    .pubkey = &acct2_pubkey, .owner = &callee_program_pubkey,
    .lamports = LAMPORTS, .dlen = INIT_DLEN, .data_fill = 0x22 };
  cfg->n_outer = 2;
  cfg->outer[1] = (outer_acct_spec_t){ .acct_idx=1, .is_writable=1 };
  cfg->n_infos = 2;
  cfg->infos[1] = (info_spec_t){ .acct_idx=1 };
  cfg->cpi_meta_writable[1] = 1;

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_VM_SUCCESS );
  FD_TEST( g_acct_metas[0]->dlen == INIT_DLEN );
  FD_TEST( g_acct_metas[1]->dlen == 100UL );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  for(int c=1;c<4;c++) for(int a=0;a<2;a++) e[c][1][a] = FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
  run_matrix( mini, cfg, "test_multi_account_realloc_within_budget", e );
}

static void
test_shrink_to_zero( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_set_data_len_text( cfg->text_buf, 0UL, 0UL );
  cfg->accts[0].dlen      = 64UL;
  cfg->accts[0].data_fill = 0xDD;

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_VM_SUCCESS );
  FD_TEST( g_acct_metas[0]->dlen == 0UL );
  FD_TEST( *(ulong *)( input_buf + canonical_dlen_off( 0UL ) ) == 0UL );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_shrink_to_zero", e );
}

static void
test_shrink_below_orig_data_len( fd_svm_mini_t * mini ) {
  /* Shrink 64 -> 32; address_space_reserved=64 still covers post=32 even under SPAR+dep. */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_set_data_len_text( cfg->text_buf, 0UL, 32UL );
  cfg->accts[0].dlen      = 64UL;
  cfg->accts[0].data_fill = 0xEE;

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_VM_SUCCESS );
  FD_TEST( g_acct_metas[0]->dlen == 32UL );
  FD_TEST( *(ulong *)( input_buf + canonical_dlen_off( 0UL ) ) == 32UL );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_shrink_below_orig_data_len", e );
}

static void
test_dm_shared_account_first_write( fd_svm_mini_t * mini ) {
  /* Combo 3 only: documents Firedancer has no CoW under DM. */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_write_data_text( cfg->text_buf, 0UL, 0xDD, 8UL );
  cfg->accts[0].dlen = 16UL;

  int e[4][2][2];
  for(int c=0;c<4;c++) for(int d=0;d<2;d++) for(int a=0;a<2;a++) e[c][d][a] = INT_MIN;
  for(int d=0;d<2;d++) for(int a=0;a<2;a++) e[3][d][a] = FD_VM_SUCCESS;
  run_matrix( mini, cfg, "test_dm_shared_account_first_write", e );

  cfg->spar=1; cfg->vasa=1; cfg->dm=1; cfg->is_deprecated=0;
  int err = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err == FD_VM_SUCCESS );
  uchar * d = (uchar *)g_acct_metas[0] + sizeof(fd_account_meta_t);
  for( ulong i=0UL; i<8UL; i++ ) FD_TEST( d[i] == 0xDD );
}

/* -------------------------------------------------------------------------- *
 * ===== Readonly account mutations (errors) =====                            *
 * -------------------------------------------------------------------------- */

static void
test_callee_readonly_with_caller_changed_dlen( fd_svm_mini_t * mini ) {
  /* CPI-readonly but update_callee_acc borrows via OUTER instr_ctx
     (outer-writable), so set_data_length(100) succeeds. */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->cpi_meta_writable[0] = 0;
  cfg->pre_cpi_hook = hook_dlen_to_100;

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_callee_readonly_with_caller_changed_dlen", e );
}

static void
test_callee_readonly_with_caller_changed_owner( fd_svm_mini_t * mini ) {
  /* Like test_callee_readonly_with_caller_changed_dlen for owner; data zeroed so set_owner passes its checks. */
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->cpi_meta_writable[0] = 0;
  cfg->pre_cpi_hook = hook_owner_system_program;

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_callee_readonly_with_caller_changed_owner", e );
}

static void
test_pda_signer_valid( fd_svm_mini_t * mini ) {
  static const uchar seed0[] = "pda_test_21";
  fd_pubkey_t pda_pubkey = {0};
  uchar bump = 0;
  find_pda_two_seeds( seed0, sizeof(seed0)-1, &pda_pubkey, &bump );

  cpi_test_cfg_t cfg[1]; memset( cfg, 0, sizeof(*cfg) );
  cfg->text_sz = build_noop_text( cfg->text_buf );
  cfg->n_accts = 1;
  cfg->accts[0] = (acct_spec_t){
    .pubkey = &pda_pubkey, .owner = &callee_program_pubkey,
    .lamports = LAMPORTS, .dlen = INIT_DLEN };
  cfg->n_outer = 1;
  cfg->outer[0] = (outer_acct_spec_t){ .acct_idx=0, .is_signer=1, .is_writable=0 };
  cfg->n_infos = 1;
  cfg->infos[0] = (info_spec_t){ .acct_idx=0 };
  cfg->cpi_meta_signer[0] = 1;

  cfg->n_signers = 1;
  cfg->signers[0].num_seeds = 2;
  cfg->signers[0].seed_lens[0] = (uchar)(sizeof(seed0)-1);
  memcpy( cfg->signers[0].seed_data[0], seed0, sizeof(seed0)-1 );
  cfg->signers[0].seed_lens[1] = 1;
  cfg->signers[0].seed_data[1][0] = bump;

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_pda_signer_valid", e );
}

static void
test_pda_signer_invalid_seeds( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->outer[0].is_writable = 0;
  cfg->cpi_meta_writable[0] = 0;
  cfg->cpi_meta_signer[0]   = 1;

  cfg->n_signers = 1;
  cfg->signers[0].num_seeds = 1;
  cfg->signers[0].seed_lens[0] = 10;
  memcpy( cfg->signers[0].seed_data[0], "wrong_seed", 10 );

  int e[4][2][2]; expect_all( e, FD_EXECUTOR_INSTR_ERR_PRIVILEGE_ESCALATION );
  run_matrix( mini, cfg, "test_pda_signer_invalid_seeds", e );
}

static void
test_pda_signer_multiple( fd_svm_mini_t * mini ) {
  static const uchar seed_23[] = "pda_23";
  fd_pubkey_t pda23 = {0};
  uchar bump23 = 0;
  find_pda_two_seeds( seed_23, sizeof(seed_23)-1, &pda23, &bump23 );

  cpi_test_cfg_t cfg[1]; memset( cfg, 0, sizeof(*cfg) );
  cfg->text_sz = build_noop_text( cfg->text_buf );
  cfg->n_accts = 2;
  cfg->accts[0] = (acct_spec_t){
    .pubkey = &acct1_pubkey, .owner = &callee_program_pubkey,
    .lamports = LAMPORTS, .dlen = INIT_DLEN };
  cfg->accts[1] = (acct_spec_t){
    .pubkey = &pda23, .owner = &callee_program_pubkey,
    .lamports = LAMPORTS, .dlen = INIT_DLEN };
  cfg->n_outer = 2;
  cfg->outer[0] = (outer_acct_spec_t){ .acct_idx=0, .is_signer=1, .is_writable=0 };
  cfg->outer[1] = (outer_acct_spec_t){ .acct_idx=1, .is_signer=0, .is_writable=0 };
  cfg->n_infos = 2;
  cfg->infos[0] = (info_spec_t){ .acct_idx=0 };
  cfg->infos[1] = (info_spec_t){ .acct_idx=1 };
  cfg->cpi_meta_signer[0] = 1;
  cfg->cpi_meta_signer[1] = 1;

  cfg->n_signers = 1;
  cfg->signers[0].num_seeds = 2;
  cfg->signers[0].seed_lens[0] = (uchar)(sizeof(seed_23)-1);
  memcpy( cfg->signers[0].seed_data[0], seed_23, sizeof(seed_23)-1 );
  cfg->signers[0].seed_lens[1] = 1;
  cfg->signers[0].seed_data[1][0] = bump23;

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_pda_signer_multiple", e );
}

static void
test_empty_signer_seeds( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  /* n_signers=0 is the default. */

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_empty_signer_seeds", e );
}

static void
test_too_many_signers( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );

  env_build( mini, cfg );
  fd_vm_t * vm = mini->vm;
  ulong instr_va, infos_va, n_infos;
  rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
  ulong outer_off = 4096UL;
  memset( vm->heap + outer_off, 0, 17 * FD_VM_VEC_SIZE );
  ulong ret = 0UL;
  int got = fd_vm_syscall_cpi_rust( vm, instr_va, infos_va, n_infos,
                                    HEAP_VA( outer_off ), 17UL, &ret );
  FD_TEST( got == FD_VM_SYSCALL_ERR_TOO_MANY_SIGNERS );

  env_build( mini, cfg );
  c_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
  memset( vm->heap + outer_off, 0, 17 * FD_VM_VEC_SIZE );
  got = fd_vm_syscall_cpi_c( vm, instr_va, infos_va, n_infos,
                             HEAP_VA( outer_off ), 17UL, &ret );
  FD_TEST( got == FD_VM_SYSCALL_ERR_TOO_MANY_SIGNERS );
}

static void
test_too_many_seeds_per_signer( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );

  env_build( mini, cfg );
  fd_vm_t * vm = mini->vm;
  ulong instr_va, infos_va, n_infos;
  rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
  ulong outer_off = 4096UL;
  fd_vm_vec_t * outer = (fd_vm_vec_t *)( vm->heap + outer_off );
  ulong mid_off = outer_off + FD_VM_VEC_SIZE;
  memset( vm->heap + mid_off, 0, 17 * FD_VM_VEC_SIZE );
  outer->addr = HEAP_VA( mid_off );
  outer->len  = 17UL;
  ulong ret = 0UL;
  int got = fd_vm_syscall_cpi_rust( vm, instr_va, infos_va, n_infos,
                                    HEAP_VA( outer_off ), 1UL, &ret );
  FD_TEST( got == FD_EXECUTOR_INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED );

  env_build( mini, cfg );
  c_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
  outer = (fd_vm_vec_t *)( vm->heap + outer_off );
  memset( vm->heap + mid_off, 0, 17 * FD_VM_VEC_SIZE );
  outer->addr = HEAP_VA( mid_off );
  outer->len  = 17UL;
  got = fd_vm_syscall_cpi_c( vm, instr_va, infos_va, n_infos,
                             HEAP_VA( outer_off ), 1UL, &ret );
  FD_TEST( got == FD_EXECUTOR_INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED );
}

static void
test_seed_too_long( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );

  env_build( mini, cfg );
  fd_vm_t * vm = mini->vm;
  ulong instr_va, infos_va, n_infos;
  rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
  ulong outer_off = 4096UL;
  fd_vm_vec_t * outer = (fd_vm_vec_t *)( vm->heap + outer_off );
  ulong mid_off  = outer_off + FD_VM_VEC_SIZE;
  fd_vm_vec_t * mid = (fd_vm_vec_t *)( vm->heap + mid_off );
  ulong seed_off = mid_off + FD_VM_VEC_SIZE;
  memset( vm->heap + seed_off, 0xAB, 33 );
  mid->addr = HEAP_VA( seed_off );
  mid->len  = 33UL;
  outer->addr = HEAP_VA( mid_off );
  outer->len  = 1UL;
  ulong ret = 0UL;
  int got = fd_vm_syscall_cpi_rust( vm, instr_va, infos_va, n_infos,
                                    HEAP_VA( outer_off ), 1UL, &ret );
  FD_TEST( got == FD_VM_SYSCALL_ERR_BAD_SEEDS );

  env_build( mini, cfg );
  c_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
  outer = (fd_vm_vec_t *)( vm->heap + outer_off );
  mid   = (fd_vm_vec_t *)( vm->heap + mid_off );
  memset( vm->heap + seed_off, 0xAB, 33 );
  mid->addr = HEAP_VA( seed_off );
  mid->len  = 33UL;
  outer->addr = HEAP_VA( mid_off );
  outer->len  = 1UL;
  got = fd_vm_syscall_cpi_c( vm, instr_va, infos_va, n_infos,
                             HEAP_VA( outer_off ), 1UL, &ret );
  FD_TEST( got == FD_VM_SYSCALL_ERR_BAD_SEEDS );
}

static void
test_entry_borrow_conflict( fd_svm_mini_t * mini ) {
  for( int abi=0; abi<2; abi++ ) {
    cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
    env_build( mini, cfg );
    fd_vm_t * vm = mini->vm;

    fd_borrowed_account_t pre_borrow[1] = {0};
    int berr = fd_exec_instr_ctx_try_borrow_instr_account( vm->instr_ctx, 1,
                                                           pre_borrow );
    FD_TEST( berr == FD_EXECUTOR_INSTR_SUCCESS );

    ulong instr_va, infos_va, n_infos;
    if( abi==0 ) rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
    else         c_cpi_build   ( vm, cfg, &instr_va, &infos_va, &n_infos );

    cpi_syscall_fn_t fn = (abi==0) ? fd_vm_syscall_cpi_rust : fd_vm_syscall_cpi_c;
    ulong ret = 0UL;
    int got = fn( vm, instr_va, infos_va, n_infos, 0UL, 0UL, &ret );
    FD_TEST( got == FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED );
    fd_borrowed_account_drop( pre_borrow );
  }
}

static void
test_borrow_lifecycle( fd_svm_mini_t * mini ) {
  for( int abi=0; abi<2; abi++ ) {
    cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
    env_build( mini, cfg );
    fd_vm_t * vm = mini->vm;
    ulong instr_va, infos_va, n_infos;
    if( abi==0 ) rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
    else         c_cpi_build   ( vm, cfg, &instr_va, &infos_va, &n_infos );

    cpi_syscall_fn_t fn = (abi==0) ? fd_vm_syscall_cpi_rust : fd_vm_syscall_cpi_c;
    ulong ret = 0UL;
    int got = fn( vm, instr_va, infos_va, n_infos, 0UL, 0UL, &ret );
    FD_TEST( got == FD_VM_SUCCESS );

    fd_borrowed_account_t pb[1] = {0};
    int berr = fd_exec_instr_ctx_try_borrow_instr_account( vm->instr_ctx, 1, pb );
    FD_TEST( berr == FD_EXECUTOR_INSTR_SUCCESS );
    fd_borrowed_account_drop( pb );
  }
}

static void
test_callee_borrow_modify_release_lifecycle( fd_svm_mini_t * mini ) {
  for( int abi=0; abi<2; abi++ ) {
    cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
    cfg->text_sz = build_write_data_text( cfg->text_buf, 0UL, 0xEE, 4UL );

    env_build( mini, cfg );
    fd_vm_t * vm = mini->vm;
    ulong instr_va, infos_va, n_infos;
    if( abi==0 ) rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
    else         c_cpi_build   ( vm, cfg, &instr_va, &infos_va, &n_infos );

    cpi_syscall_fn_t fn = (abi==0) ? fd_vm_syscall_cpi_rust : fd_vm_syscall_cpi_c;
    ulong ret = 0UL;
    int got = fn( vm, instr_va, infos_va, n_infos, 0UL, 0UL, &ret );
    FD_TEST( got == FD_VM_SUCCESS );

    fd_borrowed_account_t pb[1] = {0};
    int berr = fd_exec_instr_ctx_try_borrow_instr_account( vm->instr_ctx, 1, pb );
    FD_TEST( berr == FD_EXECUTOR_INSTR_SUCCESS );
    uchar const * data = fd_borrowed_account_get_data( pb );
    for( ulong i=0UL; i<4UL; i++ ) FD_TEST( data[i] == 0xEE );
    fd_borrowed_account_drop( pb );
  }
}

static void
test_caller_borrow_released_before_cpi( fd_svm_mini_t * mini ) {
  for( int abi=0; abi<2; abi++ ) {
    cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
    env_build( mini, cfg );
    fd_vm_t * vm = mini->vm;

    fd_borrowed_account_t pb[1] = {0};
    int berr = fd_exec_instr_ctx_try_borrow_instr_account( vm->instr_ctx, 1, pb );
    FD_TEST( berr == FD_EXECUTOR_INSTR_SUCCESS );
    fd_borrowed_account_drop( pb );

    ulong instr_va, infos_va, n_infos;
    if( abi==0 ) rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
    else         c_cpi_build   ( vm, cfg, &instr_va, &infos_va, &n_infos );

    cpi_syscall_fn_t fn = (abi==0) ? fd_vm_syscall_cpi_rust : fd_vm_syscall_cpi_c;
    ulong ret = 0UL;
    int got = fn( vm, instr_va, infos_va, n_infos, 0UL, 0UL, &ret );
    FD_TEST( got == FD_VM_SUCCESS );
  }
}

static void
test_sequential_cpis_re_borrow( fd_svm_mini_t * mini ) {
  for( int abi=0; abi<2; abi++ ) {
    cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
    env_build( mini, cfg );
    fd_vm_t * vm = mini->vm;
    cpi_syscall_fn_t fn = (abi==0) ? fd_vm_syscall_cpi_rust : fd_vm_syscall_cpi_c;

    ulong instr_va, infos_va, n_infos;
    if( abi==0 ) rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
    else         c_cpi_build   ( vm, cfg, &instr_va, &infos_va, &n_infos );
    ulong ret = 0UL;
    FD_TEST( fn( vm, instr_va, infos_va, n_infos, 0UL, 0UL, &ret ) == FD_VM_SUCCESS );

    if( abi==0 ) rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
    else         c_cpi_build   ( vm, cfg, &instr_va, &infos_va, &n_infos );
    ret = 0UL;
    FD_TEST( fn( vm, instr_va, infos_va, n_infos, 0UL, 0UL, &ret ) == FD_VM_SUCCESS );
  }
}

static void
test_stack_depth_limit( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );

  static int const cs[4] = { 0, 1, 1, 1 };
  static int const cv[4] = { 0, 0, 1, 1 };
  static int const cd[4] = { 0, 0, 0, 1 };

  for( int c=0; c<4; c++ ) {
    for( int dep=0; dep<2; dep++ ) {
      for( int abi=0; abi<2; abi++ ) {
        cfg->spar=cs[c]; cfg->vasa=cv[c]; cfg->dm=cd[c]; cfg->is_deprecated=dep;
        env_build( mini, cfg );
        fd_vm_t * vm = mini->vm;

        ulong instr_va, infos_va, n_infos;
        if( abi==0 ) rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
        else         c_cpi_build   ( vm, cfg, &instr_va, &infos_va, &n_infos );

        fd_runtime_t * rt = mini->runtime;
        for( ulong lvl=1UL; lvl < FD_MAX_INSTRUCTION_STACK_DEPTH; lvl++ ) {
          fd_instr_info_t * fi = &rt->instr.trace[ lvl ];
          memset( fi, 0, sizeof(*fi) );
          fi->program_id = 0U;
          rt->instr.stack[ lvl ] = (fd_exec_instr_ctx_t){
            .instr   = fi,
            .runtime = rt,
            .txn_out = vm->instr_ctx->txn_out,
            .bank    = vm->instr_ctx->bank,
          };
        }
        rt->instr.trace_length = FD_MAX_INSTRUCTION_STACK_DEPTH;
        rt->instr.stack_sz     = (uchar)FD_MAX_INSTRUCTION_STACK_DEPTH;

        ulong ret = 0UL;
        cpi_syscall_fn_t fn = (abi==0) ? fd_vm_syscall_cpi_rust : fd_vm_syscall_cpi_c;
        int got = fn( vm, instr_va, infos_va, n_infos, 0UL, 0UL, &ret );
        if( FD_UNLIKELY( got != FD_EXECUTOR_INSTR_ERR_CALL_DEPTH ) ) {
          FD_LOG_ERR(( "test_stack_depth_limit: combo=%d dep=%d abi=%s got=%d", c, dep, abi==0?"rust":"c", got ));
        }
      }
    }
  }
}

static void
test_sequential_cpis( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );

  for( int abi=0; abi<2; abi++ ) {
    FD_TEST( run_one( mini, cfg, /*rust_abi=*/abi==0 ) == FD_VM_SUCCESS );
    FD_TEST( run_one( mini, cfg, /*rust_abi=*/abi==0 ) == FD_VM_SUCCESS );
  }

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_sequential_cpis", e );
}

static void
test_sequential_cpis_state_visible( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_write_data_text( cfg->text_buf, 0UL, 0xBB, 4UL );

  FD_TEST( run_one( mini, cfg, /*rust_abi=*/1 ) == FD_VM_SUCCESS );
  uchar * d1 = (uchar *)g_acct_metas[0] + sizeof(fd_account_meta_t);
  for( ulong i=0UL; i<4UL; i++ ) FD_TEST( d1[i] == 0xBB );

  FD_TEST( run_one( mini, cfg, /*rust_abi=*/1 ) == FD_VM_SUCCESS );
  uchar * d2 = (uchar *)g_acct_metas[0] + sizeof(fd_account_meta_t);
  for( ulong i=0UL; i<4UL; i++ ) FD_TEST( d2[i] == 0xBB );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  run_matrix( mini, cfg, "test_sequential_cpis_state_visible", e );
}

static void
test_sequential_cpis_modify_same_account( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );

  cfg->text_sz = build_grow_then_write_text( cfg->text_buf, 0UL, 16UL, 0xAA, 8UL );
  FD_TEST( run_one( mini, cfg, /*rust_abi=*/1 ) == FD_VM_SUCCESS );
  FD_TEST( g_acct_metas[0]->dlen == 16UL );
  uchar * d1 = (uchar *)g_acct_metas[0] + sizeof(fd_account_meta_t);
  for( ulong i=0UL; i<8UL; i++ ) FD_TEST( d1[i] == 0xAA );

  cfg->text_sz = build_grow_then_write_text( cfg->text_buf, 0UL, 16UL, 0xFF, 8UL );
  FD_TEST( run_one( mini, cfg, /*rust_abi=*/1 ) == FD_VM_SUCCESS );
  FD_TEST( g_acct_metas[0]->dlen == 16UL );
  uchar * d2 = (uchar *)g_acct_metas[0] + sizeof(fd_account_meta_t);
  for( ulong i=0UL; i<8UL; i++ ) FD_TEST( d2[i] == 0xFF );

  int e[4][2][2]; expect_all( e, FD_VM_SUCCESS );
  for( int c=1;c<4;c++) for(int a=0;a<2;a++) e[c][1][a] = FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC;
  run_matrix( mini, cfg, "test_sequential_cpis_modify_same_account", e );
}

static void
test_callee_returns_error( fd_svm_mini_t * mini ) {
  cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
  cfg->text_sz = build_error_return_text( cfg->text_buf, 42UL );

  cfg->spar=0; cfg->vasa=0; cfg->dm=0; cfg->is_deprecated=0;
  int err_observed = run_one( mini, cfg, /*rust_abi=*/1 );
  FD_TEST( err_observed != FD_VM_SUCCESS );

  int e[4][2][2]; expect_all( e, err_observed );
  run_matrix( mini, cfg, "test_callee_returns_error", e );
}

static void
test_cpi_to_authorized_program_restricted( fd_svm_mini_t * mini ) {
  for( int abi=0; abi<2; abi++ ) {
    cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
    cfg->outer[0].is_writable = 0;
    cfg->cpi_meta_writable[0] = 0;

    env_build( mini, cfg );
    fd_vm_t * vm = mini->vm;
    ulong instr_va, infos_va, n_infos;
    if( abi==0 ) rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
    else         c_cpi_build   ( vm, cfg, &instr_va, &infos_va, &n_infos );

    if( abi==0 ) {
      fd_vm_rust_instruction_t * instr = (fd_vm_rust_instruction_t *)
        ( vm->heap + (instr_va - HEAP_VA(0)) );
      memcpy( instr->pubkey, fd_solana_ed25519_sig_verify_program_id.uc, 32 );
    } else {
      fd_vm_c_instruction_t * instr = (fd_vm_c_instruction_t *)
        ( vm->heap + (instr_va - HEAP_VA(0)) );
      memcpy( vm->heap + (instr->program_id_addr - HEAP_VA(0)),
              fd_solana_ed25519_sig_verify_program_id.uc, 32 );
    }

    cpi_syscall_fn_t fn = (abi==0) ? fd_vm_syscall_cpi_rust : fd_vm_syscall_cpi_c;
    ulong ret = 0UL;
    int got = fn( vm, instr_va, infos_va, n_infos, 0UL, 0UL, &ret );
    FD_TEST( got == FD_VM_SYSCALL_ERR_PROGRAM_NOT_SUPPORTED );
  }
}

/* CU exhaustion mid-callee-execution. */
static void
test_callee_cu_exhaustion_during( fd_svm_mini_t * mini ) {
  for( int abi=0; abi<2; abi++ ) {
    cpi_test_cfg_t cfg[1]; simple_writable_cfg( cfg );
    cfg->text_sz = build_burn_cus_text( cfg->text_buf, 60UL );

    env_build( mini, cfg );
    fd_vm_t * vm = mini->vm;
    ulong instr_va, infos_va, n_infos;
    if( abi==0 ) rust_cpi_build( vm, cfg, &instr_va, &infos_va, &n_infos );
    else         c_cpi_build   ( vm, cfg, &instr_va, &infos_va, &n_infos );

    vm->cu = FD_VM_INVOKE_UNITS + 30UL;

    cpi_syscall_fn_t fn = (abi==0) ? fd_vm_syscall_cpi_rust : fd_vm_syscall_cpi_c;
    ulong ret = 0UL;
    int got = fn( vm, instr_va, infos_va, n_infos, 0UL, 0UL, &ret );
    FD_TEST( got != FD_VM_SUCCESS );
  }
}

int
main( int argc, char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  test_escalation_writable                    ( mini );
  test_signer_demotion                        ( mini );
  test_cpi_demotion_input_region_not_clobbered( mini );

  /* ===== Account translation ===== */
  test_missing_account                          ( mini );
  test_duplicate_accounts                       ( mini );
  test_executable_account                       ( mini );
  test_cpi_dup_writable_or_merge                ( mini );
  test_cpi_dup_signer_or_merge                  ( mini );
  test_empty_data_account                       ( mini );
  test_max_data_length                          ( mini );
  test_zero_account_cpi                         ( mini );
  test_zero_data_cpi                            ( mini );
  test_max_instruction_accounts_at_limit        ( mini );
  test_exceed_max_account_infos                 ( mini );
  test_account_infos_at_max_limit               ( mini );
  test_exceed_max_instruction_accounts          ( mini );
  test_carrier_overflow_max_instruction_accounts( mini );
  test_mixed_carrier                            ( mini );

  /* ===== Pointer equality checks ===== */
  test_spar_bad_owner                             ( mini );
  test_spar_bad_lamports                          ( mini );
  test_spar_bad_data                              ( mini );
  test_account_infos_array_in_input_region        ( mini );
  test_account_info_struct_in_input_region        ( mini );
  test_data_refcell_vec_in_input_region           ( mini );
  test_data_in_rodata_under_no_spar               ( mini );
  test_caller_lamports_box_in_rodata_under_no_spar( mini );

  /* ===== lamports / owner / data update propagation ===== */
  test_length_grow_propagation                     ( mini );
  test_length_shrink_propagation                   ( mini );
  test_lamports_change                             ( mini );
  test_owner_change                                ( mini );
  test_region_size_update_under_vasa               ( mini );
  test_region_size_shrink_under_vasa               ( mini );
  test_region_size_unchanged_when_callee_no_modify ( mini );
  test_lamports_noop                               ( mini );
  test_owner_noop                                  ( mini );
  test_data_noop                                   ( mini );
  test_lamports_change_readonly                    ( mini );
  test_owner_change_readonly                       ( mini );
  test_owner_change_to_system_program              ( mini );
  test_lamports_uint64_max                         ( mini );
  test_lamports_drain_to_zero                      ( mini );
  test_multi_field_update_in_cpi                   ( mini );
  test_owner_change_last_ordering                  ( mini );
  test_executable_flag_immutable_via_cpi           ( mini );
  test_caller_view_propagated_via_update_callee_acc( mini );

  /* ===== Realloc / data growth ===== */
  test_realloc_cap_exact_boundary         ( mini );
  test_realloc_to_exact_cap               ( mini );
  test_realloc_cap_exceeded               ( mini );
  test_callee_modifies_outer_readonly     ( mini );
  test_empty_grown_to_nonzero             ( mini );
  test_already_at_max_grow_attempt        ( mini );
  test_callee_writes_within_data          ( mini );
  test_callee_writes_past_dlen            ( mini );
  test_growth_budget_exhausted            ( mini );
  test_multi_account_realloc_within_budget( mini );
  test_shrink_to_zero                     ( mini );
  test_shrink_below_orig_data_len         ( mini );
  test_dm_shared_account_first_write      ( mini );

  /* ===== Readonly account mutations ===== */
  test_callee_readonly_with_caller_changed_dlen ( mini );
  test_callee_readonly_with_caller_changed_owner( mini );

  /* ===== PDA signers ===== */
  test_pda_signer_valid                 ( mini );
  test_pda_signer_invalid_seeds         ( mini );
  test_pda_signer_multiple              ( mini );
  test_empty_signer_seeds               ( mini );
  test_too_many_signers                 ( mini );
  test_too_many_seeds_per_signer        ( mini );
  test_seed_too_long                    ( mini );

  /* ===== Borrow lifecycle ===== */
  test_entry_borrow_conflict                   ( mini );
  test_borrow_lifecycle                        ( mini );
  test_callee_borrow_modify_release_lifecycle  ( mini );
  test_caller_borrow_released_before_cpi       ( mini );
  test_sequential_cpis_re_borrow               ( mini );

  /* ===== Stack depth / sequential ===== */
  test_stack_depth_limit                  ( mini );
  test_sequential_cpis                    ( mini );
  test_sequential_cpis_state_visible      ( mini );
  test_sequential_cpis_modify_same_account( mini );

  /* ===== Error propagation / restricted programs ===== */
  test_callee_returns_error                ( mini );
  test_cpi_to_authorized_program_restricted( mini );
  test_callee_cu_exhaustion_during         ( mini );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
