#include "fd_program_lookup.h"
#include "fd_system_ids.h"

#include "../../ballet/base58/fd_base58.h"
#include "../../disco/pack/fd_pack.h"
#include "../../disco/pack/fd_pack_cost.h"

#include "program/fd_address_lookup_table_program.h"
#include "program/fd_bpf_loader_program.h"
#include "program/fd_loader_v4_program.h"
#include "program/fd_compute_budget_program.h"
#include "program/fd_config_program.h"
#include "program/fd_precompiles.h"
#include "program/fd_stake_program.h"
#include "program/fd_system_program.h"
#include "program/fd_builtin_programs.h"
#include "program/fd_vote_program.h"
#include "program/fd_zk_elgamal_proof_program.h"
#include "program/fd_bpf_program_util.h"


struct fd_native_prog_info {
  fd_pubkey_t key;
  fd_exec_instr_fn_t fn;
  uchar is_bpf_loader;
};
typedef struct fd_native_prog_info fd_native_prog_info_t;

#define MAP_PERFECT_NAME fd_native_program_fn_lookup_tbl
#define MAP_PERFECT_LG_TBL_SZ 4
#define MAP_PERFECT_T fd_native_prog_info_t
#define MAP_PERFECT_HASH_C 478U
#define MAP_PERFECT_KEY key.uc
#define MAP_PERFECT_KEY_T fd_pubkey_t const *
#define MAP_PERFECT_ZERO_KEY  (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (!memcmp( (k1), (k2), 32UL ))

#define PERFECT_HASH( u ) (((MAP_PERFECT_HASH_C*(u))>>28)&0xFU)

#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15, \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
                                          PERFECT_HASH( (a08 | (a09<<8) | (a10<<16) | (a11<<24)) )
#define MAP_PERFECT_HASH_R( ptr ) PERFECT_HASH( fd_uint_load_4( (uchar const *)ptr + 8UL ) )

#define MAP_PERFECT_0       ( VOTE_PROG_ID            ), .fn = fd_vote_program_execute,                      .is_bpf_loader = 0
#define MAP_PERFECT_1       ( SYS_PROG_ID             ), .fn = fd_system_program_execute,                    .is_bpf_loader = 0
#define MAP_PERFECT_2       ( CONFIG_PROG_ID          ), .fn = fd_config_program_execute,                    .is_bpf_loader = 0
#define MAP_PERFECT_3       ( STAKE_PROG_ID           ), .fn = fd_stake_program_execute,                     .is_bpf_loader = 0
#define MAP_PERFECT_4       ( COMPUTE_BUDGET_PROG_ID  ), .fn = fd_compute_budget_program_execute,            .is_bpf_loader = 0
#define MAP_PERFECT_5       ( ADDR_LUT_PROG_ID        ), .fn = fd_address_lookup_table_program_execute,      .is_bpf_loader = 0
#define MAP_PERFECT_6       ( ZK_EL_GAMAL_PROG_ID     ), .fn = fd_executor_zk_elgamal_proof_program_execute, .is_bpf_loader = 0
#define MAP_PERFECT_7       ( BPF_LOADER_1_PROG_ID    ), .fn = fd_bpf_loader_program_execute,                .is_bpf_loader = 1
#define MAP_PERFECT_8       ( BPF_LOADER_2_PROG_ID    ), .fn = fd_bpf_loader_program_execute,                .is_bpf_loader = 1
#define MAP_PERFECT_9       ( BPF_UPGRADEABLE_PROG_ID ), .fn = fd_bpf_loader_program_execute,                .is_bpf_loader = 1
#define MAP_PERFECT_10      ( LOADER_V4_PROG_ID       ), .fn = fd_loader_v4_program_execute,                 .is_bpf_loader = 1

#include "../../util/tmpl/fd_map_perfect.c"
#undef PERFECT_HASH

#define MAP_PERFECT_NAME fd_native_precompile_program_fn_lookup_tbl
#define MAP_PERFECT_LG_TBL_SZ 2
#define MAP_PERFECT_T fd_native_prog_info_t
#define MAP_PERFECT_HASH_C 63546U
#define MAP_PERFECT_KEY key.uc
#define MAP_PERFECT_KEY_T fd_pubkey_t const *
#define MAP_PERFECT_ZERO_KEY  (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (!memcmp( (k1), (k2), 32UL ))

#define PERFECT_HASH( u ) (((MAP_PERFECT_HASH_C*(u))>>30)&0x3U)

#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15, \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
                                          PERFECT_HASH( (a00 | (a01<<8)) )
#define MAP_PERFECT_HASH_R( ptr ) PERFECT_HASH( fd_uint_load_2( (uchar const *)ptr ) )

#define MAP_PERFECT_0      ( ED25519_SV_PROG_ID      ), .fn = fd_precompile_ed25519_verify
#define MAP_PERFECT_1      ( KECCAK_SECP_PROG_ID     ), .fn = fd_precompile_secp256k1_verify
#define MAP_PERFECT_2      ( SECP256R1_PROG_ID       ), .fn = fd_precompile_secp256r1_verify

#include "../../util/tmpl/fd_map_perfect.c"
#undef PERFECT_HASH

fd_exec_instr_fn_t
fd_program_lookup_precompile_entrypoint( fd_pubkey_t const * pubkey ) {
  const fd_native_prog_info_t null_function = {0};
  return fd_native_precompile_program_fn_lookup_tbl_query( pubkey, &null_function )->fn;
}

int
fd_program_lookup_native_entrypoint( fd_txn_account_t const * prog_acc,
                                   fd_exec_txn_ctx_t *      txn_ctx,
                                   fd_exec_instr_fn_t *     native_prog_fn,
                                   uchar *                  is_precompile ) {
  /* First lookup to see if the program key is a precompile */
  *is_precompile = 0;
  *native_prog_fn = fd_program_lookup_precompile_entrypoint( prog_acc->pubkey );
  if( FD_UNLIKELY( *native_prog_fn!=NULL ) ) {
    *is_precompile = 1;
    return 0;
  }

  fd_pubkey_t const * pubkey = prog_acc->pubkey;
  fd_pubkey_t const * owner  = prog_acc->vt->get_owner( prog_acc );

  /* Native programs should be owned by the native loader...
     This will not be the case though once core programs are migrated to BPF. */
  int is_native_program = !memcmp( owner, fd_solana_native_loader_id.key, sizeof(fd_pubkey_t) );

  if( !is_native_program && FD_FEATURE_ACTIVE_BANK( txn_ctx->bank, remove_accounts_executable_flag_checks ) ) {
    if( FD_UNLIKELY( !fd_pubkey_is_bpf_loader( owner ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
    }
  }

  fd_pubkey_t const * lookup_pubkey = is_native_program ? pubkey : owner;

  /* Migrated programs must be executed via the corresponding BPF
     loader(s), not natively. This check is performed at the transaction
     level, but we re-check to please the instruction level (and below)
     fuzzers. */
  uchar has_migrated;
  if( FD_UNLIKELY( fd_is_migrating_builtin_program( txn_ctx, lookup_pubkey, &has_migrated ) && has_migrated ) ) {
    *native_prog_fn = NULL;
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
  }

  fd_native_prog_info_t const null_function = {0};
  *native_prog_fn                           = fd_native_program_fn_lookup_tbl_query( lookup_pubkey, &null_function )->fn;
  return 0;
}

uchar
fd_pubkey_is_bpf_loader( fd_pubkey_t const * pubkey ) {
  fd_native_prog_info_t const null_function = {0};
  return fd_native_program_fn_lookup_tbl_query( pubkey, &null_function )->is_bpf_loader;
}
