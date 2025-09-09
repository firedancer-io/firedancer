#include "fd_sysvar_last_restart_slot.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../fd_runtime.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../../accdb/fd_accdb_sync.h"

void
fd_sysvar_last_restart_slot_write(
    fd_exec_slot_ctx_t * slot_ctx,
    fd_sol_sysvar_last_restart_slot_t const * sysvar
) {
  uchar enc[ 8 ];
  FD_STORE( ulong, enc, sysvar->slot );
  fd_sysvar_account_update( slot_ctx, &fd_sysvar_last_restart_slot_id, enc, sizeof(enc) );
}

void
fd_sysvar_last_restart_slot_init( fd_exec_slot_ctx_t * slot_ctx ) {

  if( !FD_FEATURE_ACTIVE_BANK( slot_ctx->bank, last_restart_slot_sysvar ) ) {
    return;
  }

  fd_sol_sysvar_last_restart_slot_t sysvar = {0};
  fd_sysvar_last_restart_slot_write( slot_ctx, &sysvar );
}

/* https://github.com/anza-xyz/agave/blob/v2.3.2/runtime/src/bank.rs#L2217 */

ulong
fd_sysvar_last_restart_slot_derive(
    fd_hard_forks_global_t const * hard_forks,
    ulong                          current_slot
) {

  if( FD_UNLIKELY( hard_forks->hard_forks_len == 0 ) ) {
    /* SIMD-0047: The first restart slot should be `0` */
    return 0UL;
  }

  fd_slot_pair_t const * head = fd_hard_forks_hard_forks_join( (fd_hard_forks_global_t *)hard_forks );
  fd_slot_pair_t const * tail = head + hard_forks->hard_forks_len - 1UL;

  for( fd_slot_pair_t const *pair = tail; pair >= head; pair-- ) {
    if( pair->slot <= current_slot ) {
      return pair->slot;
    }
  }

  return 0UL;
}

fd_sol_sysvar_last_restart_slot_t *
fd_sysvar_last_restart_slot_read(
    fd_accdb_client_t *                 accdb,
    fd_sol_sysvar_last_restart_slot_t * out
) {
  FD_ACCDB_READ_BEGIN( accdb, &fd_sysvar_last_restart_slot_id, rec ) {
    return fd_bincode_decode_static(
        sol_sysvar_last_restart_slot, out,
        fd_accdb_ref_data   ( rec ),
        fd_accdb_ref_data_sz( rec ),
        &err );
  }
  FD_ACCDB_READ_END;
}

/* fd_sysvar_last_restart_slot_update is equivalent to
   Agave's solana_runtime::bank::Bank::update_last_restart_slot */

void
fd_sysvar_last_restart_slot_update(
    fd_exec_slot_ctx_t * slot_ctx,
    ulong                last_restart_slot_want
) {

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2093-L2095 */
  if( !FD_FEATURE_ACTIVE_BANK( slot_ctx->bank, last_restart_slot_sysvar ) ) return;

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2098-L2106 */
  ulong last_restart_slot_have = ULONG_MAX;
  fd_sol_sysvar_last_restart_slot_t sysvar;
  if( FD_LIKELY( fd_sysvar_last_restart_slot_read( slot_ctx->accdb, &sysvar ) ) ) {
    last_restart_slot_have = sysvar.slot;
  }

  /* https://github.com/solana-labs/solana/blob/v1.18.18/runtime/src/bank.rs#L2122-L2130 */
  if( last_restart_slot_have != last_restart_slot_want ) {
    sysvar.slot = last_restart_slot_want;
    fd_sysvar_last_restart_slot_write( slot_ctx, &sysvar );
  }
}
