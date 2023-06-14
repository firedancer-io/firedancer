#include "../fd_types.h"
#include "../fd_banks_solana.h"
#include "../fd_acc_mgr.h"
#include "../fd_hashes.h"
#include "../fd_runtime.h"
#include "fd_sysvar.h"

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

void fd_sysvar_set(fd_global_ctx_t *state, const unsigned char *owner, const unsigned char *pubkey, unsigned char *data, unsigned long sz, ulong slot) {
  // MAYBE, as a defense in depth thing, we should only let it reset the lamports on initial creation?

  fd_solana_account_t account = {
    .lamports = (sz + 128) * ((ulong) ((double)state->genesis_block.rent.lamports_per_uint8_year * state->genesis_block.rent.exemption_threshold)),
    .rent_epoch = 0,
    .data_len = sz,
    .data = (unsigned char *) data,
    .executable = (uchar) 0
  };
  fd_memcpy( account.owner.key, owner, 32 );

  fd_acc_mgr_write_structured_account( state->acc_mgr, state->funk_txn, slot, (fd_pubkey_t *)  pubkey, &account );
}
