#include "../fd_banks_solana.h"
#include "../fd_acc_mgr.h"
#include "../fd_hashes.h"
#include "../fd_runtime.h"
#include "fd_sysvar.h"

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

void fd_sysvar_set(fd_global_ctx_t *global, const unsigned char *owner, const unsigned char *pubkey, unsigned char *data, unsigned long sz, ulong slot) {
  // TODO: as a defense in depth thing, we should only let it reset the lamports on initial creation?

  fd_solana_account_t account = {
    .lamports = (sz + 128) * ((ulong) ((double)global->bank.rent.lamports_per_uint8_year * global->bank.rent.exemption_threshold)),
    .rent_epoch = 0,
    .data_len = sz,
    .data = (unsigned char *) data,
    .executable = (uchar) 0
  };
  fd_memcpy( account.owner.key, owner, 32 );

  fd_acc_mgr_write_structured_account( global->acc_mgr, global->funk_txn, slot, (fd_pubkey_t *)  pubkey, &account );
}
