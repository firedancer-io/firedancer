#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_init_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_init_h

/* fd_runtime_init.h provides APIs for backing up and restoring a Solana
   runtime environment.  This file must not depend on fd_executor.h. */

#include "../fd_flamenco_base.h"
#include "../../funk/fd_funk_rec.h"

#define FD_RUNTIME_ENC_BINCODE 0xB13C0DEFU /* classic bincode encoding */
#define FD_RUNTIME_ENC_ARCHIVE 0xA3C417EAU /* archival encoding */

/* https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L36-L38 */
#define FD_FEATURE_SIZEOF      (9UL)

FD_PROTOTYPES_BEGIN

/* fd_features_restore loads all known feature accounts from the
   accounts database.  This is used when initializing bank from a
   snapshot. */

void
fd_features_restore( fd_bank_t *               bank,
                     fd_funk_t *               funk,
                     fd_funk_txn_xid_t const * xid );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_init_h */
