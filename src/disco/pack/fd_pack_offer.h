#ifndef HEADER_fd_src_disco_pack_fd_pack_offer_h
#define HEADER_fd_src_disco_pack_fd_pack_offer_h

/* fd_pack_offer estimates what a transaction pays the validator before
   it executes, for bundle observability metrics: its priority fee, and
   the lamports it sends to Jito tip accounts with top-level System
   program transfers ("static tip").  Tips paid through a CPI are not
   visible here.  Never used for scheduling. */

#include "../../ballet/txn/fd_txn.h"

struct fd_pack_offer {
  ulong static_tip;   /* lamports */
  ulong priority_fee; /* lamports, as computed by fd_pack_compute_cost; 0 if that fails */
};
typedef struct fd_pack_offer fd_pack_offer_t;

FD_PROTOTYPES_BEGIN

/* fd_pack_offer_compute fills out for the transaction txn with payload
   payload.  alt_accts points to the addresses loaded from address
   lookup tables, indexed from 0 (i.e. the account with index
   fd_txn_account_cnt( txn, IMM ) is alt_accts[0]); it may be NULL if
   the transaction loads no addresses.  Returns out. */

fd_pack_offer_t *
fd_pack_offer_compute( fd_txn_t       const * txn,
                       uchar          const * payload,
                       fd_acct_addr_t const * alt_accts,
                       fd_pack_offer_t      * out );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_pack_fd_pack_offer_h */
