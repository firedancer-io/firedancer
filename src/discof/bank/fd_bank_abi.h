#ifndef HEADER_fd_src_discof_fd_bank_abi_h
#define HEADER_fd_src_discof_fd_bank_abi_h

// Make sure the wrong header file doesn't also sneak in...
#define HEADER_fd_src_discoh_fd_bank_abi_h

#include "../../disco/pack/fd_pack.h"

#define FD_BANK_ABI_TXN_INIT_SUCCESS                   ( 0)
#define FD_BANK_ABI_TXN_INIT_ERR_ACCOUNT_NOT_FOUND     (-1)
#define FD_BANK_ABI_TXN_INIT_ERR_INVALID_ACCOUNT_OWNER (-2)
#define FD_BANK_ABI_TXN_INIT_ERR_INVALID_ACCOUNT_DATA  (-3)
#define FD_BANK_ABI_TXN_INIT_ERR_ACCOUNT_UNINITIALIZED (-4)
#define FD_BANK_ABI_TXN_INIT_ERR_INVALID_LOOKUP_INDEX  (-5)

FD_PROTOTYPES_BEGIN

/* This function resolves the address lookup tables for the provided
   transaction by writing them out to the out_lut_accts.  The accounts
   are written, writable first, then readable, in the order they are
   referenced by the transaction.

   The function returns FD_BANK_ABI_TXN_INIT_SUCCESS on success and one
   of the FD_BANK_ABI_TXN_INIT_ERR_* error codes on failure.

   The address lookup table is retrieved as-of a particular slot that's
   provided.  The slot is important in determining if the ALUT has been
   deactivated yet, or if it has been extended and the extension is in
   effect (extensions do not become active on the slot they occur in). */

int
fd_bank_abi_resolve_address_lookup_tables( void const *     bank,
                                           int              fixed_root,
                                           ulong            slot,
                                           fd_txn_t const * txn,
                                           uchar const *    payload,
                                           fd_acct_addr_t * out_lut_accts );


void fd_ext_bank_release( void const * bank );

int
fd_ext_admin_rpc_set_identity( uchar const * identity_keypair,
                               int           require_tower );

void
fd_ext_bank_acquire( void const * bank );

int
fd_ext_bank_load_account( void const *  bank,
                          int           fixed_root,
                          uchar const * addr,
                          uchar *       owner,
                          uchar *       data,
                          ulong *       data_sz );

void
fd_ext_poh_register_tick( void const * bank, uchar const * hash );

void
fd_ext_poh_signal_leader_change( void * sender );

FD_PROTOTYPES_END

#endif
