#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_hashes_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_hashes_h

#include "../../../funk/fd_funk.h"
#include "../../../funk/fd_funk_txn.h"
#include "../../fd_flamenco_base.h"
#include "../../types/fd_types.h"
/* The slot hashes sysvar contains the most recent hashes of the slot's parent bank hashes. */

/* FD_SYSVAR_SLOT_HASHES_CAP is the max number of entries that the
   "slot hashes" sysvar will include.

   https://github.com/anza-xyz/agave/blob/6398ddf6ab8a8f81017bf675ab315a70067f0bf0/sdk/program/src/slot_hashes.rs#L19 */

#define FD_SYSVAR_SLOT_HASHES_CAP   (512UL)

FD_PROTOTYPES_BEGIN

ulong
fd_sysvar_slot_hashes_footprint( ulong slot_hashes_cap );

void *
fd_sysvar_slot_hashes_new( void *   mem,
                           ulong    slot_hashes_cap );

fd_slot_hashes_global_t *
fd_sysvar_slot_hashes_join( void *            shmem,
                            fd_slot_hash_t ** slot_hash );

void *
fd_sysvar_slot_hashes_leave( fd_slot_hashes_global_t * slot_hashes_global,
                             fd_slot_hash_t *          slot_hash );

void *
fd_sysvar_slot_hashes_delete( void * mem );

/* Write a funk entry for the slot hashes sysvar account (exposed for tests) */
void
fd_sysvar_slot_hashes_write( fd_bank_t *               bank,
                             fd_funk_t *               funk,
                             fd_funk_txn_xid_t const * xid,
                             fd_capture_ctx_t *        capture_ctx,
                             fd_slot_hashes_global_t * slot_hashes_global );

void
fd_sysvar_slot_hashes_init( fd_bank_t *               bank,
                            fd_funk_t *               funk,
                            fd_funk_txn_xid_t const * xid,
                            fd_capture_ctx_t *        capture_ctx,
                            fd_spad_t *               runtime_spad );

/* Update the slot hashes sysvar account. This should be called at the end of every slot, before execution commences. */
void
fd_sysvar_slot_hashes_update( fd_bank_t *               bank,
                              fd_funk_t *               funk,
                              fd_funk_txn_xid_t const * xid,
                              fd_capture_ctx_t *        capture_ctx,
                              fd_spad_t *               runtime_spad );

/* fd_sysvar_slot_hashes_read reads the slot hashes sysvar from funk.
   If the account doesn't exist in funk or if the account has zero
   lamports, this function returns NULL. */
fd_slot_hashes_global_t *
fd_sysvar_slot_hashes_read( fd_funk_t *               funk,
                            fd_funk_txn_xid_t const * xid,
                            fd_spad_t *               spad );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_slot_hashes_h */
