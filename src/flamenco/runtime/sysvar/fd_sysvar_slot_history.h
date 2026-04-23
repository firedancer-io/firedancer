#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_slot_history_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_slot_history_h

#include "../../fd_flamenco_base.h"
#include "../fd_bank.h"

#define FD_SLOT_HISTORY_SLOT_FOUND     (0)
#define FD_SLOT_HISTORY_SLOT_FUTURE    (-1)
#define FD_SLOT_HISTORY_SLOT_NOT_FOUND (-2)
#define FD_SLOT_HISTORY_SLOT_TOO_OLD   (-3)

/* https://github.com/solana-labs/solana/blob/v1.18.26/sdk/program/src/slot_history.rs#L43 */
#define FD_SLOT_HISTORY_MAX_ENTRIES (1024UL * 1024UL)

struct fd_slot_history_view {
  uchar const * bits;
  ulong         blocks_len;
  ulong         bits_len;
  ulong         next_slot;
};
typedef struct fd_slot_history_view fd_slot_history_view_t;

FD_PROTOTYPES_BEGIN

void
fd_sysvar_slot_history_init( fd_bank_t *               bank,
                             fd_accdb_user_t *         accdb,
                             fd_funk_txn_xid_t const * xid,
                             fd_capture_ctx_t *        capture_ctx );

void
fd_sysvar_slot_history_update( fd_bank_t *               bank,
                               fd_accdb_user_t *         accdb,
                               fd_funk_txn_xid_t const * xid,
                               fd_capture_ctx_t *        capture_ctx );

int
fd_sysvar_slot_history_validate( uchar const * data,
                                 ulong         sz );

fd_slot_history_view_t *
fd_sysvar_slot_history_view( fd_slot_history_view_t * view,
                             uchar const *            data,
                             ulong                    sz );

/* Returns FD_SLOT_HISTORY_SLOT_*. */
int
fd_sysvar_slot_history_find_slot( fd_slot_history_view_t const * view,
                                  ulong                          slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_slot_history_h */
