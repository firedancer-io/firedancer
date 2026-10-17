#ifndef HEADER_fd_src_discof_backup_fd_strmk_keys_h
#define HEADER_fd_src_discof_backup_fd_strmk_keys_h

/* fd_strmk_keys.h is the feed of account keys from the exec tiles to
   the stream maker.  Once an exec tile has run a transaction it sends
   the stream maker every key the transaction looked up in the accounts
   database, so that a fast boot stream can carry those accounts to a
   peer. */

#include "../../disco/stem/fd_stem.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_executor.h"

/* 64 account keys, one program data account per program, and up to
   127 lookup tables. */
#define FD_STRMK_READ_KEYS_MAX (255UL)

FD_STATIC_ASSERT( FD_STRMK_READ_KEYS_MAX>=2UL*MAX_TX_ACCOUNT_LOCKS+FD_TXN_ADDR_TABLE_LOOKUP_MAX, read_keys_max );

struct fd_strmk_keys_msg {
  ulong       slot;
  ulong       key_cnt;
  fd_pubkey_t keys[ FD_STRMK_READ_KEYS_MAX ];
};

typedef struct fd_strmk_keys_msg fd_strmk_keys_msg_t;

FD_PROTOTYPES_BEGIN

/* fd_strmk_keys_publish sends a transaction's keys to the stream
   maker on out link out_idx.  Replay sends every transaction of a
   block, committed or not.  bank is the bank the transaction ran on. */

static inline void
fd_strmk_keys_publish( fd_stem_context_t *  stem,
                       ulong                out_idx,
                       void *               out_mem,
                       ulong                out_chunk0,
                       ulong                out_wmark,
                       ulong *              out_chunk,
                       fd_bank_t const *    bank,
                       fd_txn_in_t const *  txn_in,
                       fd_txn_out_t const * txn_out ) {
  fd_strmk_keys_msg_t * msg = fd_chunk_to_laddr( out_mem, *out_chunk );
  msg->slot    = bank->f.slot;
  msg->key_cnt = fd_executor_read_keys( txn_in, txn_out, msg->keys );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, out_idx, bank->f.slot, *out_chunk, sizeof(fd_strmk_keys_msg_t), 0UL, 0UL, tspub );
  *out_chunk = fd_dcache_compact_next( *out_chunk, sizeof(fd_strmk_keys_msg_t), out_chunk0, out_wmark );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_strmk_keys_h */
