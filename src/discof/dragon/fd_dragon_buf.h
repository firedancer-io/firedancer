#ifndef HEADER_fd_src_discof_dragon_fd_dragon_buf_h
#define HEADER_fd_src_discof_dragon_fd_dragon_buf_h

/* fd_dragon_buf.h is the buffer the Dragon's Mouth service serves
   confirmed and finalized subscribers, and block subscribers, from.

   The geyser core reports every transaction and every account write
   once, when it happens on some bank, and reports the commitment
   levels above processed as slot statuses (fd_geyser_api.h).  A
   subscriber at confirmed or finalized is therefore served, at the
   moment its bank reaches that level, from what the service kept.
   That is this buffer: per bank, its transactions as the bytes they go
   out as and its account writes as the state each write left the
   account in.

   The buffer is a ring shaped like a link: an mcache of fixed depth
   and a dcache of fixed size, written in the order the records arrive
   and reclaimed in that order.  Nothing is freed: the ring overwrites
   its oldest bytes as it goes, so a bank whose oldest entry has been
   overwritten before it was served is lost, which the owner finds out
   when it comes to serve the bank (fd_dragon_buf_bank_live).

   A bank's entries are found through the mcache: the bank keeps the
   sequence numbers of its first and last entry, and a walk over that
   range skips the entries of other banks, which interleave when banks
   commit side by side.

   The writes of one bank to one account are deduplicated when the bank
   is served, to the write with the highest write version, which is
   what makes the set of them the block's account set (yellowstone
   block_reconstruction.rs:114-135).  The writes of one bank do not
   arrive in that order, because the transactions of a block commit in
   parallel.  A tombstone at ingest would free nothing, since the ring
   reclaims in order, so the losers are marked in place when the bank
   is served (fd_dragon_buf_dedup). */

#include "fd_geyser_api.h"
#include "../../tango/fd_tango_base.h"

#define FD_DRAGON_BUF_ALIGN (128UL)

/* The kinds of entry. */

#define FD_DRAGON_BUF_TXN  (0U)
#define FD_DRAGON_BUF_ACCT (1U)

/* The name masks an entry keeps per client: the names of the client's
   transactions filters that matched, of its transactions status
   filters, and of its blocks filters whose block the entry belongs
   to.  An account entry uses the first of the three for its accounts
   filters. */

#define FD_DRAGON_BUF_NAME_TXN    (0UL)
#define FD_DRAGON_BUF_NAME_STATUS (1UL)
#define FD_DRAGON_BUF_NAME_ACCT   (0UL)
#define FD_DRAGON_BUF_NAME_BLOCK  (2UL)
#define FD_DRAGON_BUF_NAME_CNT    (3UL)

/* FD_DRAGON_BUF_CLIENT_MAX is the number of client slots a mask
   covers. */

#define FD_DRAGON_BUF_CLIENT_MAX (64UL)

struct fd_dragon_buf;
typedef struct fd_dragon_buf fd_dragon_buf_t;

struct fd_dragon_buf_params {
  /* bank_max is the number of banks the buffer can hold state for at
     once, which has to cover every bank that can be in flight between
     a record arriving and its bank being rooted or dropped. */
  ulong bank_max;

  /* depth is the mcache depth, a power of two: the most entries the
     ring holds.  The footprint depends on it; mcache, dcache and base
     do not, and are only needed by fd_dragon_buf_new. */
  ulong depth;

  /* mcache and dcache are joined by the owner, and base is what the
     chunk indexes of the mcache lines are relative to: the workspace
     the dcache lives in when the objects come from a topology. */
  fd_frag_meta_t * mcache;
  uchar *          dcache;
  void *           base;
};

typedef struct fd_dragon_buf_params fd_dragon_buf_params_t;

/* fd_dragon_buf_hdr_t heads every entry.  The per client name masks
   follow it, FD_DRAGON_BUF_NAME_CNT per client of push_mask in slot
   order, and the kind's own header and bodies follow those.

   mask is the client slots whose own subscriptions the entry is for,
   status_mask the ones whose transactions status subscriptions it is
   for, and block_mask the ones whose blocks it belongs to.  All three
   are zero when the filters run at delivery instead.  push_mask is
   their union, which indexes the names.

   superseded marks an account write that a later write of the same
   bank to the same account replaced, set by fd_dragon_buf_dedup. */

struct fd_dragon_buf_hdr {
  ulong seq;
  ulong bank_seq;
  ulong slot;
  ulong sz;          /* the whole entry, header included, a multiple of 8 */
  ulong mask;
  ulong status_mask;
  ulong block_mask;
  ulong push_mask;
  uint  kind;
  uint  name_cnt;    /* popcount of push_mask */
  uint  superseded;
  uint  pad;
};

typedef struct fd_dragon_buf_hdr fd_dragon_buf_hdr_t;

/* fd_dragon_buf_txn_t is one committed transaction: the body of a
   geyser.SubscribeUpdateTransactionInfo, which an update wraps in its
   own fields and a block carries as one of its repeated transactions,
   the body of a geyser.SubscribeUpdateTransactionStatus, and what the
   transaction filters look at, for a buffer whose filters run at
   delivery.  The info bytes follow the header, the status bytes follow
   them, and the keys follow those, each at an 8 byte boundary. */

struct fd_dragon_buf_txn {
  ulong info_sz;
  ulong status_sz;
  ulong key_cnt;    /* 0 when the filters ran at ingest */
  uint  is_vote;
  uint  failed;
  uchar signature[ 64UL ];
};

typedef struct fd_dragon_buf_txn fd_dragon_buf_txn_t;

/* fd_dragon_buf_acct_t is one account write: the state it left the
   account in.  The data is kept as seg_cnt segments of the account's
   data_sz bytes, back to back behind the segment table: the whole
   account as one segment, or the union of the slices the matching
   subscriptions asked for. */

struct fd_dragon_buf_seg {
  ulong off;
  ulong len;
};

typedef struct fd_dragon_buf_seg fd_dragon_buf_seg_t;

struct fd_dragon_buf_acct {
  ulong write_version;
  ulong lamports;
  ulong data_sz;
  ulong seg_cnt;
  uint  executable;
  uint  has_signature;
  uchar pubkey   [ 32UL ];
  uchar owner    [ 32UL ];
  uchar signature[ 64UL ];
};

typedef struct fd_dragon_buf_acct fd_dragon_buf_acct_t;

/* fd_dragon_buf_bank_t is what the buffer keeps per bank: where its
   entries are, the block summary the bank reported when it froze, and
   whether the bank is still deliverable.

   block_mask is the clients a block of this bank is owed to, which is
   why every transaction and every account write of the bank is kept
   whatever the per-message filters matched.

   incomplete records that the owner gave up on the bank, so nothing
   is delivered for it at confirmed or finalized. */

struct fd_dragon_buf_bank {
  ulong bank_seq;   /* ULONG_MAX when the entry is free */
  ulong slot;

  ulong first_seq;  /* ULONG_MAX while the bank has no entries */
  ulong last_seq;
  ulong first_pos;  /* byte position of the first entry */
  ulong entry_cnt;
  ulong txn_cnt;
  ulong acct_cnt;   /* account writes, before deduplication */

  ulong block_mask;

  fd_geyser_block_meta_t meta;
  int                    has_meta;

  int   incomplete;
  int   sent_processed;
  int   sent_confirmed;
  int   sent_finalized;
};

typedef struct fd_dragon_buf_bank fd_dragon_buf_bank_t;

struct fd_dragon_buf_metrics {
  ulong bank_open_cnt;
  ulong bank_drop_cnt;
  ulong push_cnt[ 2 ];   /* entries written, by kind */
  ulong push_byte_cnt;   /* bytes written */
  ulong push_fail_cnt;   /* entries larger than the ring */
  ulong bank_full_cnt;   /* banks the table had no room for */
  ulong overrun_cnt;     /* banks whose entries the ring overwrote before they were served */
  ulong byte_hi;         /* the most bytes the ring held for unserved banks at once */
  ulong entry_hi;        /* the most entries it held for them at once */
};

typedef struct fd_dragon_buf_metrics fd_dragon_buf_metrics_t;

FD_PROTOTYPES_BEGIN

/* Entry layout ********************************************************/

FD_FN_CONST static inline ulong *
fd_dragon_buf_hdr_names( fd_dragon_buf_hdr_t * hdr ) {
  return (ulong *)( hdr+1 );
}

/* fd_dragon_buf_names returns the filter name mask of one client on an
   entry, which is 0 for a client the entry was never stored for.
   which is one of FD_DRAGON_BUF_NAME_*. */

FD_FN_PURE static inline ulong
fd_dragon_buf_names( fd_dragon_buf_hdr_t const * hdr,
                     ulong                       client_idx,
                     ulong                       which ) {
  ulong bit = 1UL<<client_idx;
  if( FD_UNLIKELY( !( hdr->push_mask & bit ) ) ) return 0UL;
  /* The name masks are stored for the clients of push_mask, in slot
     order, so a client's own set is behind the sets of the ones below
     it. */
  ulong n = (ulong)fd_ulong_popcnt( hdr->push_mask & (bit-1UL) );
  return ( (ulong const *)( hdr+1 ) )[ n*FD_DRAGON_BUF_NAME_CNT + which ];
}

FD_FN_PURE static inline void *
fd_dragon_buf_hdr_body( fd_dragon_buf_hdr_t * hdr ) {
  return (void *)( fd_dragon_buf_hdr_names( hdr ) + (ulong)hdr->name_cnt*FD_DRAGON_BUF_NAME_CNT );
}

FD_FN_CONST static inline uchar *
fd_dragon_buf_txn_info( fd_dragon_buf_txn_t * txn ) {
  return (uchar *)( txn+1 );
}

FD_FN_PURE static inline uchar *
fd_dragon_buf_txn_status( fd_dragon_buf_txn_t * txn ) {
  return fd_dragon_buf_txn_info( txn ) + fd_ulong_align_up( txn->info_sz, 8UL );
}

FD_FN_PURE static inline uchar (*
fd_dragon_buf_txn_keys( fd_dragon_buf_txn_t * txn ))[ 32UL ] {
  return (uchar (*)[ 32UL ])( fd_dragon_buf_txn_status( txn ) + fd_ulong_align_up( txn->status_sz, 8UL ) );
}

FD_FN_CONST static inline fd_dragon_buf_seg_t *
fd_dragon_buf_acct_seg( fd_dragon_buf_acct_t * acct ) {
  return (fd_dragon_buf_seg_t *)( acct+1 );
}

FD_FN_PURE static inline uchar *
fd_dragon_buf_acct_bytes( fd_dragon_buf_acct_t * acct ) {
  return (uchar *)( fd_dragon_buf_acct_seg( acct ) + acct->seg_cnt );
}

/* fd_dragon_buf_txn_sz and fd_dragon_buf_acct_sz are the entry sizes
   to ask fd_dragon_buf_push for.  name_cnt is popcount(push_mask). */

FD_FN_CONST static inline ulong
fd_dragon_buf_txn_sz( ulong name_cnt,
                      ulong info_sz,
                      ulong status_sz,
                      ulong key_cnt ) {
  return sizeof(fd_dragon_buf_hdr_t) + name_cnt*FD_DRAGON_BUF_NAME_CNT*sizeof(ulong)
       + sizeof(fd_dragon_buf_txn_t)
       + fd_ulong_align_up( info_sz, 8UL ) + fd_ulong_align_up( status_sz, 8UL ) + key_cnt*32UL;
}

FD_FN_CONST static inline ulong
fd_dragon_buf_acct_sz( ulong name_cnt,
                       ulong seg_cnt,
                       ulong byte_cnt ) {
  return sizeof(fd_dragon_buf_hdr_t) + name_cnt*FD_DRAGON_BUF_NAME_CNT*sizeof(ulong)
       + sizeof(fd_dragon_buf_acct_t) + seg_cnt*sizeof(fd_dragon_buf_seg_t) + byte_cnt;
}

/* Construction ********************************************************/

FD_FN_CONST ulong
fd_dragon_buf_align( void );

/* fd_dragon_buf_footprint returns the size of the memory region the
   buffer's own state needs, which is the bank table and the
   deduplication table, or 0 if the parameters are invalid.  The ring
   itself is the mcache and dcache the owner brings. */

ulong
fd_dragon_buf_footprint( fd_dragon_buf_params_t const * params );

/* fd_dragon_buf_new formats mem and takes the ring the parameters
   name, whose mcache must have depth entries.  Returns mem on success,
   NULL on failure (logs warning). */

void *
fd_dragon_buf_new( void *                         mem,
                   fd_dragon_buf_params_t const * params );

fd_dragon_buf_t *
fd_dragon_buf_join( void * mem );

/* Banks ***************************************************************/

/* fd_dragon_buf_bank returns the state of a bank, or NULL if the
   buffer holds none.  fd_dragon_buf_bank_open returns it, creating it
   if needed, or NULL if the table is full.  fd_dragon_buf_bank_drop
   frees the entry; the bank's bytes in the ring are reclaimed as the
   ring comes round to them. */

fd_dragon_buf_bank_t *
fd_dragon_buf_bank( fd_dragon_buf_t * buf,
                    ulong             bank_seq );

fd_dragon_buf_bank_t *
fd_dragon_buf_bank_open( fd_dragon_buf_t * buf,
                         ulong             bank_seq,
                         ulong             slot );

void
fd_dragon_buf_bank_drop( fd_dragon_buf_t *      buf,
                         fd_dragon_buf_bank_t * bank );

/* fd_dragon_buf_bank_live returns 1 if every entry of the bank is
   still in the ring, and 0 if the ring has come round and overwritten
   its oldest one, which counts the bank as overrun the first time it
   is seen. */

int
fd_dragon_buf_bank_live( fd_dragon_buf_t *      buf,
                         fd_dragon_buf_bank_t * bank );

/* fd_dragon_buf_bank_iter walks the banks the buffer holds state for.
   Start with idx 0 and stop when the return value is NULL; *idx is
   left pointing past the bank returned. */

fd_dragon_buf_bank_t *
fd_dragon_buf_bank_iter( fd_dragon_buf_t * buf,
                         ulong *           idx );

/* Entries *************************************************************/

/* fd_dragon_buf_push writes the next entry of a bank: sz bytes at the
   ring's write position, whose header is filled with the sequence
   number, bank, slot, size and kind, and whose masks, names and bodies
   the caller fills in before it does anything else with the buffer.
   Returns the header, or NULL if sz is larger than the ring can ever
   hold.  An entry that fits pushes the oldest bytes out of the ring,
   whatever bank they belong to. */

fd_dragon_buf_hdr_t *
fd_dragon_buf_push( fd_dragon_buf_t *      buf,
                    fd_dragon_buf_bank_t * bank,
                    uint                   kind,
                    ulong                  sz );

/* fd_dragon_buf_entry returns the entry with the given sequence number
   if it belongs to the bank, and NULL otherwise.  A walk over a bank
   is a walk of seq from first_seq to last_seq of a bank that
   fd_dragon_buf_bank_live said was live, and nothing may be pushed in
   the meantime. */

fd_dragon_buf_hdr_t *
fd_dragon_buf_entry( fd_dragon_buf_t *            buf,
                     fd_dragon_buf_bank_t const * bank,
                     ulong                        seq );

/* fd_dragon_buf_dedup marks superseded every account write of the bank
   that a write with a higher write version to the same account
   replaced, and returns how many accounts are left, which is how many
   the block updated.  Valid for a live bank; safe to call again. */

ulong
fd_dragon_buf_dedup( fd_dragon_buf_t *            buf,
                     fd_dragon_buf_bank_t const * bank );

/* Accounting **********************************************************/

FD_FN_PURE ulong
fd_dragon_buf_bank_cnt( fd_dragon_buf_t const * buf );

/* fd_dragon_buf_entry_cnt is the entries of the banks the buffer holds
   state for, and fd_dragon_buf_byte_cnt the bytes of the ring from the
   oldest of those entries to the write position.  fd_dragon_buf_byte_max
   is the size of the ring. */

FD_FN_PURE ulong
fd_dragon_buf_entry_cnt( fd_dragon_buf_t const * buf );

FD_FN_PURE ulong
fd_dragon_buf_byte_cnt( fd_dragon_buf_t const * buf );

FD_FN_PURE ulong
fd_dragon_buf_byte_max( fd_dragon_buf_t const * buf );

FD_FN_PURE ulong
fd_dragon_buf_depth( fd_dragon_buf_t const * buf );

FD_FN_PURE fd_dragon_buf_metrics_t const *
fd_dragon_buf_metrics( fd_dragon_buf_t const * buf );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_dragon_fd_dragon_buf_h */
