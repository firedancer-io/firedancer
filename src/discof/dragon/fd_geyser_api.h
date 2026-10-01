#ifndef HEADER_fd_src_discof_dragon_fd_geyser_api_h
#define HEADER_fd_src_discof_dragon_fd_geyser_api_h

/* fd_geyser_api.h is the interface between the geyser core and the
   things built on top of it.

   The shape is agave's geyser plugin interface: accounts and
   transactions are reported once, when they are committed on some
   bank, and the commitment levels above processed are reported as slot
   statuses only (agave accounts.rs, update_bank_status).  Everything a
   Dragon's Mouth client sees at confirmed or finalized is therefore
   reconstruction done by the consumer, exactly as it is done by the
   yellowstone plugin on top of agave.

   Several consumers may register with one core.  A consumer that uses
   nothing but the callbacks below gets agave's contract.

   The extensions below the vtable are what a consumer cannot do for
   itself: hold a Firedancer bank so its fork stays readable, ask
   whether a bank is sealed, and read an account at a bank's accdb
   fork.  A hold is a claim on a bank; the core keeps the bank
   reference it got from replay until every claim is gone.  Claims on a
   bank are void once on_bank_discarded reports it, and a read at a
   discarded bank is refused. */

#include "../../flamenco/fd_flamenco_base.h"
#include "../../flamenco/txnmeta/fd_txn_meta.h"
#include "../../flamenco/accdb/fd_accdb_base.h"
#include "../../disco/events/generated/fd_event_internal_gen.h"

/* FD_DRAGON_WARN_POW2 logs a warning the first time a condition is
   seen and then when its count reaches a power of two, so a condition
   that repeats once per bank, per record or per poll costs a
   logarithmic number of log lines instead of one each.  n is the
   number of times it has now happened, which every site of it also
   counts in a metric; the metric is the exact number. */

#define FD_DRAGON_WARN_POW2( n, ... )                              \
  do {                                                             \
    ulong _warn_n = (n);                                           \
    if( FD_UNLIKELY( !( _warn_n & ( _warn_n-1UL ) ) ) ) FD_LOG_WARNING(( __VA_ARGS__ )); \
  } while(0)

/* Slot statuses, in the encoding of geyser.proto SlotStatus. */

#define FD_GEYSER_SLOT_PROCESSED           (0)
#define FD_GEYSER_SLOT_CONFIRMED           (1)
#define FD_GEYSER_SLOT_FINALIZED           (2)
#define FD_GEYSER_SLOT_FIRST_SHRED_RECEIVED (3)
#define FD_GEYSER_SLOT_COMPLETED           (4)
#define FD_GEYSER_SLOT_CREATED_BANK        (5)
#define FD_GEYSER_SLOT_DEAD                (6)

/* Reasons a bank was discarded.  The bank is gone for good: claims on
   it are void, reads at it are refused, and no further status will
   name it. */

#define FD_GEYSER_DISCARD_DEAD    (0) /* the slot was marked dead */
#define FD_GEYSER_DISCARD_LOSER   (1) /* another bank of the slot was confirmed or rooted */
#define FD_GEYSER_DISCARD_DROPPED (2) /* replay asked for the reference back */
#define FD_GEYSER_DISCARD_PRUNED  (3) /* the bank does not descend from the root */
#define FD_GEYSER_DISCARD_STALE   (4) /* the bank never resolved and fell behind */
#define FD_GEYSER_DISCARD_FLUSH   (5) /* replay restarted its bank sequence, or an input gap */
#define FD_GEYSER_DISCARD_PENDING (6) /* the bank owed a status its records never let it seal for */

/* Reasons a bank is not sealed.  A bank that is not sealed produces
   nothing at confirmed or finalized. */

#define FD_GEYSER_INCOMPLETE_NONE      (0)
#define FD_GEYSER_INCOMPLETE_PENDING   (1) /* not frozen yet */
#define FD_GEYSER_INCOMPLETE_DROPPED   (2) /* the bank reference was taken back */
#define FD_GEYSER_INCOMPLETE_RECORDS   (3) /* fewer transaction records than the bank executed */
#define FD_GEYSER_INCOMPLETE_SYSVARS   (4) /* a sysvar write of the slot was not seen */
#define FD_GEYSER_INCOMPLETE_GAP       (5) /* an input link overran, so records may be missing */
#define FD_GEYSER_INCOMPLETE_CNT       (6)

/* fd_geyser_block_meta_t is the block level summary of one bank.  It
   is reported once, when the bank freezes. */

struct fd_geyser_block_meta {
  ulong     slot;
  ulong     parent_slot;
  int       has_parent;
  fd_hash_t block_hash;   /* last microblock hash, agave's blockhash */
  fd_hash_t block_id;     /* merkle root of the last FEC set */
  ulong     block_height;
  ulong     parent_block_height;
  ulong     executed_txn_cnt;
  ulong     entry_cnt;    /* always 0: entries are not reconstructed */
};

typedef struct fd_geyser_block_meta fd_geyser_block_meta_t;

/* fd_geyser_account_t, fd_geyser_txn_t and fd_geyser_deshred_txn_t are
   the payloads of the callbacks that carry content.  They are views of
   the record the producer sent, valid only for the duration of the
   call: a consumer that keeps anything copies it.

   fd_geyser_account_t is one account write.  write_version orders the
   writes of one slot: the phase of the write (before, during or after
   the block's transactions), then its position within the phase, then
   its position within the record, which is agave's ordering of the same
   writes.

   data_missing says the producer did not carry the account's data with
   the write, so data is NULL and data_sz is 0 for a reason other than
   the account being empty: account reporting is off, or the record was
   too large to carry the data.  What the account holds can then only be
   read at the bank's fork, through fd_geyser_read_account. */

struct fd_geyser_account {
  ulong         slot;
  ulong         bank_id;
  uchar const * pubkey;        /* 32 bytes */
  uchar const * owner;         /* 32 bytes */
  ulong         lamports;      /* 0 means the account was closed */
  int           executable;
  uchar const * data;          /* data_sz bytes, NULL if the producer omitted it */
  ulong         data_sz;
  int           data_missing;
  ulong         write_version;
  uchar const * txn_signature; /* 64 bytes, NULL for a write outside a transaction */
};

typedef struct fd_geyser_account fd_geyser_account_t;

/* fd_geyser_txn_t is one committed transaction, as the raw commit
   record the producer sent plus the identity of the bank it committed
   on.  Everything a client is served about the transaction is built
   from rec, through fd_geyser_txn_meta, which builds it once however
   many consumers ask. */

struct fd_geyser_txn {
  ulong                                    slot;
  ulong                                    bank_id;
  ulong                                    index_in_slot;
  uchar const *                            signature;   /* 64 bytes */
  int                                      is_vote;
  fd_event_internal_commit_parts_t const * rec;
};

typedef struct fd_geyser_txn fd_geyser_txn_t;

struct fd_geyser_deshred_txn {
  ulong slot;
};

typedef struct fd_geyser_deshred_txn fd_geyser_deshred_txn_t;

/* fd_geyser_consumer_t is one registration.  Every callback may be
   NULL, in which case the core skips it.  The core calls them from the
   thread that feeds it, never reentrantly. */

struct fd_geyser_consumer {
  void * ctx;

  /* Capability flags.  A consumer that wants no content lets the core
     skip the work of building it. */
  int wants_accounts;
  int wants_transactions;
  int wants_deshred;

  /* on_slot_status reports one status of one slot.  bank_id is the
     bank the status belongs to, absent for statuses that belong to no
     bank (Dead, and in v1 FirstShredReceived and Completed).
     dead_error is the reason a slot is dead, NULL if unknown. */
  void (* on_slot_status)( void *       ctx,
                           ulong        slot,
                           ulong        parent_slot,
                           int          has_parent,
                           int          status,
                           ulong        bank_id,
                           int          has_bank_id,
                           char const * dead_error );

  /* on_block_meta reports the block summary of a frozen bank. */
  void (* on_block_meta)( void *                         ctx,
                          fd_geyser_block_meta_t const * meta,
                          ulong                          bank_id );

  /* on_bank_sealed reports that a bank is sealed: it froze, its block
     summary has been reported, and every record it produced was seen.
     Reported once per bank, and only for a bank that seals; what a
     consumer keeps per bank is complete from here on, which is what
     lets it serve the block of a bank at processed.  Yellowstone emits
     a Block to its processed subscribers at the same point
     (grpc.rs:1398-1412). */
  void (* on_bank_sealed)( void * ctx,
                           ulong  bank_id );

  /* on_account and on_transaction are the processed firehose: every
     committed write and every executed transaction, on every bank,
     including banks that later die or lose. */
  void (* on_account)( void *                      ctx,
                       fd_geyser_account_t const * acct,
                       ulong                       slot,
                       ulong                       bank_id );

  void (* on_transaction)( void *                  ctx,
                           fd_geyser_txn_t const * txn,
                           ulong                   slot,
                           ulong                   bank_id );

  /* on_deshred_transaction reports a transaction as it came out of the
     shreds, before execution.  Reserved: nothing calls it in v0. */
  void (* on_deshred_transaction)( void *                          ctx,
                                   fd_geyser_deshred_txn_t const * dtxn,
                                   ulong                           slot,
                                   ulong                           bank_id );

  /* on_end_of_startup reports that the validator caught up, so that a
     consumer can stop treating its state as partial. */
  void (* on_end_of_startup)( void * ctx );

  /* on_bank_discarded reports that a bank is gone, with one of
     FD_GEYSER_DISCARD_*. */
  void (* on_bank_discarded)( void * ctx,
                              ulong  bank_id,
                              int    reason );
};

typedef struct fd_geyser_consumer fd_geyser_consumer_t;

struct fd_geyser_core;
typedef struct fd_geyser_core fd_geyser_core_t;

FD_PROTOTYPES_BEGIN

/* fd_geyser_bank_hold claims the bank bank_id, so that the core keeps
   its replay reference and the bank's fork stays readable.  Returns 0
   on success, or -1 if the bank is unknown or discarded, in which case
   nothing is claimed.  Every successful hold must be matched by one
   fd_geyser_bank_release, except for a bank reported by
   on_bank_discarded, whose claims the core has already dropped. */

int
fd_geyser_bank_hold( fd_geyser_core_t * core,
                     ulong              bank_id );

void
fd_geyser_bank_release( fd_geyser_core_t * core,
                        ulong              bank_id );

/* fd_geyser_txn_meta returns the meta object of the transaction an
   on_transaction callback is reporting: the transaction as the
   commitment levels describe it, built from the record through
   fd_txn_meta.  Valid only for the duration of the callback, and only
   for the transaction the callback is about.

   The core builds it on the first ask and keeps it for the rest of the
   callback, so a record nobody asks about costs nothing and one every
   consumer asks about is built once.  Returns NULL if the record's
   transaction does not parse. */

fd_txn_meta_t const *
fd_geyser_txn_meta( fd_geyser_core_t *      core,
                    fd_geyser_txn_t const * txn );

/* fd_geyser_bank_is_complete returns 1 if the bank is sealed: it
   froze, every record it produced was seen, and its reference was not
   taken back.  A consumer delivers content at confirmed or finalized
   only for a sealed bank. */

int
fd_geyser_bank_is_complete( fd_geyser_core_t const * core,
                            ulong                    bank_id );

/* fd_geyser_read_account reads one account at the bank's accdb fork,
   which holds the state the block left the account in.  Valid only
   while the caller holds a claim on the bank: the claim keeps the bank
   reference the core got from replay, and replay's storage reclamation
   waits on that reference, so the fork stays readable (§3.1 of the
   design).

   Fills lamports, executable, owner, data, data_sz, slot, bank_id and
   pubkey of out; the write version and the transaction signature of a
   write are not in the accounts database, so the caller fills those in
   itself.  lamports of 0 is an account that does not exist at the fork,
   which for the caller is a closed account with no data.  out->data
   points into memory the reader owns, valid until the next read.

   Returns 0 on success, or -1 if the bank is unknown, discarded,
   unclaimed, has no fork yet, or the core was made without a reader. */

int
fd_geyser_read_account( fd_geyser_core_t *    core,
                        ulong                 bank_id,
                        uchar const *         pubkey,
                        fd_geyser_account_t * out );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_dragon_fd_geyser_api_h */
