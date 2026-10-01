#ifndef HEADER_fd_src_discof_dragon_fd_dragon_session_h
#define HEADER_fd_src_discof_dragon_fd_dragon_session_h

/* fd_dragon_session.h holds the per-stream state of a Dragon's Mouth
   subscription: the filter set decoded from the client's most recent
   SubscribeRequest, the server side ping deadline, and the counters
   that bound what one client may ask for.

   A SubscribeRequest replaces the stream's filter set as a whole.  The
   decoder counts the entries of each filter map and keeps their names,
   which a later update echoes back in SubscribeUpdate.filters; the
   predicates inside each map entry are skipped without being
   materialized, so a request carrying thousands of entries costs the
   bytes it took to receive and nothing else. */

#include "fd_geyser_api.h"
#include "fd_dragon_cuckoo.h"
#include "fd_dragon_limits.h"

/* Commitment levels, geyser.proto CommitmentLevel */

#define FD_DRAGON_COMMITMENT_PROCESSED (0)
#define FD_DRAGON_COMMITMENT_CONFIRMED (1)
#define FD_DRAGON_COMMITMENT_FINALIZED (2)

/* The state predicates of an accounts filter (geyser.proto
   SubscribeRequestFilterAccountsFilter).  A filter that carries none
   matches any account state.

   FD_DRAGON_ACCT_STATE_MAX is how many one filter may carry, which is
   yellowstone's MAX_FILTERS (plugin/filter/filter.rs:1311).
   FD_DRAGON_FILTER_STATE_MAX bounds them across a whole request, and
   FD_DRAGON_FILTER_STATE_BYTES the bytes their memcmp predicates
   compare against; a memcmp predicate carries at most
   FD_DRAGON_MEMCMP_BYTES_MAX of them (yellowstone's MAX_DATA_SIZE). */

#define FD_DRAGON_ACCT_STATE_MEMCMP      (0)
#define FD_DRAGON_ACCT_STATE_DATASIZE    (1)
#define FD_DRAGON_ACCT_STATE_TOKEN       (2)
#define FD_DRAGON_ACCT_STATE_LAMPORTS_EQ (3)
#define FD_DRAGON_ACCT_STATE_LAMPORTS_NE (4)
#define FD_DRAGON_ACCT_STATE_LAMPORTS_LT (5)
#define FD_DRAGON_ACCT_STATE_LAMPORTS_GT (6)

#define FD_DRAGON_ACCT_STATE_MAX        (   4UL)
#define FD_DRAGON_FILTER_STATE_MAX      (  64UL)
#define FD_DRAGON_FILTER_STATE_BYTES    (8192UL)
#define FD_DRAGON_MEMCMP_BYTES_MAX      ( 128UL)
#define FD_DRAGON_MEMCMP_BASE58_MAX     ( 175UL)
#define FD_DRAGON_MEMCMP_BASE64_MAX     ( 172UL)

struct fd_dragon_acct_state {
  int   kind;      /* FD_DRAGON_ACCT_STATE_* */
  ulong value;     /* the data size, or the lamports a comparison is against */
  ulong offset;    /* memcmp: where in the account data to compare */
  uint  data_off;  /* memcmp: the bytes in the filter set's pool */
  uint  data_sz;
};

typedef struct fd_dragon_acct_state fd_dragon_acct_state_t;

/* FD_DRAGON_ERR_MAX bounds the gRPC status text that a rejected
   request produces. */

#define FD_DRAGON_ERR_MAX (192UL)

/* Stream kinds.  Subscribe and the health service's Watch are the two
   that stay open after their request; everything else is unary. */

#define FD_DRAGON_SESSION_NONE         (0)
#define FD_DRAGON_SESSION_SUBSCRIBE    (1)
#define FD_DRAGON_SESSION_HEALTH_WATCH (2)

struct fd_dragon_filter_name {
  char  cstr[ FD_DRAGON_FILTER_NAME_MAX+1UL ];
  ulong len;
  int   type; /* FD_DRAGON_FILTER_* */

  /* The predicates of a slots filter.  filter_by_commitment keeps only
     the status that is the subscription's commitment;
     interslot_updates lets the statuses that belong to no commitment
     through. */
  int   filter_by_commitment;
  int   interslot_updates;

  /* The predicates of a transactions or transactions_status filter.  A
   filter that sets none of them matches every transaction.  The
   account lists are ranges of the filter set's address pool, and are
   evaluated over the transaction's whole key set: the message's own
   addresses and the ones its lookup tables loaded. */
  int    has_vote;
  int    vote;
  int    has_failed;
  int    failed;
  int    has_signature;
  uchar  signature[ 64UL ];
  ushort include_off;
  ushort include_cnt;
  ushort exclude_off;
  ushort exclude_cnt;
  ushort required_off;
  ushort required_cnt;

  /* The token account expansion the request asked for.  Nothing
     expands it, because no pre or post token balances are computed. */
  int    has_token_accounts;

  /* The predicates of an accounts filter.  acct is the account set and
     owner the owner set, both ranges of the filter set's address pool;
     an empty set matches any account.  has_txn_sig requires the write
     to have come from a transaction, or not to have, and state is the
     filter's range of the set's state predicates, all of which have to
     hold. */
  ushort acct_off;
  ushort acct_cnt;
  ushort owner_off;
  ushort owner_cnt;
  int    has_txn_sig;
  int    txn_sig;
  ushort state_off;
  ushort state_cnt;

  /* The cuckoo filter of an accounts, transactions,
     transactions_status or blocks filter: a probabilistic account set
     the client uploaded in place of naming every address, which
     matches alongside the explicit account list rather than narrowing
     it (an address in either one is a hit).  cuckoo_bucket_cnt is 0
     when the filter carries none.  The buckets live in the filter
     set's arena at cuckoo_off. */
  ulong  cuckoo_seed;
  uint   cuckoo_off;
  uint   cuckoo_bucket_cnt;

  /* The predicates of a blocks filter.  The account set is acct above,
     yellowstone's account_include, which selects the transactions and
     the accounts a block carries rather than the blocks themselves.
     The include flags say what the block carries: transactions unless
     they are turned off, accounts and entries only when asked for
     (plugin/filter/filter.rs:2157-2203). */
  int    include_txns;
  int    include_accts;
  int    include_entries;
};

typedef struct fd_dragon_filter_name fd_dragon_filter_name_t;

struct fd_dragon_data_slice {
  ulong offset;
  ulong length;
};

typedef struct fd_dragon_data_slice fd_dragon_data_slice_t;

struct fd_dragon_filter_set {
  int   commitment; /* FD_DRAGON_COMMITMENT_* */

  ulong                   name_cnt;
  fd_dragon_filter_name_t name[ FD_DRAGON_FILTER_MAX ];
  ulong                   type_cnt[ FD_DRAGON_FILTER_TYPE_CNT ];

  ulong                  slice_cnt;
  fd_dragon_data_slice_t slice[ FD_DRAGON_DATA_SLICE_MAX ];

  /* The address pool the account lists of the filters point into. */
  ulong                  acct_cnt;
  uchar                  acct[ FD_DRAGON_FILTER_ACCT_MAX ][ 32UL ];

  /* The state predicates of the accounts filters, and the bytes their
     memcmp predicates compare against. */
  ulong                  state_cnt;
  fd_dragon_acct_state_t state[ FD_DRAGON_FILTER_STATE_MAX ];
  ulong                  state_byte_cnt;
  uchar                  state_byte[ FD_DRAGON_FILTER_STATE_BYTES ];

  int   has_ping;
  int   ping_id;

  int   has_from_slot;
  ulong from_slot;

  /* The bucket arena the cuckoo filters of the filters point into, and
     how many of its entries they use.  The arena is not part of the
     set: fd_dragon_filter_decode fills the one it is handed, and a
     caller that copies a set copies cuckoo_entry_cnt entries of the
     arena and repoints cuckoo at its own copy
     (fd_dragon_filter_set_adopt). */
  ushort * cuckoo;
  ulong    cuckoo_entry_cnt;
  ulong    cuckoo_entry_max;
};

typedef struct fd_dragon_filter_set fd_dragon_filter_set_t;

struct fd_dragon_session {
  void * stream;  /* fd_grpc_server_stream_t of the call, NULL if the slot is free */
  int    kind;    /* FD_DRAGON_SESSION_* */
  int    method;  /* FD_DRAGON_METHOD_* of the call */
  int    answered; /* a unary call was answered */
  int    finished; /* the call was ended, the transport still owns the stream */

  int   warned_oversize; /* an update too large for this client was reported */

  /* The serving status a health Watch stream was last told about, so
     that it is sent again only when it changes. */
  int   health_status;

  long  next_ping_nanos; /* wallclock deadline of the next server ping */
  long  reap_nanos;      /* wallclock after which an undeliverable response gives up the connection, 0 if none */
  long  request_nanos;   /* wallclock by which the call must send its request, 0 once it has */
  ulong names_seen;      /* filter names introduced over the stream's lifetime */
  ulong update_cnt;      /* updates sent on this stream */

  /* deferred marks a subscription whose commitment is above processed,
     which is served from the deferred store.  It is eligible for the
     banks created after its filters were installed, so it is never
     served a bank that was in flight under someone else's filters:
     eligible_from_bank_seq is the first bank id it may see. */
  int   deferred;
  ulong eligible_from_bank_seq;

  fd_dragon_filter_set_t filter[1];
};

typedef struct fd_dragon_session fd_dragon_session_t;

FD_PROTOTYPES_BEGIN

/* fd_dragon_filter_set_init clears a filter set to the defaults of an
   empty SubscribeRequest: commitment processed, no filters.  cuckoo is
   the bucket arena the set's cuckoo filters are decoded into, which
   holds cuckoo_entry_max ushorts; NULL refuses every request that
   carries a cuckoo filter. */

void
fd_dragon_filter_set_init( fd_dragon_filter_set_t * set,
                           ushort *                 cuckoo,
                           ulong                    cuckoo_entry_max );

/* fd_dragon_filter_set_adopt copies src into dst, moving the cuckoo
   buckets src holds into dst's own arena.  dst's arena must have room
   for src->cuckoo_entry_cnt entries, which the limits guarantee when
   both arenas were sized by the same configuration. */

void
fd_dragon_filter_set_adopt( fd_dragon_filter_set_t *       dst,
                            fd_dragon_filter_set_t const * src,
                            ushort *                       cuckoo,
                            ulong                          cuckoo_entry_max );

/* fd_dragon_filter_limits_default fills limits with the most
   permissive values this server can serve, which is the structural
   maximum of every knob.  It is what yellowstone's unlimited defaults
   become here. */

void
fd_dragon_filter_limits_default( fd_dragon_filter_limits_t * limits );

/* fd_dragon_slots_match returns 1 if a slots filter at the given
   subscription commitment passes a status update, following
   yellowstone's FilterSlots::get_updates: the status has to be the
   subscription's commitment when filter_by_commitment is set, and a
   status that belongs to no commitment needs interslot_updates. */

FD_FN_PURE int
fd_dragon_slots_match( fd_dragon_filter_name_t const * name,
                       int                             commitment,
                       int                             status );

/* fd_dragon_txn_match returns 1 if one transactions or
   transactions_status filter passes a transaction, following
   yellowstone's FilterTransactions::get_updates
   (plugin/filter/filter.rs:1640-1745): vote and failed have to equal
   the transaction's when they are set, signature has to be its first
   signature, every address of account_required has to be among its
   keys, one address of account_include has to be (when the list is not
   empty), and none of account_exclude may be.

   keys is the transaction's whole key set, the message's addresses
   followed by the loaded ones. */

FD_FN_PURE int
fd_dragon_txn_match( fd_dragon_filter_set_t const *  set,
                     fd_dragon_filter_name_t const * name,
                     uchar const *                   signature,
                     int                             is_vote,
                     int                             failed,
                     uchar const                     (* keys)[ 32UL ],
                     ulong                           key_cnt );

/* fd_dragon_acct_match returns 1 if one accounts filter passes an
   account write, following yellowstone's FilterAccountAggregate::
   match_filter (plugin/filter/filter.rs:464-541): the write has to
   have a transaction signature when the filter asks for one (or not
   have one when it asks for that), the account has to be in the
   filter's account set and its owner in the owner set when those are
   not empty, and every state predicate has to hold.

   data and data_sz are the state the write left the account in.  A
   write whose data the producer did not carry is passed as empty,
   which the state predicates reject unless they happen to hold for no
   data. */

FD_FN_PURE int
fd_dragon_acct_match( fd_dragon_filter_set_t const *  set,
                      fd_dragon_filter_name_t const * name,
                      uchar const *                   pubkey,
                      uchar const *                   owner,
                      ulong                           lamports,
                      uchar const *                   data,
                      ulong                           data_sz,
                      int                             has_txn_sig );

/* fd_dragon_blocks_txn_match returns 1 if a transaction belongs in the
   block a blocks filter produces, and fd_dragon_blocks_acct_match the
   same for an account: the filter's account set is empty, or it names
   one of the transaction's keys, or it names the account
   (plugin/filter/filter.rs:2224-2270). */

FD_FN_PURE int
fd_dragon_blocks_txn_match( fd_dragon_filter_set_t const *  set,
                            fd_dragon_filter_name_t const * name,
                            uchar const                     (* keys)[ 32UL ],
                            ulong                           key_cnt );

FD_FN_PURE int
fd_dragon_blocks_acct_match( fd_dragon_filter_set_t const *  set,
                             fd_dragon_filter_name_t const * name,
                             uchar const *                   pubkey );

/* fd_dragon_filter_decode decodes a SubscribeRequest into set.  set is
   cleared first: a request replaces the filter set as a whole.

   limits is the configured bound on what the request may ask for, or
   NULL for the structural maximums.  cuckoo is the bucket arena the
   set's cuckoo filters are decoded into and cuckoo_entry_max its
   length in ushorts; a NULL arena refuses a request that carries a
   cuckoo filter.

   Returns 0 on success.  Returns -1 if the request is malformed or
   violates a limit, and writes a NUL terminated reason of at most
   FD_DRAGON_ERR_MAX bytes into err, which the caller reports as
   invalid_argument("failed to create filter: {err}").  On failure set
   holds no filters.

   names_seen counts the names the stream introduced so far and is
   updated in place; a stream that exceeds FD_DRAGON_FILTER_NAMES_MAX
   is rejected. */

int
fd_dragon_filter_decode( fd_dragon_filter_set_t *          set,
                         fd_dragon_filter_limits_t const * limits,
                         ushort *                          cuckoo,
                         ulong                             cuckoo_entry_max,
                         ulong *                           names_seen,
                         uchar const *                     msg,
                         ulong                             msg_sz,
                         char *                            err,
                         ulong                             err_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_dragon_fd_dragon_session_h */
