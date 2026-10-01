#ifndef HEADER_fd_src_discof_dragon_fd_dragon_limits_h
#define HEADER_fd_src_discof_dragon_fd_dragon_limits_h

/* fd_dragon_limits.h holds the filter types of the Dragon's Mouth
   Subscribe API, the structural bounds on one subscription's filter
   set, and the configured limits an operator puts on top of them.  It
   is separate from fd_dragon_session.h because the topology carries a
   filter limit table into the tile.

   The structural bounds are what the fixed size filter set of a
   session can hold; the configured limits are yellowstone's
   plugin/filter/limits.rs knobs, which can only narrow them. */

#include "../../util/fd_util_base.h"

/* Filter map types, one per map field of SubscribeRequest */

#define FD_DRAGON_FILTER_ACCOUNTS            (0)
#define FD_DRAGON_FILTER_SLOTS               (1)
#define FD_DRAGON_FILTER_TRANSACTIONS        (2)
#define FD_DRAGON_FILTER_TRANSACTIONS_STATUS (3)
#define FD_DRAGON_FILTER_BLOCKS              (4)
#define FD_DRAGON_FILTER_BLOCKS_META         (5)
#define FD_DRAGON_FILTER_ENTRY               (6)
#define FD_DRAGON_FILTER_TYPE_CNT            (7)

/* FD_DRAGON_FILTER_NAME_MAX is the longest filter name accepted,
   matching yellowstone's filter_name_size_limit default.
   FD_DRAGON_FILTER_MAX is the number of filters one request may carry
   across all maps.  FD_DRAGON_FILTER_NAMES_MAX is the number of names
   a stream may introduce over its lifetime. */

#define FD_DRAGON_FILTER_NAME_MAX  ( 128UL)
#define FD_DRAGON_FILTER_MAX       (  64UL)
#define FD_DRAGON_DATA_SLICE_MAX   (  16UL)
#define FD_DRAGON_FILTER_NAMES_MAX (4096UL)

/* FD_DRAGON_FILTER_ACCT_MAX is the number of account addresses one
   request may name across all of its filters, which is yellowstone's
   per list account_include_max and friends applied to the whole
   request. */

#define FD_DRAGON_FILTER_ACCT_MAX (256UL)

/* Configured filter limits.  These are yellowstone's
   plugin/filter/limits.rs knobs under [tiles.dragon.filter_limits],
   which an operator lowers to bound what one client may ask of the
   server.  Yellowstone's defaults are unlimited; this server's storage
   for a filter set is fixed, so the defaults are the structural
   maximums above, and the configured values are checked against those
   at config time.

   FD_DRAGON_REJECT_* index the address lists an operator can forbid
   addresses in, which are the lists yellowstone has a reject set for.
   FD_DRAGON_REJECT_MAX is how many addresses one such list may hold. */

#define FD_DRAGON_REJECT_ACCOUNT        (0) /* accounts.account_reject */
#define FD_DRAGON_REJECT_OWNER          (1) /* accounts.owner_reject */
#define FD_DRAGON_REJECT_TXN_INCLUDE    (2) /* transactions.account_include_reject */
#define FD_DRAGON_REJECT_STATUS_INCLUDE (3) /* transactions_status.account_include_reject */
#define FD_DRAGON_REJECT_BLOCKS_INCLUDE (4) /* blocks.account_include_reject */
#define FD_DRAGON_REJECT_CNT            (5)

#define FD_DRAGON_REJECT_MAX (16UL)

struct fd_dragon_filter_limits {
  /* limits.<type>.max: how many filters of one type a request may
     carry, indexed by FD_DRAGON_FILTER_*. */
  ulong filter_max[ FD_DRAGON_FILTER_TYPE_CNT ];

  /* limits.<type>.any: whether a filter of this type may match
     everything, which is a filter that names no address at all.
     accounts, transactions and transactions_status have it;
     blocks.account_include_any is the same knob; the types with no
     address list are always permissive. */
  int any[ FD_DRAGON_FILTER_TYPE_CNT ];

  /* limits.<type>.cuckoo_max_size: bytes of the CuckooFilter.data
     field one filter of this type may carry. */
  ulong cuckoo_max_size[ FD_DRAGON_FILTER_TYPE_CNT ];

  ulong account_max;        /* accounts.account_max */
  ulong owner_max;          /* accounts.owner_max */
  ulong data_slice_max;     /* accounts.data_slice_max */

  ulong txn_include_max;    /* transactions.account_include_max */
  ulong txn_exclude_max;    /* transactions.account_exclude_max */
  ulong txn_required_max;   /* transactions.account_required_max */
  ulong status_include_max; /* transactions_status.account_include_max */
  ulong status_exclude_max; /* transactions_status.account_exclude_max */
  ulong status_required_max;/* transactions_status.account_required_max */
  ulong blocks_include_max; /* blocks.account_include_max */

  int include_transactions; /* blocks.include_transactions */
  int include_accounts;     /* blocks.include_accounts */
  int include_entries;      /* blocks.include_entries */

  ulong reject_cnt[ FD_DRAGON_REJECT_CNT ];
  uchar reject[ FD_DRAGON_REJECT_CNT ][ FD_DRAGON_REJECT_MAX ][ 32UL ];
};

typedef struct fd_dragon_filter_limits fd_dragon_filter_limits_t;

#endif /* HEADER_fd_src_discof_dragon_fd_dragon_limits_h */
