/* The accdb tile is a thread dedicated to servicing requests for reads
   from and writes to a special key-value store, the accounts database.
   This database just maps account pubkeys to the data in them, with a
   special bit of additional metadata to perform AS-OF queries, where we
   wish to query not just the state of an account, but the state as-of a
   specific slot.

   Under the hood, this is basically just a

     Map<(Pubkey, Slot), AccountInfo>

   With a special query function to traverse to the latest version of a
   given account (on the same fork) up to the given slot.

   The accounts database is single threaded and should not be accessed
   directly, all access must be done via. issuing requests across a
   message bus to this spin loop.  The request and response format is
   documented below.

   Many requests will need to read from an underlying disk, and reading
   or writing should not be assumed to be fast.

   The accounts database assumes that reads and writes are structured by
   callers in special ways to prevent garbage data being returned.
   Specifically,

     1. Reads are only issued for slots higher than or equal to the
        current root, and for slots that exist in the parentage tree.
        Reads outside of this range may return garbage data.

     2. Writes are only issued for slots higher than the current root,
        and for slots that exist in the parentage tree.  Writes outside
        of this range may cause garbage data to be written.

     3. Parentage relationships form a tree, and do not create cycles.
        Rooting progresses linearly down the tree, and no slot can be
        rooted before its parent is rooted.

   The accounts database is not concurrent in that all requests must be
   performed by the single accdb control plane, but there are
   concurrency concerns with how it is used.  In particular, a caller
   cannot freely issue requests outside the context of the replay system
   which is advancing the root slot, because otherwise it cannot
   guarantee that the root slot will exist when the tile chooses to
   service the query.  External synchronization is needed to ensure
   invariants (1), (2), and (3) above are maintained. */

#include "../../util/fd_util.h"

#define FD_ACCDB_OP_READ  (0)
#define FD_ACCDB_OP_WRITE (1)
#define FD_ACCDB_OP_BEGIN (2)
#define FD_ACCDB_OP_ROOT  (3)
#define FD_ACCDB_OP_PURGE (4)

/* To support the special fork-aware querying, the accounts database
   needs to know the ancestry of slots on the chain.  This is done by
   some replaying system sending special ancestry messages.  These
   messages do not have any response.

   The first message "begin" begins a slot, and establishes that it is a
   child of some other slot which has been begun before it. */

struct fd_accdb_begin {
  ulong slot;
  ulong parent_slot;
};

typedef struct fd_accdb_begin fd_accdb_begin_t;

/* The second ancestry message is for advancing the root, which removes
   any competing forks from the accounts database (they must not be
   accessed again) and establishes the slot as the new root of the
   accounts database. */

struct fd_accdb_root {
  ulong slot;
};

typedef struct fd_accdb_root fd_accdb_root_t;

/* There is a third and final ancestry (kind of) message, which is used
   to "purge" a slot.  This is used for the very special case where a
   node has equivocated (produced two competing blocks for the same
   slot) and we need to dump one of them and repair to continue
   replaying.

   Dumping a slot requires removing it immediately from the index
   without waiting for a competing fork to be rooted. */

struct fd_accdb_purge {
  ulong slot;
};

typedef struct fd_accdb_purge fd_accdb_purge_t;

/* Requests arriving on a single message bus (mcache) are naturally
   sequenced, and the accounts database will respond to them in the
   order they are received.  But, because requests can arrive to the
   accounts database from many mcaches at once, the tile will by default
   choose which queue to service at random.  Sometimes it is desirable
   to establish an explicit ordering of requests across different
   queues, which can be done by setting the sequence_after field in the
   incoming request.

   To establish an explicit ordering, the caller must set the in_idx to
   the index of the in mcache for the accounts database, and the seqno
   to the sequence number of the request on the in mcache that the
   request must follow after.

   TODO: Not actually respected yet.. wire this up once it's used. */

struct fd_accdb_sequence_after {
  ulong in_idx;
  ulong seqno;
};

typedef struct fd_accdb_sequence_after fd_accdb_sequence_after_t;

struct fd_accdb_read_request {
  ulong slot;
  uchar pubkey[ 32UL ];

  fd_accdb_sequence_after_t sequence;
};

typedef struct fd_accdb_read_request fd_accdb_read_request_t;

struct fd_accdb_read_response {
  ulong lamports;
  uchar owner[ 32UL ];
  ulong data_len;
  /* data of size data_len follow here */
};

typedef struct fd_accdb_read_response fd_accdb_read_response_t;

struct fd_accdb_write_request {
  ulong slot;
  uchar pubkey[ 32UL ];

  ulong lamports;
  uchar owner[ 32UL ];

  fd_accdb_sequence_after_t sequence;

  ulong data_len;
  /* data of size data_len follows immediately here */
};

typedef struct fd_accdb_write_request fd_accdb_write_request_t;
