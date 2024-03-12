#ifndef HEADER_fd_src_app_fdctl_run_tiles_h
#define HEADER_fd_src_app_fdctl_run_tiles_h

#include "../../fdctl.h"

#include "../../../../disco/mux/fd_mux.h"
#include "../../../../disco/shred/fd_shredder.h"
#include "../../../../ballet/shred/fd_shred.h"
#include "../../../../ballet/pack/fd_pack.h"

#include <linux/filter.h>

/* Each block is limited to 32k parity shreds.  At worst, the shred tile
   generates 40 parity shreds per microblock (see #1 below).  We need to
   adjust the parity shred count to account for the empty tick
   microblocks which can be produced in the worst case, but that
   consumes at most 64 parity shreds (see #2 below).  Thus, the limit of
   the number of microblocks is (32*1024 - 64)/40 = 817.

   Proof of #1: In the current mode of operation, the shredder only
   produces microblock batches that fit in a single FEC set.  This means
   that each FEC set contains an integral number of microblocks.  Since
   each FEC set has at most 67 parity shreds, any FEC set containing >=
   2 microblocks has at most 34 parity shreds per microblock, which
   means we don't need to consider them further.  Thus, the only need to
   consider the case where we have a single microblock in an FEC set.
   In this case, the largest number of parity shreds comes from making
   the largest possible microblock, which is achieved by
   MAX_MICROBLOCK_SZ MTU-sized transactions.  This microblock has
   31*1232=38192 B of transaction data, which means 38248B of microblock
   data after being stamped by the PoH thread, putting it in the
   975B/data shred and 1:1 data/parity shred buckets, giving 40 parity
   shreds.

   Proof of #2: In the worst case, the PoH thread can produce 64
   microblocks with no transactions, one for each tick.  If these are
   not part of the last FEC set in the block, then they're part of an
   FEC set with at least HEADROOM bytes of data.  In that case, the
   addition of 48B to an FEC set can cause the addition of at most 1
   parity shred to the FEC set.  There is only one last FEC set, so even
   if all 64 of these were somehow part of the last FEC set, it would
   add at most 3072B to the last FEC set, which can add at most 4 parity
   shreds.

   Note that the number of parity shreds in each FEC set is always at
   least as many as the number of data shreds, so we don't need to
   consider the data shreds limit.

   It's also possible to guarantee <= 32k parity shreds by bounding the
   total data size.  That bound is 27,337,191 bytes, including the 48
   byte overhead for each microblock.  This comes from taking 1057 of
   the worst case FEC set we might produce (worst as in lowest rate of
   bytes/parity shred) of 25871 bytes -> 31 parity shreds.  Both this
   byte limit and the microblock limit are sufficient but not necessary,
   i.e.  if either of these limits is satisfied, the block will have no
   more than 32k parity shreds.  Interestingly, neither bound strictly
   implies the other, but max microblocks is simpler, so we go with that
   for now. */
#define FD_PACK_MAX_MICROBLOCKS_PER_BLOCK 817UL

/* fd_shred34 is a collection of up to 34 shreds batched in a way that's
   convenient for use in a dcache and for access from Rust. The limit of
   34 comes so that sizeof( fd_shred34_t ) < USHORT_MAX. */

struct __attribute__((aligned(FD_CHUNK_ALIGN))) fd_shred34 {
  ulong shred_cnt;
  ulong stride;
  ulong offset;
  ulong shred_sz; /* The size of each shred */
  /* For i in [0, shred_cnt), shred i's payload spans bytes
     [i*stride+offset, i*stride+offset+shred_sz ), counting from the
     start of the struct, not this point. */
  union {
    fd_shred_t shred;
    uchar      buffer[ FD_SHRED_MAX_SZ ];
  } pkts[ 34 ];
};
typedef struct fd_shred34 fd_shred34_t;

struct fd_became_leader {
  /* Start time of the slot in nanoseconds. */
  long   slot_start_ns;

  /* An opaque pointer to a Rust Arc<Bank> object, which should only
     be used with fd_ext_* functions to execute transactions or drop
     the bank.  The ownership is complicated, but basically any bank
     tile that receives this frag has a strong refcnt to the bank and
     should release it when done, other tiles should ignore and never
     use the bank. */
  void const * bank;

  /* The maximum number of microblocks that pack is allowed to put
   . into the slot. This allows PoH to accurately track and make sure
     microblocks do not need to be dropped. */
  ulong max_microblocks_in_slot;
};
typedef struct fd_became_leader fd_became_leader_t;

struct fd_microblock_trailer {
  /* The hash of the transactions in the microblock, ready to be
     mixed into PoH. */
  uchar hash[ 32UL ];
};
typedef struct fd_microblock_trailer fd_microblock_trailer_t;

struct fd_microblock_bank_trailer {
  /* An opauque pointer to the bank to use when executing and committing
     transactions.  The lifetime of the bank is owned by the PoH tile,
     which guarantees it is valid while pack or bank tiles might be
     using it. */
  void const * bank;
};
typedef struct fd_microblock_bank_trailer fd_microblock_bank_trailer_t;

#endif /* HEADER_fd_src_app_fdctl_run_tiles_h */
