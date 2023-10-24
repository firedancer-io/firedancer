#ifndef HEADER_fd_src_disco_shred_fd_shred_dest_h
#define HEADER_fd_src_disco_shred_fd_shred_dest_h

#include "../../ballet/shred/fd_shred.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/wsample/fd_wsample.h"
#include "../../flamenco/leaders/fd_leaders.h"

/* This header defines a collection of methods for using stake weights
   to compute the destination of a specific shred for the leader and
   non-leader.  This is where the Turbine tree logic is implemented. */

/* For a given FEC, we might need to produce 200 destinations for each
   of 134 shreds, which is a lot of destinations!  Full destination
   information (ip, port, mac) is 12 B. A pointer is 8 B, but an index
   can be as small as 2 B, since currently Turbine doesn't work with
   more than fanout^2 nodes which is less than USHORT_MAX.  Thus, we go
   with the index, which can cheaply be mapped to the full information
   using fd_shred_dest_idx_to_dest below. */
typedef ushort fd_shred_dest_idx_t;


#define FD_SHRED_DEST_MAX_SHRED_CNT (134UL) /* DATA_SHREDS_MAX+PARITY_SHREDS_MAX */
#define FD_SHRED_DEST_NO_DEST       (USHORT_MAX)

/* fd_shred_dest_weighted_t specifies a destination to which a shred might be
   sent.  The information comes from Gossip typically. */
struct fd_shred_dest_weighted {
  fd_pubkey_t  pubkey;   /* The valiator's identity key */
  ulong  stake_lamports; /* Stake, measured in lamports, or 0 for an unstaked validator */
  uint   ip4;            /* The validator's IP address, in host byte order */
  ushort port;           /* The TVU port, in host byte order */
  uchar  mac_addr[6]; /* The mac address that should be used as the
                         destination field in the ethernet header.  This is
                         typically the gateway mac address, not the validator's
                         mac address (which is neither easy nor helpful to
                         know). */
};
typedef struct fd_shred_dest_weighted fd_shred_dest_weighted_t;

/* Internal type, forward declared to be able to declare the struct
   here. */
struct pubkey_to_idx;
typedef struct pubkey_to_idx pubkey_to_idx_t;

#define FD_SHRED_DEST_ALIGN (128UL)
FD_STATIC_ASSERT( FD_SHRED_DEST_ALIGN>=FD_SHA256_BATCH_ALIGN, fd_shred_dest_private_align );

struct __attribute__((aligned(FD_SHRED_DEST_ALIGN))) fd_shred_dest_private {
  uchar      _sha256_batch[ FD_SHA256_BATCH_FOOTPRINT ]  __attribute__((aligned(FD_SHA256_BATCH_ALIGN)));
  fd_chacha20rng_t rng[1];

  /* null_dest is initialized to all zeros.  Returned when the destination
     doesn't exist (e.g. you've asked for the 5th destination, but you only
     need to send to 4 recipients. */
  fd_shred_dest_weighted_t null_dest[1];

  fd_epoch_leaders_t const * lsched;

  ulong cnt;
  fd_shred_dest_weighted_t * all_destinations; /* a local copy, points to memory after the struct */

  fd_wsample_t * staked;
  struct {
    /* These two variables are maintained by the unstaked sampling functions. */
    ulong * unstaked;
    ulong   unstaked_unremoved_cnt;
  };
  ulong staked_cnt;
  ulong unstaked_cnt;

  pubkey_to_idx_t * pubkey_to_idx_map; /* maps pubkey -> [0, staked_cnt+unstaked_cnt) */

  ulong source_validator_orig_idx; /* in [0, staked_cnt+unstaked_cnt) */
};
typedef struct fd_shred_dest_private fd_shred_dest_t;


/* fd_shred_dest_{align, footprint} return the alignment and footprint
   (respectively) required of a region of memory to format it as an
   fd_shred_dest_t object.  cnt is the number of destinations, both
   staked and unstaked, that this object can store. */
static inline ulong fd_shred_dest_align    ( void      ) { return FD_SHRED_DEST_ALIGN; }
/*         */ ulong fd_shred_dest_footprint( ulong cnt );

/* fd_shred_dest_new formats a region of memory for use as an
   fd_shred_dest_t object. mem points to the first byte of a region of
   memory with the required footprint and alignment.  info points to the
   first of cnt destinations that the fd_shred_dest_t will be aware of.
   info must be sorted in the typical Solana stake weighted way: largest
   stake to smallest stake, with ties broken by pubkey (again, largest
   to smallest lexicographically).  src must contain all staked
   validators, even if some do not have contact info (set ip to 0 if
   so).  src can also contain unstaked validators, but they must be at
   the end of the list.  Each fd_shred_dest_t object is tied to a
   specific epoch, and so the stake weights are constant within the
   epoch.  The information in info will be copied, and no read interest
   in info will be retained.  lsched points to a local join of an
   fd_epoch_leaders_t object with the leader information for the slots
   when the shreds for which this shred dest object computes
   destinations were produced.  This function retains a read interest in
   lsched that persists until the memory is unformatted.  `source`
   points to the public key of the identity key of the current
   validator, i.e. the one who sends out the shreds computed by this
   object.  info must contain contact info for `source,` although it
   will never be returned as a destination.

   Returns mem on success and NULL on errors.  Logs a warning if so. */
void *
fd_shred_dest_new( void                           * mem,
                   fd_shred_dest_weighted_t const * info, /* Accessed [0, cnt) */
                   ulong                            cnt,
                   fd_epoch_leaders_t       const * lsched,
                   fd_pubkey_t              const * source );

/* fd_shred_dest_join joins the caller to a region of memory formatted
   as an fd_shred_dest_t. fd_shred_dest_leave does the opposite.
   fd_shred_dest_delete unformats a region of memory. */
fd_shred_dest_t * fd_shred_dest_join( void * mem );
void * fd_shred_dest_leave( fd_shred_dest_t * sdest );
void * fd_shred_dest_delete( void * mem );

/* fd_shred_dest_cnt_{staked, unstaked, all} returns the number of known
   destination that are staked, unstaked, or either, respectively.  The
   staked destinations have index [0, fd_shred_dest_cnt_staked()) and
   the unstaked destinations have index [fd_shred_dest_cnt_staked(),
   fd_shred_dest_cnt_all() ).  fd_shred_dest_cnt_all() ==
   fd_shred_dest_cnt_staked() + fd_shred_dest_cnt_unstaked(). */
static inline ulong fd_shred_dest_cnt_staked  ( fd_shred_dest_t * sdest ) { return sdest->staked_cnt                      ; }
static inline ulong fd_shred_dest_cnt_unstaked( fd_shred_dest_t * sdest ) { return                     sdest->unstaked_cnt; }
static inline ulong fd_shred_dest_cnt_all     ( fd_shred_dest_t * sdest ) { return sdest->staked_cnt + sdest->unstaked_cnt; }

/* fd_shred_dest_compute_first computes the root of the Turbine tree for
   each of the provided shreds.  All the provided shreds must come from
   the same slot (and thus have the same leader).  This should only be
   called for shreds from a slot in which the source validator provided
   in _new is the leader (determined using the leader schedule provided
   in _new).  shred_cnt specifies the number of shreds for which
   destinations should be computes.  input_shreds is accessed
   input_shreds[i] for i in [0, shred_cnt).  shred_cnt must be in [0,
   67].  The destination index for input_shreds[i] is stored at out[i].
   input_shreds==NULL is fine if shred_cnt==0, in which case this
   function is a no-op.  Returns out on success and NULL on failure.
   This function uses the sha256 batch API internally for performance,
   which is why it operates on several shreds at the same time as
   opposed to one at a time. */
fd_shred_dest_idx_t *
fd_shred_dest_compute_first( fd_shred_dest_t          * sdest,
                             fd_shred_t const * const * input_shreds,
                             ulong                      shred_cnt,
                             fd_shred_dest_idx_t      * out );

/* fd_shred_dest_compute_children computes the source validator's
   children in the Turbine tree for each of the provided shreds.
   Although Solana has the concept of "neighborhoods" in Turbine, we
   treat it as a standard high-radix tree, and a child is any validator
   to which the source validator should send the shred directly.
   All provided shreds must be from the same slot, and that leader for
   that slot must be known by the leader schedule.  As in
   fd_shred_dest_compute_first, shred_cnt specifies the number of
   shreds, input_shreds is accessed input_shreds[i] for i in [0,
   shred_cnt), and 0<=shred_cnt<=67.  Computes the first dest_cnt
   destinations for each shred, using a tree with fanout `fanout`.
   Exactly dest_cnt destination indices will be written for each shreds,
   so if that is more than the number of destinations that the source
   validator needs to send to, it will be padded out with
   FD_SHRED_DEST_NO_DEST.  The typical case is to pass dest_cnt==fanout.
   Results are stored in out, but there's some awkwardness associated
   with something that's logically a 2d array, so out_stride specifies
   the number of elements in each logical row of the output.
   Preciesely, destination j for shred i is written to out[ j*out_stride
   + i ]. Graphically:
   [ shred0 dest0, shred1 dest0, shred2 dest0, ... (skip until stride)
     shred0 dest1, shred1 dest1, shred2 dest1, ... (skip until 2stride)
     ...
     shred0 dest dest_cnt-1, ... ].
   out_stride must be at least shred_cnt.
   If opt_max_dest_cnt is non-NULL, the maximum number of real
   destinations for any of the provided shreds will be stored in
   opt_max_dest_cnt.  This value is always <= dest_cnt, but in many
   cases may be much lower (especially if the source validator has low
   stake).

   Returns out on success and NULL on failure. */
/* TODO: Would it be better if out were transposed? Should I get rid of
   stride? */
fd_shred_dest_idx_t *
fd_shred_dest_compute_children( fd_shred_dest_t          * sdest,
                                fd_shred_t const * const * input_shreds,
                                ulong                      shred_cnt,
                                fd_shred_dest_idx_t      * out,
                                ulong                      out_stride,
                                ulong                      fanout,
                                ulong                      dest_cnt,
                                ulong                    * opt_max_dest_cnt );

/* fd_shred_dest_idx_to_dest maps a destination index (as produced by
   fd_shred_dest_compute_children or fd_shred_dest_compute_first) to an
   actual destination.  The lifetime of the returned pointer is the same
   as the lifetime of sdest.  idx==FD_SHRED_DEST_NO_DEST is fine, and
   this will return a pointer to a destination with all fields set to 0.
   It's safe for the caller to update the IP, port, and mac fields of
   the returned struct, although the caller must not modify the weight
   or pubkey fields.  The caller can use this to update contact info for
   a validator. */
static inline fd_shred_dest_weighted_t *
fd_shred_dest_idx_to_dest( fd_shred_dest_t * sdest, fd_shred_dest_idx_t idx ) {
  return fd_ptr_if( idx!=FD_SHRED_DEST_NO_DEST, sdest->all_destinations + idx, sdest->null_dest );
}

/* fd_shred_dest_idx_t maps a pubkey to a destination index, if the
   pubkey is known as a destination.  If the pubkey is not know, returns
   FD_SHRED_DEST_NO_DEST. */
fd_shred_dest_idx_t fd_shred_dest_pubkey_to_idx( fd_shred_dest_t * sdest, fd_pubkey_t const * pubkey );

#endif /* HEADER_fd_src_disco_shred_fd_shred_dest_h */
