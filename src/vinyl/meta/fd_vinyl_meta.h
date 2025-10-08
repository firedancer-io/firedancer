#ifndef HEADER_fd_src_vinyl_meta_fd_vinyl_meta_h
#define HEADER_fd_src_vinyl_meta_fd_vinyl_meta_h

/* The metadata for all current pairs and pairs in the process of being
   created is cached in DRAM and can be queried by key lockfree
   concurrent in fast O(1) operations via a fd_vinyl_meta_t.  The
   "current pairs" are the set of pairs that would be obtained by
   recovering the key-val state from the bstream's blocks
   [seq_past,seq_present).

   This is implemented as a fd_map_slot_para with a some specialized
   implementation to optimize various API in normal operation.  That is,
   in normal operation, a meta cache has a single writer (the vinyl
   tile) and multiple concurrent readers (various clients needing to
   test if a pair is present, where it is located, how big the val is
   and other application specific pair info like timestamps, balances,
   expirations, etc).

   During recovery, a meta cache can have multiple concurrent readers
   and writers (the individual threads replaying their segments of the
   bstream's past).

   Given it is based on fd_map_slot_para, a fd_vinyl_meta_t can be
   shared between threads in different processes.  Likewise, it can be
   used persistent.  But, as it can be exactly reconstructed during
   recovery from the bstream's past and there are no provisions for
   "syncing" the meta cache with the bstream in the face of unexpected
   processs interruptions, persistence should only be used for post
   mortem debugging. */

#include "../bstream/fd_vinyl_bstream.h"

/* Instantiate a library header API for a fd_vinyl_meta_t as a
   fd_map_slot_para of mapping of keys to fd_vinyl_meta_ele_t.  Note
   that, when an element is not locked:

     phdr.ctl will be 0 if a meta element is free.  All other element
     fields should be ignored if the element is free.

     phdr.ctl will be ULONG_MAX if the mapped version of pair is not in
     the bstream's past yet (i.e. the pair is being created).  memo,
     phdr.key, and line_idx are valid.  phdr.info (including the val_sz)
     and seq should be ignored.

     Otherwise, phdr _exactly_ mirrors the most recent version of phdr
     in the bstream's past.  All element fields are valid.

   IMPORTANT SAFETY TIP!  meta_seed and bstream_seed are _not_ the same
   thing.  meta_seed ideally is unique and random for each run but the
   bstream_seed should be persistent across all users of the underlying
   bstream. */

struct fd_vinyl_meta_ele {

  ulong                   memo;     /* ==fd_vinyl_key_memo( seed, key ) */
  fd_vinyl_bstream_phdr_t phdr;

  /* The below fields are used only by the vinyl tile.  Concurrent
     readers should ignore them. */

  ulong                   seq;      /* If pair exists at bstream seq_present, bstream seq of the most recent version.
                                       This will be in the bstream's past and there will be no bstream objects concerning phdr.key
                                       at a later seq. */
  ulong                   line_idx; /* If a pair decoded val is cached, vinyl cache line assigned to pair, ULONG_MAX if not. */

};

typedef struct fd_vinyl_meta_ele fd_vinyl_meta_ele_t;

/* Note: When remove needs to move an element to preserve its probe
   sequence, if the corresponding pair is in cache, it also needs to
   update the vinyl line structure to reflect the new location of the
   element.  We could do this by stashing the vinyl line / line_cnt into
   the meta ctx and incorporating the needed update in MAP_ELE_MOVE
   below (its what ctx is for).

   But we don't actually use the remove API currently as we have a
   specialized version for single producer use below.  And that version
   does handle the line updates.  So we omit here.  The upshot is that:

   IMPORTANT SAFETY TIP:  fd_vinyl_meta_remove currently does not update
   the line-to-element mapping.  So it is not safe to use if there are
   items in data cache.  (It is currently used in parallel recovery but
   then at a time when the data cache is flushed.  So it is safe then.) */

struct fd_vinyl_line;
typedef struct fd_vinyl_line fd_vinyl_line_t;

#define MAP_NAME                  fd_vinyl_meta
#define MAP_ELE_T                 fd_vinyl_meta_ele_t
#define MAP_KEY_T                 fd_vinyl_key_t
#define MAP_KEY                   phdr.key
#define MAP_KEY_EQ(k0,k1)         fd_vinyl_key_eq( (k0), (k1) )
#define MAP_KEY_HASH(key,seed)    fd_vinyl_key_memo( (seed), (key) )
#define MAP_MEMOIZE               1
#define MAP_MEMO                  memo
#define MAP_KEY_EQ_IS_SLOW        1
#define MAP_ELE_IS_FREE(ctx,ele)  (!(ele)->phdr.ctl)
#define MAP_ELE_FREE(ctx,ele)     do { (ele)->phdr.ctl = 0UL; } while(0)
#define MAP_ELE_MOVE(ctx,dst,src) do { fd_vinyl_meta_ele_t * _src = (src); *(dst) = *_src; _src->phdr.ctl = 0UL; } while(0)
#define MAP_IMPL_STYLE            1
#include "../../util/tmpl/fd_map_slot_para.c"

FD_PROTOTYPES_BEGIN

/* fd_vinyl_meta_ele_in_use returns 1 if the given ele is in use and 0
   otherwise.  Assumes ele is valid.  If the element is in use,
   ele->phdr.key and ele->memo are valid.

   fd_vinyl_meta_ele_in_bstream returns 1 if the given ele is present at
   bstream seq_present and 0 otherwise.  Assumes ele valid and in use.
   If ele is in bstream, ele->phdr exactly mirrors the pair header for
   the version of the pair present at seq_present and ele->seq gives the
   location in the bstream's past of this version of the pair.

   fd_vinyl_meta_ele_in_cache returns 1 if space has been allocated in
   the vinyl's data cache for the pair.  Assumes ele is valid and in
   use.  If ele is in cache, ele->line_idx gives vinyl cache line
   assigned to the pair value. */

FD_FN_PURE static inline int fd_vinyl_meta_ele_in_use    ( fd_vinyl_meta_ele_t const * ele ) { return !!ele->phdr.ctl;          }
FD_FN_PURE static inline int fd_vinyl_meta_ele_in_bstream( fd_vinyl_meta_ele_t const * ele ) { return ele->phdr.ctl!=ULONG_MAX; }
FD_FN_PURE static inline int fd_vinyl_meta_ele_in_cache  ( fd_vinyl_meta_ele_t const * ele ) { return ele->line_idx!=ULONG_MAX; }

/* fd_vinyl_meta_prepare_fast prepares to modify meta element ele_idx
   under the assumption the caller is the only active writer and there
   are no meta prepares in progress.

   fd_vinyl_meta_publish_fast completes a prepare of meta element
   ele_idx, making the modifications visible to concurrent readers.

   fd_vinyl_meta_cancel_fast completes a prepare of meta element
   ele_idx, indicating to concurrent readers that no modifications were
   made.  The caller promises that shared fields of the meta element was
   not modified at any point in time during the prepare.

   l is a pointer to the meta lock array, s is the meta lock shift and e
   is the meta element index.  Does no input argument checking.  These
   functions cannot fail. */

static inline void
fd_vinyl_meta_lock_update_fast( ulong * lock,
                                long    dir ) {
  ulong version = (*lock) + (ulong)dir;
  FD_COMPILER_MFENCE();
  *lock = version;
  FD_COMPILER_MFENCE();
}

#define fd_vinyl_meta_prepare_fast(l,s,e) fd_vinyl_meta_lock_update_fast( (l) + ((e)>>(s)),  1L )
#define fd_vinyl_meta_publish_fast(l,s,e) fd_vinyl_meta_lock_update_fast( (l) + ((e)>>(s)),  1L )
#define fd_vinyl_meta_cancel_fast( l,s,e) fd_vinyl_meta_lock_update_fast( (l) + ((e)>>(s)), -1L )

/* fd_vinyl_meta_query_fast queries a meta for key under the assumption
   the caller is the only active meta writer and there are no meta
   prepares in progress.  Does no input arg checking.  On success,
   returns FD_VINYL_SUCCESS (0) (key was found, on return *_ele_idx
   gives key's current meta element index).  On failure, returns a
   FD_VINYL_ERR code (negative).  Reasons for failure include KEY (key
   was not found, on return *_ele_idx gives the meta element index
   suitable for storing pair metadata if the meta is not already at
   capacity).  Will FD_LOG_CRIT if anything wonky is detected.

   IMPORTANT SAFETY TIP!  In general, meta element ele_idx should not be
   modified by the writer unless it is protected by a prepare.
   Inserting without doing a prepare is fine so long as phdr.ctl becomes
   visible last. */

FD_FN_PURE int
fd_vinyl_meta_query_fast( fd_vinyl_meta_ele_t const * ele0,       /* indexed [0,ele_max) */
                          ulong                       ele_max,    /* power of 2 */
                          fd_vinyl_key_t const *      key,        /* key to query */
                          ulong                       memo,       /* == fd_vinyl_key_memo( seed, key ) */
                          ulong *                     _ele_idx ); /* will be in [0,ele_max) on return */

/* fd_vinyl_meta_remove_fast removes the key<>metadata mapping at meta
   element ele_idx from the meta under the asumption the caller is the
   only active writer to the meta and there are no meta prepares in
   progress.  This cannot fail from the caller's perspective
   (FD_LOG_CRIT if meta or line is corruption detected during removal). */

void
fd_vinyl_meta_remove_fast( fd_vinyl_meta_ele_t * ele0,       /* Assumes at least one unoccupied element in the meta */
                           ulong                 ele_max,    /* Assumes power of 2 (of at least 2 given 1 occupied and 1 hole) */
                           ulong *               lock,       /* lock_max == ele_max >> lock_shift */
                           int                   lock_shift, /* ==log2 ele_max / lock_cnt where lock_cnt is a power 2 <= ele_max */
                           fd_vinyl_line_t *     line,       /* Indexed [0,line_cnt) */
                           ulong                 line_cnt,   /* In [3,FD_VINYL_LINE_MAX] */
                           ulong                 ele_idx );  /* Assumes map element ele_idx is occupied */

/* fd_vinyl_meta_query is a simplified query for key for concurrent
   readers.  It handles out try / test and filters out keys that are in
   the process of being created.  Assumes meta is a current local join,
   key and _info are valid for the duration of the call and _info is
   a fd_vinyl_info_t compatible memory region.

   Returns FD_VINYL_SUCCESS (0) if pair key existed in the bstream's
   seq_present when the bstream was observed during the call.  On
   return, *_info will be populated with the pair key's info at that
   seq_present (including the val byte size).

   Returns FD_VINYL_ERR_KEY (negative) if pair key did not exist in the
   bstream's seq_present when the bstream was observed.  On return,
   *_info will be clobbered.  Retains no interest in key or _info.

   IMPORTANT SAFETY TIP!  This can block the caller until the query
   resolves.  Concurrent readers wanting guaranteed non-blocking
   behavior in the face of a vinyl tile dying in the middle of updating
   conflicting ele meta, wanting to provide hints / extract the key memo
   for reuse / etc, should use more general lockfree query API. */

static inline int
fd_vinyl_meta_query( fd_vinyl_meta_t *      meta,
                     fd_vinyl_key_t const * key,
                     void *                 _info ) {
  ulong ctl;

  for(;;) {

    fd_vinyl_meta_query_t query[1];
    int err = fd_vinyl_meta_query_try( meta, key, NULL, query, FD_MAP_FLAG_BLOCKING );
    if( FD_UNLIKELY( err ) ) return err;
    fd_vinyl_meta_ele_t const * ele  = fd_vinyl_meta_query_ele_const( query );

    ctl = ele->phdr.ctl;
    *(fd_vinyl_info_t *)_info = ele->phdr.info;

    if( FD_LIKELY( !fd_vinyl_meta_query_test( query ) ) ) break;

    FD_SPIN_PAUSE();

  }

  return fd_int_if( ctl!=ULONG_MAX, FD_MAP_SUCCESS, FD_MAP_ERR_KEY );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vinyl_meta_fd_vinyl_meta_h */
