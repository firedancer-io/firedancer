#ifndef HEADER_fd_src_vinyl_bstream_fd_vinyl_bstream_h
#define HEADER_fd_src_vinyl_bstream_fd_vinyl_bstream_h

/* Client modifications to a vinyl key-val store are sequenced into
   total order by the vinyl tile and encoded into a stream of direct I/O
   friendly blocks (a "bstream").  A bstream has the strict mathematical
   property that a sufficient contiguous range of blocks ("the bstream's
   past") can be used to reconstruct the exact state of the vinyl
   key-val store at the bstream's "present" and then with a high
   probability of detecting random data corruption.  Further, the
   bstream's past can be efficiently and continuously updated at the
   same time the bstream is being modified with bounded space and time
   overheads.

   To introduce concepts and give more details:

   - sequence space: Every byte in a bstream has a sequence number that
     is that byte's offset from the leading bstream byte.  sequence
     numbers are 64-bit and wrap cyclicly (sequence wrapping is not a
     concern on practical timescales but the code handles it).

   - blocks: bstream bytes are accessed at block granularity.
     FD_VINYL_BSTREAM_BLOCK_SZ gives the block byte size.  bstream
     blocks always start at FD_VINYL_BSTREAM_BLOCK_SZ multiples.

   - history: A bstream reader/writer maintains four block sequence
     numbers: seq_ancient, seq_past, seq_present, seq_future with
     seq_ancient <= seq_past <= seq_present <= seq_future (cyclic).
     These partition bstream sequence space into four regions:

       [seq_ancient,seq_past)    (cyclic) is antiquity: these blocks have been written and forgotten (no read, no write)
       [seq_past,   seq_present) (cyclic) is past:      these blocks have been written               (read only)
       [seq_present,seq_future)  (cyclic) is present:   these blocks are being written               (write only)
       [seq_future, seq_ancient) (cyclic) is future:    these blocks have not been written           (no read, no write)

   - synchronization: The distinction between antiquity and the future
     is that blocks from antiquity will not be reused until the physical
     hardware has recorded the current location of the bstream's past.

   - recovery: the bstream's past is sufficient to exactly reconstruct
     the state of the key-val store at seq_present.

   - compaction: a bstream writer can cheaply prove whether or not a
     block is needed for recovery (blocked not needed for recovery are
     "garbage") and precisely track the amount of garbage in the
     bstream's past.  The writer can use this information to decide when
     and how to continuously reorganize the bstream's past to yield a
     minimally sized past asymptotically with a bounded amount of
     garbage during transients ("compaction").

   - compression: Compaction can also statelessly re-encode the storage
     represetation of pairs.  This will naturally compress seldom used
     pair data in the background while frequently used pairs will be
     stored uncompressed (RAW encoded) for speed.

   - encoding: A bstream encodes a key-val pair as follows:

     ----------------------------------------------------------------------- <- seq (FD_VINYL_BSTREAM_BLOCK_SZ multiple)
     ctl           8          type PAIR, val encoding style and val_esz  ^ ^
     key           key_sz     fix sz, 8 multiple                         | | fd_vinyl_bstream_phdr_t
     val_sz        4          decoded val_sz           fd_vinyl_info_t ^ | |
     app info      INFO_SZ-4  app info                                 v | v
     val           val_esz    encoded according to style                 |
     zero padding  zpad_sz    in [0,FD_VINYL_BSTREAM_BLOCK_SZ)           | pair_sz (FD_VINYL_BSTREAM_BLOCK_SZ multiple)
     hash_trail    8                                                   ^ |
     hash_blocks   8                           FD_VINYL_BSTREAM_FTR_SZ v v
     -----------------------------------------------------------------------

     There is much nuance in the above:

     * Since sizeof(fd_vinyl_bstream_phdr_t) + FD_VINYL_BSTREAM_FTR_SZ is
       less than FD_VINYL_BSTREAM_BLOCK_SZ, a pair with a small enough
       encoded val can fit in a single block.  It is not possible to
       encode multiple pairs in a single block though.

     * hash_trail covers all the pair's trailing blocks.  hash_trail for
       a single block item is the bstream's hash seed.  hash_blocks is
       the hash of the leading block with hash_trail as the seed.

     * Hashing is block oriented to create a single easily optimized
       case for software and hardware to target.  Implementations can
       optimize and specialize data integrity hash functions to the case
       that maps a 64-bit seed and a FD_VINYL_BSTREAM_BLOCK_SZ aligned
       and FD_VINYL_BSTREAM_BLOCK_SZ footprint input buffer to a 64-bit
       output for all hashing operations.

     * The hashes are located at the pair end so that pairs can be
       streamed to storage cut-through / zero-copy style by writers with
       no seeking.  Reading into memory can likewise be done with no
       intermediate copies of the pair (especially for RAW encoded
       pairs).

     * Hashing the trailing blocks and hash chaining the leading block
       allows updating pair metadata (e.g.  renaming a pair, copying a
       pair, moving a pair, etc) without requiring rehashing all the
       data while maintaining strong data integrity protections (e.g.
       can detect with high probability whether the leading block has
       been mismatched from its trailing blocks).

     * Storing both hashes also allows fast high integrity bstream
       iteration.  Specifically, iterators can fully validate small
       pairs and partially validate large pairs (the pair key, pair
       metadata and leading pair val bytes are valid and the trailing
       val bytes are matched to these bytes) cheaply (i.e. without
       needing to compute a full pair hash) with very low cost in
       storage or overhead on read or write.

     * The hashes are computed with the hash fields zeroed.  The hash
       fields are then set when the pair is written.

     * This representation is cheaply relocatable (this is particularly
       important for compaction).  For example, we could include the
       bstream seq in the pair header for extra redundancy (e.g. can
       potentially estimate bstream's past if the bstream's metadata
       gets corrupted) and extra data integrity checks.  But then we'd
       have to either:

       - Recompute pair hashes when reorganizing the bstream's past
         during background compaction (which would prevent generic I/O
         hardware offload of bulk copies used for compaction).

       - Exclude seq from the block header hashing (which helps some
         but we'd still need to update seq in the header and thus
         prevent generic I/O hardware offload of bulk copies).

       - Keep seq constant during the compaction.  This would turn seq
         into an indicator of when the pair was first created (or
         recreated if after an erase or move).  Ignoring sequence wrap,
         this could preserve some data integrity checking (e.g. seq
         aligned and at or before the pair's current position) but this
         weakens the sync metadata redundancy benefits of including seq
         (can't just search for a contiguous range of well formatted
         blocks and use seq to get a bstream's past range estimate).

       - ...

       Instead, we go the simpler, faster and more flexible route.  We
       omit bstream seq here from the pair.  This allows pairs to be
       moved around in the bstream with simple bulk copies.  Simpler
       code, more application pair metadata and faster background
       compaction.

   - control blocks: the bstream can contain control blocks to support
     recovery.  A control block can only refer to bstream blocks before
     it in the bstream.  Thus, they are always garbage from the point of
     view of compaction as they can be always be removed from the
     bstream's past once they are at seq_past.

   - zero padding: one type of control block is zero padding.  These
     can be inserted by the bstream writer in order ensure sets of
     blocks are kept continguous in the underlying physical storage
     (e.g. making sure an encoded pair is never split across two
     physical volumes).

   - partitions: another type of control block is a partition.  The
     bstream writer can insert partitions periodically to allow the
     bstream past to be quickly partitioned at object boundaries into
     approximately uniform slices that can be used for parallel
     recovery.  These partitions also include the number of erases and
     moves that happend in the partition to aid in parallel recovery (to
     optionally tightly bound the size of temporary data structures at
     start).

   - hot or not: the metadata for all pairs at seq_present is always
     available fast O(1) to concurent vinyl users.  This includes a
     small amount of application info (like balances, expirations, etc). */

#include "../fd_vinyl_base.h"

/* FD_VINYL_BSTREAM_BLOCK_SZ gives the block size in bytes of a bstream
   block.  It is a direct I/O friendly power-of-2 (i.e. a power-of-2 >=
   512).  FD_VINYL_BSTEAM_BLOCK_LG_SZ gives the log2 of this. */

#define FD_VINYL_BSTREAM_BLOCK_SZ    (512UL)
#define FD_VINYL_BSTREAM_BLOCK_LG_SZ (9)

/* A FD_VINYL_BSTREAM_CTL_TYPE_* specifies how to interpret the next
   range of blocks in the bstream.  A FD_VINYL_BSTREAM_CTL_STYLE_*
   specifies the encoding style for that range of blocks (e.g. whether
   or not a pair is compressed).  We use a 16-bit and a 12-bit
   non-compact encoding respectively for these so that simple data
   corruption errors can be detected without doing more expensive
   validation first.  This leaves 36 bits for ctl sz, limiting a pair's
   encoded val size to be in [0,2^36).  The LZ4 API inexplicably uses
   signed 32-bit ints for buffer sizes so an encoded / decode value size
   is further limited to be in [0,LZ4_MAX_INPUT_SIZE) (where
   LZ4_MAX_INPUT_SIZE is a little under 2^31). */

#define FD_VINYL_BSTREAM_CTL_TYPE_PAIR ((int)(0x9a17)) /* "pair"         */
#define FD_VINYL_BSTREAM_CTL_TYPE_SYNC ((int)(0x512c)) /* "sync"         */
#define FD_VINYL_BSTREAM_CTL_TYPE_DEAD ((int)(0xdead)) /* "dead"         */
#define FD_VINYL_BSTREAM_CTL_TYPE_MOVE ((int)(0x30c3)) /* "move"         */
#define FD_VINYL_BSTREAM_CTL_TYPE_PART ((int)(0xd121)) /* "divi"der      */
#define FD_VINYL_BSTREAM_CTL_TYPE_ZPAD (0)             /* (must be zero) */

#define FD_VINYL_BSTREAM_CTL_STYLE_RAW ((int)0x7a3)    /* "raw" */
#define FD_VINYL_BSTREAM_CTL_STYLE_LZ4 ((int)0x124)    /* "lz4" */

/* A fd_vinyl_bstream_phdr_t gives the layout of bstream pair header
   (e.g. ctl, type PAIR, val encoding style, val encoding size, key,
   decoded val size and other application info). */

struct fd_vinyl_bstream_phdr {
  ulong           ctl;
  fd_vinyl_key_t  key;
  fd_vinyl_info_t info;
};

typedef struct fd_vinyl_bstream_phdr fd_vinyl_bstream_phdr_t;

/* FD_VINYL_BSTREAM_FTR_SZ gives the number of bytes in a bstream
   object footer. */

#define FD_VINYL_BSTREAM_FTR_SZ (2UL*sizeof(ulong))

/* If pair val byte size is greater than
   FD_VINYL_BSTREAM_LZ4_VAL_THRESH, it is considered worth trying to
   encode with lz4 compression (if lz4 compression is enabled).  The
   default below is such that, even if the val smaller than this
   compressed to 0 bytes, it would still require one block of bstream
   space.  (FIXME: make this dynamically run time configured?) */

#define FD_VINYL_BSTREAM_LZ4_VAL_THRESH (FD_VINYL_BSTREAM_BLOCK_SZ - sizeof(fd_vinyl_bstream_phdr_t) - FD_VINYL_BSTREAM_FTR_SZ)

/* FD_VINYL_BSTREAM_*_INFO_MAX give the max app info bytes that can be
   stashed in the eponymous control block. */

#define FD_VINYL_BSTREAM_SYNC_INFO_MAX (FD_VINYL_BSTREAM_BLOCK_SZ - 6UL*sizeof(ulong))
#define FD_VINYL_BSTREAM_DEAD_INFO_MAX (FD_VINYL_BSTREAM_BLOCK_SZ - 5UL*sizeof(ulong) - sizeof(fd_vinyl_bstream_phdr_t))
#define FD_VINYL_BSTREAM_MOVE_INFO_MAX (FD_VINYL_BSTREAM_BLOCK_SZ - 5UL*sizeof(ulong) - sizeof(fd_vinyl_bstream_phdr_t) - sizeof(fd_vinyl_key_t))
#define FD_VINYL_BSTREAM_PART_INFO_MAX (FD_VINYL_BSTREAM_BLOCK_SZ - 8UL*sizeof(ulong))

/* A fd_vinyl_bstream_block gives the binary layouts for various types
   of blocks.  Note that direct I/O requires our memory alignments to
   match device alignments.  Hence is this aligned
   FD_VINYL_BSTREAM_BLOCK_SZ in memory too. */

union __attribute__((aligned(FD_VINYL_BSTREAM_BLOCK_SZ))) fd_vinyl_bstream_block {

  ulong ctl;

  fd_vinyl_bstream_phdr_t phdr;                                     /* type PAIR, style *, sz pair val encoded sz */

  struct {
    uchar                   _[ FD_VINYL_BSTREAM_BLOCK_SZ - FD_VINYL_BSTREAM_FTR_SZ ];
    ulong                   hash_trail;
    ulong                   hash_blocks;
  } ftr;

  struct {
    ulong                   ctl;                                    /* type SYNC, style 0 (ABI version), sz VAL_MAX */
    ulong                   seq_past;                               /* recover using blocks [seq_past,seq_present) */
    ulong                   seq_present;                            /* these are FD_VINYL_BSTREAM_BLOCK_SZ multiples */
    ulong                   info_sz;                                /* info byte size, in [0,FD_VINYL_BSTREAM_SYNC_INFO_MAX]. */
    uchar                   info[ FD_VINYL_BSTREAM_SYNC_INFO_MAX ]; /* sync info */
    ulong                   hash_trail;                             /* establishes bstream's hash seed */
    ulong                   hash_blocks;
  } sync; /* Note: this is located "outside" the bstream */

  struct {
    ulong                   ctl;                                    /* type DEAD, style RAW, sz BLOCK_SZ */
    ulong                   seq;                                    /* bstream seq num of this block */
    fd_vinyl_bstream_phdr_t phdr;                                   /* pair header of the key getting erased */
    ulong                   info_sz;                                /* info byte size, in [0,FD_VINYL_BSTREAM_DEAD_INFO_MAX] */
    uchar                   info[ FD_VINYL_BSTREAM_DEAD_INFO_MAX ]; /* dead info */
    ulong                   hash_trail;
    ulong                   hash_blocks;
  } dead;

  struct {
    ulong                   ctl;                                    /* type MOVE, style RAW, sz BLOCK_SZ */
    ulong                   seq;                                    /* bstream seq num of this block */
    fd_vinyl_bstream_phdr_t src;                                    /* src pair header */
    fd_vinyl_key_t          dst;                                    /* pair src.key renamed to pair dst or replaced pair dst */
    ulong                   info_sz;                                /* info byte size, in [0,FD_VINYL_BSTREAM_MOVE_INFO_MAX] */
    uchar                   info[ FD_VINYL_BSTREAM_MOVE_INFO_MAX ]; /* move info */
    ulong                   hash_trail;
    ulong                   hash_blocks;
  } move; /* Note: a move block is immediately followed by a matching pair */

  struct {
    ulong                   ctl;                                    /* type PART, style RAW, sz BLOCK_SZ */
    ulong                   seq;                                    /* bstream seq num of this block */
    ulong                   seq0;                                   /* Partition starts at seq0 (at most seq, BLOCK_SZ aligned) */
    ulong                   dead_cnt;                               /* num dead blocks in this partition (for parallel recovery) */
    ulong                   move_cnt;                               /* num move blocks in this partition (for parallel recovery) */
    ulong                   info_sz;                                /* info byte size, in [0,FD_VINYL_BSTREAM_PART_INFO_MAX] */
    uchar                   info[ FD_VINYL_BSTREAM_PART_INFO_MAX ]; /* partition info */
    ulong                   hash_trail;
    ulong                   hash_blocks;
  } part;

  uchar zpad[ FD_VINYL_BSTREAM_BLOCK_SZ ]; /* all zeros (type, style, sz, hash_trail, hash_blocks ...) */

  uchar data[ FD_VINYL_BSTREAM_BLOCK_SZ ]; /* arbitrary (type, style, sz, hash_trail, hash_blocks ...) */

};

typedef union fd_vinyl_bstream_block fd_vinyl_bstream_block_t;

FD_PROTOTYPES_BEGIN

/* fd_vinyl_seq_* compare bstream sequence numbers, correctly handling
   wrap around. */

FD_FN_CONST static inline int fd_vinyl_seq_lt( ulong a, ulong b ) { return ((long)(a-b))< 0L; }
FD_FN_CONST static inline int fd_vinyl_seq_gt( ulong a, ulong b ) { return ((long)(a-b))> 0L; }
FD_FN_CONST static inline int fd_vinyl_seq_le( ulong a, ulong b ) { return ((long)(a-b))<=0L; }
FD_FN_CONST static inline int fd_vinyl_seq_ge( ulong a, ulong b ) { return ((long)(a-b))>=0L; }
FD_FN_CONST static inline int fd_vinyl_seq_eq( ulong a, ulong b ) { return ((long)(a-b))==0L; }
FD_FN_CONST static inline int fd_vinyl_seq_ne( ulong a, ulong b ) { return ((long)(a-b))!=0L; }

/* fd_vinyl_bstream_ctl return the bstream control field that encodes a
   FD_VINYL_BSTREAM_CTL_TYPE_* type, FD_VINYL_BSTREAM_CTL_STYLE_* style,
   and a byte size in [0,2^36).  fd_vinyl_bstream_ctl_* return the
   eponymous field from the given bstream ctl. */

FD_FN_CONST static inline ulong
fd_vinyl_bstream_ctl( int   type,
                      int   style,
                      ulong val_sz ) {
  return ((ulong)type) | (((ulong)style)<<16) | (val_sz<<28);
}

FD_FN_CONST static inline int   fd_vinyl_bstream_ctl_type ( ulong ctl ) { return (int)( ctl      & 65535UL); }
FD_FN_CONST static inline int   fd_vinyl_bstream_ctl_style( ulong ctl ) { return (int)((ctl>>16) &  4095UL); }
FD_FN_CONST static inline ulong fd_vinyl_bstream_ctl_sz   ( ulong ctl ) { return        ctl>>28;             }

/* fd_vinyl_bstream_pair_sz returns the byte footprint of a pair with a
   val_esz encoded value byte size.  Assumes val_esz in [0,2^48) which
   implies the worst case maximum encoded value size allowed is in
   [0,2^48).  Returns a positive FD_VINYL_BSTREAM_BLOCK_SZ multiple. */

FD_FN_CONST static inline ulong
fd_vinyl_bstream_pair_sz( ulong val_esz ) {
  return fd_ulong_align_up( sizeof(fd_vinyl_bstream_phdr_t) + val_esz + FD_VINYL_BSTREAM_FTR_SZ, FD_VINYL_BSTREAM_BLOCK_SZ );
}

/* fd_vinyl_bstream_hash returns a 64-bit hash of the 64-bit seed and
   the sz byte buffer buf.  Assumes buf is points to well aligned range
   of blocks stable for the duration of the call and sz is a multiple of
   FD_VINYL_BSTREAM_BLOCK_SZ.  sz 0 returns seed.  Retains no interest
   in buf. */

FD_FN_PURE static inline ulong
fd_vinyl_bstream_hash( ulong                            seed,
                       fd_vinyl_bstream_block_t const * buf,
                       ulong                            buf_sz ) {
  return FD_LIKELY( buf_sz ) ? fd_hash( seed, buf, buf_sz ) : seed;
}

/* fd_vinyl_bstream_block_hash initializes the hash fields of a bstream
   object that fits into a single block (i.e. a small val pair, sync
   block, a dead block, a move block or a part block).  block's hash
   fields and any zero padding should be zero on entry.  block's hash
   fields will be set correctly on exit.  Assumes block is valid. */

static inline void
fd_vinyl_bstream_block_hash( ulong                      seed,
                             fd_vinyl_bstream_block_t * block ) {

  ulong hash_trail  = seed;
  ulong hash_blocks = fd_vinyl_bstream_hash( hash_trail, block, FD_VINYL_BSTREAM_BLOCK_SZ );

  block->ftr.hash_trail  = hash_trail;
  block->ftr.hash_blocks = hash_blocks;

}

/* fd_vinyl_bstream_block_test returns FD_VINYL_SUCCESS if a bstream
   object that fits into a single bstream block (i.e. a small val pair,
   a sync block, a dead block, a move block or a part block) has valid
   data integrity hashes and FD_VINYL_ERR_CORRUPT if not.  seed is the
   bstream's data integrity seed.  Assumes block points to the valid
   stable location.  block's hash fields will be clobbered on return
   (will be zero on success). */

static inline int
fd_vinyl_bstream_block_test( ulong                      seed,
                             fd_vinyl_bstream_block_t * block ) {

  ulong hash_trail  = block->ftr.hash_trail;
  ulong hash_blocks = block->ftr.hash_blocks;

  block->ftr.hash_trail  = 0UL;
  block->ftr.hash_blocks = 0UL;

  if( FD_UNLIKELY( hash_trail                                                      != seed        ) ||
      FD_UNLIKELY( fd_vinyl_bstream_hash( seed, block, FD_VINYL_BSTREAM_BLOCK_SZ ) != hash_blocks ) )
    return FD_VINYL_ERR_CORRUPT;

  return FD_VINYL_SUCCESS;
}

/* fd_vinyl_bstream_pair_hash clears the footer region and any zero
   padding region of pair and then populates the hash fields
   appropriately.  seed is the bstream data integrity seed.  Assumes
   pair points to any appropriately sized and aligned memory region and
   the phdr and val fields are correctly populated (in particular,
   val_esz is set correctly). */

void
fd_vinyl_bstream_pair_hash( ulong                      seed,
                            fd_vinyl_bstream_block_t * phdr );

/* fd_vinyl_bstream_*_test returns NULL if bstream object at seq is
   well formed and an infinite lifetime human-readable cstr describing
   the issue detected if not.  The footer has been clobbered on return
   (will be zero on success).  seed is the bstream's data integrity
   seed.  Assumes pair points to a valid pair_sz footprint location.

   For fd_vinyl_bstream_pair_test, the pair is assumed fit within the
   the buf_sz buffer buf, not exactly fill the buffer.

   fd_vinyl_bstream_pair_test_fast is the same thing but omits testing
   any interior blocks for use in fast iteration.  hdr / ftr point
   locations holding the first/last block in the pair.  These should
   point to the same location if the pair fits into a single block. */

char const *
fd_vinyl_bstream_pair_test( ulong                      seed,
                            ulong                      seq,
                            fd_vinyl_bstream_block_t * buf,
                            ulong                      buf_sz );

char const *
fd_vinyl_bstream_pair_test_fast( ulong                            seed,
                                 ulong                            seq,
                                 fd_vinyl_bstream_block_t const * hdr,
                                 fd_vinyl_bstream_block_t *       ftr );

char const *
fd_vinyl_bstream_dead_test( ulong                      seed,
                            ulong                      seq,
                            fd_vinyl_bstream_block_t * block );

char const *
fd_vinyl_bstream_move_test( ulong                      seed,
                            ulong                      seq,
                            fd_vinyl_bstream_block_t * block,
                            fd_vinyl_bstream_block_t * dst );

char const *
fd_vinyl_bstream_part_test( ulong                      seed,
                            ulong                      seq,
                            fd_vinyl_bstream_block_t * block );

char const *
fd_vinyl_bstream_zpad_test( ulong                      seed,
                            ulong                      seq,
                            fd_vinyl_bstream_block_t * block );

/* fd_vinyl_bstream_ctl_style_cstr returns an infinite lifetime human
   readable cstr for the given style.  Return value is always non-NULL
   (if style is not a valid style, the string will be "unk").

   fd_cstr_to_vinyl_bstream_ctl_style returns the style corresponding to
   the given cstr.  Returns -1 if cstr does not correspond to a
   supported style. */

char const *
fd_vinyl_bstream_ctl_style_cstr( int style );

int
fd_cstr_to_vinyl_bstream_ctl_style( char const * cstr );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vinyl_bstream_fd_vinyl_bstream_h */
