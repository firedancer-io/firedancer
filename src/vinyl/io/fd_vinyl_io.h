#ifndef HEADER_fd_src_vinyl_io_fd_vinyl_io_h
#define HEADER_fd_src_vinyl_io_fd_vinyl_io_h

/* A fd_vinyl_io_t reads from / appends to a bstream stored in some
   physical layer (typically slow and non-volatile).  Supports massive
   numbers of async concurrent reads and appends and the ability to
   recover from unexpected interrupts (Ctrl-C, power failures, etc).  To
   accommodate the myriad of different styles of physical layers and
   interfaces, the API is run time plugin friendly.  Summary of
   operations:

     read_imm: blocking read a contiguous range of blocks in the
     bstream's past.  Mostly used for iterating over a bstream's past.

     read: start reading a contiguous range of blocks in the bstream's
     past.  The caller promises the range to read is contiguous in the
     underlying physical storage.

     poll: finish an outstanding read.  Outstanding reads can complete
     in an arbitary order.  All reads must be finished by poll but note
     that it is possible to detect a read is complete out-of-band too
     (for speculative processing).

     append: start appending a set of blocks to the end of the bstream's
     present (moving blocks from the bstream's future to the bstream's
     present).  The blocks will be contiguous in the underlying storage.
     The blocks must be suitably aligned and with a lifetime until the
     next commit.

     commit: finish all outstanding appends, moving all blocks in the
     bstream's present to the bstream's past.  This will empty the io's
     append scratch pad.  The underlying implementation is free to
     process outstanding appends in any order (and free to interleave
     them arbitrarily with outstanding reads).

     hint: indicates the next sz worth of blocks appended to the bstream
     must be contiguous in the physical storage.

     alloc: allocate memory from the io's append scratch pad.  These
     allocations will have a suitable alignment for append and a
     lifetime until the next commit.  This may trigger a commit of
     outstanding appends if there isn't enough scratch pad free.

     copy: append a contiguous range of blocks from the bstream's past
     to the end of the bstream's present.  May commit outstanding
     appends.

     forget: forget all blocks before a given sequence number, moving
     blocks from the bstream's past to the bstream's antiquity.  The
     caller can only forget up to the bstream's present.

     rewind: move blocks from the bstream's past (and potentially
     antiquity) to the bstream's future.  The bstream must have an empty
     present (i.e. no appends in progress) and no reads in progress.
     This allows, for example, on recovery, a multi-block pair that was
     incompletely written to be cleaned up.

     sync: update the range for the bstream past where recovery will
     resume.  This moves all blocks in the bstream's antiquity to end of
     the bstream's future. */

/* FIXME: consider a query to get how many reads are outstanding? (with
   this, rewind and forget could be complete generic). */

#include "../bstream/fd_vinyl_bstream.h"

/* FD_VINYL_IO_TYPE_* identifies which IO implementation is in use. */

#define FD_VINYL_IO_TYPE_MM (0)
#define FD_VINYL_IO_TYPE_BD (1)

/* FD_VINYL_IO_FLAG_* are flags used by various vinyl IO APIs */

#define FD_VINYL_IO_FLAG_BLOCKING (1) /* Okay to block the caller */

/* A fd_vinyl_io_rd_t describes a read request to the underlying I/O
   implementation to read [seq,seq+sz) (cyclic) from the bstream's past
   into dst.  seq, dst and sz should be FD_VINYL_BSTREAM_BLOCK_SZ
   aligned.  Any failure encountered while reading should FD_LOG_CRIT
   (just like reading an invalid memory address will seg fault).
   Underlying I/O implementations can add other information to this
   structure as necessary.  ctx is an arbitrary user defined value. */

#define FD_VINYL_IO_READ_SZ (64UL)

struct fd_vinyl_io_rd {
  ulong  ctx;
  ulong  seq;
  void * dst;
  ulong  sz;
  uchar  _[ FD_VINYL_IO_READ_SZ - 32UL ];
};

typedef struct fd_vinyl_io_rd fd_vinyl_io_rd_t;

/* fd_vinyl_io_t is an opaque handle of a fd_vinyl_io instance.  Some
   details are exposed to facilitate inlining in high performance
   contexts. */

struct fd_vinyl_io_private;
typedef struct fd_vinyl_io_private fd_vinyl_io_t;

typedef void   (*fd_vinyl_io_func_read_imm_t)( fd_vinyl_io_t * io, ulong seq, void * dst, ulong sz );
typedef void   (*fd_vinyl_io_func_read_t    )( fd_vinyl_io_t * io, fd_vinyl_io_rd_t * rd );
typedef int    (*fd_vinyl_io_func_poll_t    )( fd_vinyl_io_t * io, fd_vinyl_io_rd_t ** _rd, int flags );
typedef ulong  (*fd_vinyl_io_func_append_t  )( fd_vinyl_io_t * io, void const * src, ulong sz );
typedef int    (*fd_vinyl_io_func_commit_t  )( fd_vinyl_io_t * io, int flags );
typedef ulong  (*fd_vinyl_io_func_hint_t    )( fd_vinyl_io_t * io, ulong sz );
typedef void * (*fd_vinyl_io_func_alloc_t   )( fd_vinyl_io_t * io, ulong sz, int flags );
typedef ulong  (*fd_vinyl_io_func_copy_t    )( fd_vinyl_io_t * io, ulong seq, ulong sz );
typedef void   (*fd_vinyl_io_func_forget_t  )( fd_vinyl_io_t * io, ulong seq );
typedef void   (*fd_vinyl_io_func_rewind_t  )( fd_vinyl_io_t * io, ulong seq );
typedef int    (*fd_vinyl_io_func_sync_t    )( fd_vinyl_io_t * io, int flags );
typedef void * (*fd_vinyl_io_func_fini_t    )( fd_vinyl_io_t * io );

struct fd_vinyl_io_impl {
  fd_vinyl_io_func_read_imm_t read_imm;
  fd_vinyl_io_func_read_t     read;
  fd_vinyl_io_func_poll_t     poll;
  fd_vinyl_io_func_append_t   append;
  fd_vinyl_io_func_commit_t   commit;
  fd_vinyl_io_func_hint_t     hint;
  fd_vinyl_io_func_alloc_t    alloc;
  fd_vinyl_io_func_copy_t     copy;
  fd_vinyl_io_func_forget_t   forget;
  fd_vinyl_io_func_rewind_t   rewind;
  fd_vinyl_io_func_sync_t     sync;
  fd_vinyl_io_func_fini_t     fini;
};

typedef struct fd_vinyl_io_impl fd_vinyl_io_impl_t;

struct fd_vinyl_io_private {
  int                  type;
  ulong                seed;
  ulong                seq_ancient;  /* FD_VINYL_BSTREAM_BLOCK_SZ multiple */
  ulong                seq_past;     /* " */
  ulong                seq_present;  /* " */
  ulong                seq_future;   /* " */
  ulong                spad_max;     /* " */
  ulong                spad_used;    /* " */
  fd_vinyl_io_impl_t * impl;         /* implementation specific funcs */
  /* io implementation specific details follow */
};

FD_PROTOTYPES_BEGIN

/* fd_vinyl_io_* return the current value of the eponymous io field.
   Assumes io is valid.  For all but type and seed, the return value is
   a FD_VINYL_BSTREAM_BLOCK_SZ multiple.  Note that we don't have a
   generic notion of dev_max or dev_free as such is not a well defined
   concept.  Individual IO implementations can provide them as
   appropriate though. */

FD_FN_PURE static inline int   fd_vinyl_io_type( fd_vinyl_io_t const * io ) { return io->type; }

FD_FN_PURE static inline ulong fd_vinyl_io_seed( fd_vinyl_io_t const * io ) { return io->seed; }

FD_FN_PURE static inline ulong fd_vinyl_io_seq_ancient( fd_vinyl_io_t const * io ) { return io->seq_ancient; }
FD_FN_PURE static inline ulong fd_vinyl_io_seq_past   ( fd_vinyl_io_t const * io ) { return io->seq_past;    }
FD_FN_PURE static inline ulong fd_vinyl_io_seq_present( fd_vinyl_io_t const * io ) { return io->seq_present; }
FD_FN_PURE static inline ulong fd_vinyl_io_seq_future ( fd_vinyl_io_t const * io ) { return io->seq_future;  }

FD_FN_PURE static inline ulong fd_vinyl_io_spad_max ( fd_vinyl_io_t const * io ) { return io->spad_max;                 }
FD_FN_PURE static inline ulong fd_vinyl_io_spad_used( fd_vinyl_io_t const * io ) { return io->spad_used;                }
FD_FN_PURE static inline ulong fd_vinyl_io_spad_free( fd_vinyl_io_t const * io ) { return io->spad_max - io->spad_used; }

FD_FN_PURE static inline ulong fd_vinyl_io_dev_used( fd_vinyl_io_t const * io ) { return io->seq_future - io->seq_ancient; }

/* fd_vinyl_io_read_imm does an immediate (blocking) read of
   [seq,seq+dst_sz) (cyclic) from io's bstream's past into dst.  Assumes
   there are no reads currently posted on io.  Retains no interest in
   dst.  seq, dst and sz should be FD_VINYL_BSTREAM_BLOCK_SZ aligned.
   This is used mostly for sequential iterating over a bstream's past
   (i.e. serial recovery and discovering partitions for parallel
   recovery). */

static inline void
fd_vinyl_io_read_imm( fd_vinyl_io_t * io,
                      ulong           seq,
                      void *          dst,
                      ulong           sz ) {
  io->impl->read_imm( io, seq, dst, sz );
}

/* fd_vinyl_io_read starts the executing the read command rd.  That is,
   start reading bstream bytes [seq,seq+sz) (cyclic) into dst.  seq, dst
   and sz should be FD_VINYL_BSTREAM_BLOCK_SZ aligned.  Further,
   [seq,seq+sz) should be in the bstream's past and the region to read
   should be stored contiguously in the underlying storage.

   On entry, the caller should have ownership of rd and rd->dst.  The io
   has ownership of these return and a read interest in bstream bytes
   [seq,seq_sz) (cyclic).  The ownership of these will be returned to
   the caller and the read interest will end when poll returns the
   request. */

static inline void
fd_vinyl_io_read( fd_vinyl_io_t *    io,
                  fd_vinyl_io_rd_t * rd ) {
  io->impl->read( io, rd );
}

/* fd_vinyl_io_poll checks if any outstanding reads are complete.  Reads
   can complete in any order by the I/O layer.  flags is a bit-or of
   FD_VINYL_IO_FLAGs.  BLOCKING indicates the call is allowed to block
   the caller (the io layer promises the call cannot fail from the
   caller's point of view).  Returns FD_VINYL_SUCCESS if a read complete
   (*_rd will point to the read command ended with the ownership and
   read interested as described above), FD_VINYL_ERR_EMPTY if there are
   no commands pending (*_rd will be NULL) and FD_VINYL_ERR_AGAIN if
   none of the posted commands are ready (*_rd will be NULL).  AGAIN is
   only possible for a non-blocking call). */

static inline int
fd_vinyl_io_poll( fd_vinyl_io_t *     io,
                  fd_vinyl_io_rd_t ** _rd,
                  int                 flags ) {
  return io->impl->poll( io, _rd, flags );
}

/* fd_vinyl_io_append starts appending sz bytes at src to the bstream.
   src and sz should be FD_VINYL_BSTREAM_BLOCK_SZ aligned.  Returns
   bstream sequence number seq_append where the data is being appended.
   io will have a read interest in src until the next commit.  This
   moves blocks from the bstream's future to the bstream's present.  On
   commit, the region [seq_future_before,seq_append) (cyclic) will be
   filled with zero padding if the I/O implementation requires it to
   keep the append contiguous in the physical store (this region will be
   empty if covered by a previous hint or if this is an append of a
   single block) and the region [seq_append,seq_future_after) (cyclic)
   will be filled with the appended info.

   fd_vinyl_io_commit moves all blocks in the bstream's present to the
   bstream's past (i.e. sets seq_present to seq_future).  flags is a
   bit-of FD_VINYL_IO_FLAGs.  If BLOCKING is set, this is allowed to
   block the caller.  Returns FD_VINYL_SUCCESS (0) on success and
   FD_VINYL_ERR_AGAIN (negative) if commit could not be completed
   immediately (only possible for a non-blocking call).  commit empties
   the io append scratch pad on success.

   fd_vinyl_io_hint indicates the next sz bytes to append must be
   contiguous in the bstream.  This can move blocks from the bstream's
   future to the bstream's present.  Returns (the potentially updated)
   seq_future.  On commit, the region
   [seq_future_before,seq_future_after) (cyclic) will be filled with
   zero padding (this region will be empty if covered by a previous
   hint) and the region [seq_future_after,seq_future_after+sz) (cyclic)
   will contiguous in the physical storage.  This is useful for grouping
   sets of blocks from different memory regions on the host that must be
   written contiguously from a protocol point of view (e.g. a move
   control block and the pair that follows it).

   fd_vinyl_io_alloc returns a pointer to sz bytes of
   FD_VINYL_BSTREAM_BLOCK_SZ aligned memory suitable allocated from io's
   append scratch pad.  flags is a bit-or FD_VINYL_IO_FLAG_*.  BLOCKING
   indicates the call is allowed to block the caller.  If a non-blocking
   call, will return NULL if there is no suitable memory at this time.
   Will never return NULL for a blocking call.  The lifetime of the
   returned pointer is the lesser of the next append, next commit, the
   next alloc or the io.  sz should be FD_VINYL_BSTREAM_BLOCK_SZ aligned
   and at most io's spad_max.  This may do a commit to free up scratch
   pad memory if necessary (moving blocks from the present to the past).

   fd_vinyl_io_trim trims sz bytes from the end of the most recent
   fd_vinyl_io_alloc.  sz should be FD_VINYL_BSTREAM_BLOCK_SZ aligned
   and at most the size of the most recent alloc.

   fd_vinyl_io_copy starts appending a copy of the sz bytes at seq in
   the bstream's past to the bstream.  seq and sz should be
   FD_VINYL_BSTREAM_BLOCK_SZ aligned.  [seq,seq+sz) (cyclic) should be
   in the bstream's past.  io will have a read interest in this region
   until the next commit.  This will do a _blocking_ commit to free up
   scratch pad memory if necessary (moving blocks from the present to
   the past).  FIXME: consider non-blocking copy support? (copy would
   need a flags args).

   None of these can fail from the caller's perspective (they will all
   FD_LOG_CRIT if anything goes wrong ... much like accessing invalid
   memory will seg fault). */

static inline ulong
fd_vinyl_io_append( fd_vinyl_io_t * io,
                    void const *    src,
                    ulong           sz ) {
  return io->impl->append( io, src, sz );
}

static inline int
fd_vinyl_io_commit( fd_vinyl_io_t * io,
                    int             flags ) {
  return io->impl->commit( io, flags );
}

static inline ulong
fd_vinyl_io_hint( fd_vinyl_io_t * io,
                  ulong           sz ) {
  return io->impl->hint( io, sz );
}

static inline void *
fd_vinyl_io_alloc( fd_vinyl_io_t * io,
                   ulong           sz,
                   int             flags ) {
  return io->impl->alloc( io, sz, flags );
}

static inline void
fd_vinyl_io_trim( fd_vinyl_io_t * io,
                  ulong           sz ) {
  io->spad_used -= sz;
}

static inline ulong
fd_vinyl_io_copy( fd_vinyl_io_t * io,
                  ulong           seq,
                  ulong           sz ) {
  return io->impl->copy( io, seq, sz );
}

/* fd_vinyl_io_forget moves [seq_past,seq) (cyclic) from the bstream's
   past to the bstream's antiquity, setting seq_past to seq.  As such,
   seq should be in [seq_past,seq_present] (cyclic) and
   FD_VINYL_BSTREAM_BLOCK_SZ aligned.  There should be no reads, copies
   or appends in progress.  Cannot fail from the caller's perspective
   (will FD_LOG_CRIT if anything goes wrong).

   IMPORTANT SAFETY TIP!  Though the bstream has been updated from the
   caller's point of view, the bstream needs to be sync'd for recover to
   start from the new seq_past. */

static inline void
fd_vinyl_io_forget( fd_vinyl_io_t * io,
                    ulong           seq ) {
  io->impl->forget( io, seq );
}

/* fd_vinyl_io_rewind moves blocks [seq,seq_present) (cyclic) from the
   bstream's past to the bstream's future (updating seq_ancient and
   seq_past as necessary).  There should be no reads, copies or appends
   in progress.  seq should at most seq_present (cylic) and
   FD_VINYL_BSTREAM_BLOCK_SZ aligned.  Cannot fail from the caller's
   perspective (will FD_LOG_CRIT if anything goes wrong).

   IMPORTANT SAFETY TIP!  Though the bstream has been updated from the
   caller's point of view, the bstream needs to be sync'd for recovery
   to account for the rewind (and this is probably more critical than
   forget because appends will start modifying the bstream blocks that
   recovery would be expecting to be in the pre-rewind state). */

static inline void
fd_vinyl_io_rewind( fd_vinyl_io_t * io,
                    ulong           seq ) {
  io->impl->rewind( io, seq );
}

/* fd_vinyl_io_sync moves [seq_ancient,seq_past) (cyclic) from the
   bstream's antiquity to the end of the bstream's future, setting
   seq_ancient to seq_past.  It promises the caller the bstream's past
   is fully written and that the bstream's past region is what recovery
   will use to recover the bstream's key-val state at seq_present.
   flags is a bit-or of FD_VINYL_IO_FLAGs.  BLOCKING indicates the call
   is allowed to block the caller.  Returns FD_VINYL_SUCCESS (0) on
   success and a FD_VINYL_ERR_AGAIN (negative) if the call would block
   the caller (only possible for a non-blocking call). */
/* FIXME: consider allowing new user info to be passed? */

static inline int
fd_vinyl_io_sync( fd_vinyl_io_t * io,
                  int             flags ) {
  return io->impl->sync( io, flags );
}

/* fd_vinyl_io_fini tears down io, returning the memory region used to
   hold the I/O implementation state.  Implicitly completes any
   in-progress reads and cancels any in-progress appends (and thus can
   block the caller).

   IMPORTANT SAFETY TIP!  This does _not_ sync the bstream first (e.g.
   if an application is tearing down due to an anomalous condition, it
   may not want to sync on fini so that it can recover from a known good
   point). */

void *
fd_vinyl_io_fini( fd_vinyl_io_t * io );

/* Helpers ************************************************************/

/* fd_vinyl_io_spad_est() returns estimate of the smallest scratch pad
   size required most applications.  Specifically, this returns:

     2 pair_sz( LZ4_COMPRESSBOUND( VAL_MAX ) )

   so that it is possible to load a object footprint into the scratch
   pad and then have a worst case scratch memory for compression to
   re-encode the object. */

FD_FN_CONST ulong fd_vinyl_io_spad_est( void );

/* fd_vinyl_io_append_* are helper functions that start appending the
   given info, appropriately formatted and hashed, to io's bstream.
   There is no excess requirements for alignment.  They do no input
   argument checking.  On return, io retains no interest in the given
   info (that is, they use io's scratch memory and thus can trigger an
   io commit to move blocks from the bstream's present to the bstream's
   past if there isn't enough scratch pad free).  They return the
   bstream sequence number where the data is being appended.  They
   cannot fail from the caller's perspective (they will FD_LOG_CRIT if
   anything goes awry). */

ulong
fd_vinyl_io_append_pair_raw( fd_vinyl_io_t *         io,
                             fd_vinyl_key_t const *  key,   /* pair key */
                             fd_vinyl_info_t const * info,  /* pair info */
                             void const *            val ); /* contains info->val_sz bytes, in [0,FD_VINYL_VAL_MAX] */

ulong
fd_vinyl_io_append_dead( fd_vinyl_io_t *                 io,
                         fd_vinyl_bstream_phdr_t const * phdr,      /* pair header of erased pair */
                         void const *                    info,      /* contains info_sz bytes, info_sz treated as 0 if NULL */
                         ulong                           info_sz ); /* in [0,FD_VINYL_BSTREAM_DEAD_INFO_MAX] */

ulong
fd_vinyl_io_append_move( fd_vinyl_io_t *                 io,
                         fd_vinyl_bstream_phdr_t const * src,       /* pair header of src pair */
                         fd_vinyl_key_t const *          dst,       /* src pair getting renamed to dst or is replacing dst */
                         void const *                    info,      /* contains info_sz bytes, info_sz treated as 0 if NULL */
                         ulong                           info_sz ); /* in [0,FD_VINYL_BSTREAM_MOVE_INFO_MAX] */

ulong
fd_vinyl_io_append_part( fd_vinyl_io_t * io,
                         ulong           seq_prev,  /* should be a part before seq or seq */
                         ulong           dead_cnt,  /* number of dead blocks in the partition */
                         ulong           move_cnt,  /* number of move blocks in the partition */
                         void const *    info,      /* contains info_sz bytes, info_sz treated as 0 if NULL */
                         ulong           info_sz ); /* in [0,FD_VINYL_BSTREAM_PART_INFO_MAX] */

/* fd_vinyl_io_append_pair_inplace appends the style RAW pair at phdr
   to the bstream.  This will preferentially append the pair in the
   given style.  Returns the location where the pair was appended.  On
   return, *_style holds the actual style used and *_val_esz contains
   the pair encoded value byte size.

   Note that if the requested style is RAW or if the pair could not be
   usefully encoded in the requested style (e.g. the compressed size
   ended up larger than the uncompressed size), this will append from
   phdr in-place zero copy.  When appending a pair in-place, this will
   clear the zero padding region and insert the appropriate data
   integrity footers at the end of the pair.  On other cases, this will
   append from the io append scratch memory the encoded pair and the
   pair will be untouched.

   As such, the caller should assume the io has a read interest on the
   pair's header region and value region and a write interest on the
   pair zero padding region and footer region until the next append or
   commit and the pair's zero padding and footer regions may be
   clobbered by this call. */

ulong
fd_vinyl_io_append_pair_inplace( fd_vinyl_io_t *           io,
                                 int                       style,
                                 fd_vinyl_bstream_phdr_t * phdr,
                                 int *                     _style,
                                 ulong *                   _val_esz );

/* fd_vinyl_io_bd *****************************************************/

/* fd_vinyl_io_bd_{align,footprint} specify the alignment and footprint
   needed for a bstream stored on a block device / large file with a
   spad_max append scratch pad.  align will be a reasonable power-of-2
   and footprint will be a multiple of align.  Returns 0 for an invalid
   spad_max.

   fd_vinyl_io_bd_init starts using a file as a bstream store.  lmem
   points to a local memory region with suitable alignment and footprint
   to hold the bstream's state.  spad_max gives the size of the append
   scratch pad (should be a FD_VINYL_BSTREAM_BLOCK_SZ multiple).  dev_fd
   is a file descriptor for the block device / large file.  The file
   should already exist and be sized to the appropriate capacity.

   FIXME: allow user to specify a subrange of dev_fd to use for the
   store?

   If reset is non-zero, ignores any existing file contents and will
   start a new bstream.  The bstream metadata user info will be set to
   the info_sz bytes at info and the bstream will use io_seed for its
   data integrity hashing seed.

   Otherwise, this will attempt to resume at the point the bstream was
   last synchronized.  info, info_sz and io_seed will be ignored.

   IMPORTANT SAFETY TIP!  The io_seed is the not same thing as the meta
   seed.  The io_seed is a property of the bstream (with a lifetime of
   the bstream and is shared among all users of the bstream).  The meta
   seed is a property of the meta (and ideally uniquely and randomly set
   per vinyl tile run).

   Returns a handle to the bstream on success (has ownership of lmem and
   dev_fd, ownership returned on fini) and NULL on failure (logs
   details, no ownership changed).  Retains no interest in info. */

ulong fd_vinyl_io_bd_align    ( void );
ulong fd_vinyl_io_bd_footprint( ulong spad_max );

fd_vinyl_io_t *
fd_vinyl_io_bd_init( void *       lmem,
                     ulong        spad_max,
                     int          dev_fd,
                     int          reset,
                     void const * info,
                     ulong        info_sz,
                     ulong        io_seed );

/* fd_vinyl_io_mm *****************************************************/

/* fd_vinyl_io_mm_* is the same as fd_vinyl_io_bd_* but uses dev_sz byte
   sized memory region dev as the "block device".  The result is
   bit-level identical to fd_vinyl_io_bd (and vice versa).  This is
   primarily for testing purposes but, as dev could also be a memory
   mapped file / block device, this could be useful in general
   (especially for concurrent read access, e.g. parallel recovery).
   Note that "sync" only guarantees appends to the dev memory region
   happened.  If the memory region is backed by a file, when the actual
   blocks are written to the physical storage is controlled by the
   kernel / driver / physical device (it is up to the caller of sync to
   do any additional context specific control here). */

ulong fd_vinyl_io_mm_align    ( void );
ulong fd_vinyl_io_mm_footprint( ulong spad_max );

fd_vinyl_io_t *
fd_vinyl_io_mm_init( void *       lmem,
                     ulong        spad_max,
                     void *       dev,
                     ulong        dev_sz,
                     int          reset,
                     void const * info,
                     ulong        info_sz,
                     ulong        io_seed );

/* fd_vinyl_{mmio,mmio_sz} return {a pointer in the caller's address
   space to the raw bstream storage,the raw bstream storage byte size).
   These are a _subset_ of the dev / dev_sz region passed to mm_init and
   these will be FD_VINYL_BSTREAM_BLOCK_SZ aligned.  If a byte seq is in
   the store, it will be at mmio[ seq % mmio_sz ].  Note that mmio_sz is
   not necessarily a power of two.  Note also that the bstream's past is
   guaranteed to be in the store.  The lifetime of the returned region
   is the lifetime of the io.  Returns NULL and 0 if io does not support
   memory mapped io.  These exist to support thread parallel recovery. */

void * fd_vinyl_mmio   ( fd_vinyl_io_t * io );
ulong  fd_vinyl_mmio_sz( fd_vinyl_io_t * io );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vinyl_io_fd_vinyl_io_h */
