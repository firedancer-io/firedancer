#ifndef HEADER_fd_src_waltz_mib_fd_dbl_buf_h
#define HEADER_fd_src_waltz_mib_fd_dbl_buf_h

/* fd_dbl_buf.h provides a concurrent lock-free double buffer.  A double
   buffer contains two buffers that take turns holding a message for
   consumers and receiving a new message by a producer.

   Supports a single producer thread and an arbitrary number of consumer
   threads.  Optimized for rare updates and frequent polling (e.g. config).
   Use an fd_tango mcache/dcache pair if you need frequent updates.

   Currently assumes a memory model that preserves store order across
   threads (e.g. x86-TSO).  Does not use atomics or hardware fences. */

#include "../../util/bits/fd_bits.h"
#include "../../util/log/fd_log.h"
#if FD_HAS_SSE
#include <emmintrin.h>
#endif

/* FIXME COULD ALLOW FOR IN-PLACE READS WITH PODs BY ADDING A MSG ALIGN ARGUMENT */

/* fd_dbl_buf_t is the header of a dbl_buf object.  May not be locally
   declared. */

union __attribute__((aligned(16UL))) fd_dbl_buf {

  struct {
    ulong magic; /* ==FD_DBL_BUF_MAGIC */
    ulong mtu;
    ulong buf0;  /* offset to first  buffer from beginning of struct */
    ulong buf1;  /*   — " —   second              — " —              */
    ulong seq;   /* latest msg seq no */
    ulong sz;    /* latest msg size */
    ulong pad[2];
    /* objects follow here */
  };

# if FD_HAS_SSE
  struct {
    __m128i magic_mtu;
    __m128i buf0_buf1;
    __m128i seq_sz;
    __m128i pad2;
  };
# endif

};

typedef union fd_dbl_buf fd_dbl_buf_t;

#define FD_DBL_BUF_MAGIC (0xa6c6f85d431c03ceUL) /* random */

#define FD_DBL_BUF_ALIGN (16UL)
#define FD_DBL_BUF_FOOTPRINT(mtu)                                         \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,     \
    FD_DBL_BUF_ALIGN, sizeof(fd_dbl_buf_t) ),                             \
    FD_DBL_BUF_ALIGN, FD_ULONG_ALIGN_UP( mtu, FD_DBL_BUF_ALIGN )<<1UL ),                    \
    FD_DBL_BUF_ALIGN )

FD_PROTOTYPES_BEGIN

/* fd_dbl_buf_{align,footprint} describe the memory region of a double
   buffer.  mtu is the largest possible message size. */

ulong
fd_dbl_buf_align( void );

ulong
fd_dbl_buf_footprint( ulong mtu );

/* fd_dbl_buf_new formats a memory region for use as a double buffer.
   shmem points to the memory region matching fd_dbl_buf_{align,footprint}.
   Initially, the active object of the double buffer will have sequence
   number seq0 and zero byte size.  */

void *
fd_dbl_buf_new( void * shmem,
                ulong  mtu,
                ulong  seq0 );

fd_dbl_buf_t *
fd_dbl_buf_join( void * shbuf );

void *
fd_dbl_buf_leave( fd_dbl_buf_t * buf );

/* fd_dbl_buf_delete unformats the memory region backing a dbl_buf and
   releases ownership back to the caller.  Returns shbuf. */

void *
fd_dbl_buf_delete( void * shbuf );

/* fd_dbl_buf_obj_mtu returns the max message size a dbl_buf can store. */

static inline ulong
fd_dbl_buf_obj_mtu( fd_dbl_buf_t * buf ) {
  return buf->mtu;
}

/* fd_dbl_buf_seq_query peeks the current sequence number. */

static inline ulong
fd_dbl_buf_seq_query( fd_dbl_buf_t * buf ) {
  FD_COMPILER_MFENCE();
  ulong seq = FD_VOLATILE_CONST( buf->seq );
  FD_COMPILER_MFENCE();
  return seq;
}

/* fd_dbl_buf_slot returns a pointer to the buffer for the given sequence
   number. */

FD_FN_PURE static inline void *
fd_dbl_buf_slot( fd_dbl_buf_t * buf,
                 ulong          seq ) {
  return (seq&1) ? ((char *)buf)+buf->buf1 : ((char *)buf)+buf->buf0;
}

/* fd_dbl_buf_insert appends a message to the double buffer.

   Note: It is NOT safe to call this function from multiple threads. */

void
fd_dbl_buf_insert( fd_dbl_buf_t * buf,
                   void const *   msg,
                   ulong          sz );

/* fd_dbl_buf_try_read does a speculative read the most recent message
   (from the caller's POV).  The read may be overrun by a writer.  out
   points to a buffer of fd_dbl_buf_obj_mtu(buf) bytes.  opt_seqp points to
   a ulong or NULL.

   On success:
   - returns the size of the message read
   - a copy of the message is stored at out
   - *opt_seqp is set to the msg sequence number (if non-NULL)

   On failure (due to overrun):
   - returns ULONG_MAX
   - out buffer is clobbered
   - *opt_seq is clobbered (if non-NULL) */

static inline ulong
fd_dbl_buf_try_read( fd_dbl_buf_t * buf,
                     void *         out,
                     ulong          out_sz,
                     ulong *        opt_seqp ) {
  ulong  seq = fd_dbl_buf_seq_query( buf );
  void * src = fd_dbl_buf_slot( buf, seq );
  ulong  sz  = FD_VOLATILE_CONST( buf->sz );
  if( out_sz<sz ) FD_LOG_ERR(( "fd_dbl_buf_try_read failed: output buffer too small: out_sz: %lu, sz: %lu", out_sz, sz ));
  fd_memcpy( out, src, sz );
  if( FD_UNLIKELY( seq!=fd_dbl_buf_seq_query( buf ) ) ) return ULONG_MAX;
  fd_ulong_store_if( !!opt_seqp, opt_seqp, seq );
  return sz;
}

/* fd_dbl_buf_read does a blocking */

ulong
fd_dbl_buf_read( fd_dbl_buf_t * buf,
                 ulong          buf_sz,
                 void *         obj,
                 ulong *        opt_seqp );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_mib_fd_dbl_buf_h */
