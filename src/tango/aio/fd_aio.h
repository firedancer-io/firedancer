#ifndef HEADER_fd_src_tango_aio_fd_aio_h
#define HEADER_fd_src_tango_aio_fd_aio_h

#include "../fd_tango_base.h"

/* fd_aio defines a simple abstraction for asynchronous sending and
   receiving packets.  It abstracts away many details so the same code
   can work performant and transparent with different low level I/O
   libraries and hardware.

   FIXME: update the below documentation.  Also, given fd_aio_t almostly
   certainly is behaves like an abstract base class, doing a declaration
   like the below for a fd_aio_t is probably wrong because different
   implementations likely will need different footprints and the like
   long term.

   ### Example: Setup

     fd_quic_t * quic = get_quic(); // get an initialized quic instance
     fd_xdp_t *  xdp  = get_xdp();  // get an initialized xdp instance

     fd_aio_t aio_xdp_to_quic;
     fd_aio_t aio_quic_to_xdp;

     fd_quic_set_aio( quic, aio_xdp_to_quic, aio_quic_to_xdp );
     fd_xdp_set_aio ( xdp, aio_quic_to_xdp,  aio_xdp_to_quic );

     // the two *set_aio calls have the following effect:
     //   aio_xdp_to_quic.recv = fd_aio_cb_receive;
     //   aio_xdp_to_quic.ctx  = quic;

     //   aio_quic_to_xdp.recv = fd_xdp_aio_cb_receive;
     //   aio_quic_to_xdp.ctx  = xdp;

     // now whenever fd_quic_process is called on quic, quic will
     // be able to send data to xdp via fd_aio_send(...)
     // and vice versa

   ### Example: Sending

     fd_aio_t aio;

     aio.recv = my_cb_receive;
     aio.ctx   quic;

     fd_aio_pkt_info_t batch[10] = {{ .data = data, .data_sz = data_sz }};

     fd_aio_pkt_info_t cur_batch    = batch;
     ulong         cur_batch_sz = 10;
     while( cur_batch_sz ) {
       int send_rc = fd_aio_send( aio, cur_batch, cur_batch_sz ); // send a batch of buffers to the peer
       if( send_rc < 0 ) {
         fprintf( stderr, "error occurred during send\n" );
         break;
       }
       cur_batch    += send_rc;
       cur_batch_sz -= send_rc;

       // possibly do some other process that might free up resources
       // to avoid deadlock
     } */

/* FD_AIO_SUCCESS, FD_AIO_ERR_* give a number of integer error codes
   used by AIO operations.  FD_AIO_ERR_* will be negative integers.

   FIXME: these current values are largely common placeholders.  These
   should be revamped for specific AIO instance needs and harmonized
   with other fd error codes long term. */

#define FD_AIO_SUCCESS   ( 0) /* Success */
#define FD_AIO_ERR_INVAL (-1) /* Bad input args */
#define FD_AIO_ERR_AGAIN (-2) /* Try again later */

/* An fd_aio_pkt_info_t is used to describe a memory region in the
   caller's local address space for sending and receiving packets.  Note
   that, as this is only used by AIO APIs to box up info the caller
   communications with AIO instances, this is not an object (i.e. it has
   no need for object creation/destruction/accessor semantics). */

/* FD_AIO_PKT_INFO_{ALIGN,FOOTPRINT} specify the alignment and footprint
   needed for an fd_aio_pkt_info_t.  ALIGN will be positive integer
   power of 2.  FOOTPRINT will be an integer multiple of align. */

#define FD_AIO_PKT_INFO_ALIGN     (16UL)
#define FD_AIO_PKT_INFO_FOOTPRINT (16UL)

/* FD_AIO_PKT_INFO_BUF_MAX specifies the largest buffer supported by an
   fd_aio_pkt_info_t.  FIXME: fine tune this to be the smallest multiple
   of something cache line pair-ish to supporting needed functionality
   of AIO instances and the application needs. */

#define FD_AIO_PKT_INFO_BUF_MAX (4096UL)

struct __attribute__((aligned(FD_AIO_PKT_INFO_ALIGN))) fd_aio_pkt_info {

  /* buf is a pointer in the thread group's local address space to the
     first byte of a memory region:

     - Holding a packet received in the background by an AIO instance.
     - Holding a packet to be sent in the background by an AIO instance.
     - Holding a packet sent in the background by an AIO instance.
     - To be used by an AIO instance for receiving future packets.
     - ...

     The readabilty, writeability, lifetime, footprint, alignment, ...
     requirements of memory region here depending on the specific APIs
     and/or AIO instance. */

  void * buf;

  /* buf_sz is the number of bytes in the memory region.  The exact
     limitations on buf_sz can also depend on specific AIO instance.  In
     general, this will be in [0,FD_AIO_PKT_INFO_DATA_MAX] and a zero
     buf_sz (and buf==NULL for such cases) can be a possibility for some
     APIs. */

  ushort buf_sz;

  /* Padding to FD_AIO_PKT_INFO_ALIGN here (reserved for potential
     future use and/or use by specific AIO instances). */

};

typedef struct fd_aio_pkt_info fd_aio_pkt_info_t;

/* A fd_aio_send_func_t is used to tell an AIO instance to do a best
   effort packet batch send.  Unless otherwise noted by a specific API
   or implementation:

   - The AIO instance will queue up, in order, the given packet batch
     for transmission.  Packets in the batch are indexed in
     [0,batch_cnt) and info about the packet to transmit is in
     batch[idx].

   - batch[idx].buf_sz==0 (and, if so, possibly batch[idx].buf==NULL) is
     valid.  It will be treated as successfully transmitted and
     otherwise ignored.

   - batch_cnt==0 is a valid and returns success immediately.

   - There is no restriction on the packet buffers used by the send
     function.  For example, specifying the same buffer multiple times
     in the batch and/or using overlapping buffers in the batch are
     valid.

   - On success, this will return zero (FD_AIO_SUCCESS) and
     opt_batch_idx will be ignored.

   - If an error occurs, this will return a negative error code
     (FD_AIO_ERR_*).

   - If an error occurs and opt_batch_idx is non-NULL, *opt_batch_idx
     will contain the index of the first packet in the batch that was
     not "sent" from the caller's POV.

   - As such, in this case, all packets indexed [0,*opt_batch_idx) will
     have been "sent" from the caller's POV and those in
     [*opt_batch_idx,batch_cnt) were not.

   - Further, in this case and the error reason is specific to a packet,
     packets indexed [0,*opt_batch_idx) were seemingly transmissable,
     the packet indexed *opt_batch_idx was untransmissable and packets
     indexed (*opt_batch_idx,batch_cnt) had unexamined transmissability.

   - The batch array and memory regions covered by the batch array and
     any *opt_batch_idx must not be modified while this is running.
     The batch array itself and the memory regions referred to by the
     batch array are not modified by this function.  The AIO retains no
     interest in the batch array, the packet buffers referred to in the
     array on return.

   - flush requests an asychronous best-effort transmit of packets
     buffered from this and prior send operations.  Actual flush
     semantics are implementation-defined.

   Note the reception of any packets "sent" by this call is not
   guaranteed.  Reasons for failed reception could include local AIO
   instance failures not diagnosable at time of call and/or failures,
   for whatever reason, in the connectivity between the sender and
   receiver.  Likewise, though the AIO will send packets in the order
   specified, it there is no general guarantee they will be received in
   any particular order (within this batch or between batches). */

/* FIXME: consider passing an fd_aio_t instead of the aio_t ctx so
   that send function naturally has access to all other AIO
   functionality? */

typedef int
(*fd_aio_send_func_t)( void *                    ctx,
                       fd_aio_pkt_info_t const * batch,
                       ulong                     batch_cnt,
                       ulong *                   opt_batch_idx,
                       int                       flush );

/* An fd_aio_t * is an opaque handle of an AIO instance.  (It
   technically isn't here to facilitate inlining of fd_aio operations.) */

struct fd_aio_private {
  void *             ctx;       /* AIO specific context */
  fd_aio_send_func_t send_func; /* Send_func for specific AIO */

  /* FIXME: probably AIO specific functionality state follows here as
     per FIXME above (this might also clean up some of the ctx messiness
     below too, give the callbacks more power and slightly reduce
     overhead for the actual callback invocation because it doesn't need
     to do an aio->ctx load as part of the user API). */

};

typedef struct fd_aio_private fd_aio_t;

#define FD_AIO_ALIGN (alignof(fd_aio_t))
#define FD_AIO_FOOTPRINT (sizeof(fd_aio_t))

FD_PROTOTYPES_BEGIN

/* FIXME: document these.  Also fd_aio_{align,footprint,new} are
   probably not things that should be exposed as per FIXME above.  That
   is, probably should be more like
   fd_aio_{xdp,quic}_{align,footprint,new} and similar for other
   specific AIO implementations (e.g. iouring, etc).  Probably implies
   that fd_aio_private like have their own delete_func too.  Likewise,
   if the ctx gets included in the actual aio, the fd_aio_ctx function
   probably does away. */

FD_FN_CONST ulong fd_aio_align    ( void );
FD_FN_CONST ulong fd_aio_footprint( void );

void *
fd_aio_new( void *             shmem,
            void *             ctx,         /* FIXME: AIO currently has a R/W interest in ctx for lifetime of AIO */
            fd_aio_send_func_t send_func );

fd_aio_t * fd_aio_join  ( void *     shaio );
void *     fd_aio_leave ( fd_aio_t * aio   );
void *     fd_aio_delete( void *     shaio ); /* FIXME: No interest in the ctx on delete */

FD_FN_PURE static inline void *             fd_aio_ctx      ( fd_aio_t * aio ) { return FD_LIKELY( aio ) ? aio->ctx       : NULL; }
FD_FN_PURE static inline fd_aio_send_func_t fd_aio_send_func( fd_aio_t * aio ) { return FD_LIKELY( aio ) ? aio->send_func : NULL; }

/* fd_aio_send sends a batch of packets.  Assumes aio is a current local
   join to an AIO instance.  The batch, batch_cnt, opt_batch_idx and
   return value are as described in fd_aio_send_func_t with any
   additional restrictions that might be imposed by the specific AIO
   instance. */

/* TODO: This would ideally be extern inline but that causes issues with
   the build system. */

static inline int
fd_aio_send( fd_aio_t const *          aio,
             fd_aio_pkt_info_t const * batch,
             ulong                     batch_cnt,
             ulong *                   opt_batch_idx,
             int                       flush ) {
  return aio->send_func( aio->ctx, batch, batch_cnt, opt_batch_idx, flush );
}

/* fd_aio_strerror converts an FD_AIO_SUCCESS / FD_AIO_ERR_* code into
   a human readable cstr.  The lifetime of the returned pointer is
   infinite.  The returned pointer is always to a non-NULL cstr. */

FD_FN_CONST char const *
fd_aio_strerror( int err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_aio_fd_aio_h */
