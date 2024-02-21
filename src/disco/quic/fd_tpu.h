#ifndef HEADER_fd_src_disco_quic_fd_tpu_h
#define HEADER_fd_src_disco_quic_fd_tpu_h

/* fd_tpu provides the server-side of the TPU/QUIC protocol.

   TPU/QUIC is the protocol used to submit transactions to a block
   producer.  For each txn to be transferred, the client opens a
   unidirectional QUIC stream and sends its serialization (see
   fd_txn_parse).  In the happy case, a txn only requires one packet.

   For txn exceeding MTU size, the txn is fragmented over multiple
   packets.  For more information, see the specification:
   https://github.com/solana-foundation/specs/blob/main/p2p/tpu.md */

#include "../fd_disco_base.h"

/* FD_TPU_REASM_MTU is the max tango frag sz sent by an fd_tpu_reasm_t.
   FD_TPU_REASM_CHUNK_MTU*FD_CHUNK_SZ == FD_TPU_REASM_MTU */

#define FD_TPU_REASM_CHUNK_MTU (FD_ULONG_ALIGN_UP( FD_TPU_DCACHE_MTU, FD_CHUNK_SZ )>>FD_CHUNK_LG_SZ)
#define FD_TPU_REASM_MTU       (FD_TPU_REASM_CHUNK_MTU<<FD_CHUNK_LG_SZ)

#define FD_TPU_REASM_ALIGN FD_CHUNK_ALIGN
#define FD_TPU_REASM_FOOTPRINT( slot_cnt )                                                                  \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND ( FD_LAYOUT_APPEND ( FD_LAYOUT_INIT, \
    FD_TPU_REASM_ALIGN,           sizeof(fd_tpu_reasm_t)                 ), /* hdr      */                  \
    alignof(fd_tpu_reasm_slot_t), (slot_cnt)*sizeof(fd_tpu_reasm_slot_t) ), /* slots    */                  \
    alignof(ulong),               (depth)*sizeof(ulong)                  ), /* slot_idx */                  \
    FD_CHUNK_ALIGN,               (slot_cnt)*FD_TPU_REASM_MTU            ), /* chunks   */                  \
    FD_TPU_REASM_ALIGN )

/* FD_TPU_REASM_{SUCCESS,ERR_{...}} are error codes.  These values are
   persisted to logs.  Entries should not be renumbered and numeric
   values should never be reused. */

#define FD_TPU_REASM_SUCCESS   (0)
#define FD_TPU_REASM_ERR_SZ    (1)  /* oversz msg */
#define FD_TPU_REASM_ERR_SKIP  (2)  /* out-of-order data within QUIC stream */
#define FD_TPU_REASM_ERR_TXN   (3)  /* rejected transaction (invalid?) */
#define FD_TPU_REASM_ERR_STATE (4)  /* unexpected slot state */

/* FD_TPU_REASM_STATE_{...} are reasm slot states */

#define FD_TPU_REASM_STATE_FREE ((uchar)0)  /* free */
#define FD_TPU_REASM_STATE_BUSY ((uchar)1)  /* active reassembly */
#define FD_TPU_REASM_STATE_PUB  ((uchar)2)  /* published */

/* fd_tpu_reasm_t handles incoming data fragments of TPU/QUIC streams.
   Frags are expected to be provided via fd_quic callback.  Each
   tpu_reasm object may only serve a single fd_quic object.  Dispatches
   reassembled messages to an mcache.)  Should not be persisted.

   ### Flow Control

   fd_tpu_reasm is wired up as follows:

     ┌────────┐           ┌───────┐       ┌────────┐
     │  QUIC  │ callbacks │ tpu_  │ tango │ sig_   │
     │ Server ├───────────► reasm ├───────► verify │
     └────────┘           └───────┘       └────────┘

   Neither of the pictured links backpressure.  Packet loss occurs if
   (1) the QUIC server accepts more concurrent streams than available
   reassembly slots.  Also if (2) the bank of sig verify tiles is too
   slow to keepup with incoming transactions.

   The application should thus adjust the QUIC server to throttle the
   concurrent stream count and transaction rate to appropriate levels.
   (Via QUIC connection quotas)

   The tpu_reasm MUST be the only writer to the mcache.  In particular,
   another writer MUST NOT change the 'sig' field of any frag meta.

   ### Eviction Policy

   Aforementioned case 1 specifically happens whenever the QUIC server
   accepts a stream and tpu_reasm doesn't find a free slot.  tpu_reasm
   hardcodes a FIFO eviction policy to handle this case by cancelling
   the least recently prepared reassembly.  This also guarantees that
   unfragmented transaction never get dropped.

   ### Internals

   fd_tpu_reasm internally manages an array of message reassembly
   buffers.  Each of these is called a "slot" (fd_tpu_reasm_slot_t).

   Slots are either owned by the reassembly fifo (FREE, BUSY states), or
   the mcache (PUB state).  The ownership separation prevents in-flight
   reassemblies from thrashing data exposed to consumers via the mcache.
   (Data races transitioning between reassembly and fifo ownership are
   handled by the speculative receive pattern.)

   The lifecycle of a slot is:

            prepare()  publish()
     ┌─► FREE ───► BUSY ───► PUB ─┐
     │              │             │
     ▲              ▼ cancel()    ▼ implied by a later
     │              │             │ publish()/cancel()
     └──────◄───────┴──────◄──────┘

   prepare: The transition from FREE to BUSY occurs when a new QUIC
            stream is accepted.
   cancel:  The transition from BUSY to FREE occurs when stream/txn
            reassembly is aborted.  This can happen for whatever
            explicit reason (peer kicked, network error), or implicitly
            when prepare() is called but no free slot was found.
   publish: The transition from BUSY to PUB occurs when a slot holding
            a complete txn is made visible to downstream consumers.
            This moves a slot from the reassembly fifo to the mcache.

   The transition from PUB to FREE also occurs at the same time (for a
   different slot).  This moves the least recently published slot from
   the mcache into the reassembly fifo.  This keeps the number of slots
   owned by the mcache at _exactly_ depth at all times and exactly
   mirroring the set of packets exposed downstream (notwithstanding a
   startup transient of up to depth packets).  This also guarantees that
   the number of slots in the FREE and BUSY states is kept at _exactly_
   burst at all times. */

struct fd_tpu_reasm_slot;
typedef struct fd_tpu_reasm_slot fd_tpu_reasm_slot_t;

struct __attribute__((aligned(FD_TPU_REASM_ALIGN))) fd_tpu_reasm {
  ulong magic;  /* ==FD_TPU_REASM_MAGIC */

  ulong slots_off;    /* slots mem   */
  ulong slot_idx_off; /* slot_idx mem  */
  ulong chunks_off;   /* payload mem */

  uint   depth;       /* mcache depth */
  uint   burst;       /* max concurrent reassemblies */

  uint   head;        /* least recent reassembly */
  uint   tail;        /* most  recent reassembly */

  uint   slot_cnt;
  ushort orig;        /* tango orig */
};

typedef struct fd_tpu_reasm fd_tpu_reasm_t;

/* fd_tpu_reasm_slot_t holds a message reassembly buffer. */

struct __attribute__((aligned(16UL))) fd_tpu_reasm_slot {

  ulong  conn_id;
  ulong  stream_id;

  /* Private fields ... */

  uint   prev_idx;  /* unused for now */
  uint   next_idx;

  uint   tsorig;
  ushort sz;
  uchar  state;
};

FD_PROTOTYPES_BEGIN

/* Construction API */

/* fd_tpu_reasm_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a tpu_reasm that
   can reassemble up to 'burst' txns concurrently.  'depth' is the
   entry count of the target mcache.  mtu is the max sz of a serialized
   txn (usually FD_TXN_MTU). */

FD_FN_CONST ulong
fd_tpu_reasm_align( void );

FD_FN_CONST ulong
fd_tpu_reasm_footprint( ulong depth,  /* Assumed in {2^0,2^1,2^2,...,2^31} */
                        ulong burst   /* Assumed in [1,2^31) */ );

/* fd_tpu_reasm_new formats an unused memory region for use as a
   tpu_reasm.  shmem is a non-NULL pointer to this region in the local
   address space with the required footprint and alignment.  {depth,
   burst,mtu} as described above.  orig is the Tango origin ID of this
   tpu_reasm.  mcache is the target mcache (on return, tpu_reasm has an
   exclusive write interest over the mcache) */

void *
fd_tpu_reasm_new( void *           shmem,
                  ulong            depth,  /* Assumed in {2^0,2^1,2^2,...,2^32} */
                  ulong            burst,  /* Assumed in [1,2^32) */
                  ulong            orig    /* Assumed in [0,FD_FRAG_META_ORIG_MAX) */ );

fd_tpu_reasm_t *
fd_tpu_reasm_join( void * shreasm );

void *
fd_tpu_reasm_leave( fd_tpu_reasm_t * reasm );

void *
fd_tpu_reasm_delete( void * shreasm );

/* Accessor API */

/* fd_tpu_reasm_prepare starts a new stream reassembly.  If more than
   'burst' reassemblies are active, cancels the oldest active.  Returns
   a pointer to the acquired slot.  User is expected to set conn_id and
   stream_id of slot. */

fd_tpu_reasm_slot_t *
fd_tpu_reasm_prepare( fd_tpu_reasm_t * reasm,
                      ulong            tsorig );

/* fd_tpu_reasm_append appends a new stream frag to the reasm slot.
   [data,data+data_sz) is the memory region containing the stream data.
   data_off is the offset of this stream data.  Slot reassembly buffer
   is appended with copy of [data,data+data_sz) on success.  On failure,
   cancels the reassembly.

   Return values one of:

     FD_TPU_REASM_SUCCESS:   success, fragment added to reassembly
     FD_TPU_REASM_ERR_SZ:    fail, data_off + data_sz  > mtu
     FD_TPU_REASM_ERR_SKIP:  fail, data_off - slot->sz > 0

   Note on SKIP error:  RFC 9000 Section 2.2 specifies "QUIC makes no
   specific allowances for delivery of stream data out of order." */

int
fd_tpu_reasm_append( fd_tpu_reasm_t *      reasm,
                     fd_tpu_reasm_slot_t * slot,
                     uchar const *         data,
                     ulong                 data_sz,
                     ulong                 data_off );

/* fd_tpu_reasm_publish completes a stream reassembly and publishes the
   message to an mcache for downstream consumption.  base is the address
   of the chunk whose index is 0 (chunk0 param of fd_chunk_to_laddr).
   {seq,sig,tspub} are mcache frag params.  If slot does not have active
   reassembly or txn parsing failed, returns NULL.  If base is not valid
   for tpu_reasm, aborts.  Final msg sz in [0,mtu+FD_CHUNK_SZ). */

int
fd_tpu_reasm_publish( fd_tpu_reasm_t *      reasm,
                      fd_tpu_reasm_slot_t * slot,
                      fd_frag_meta_t *      mcache,
                      void *                base,  /* Assumed aligned FD_CHUNK_ALIGN */
                      ulong                 seq,
                      ulong                 tspub );

/* fd_tpu_reasm_cancel cancels the given stream reassembly. */

void
fd_tpu_reasm_cancel( fd_tpu_reasm_t *      reasm,
                     fd_tpu_reasm_slot_t * slot );

static inline FD_FN_PURE fd_tpu_reasm_slot_t *
fd_tpu_reasm_slots_laddr( fd_tpu_reasm_t * reasm ) {
  return (fd_tpu_reasm_slot_t *)( (ulong)reasm + reasm->slots_off );
}

static inline FD_FN_PURE fd_tpu_reasm_slot_t const *
fd_tpu_reasm_slots_laddr_const( fd_tpu_reasm_t const * reasm ) {
  return (fd_tpu_reasm_slot_t const *)( (ulong)reasm + reasm->slots_off );
}

static inline FD_FN_PURE ulong *
fd_tpu_reasm_slot_idx_laddr( fd_tpu_reasm_t * reasm ) {
  return (ulong *)( (ulong)reasm + reasm->slot_idx_off );
}

static inline FD_FN_PURE ulong const *
fd_tpu_reasm_slot_idx_laddr_const( fd_tpu_reasm_t const * reasm ) {
  return (ulong const *)( (ulong)reasm + reasm->slot_idx_off );
}

static inline FD_FN_PURE uchar *
fd_tpu_reasm_chunks_laddr( fd_tpu_reasm_t * reasm ) {
  return (uchar *)( (ulong)reasm + reasm->chunks_off );
}

static inline FD_FN_PURE uchar const *
fd_tpu_reasm_chunks_laddr_const( fd_tpu_reasm_t const * reasm ) {
  return (uchar const *)( (ulong)reasm + reasm->chunks_off );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_quic_fd_tpu_h */
