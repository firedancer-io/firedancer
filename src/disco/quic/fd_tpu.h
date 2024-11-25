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

#define FD_TPU_REASM_CHUNK_MTU (FD_ULONG_ALIGN_UP( FD_TPU_MTU, FD_CHUNK_SZ )>>FD_CHUNK_LG_SZ)
#define FD_TPU_REASM_MTU       (FD_TPU_REASM_CHUNK_MTU<<FD_CHUNK_LG_SZ)

#define FD_TPU_REASM_ALIGN FD_CHUNK_ALIGN

/* FD_TPU_REASM_{SUCCESS,ERR_{...}} are error codes.  These values are
   persisted to logs.  Entries should not be renumbered and numeric
   values should never be reused. */

#define FD_TPU_REASM_SUCCESS   (0)
#define FD_TPU_REASM_ERR_SZ    (1)  /* oversz msg */
#define FD_TPU_REASM_ERR_SKIP  (2)  /* out-of-order data within QUIC stream */
#define FD_TPU_REASM_ERR_STATE (3)  /* unexpected slot state */

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

   The tpu_reasm MUST be the only writer to the mcache.

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
   burst at all times.

   In order to support the above, the 'pub_slots' lookup table tracks
   which published mcache lines (indexed by `seq % depth`) correspond to
   which slot indexes. */


/* fd_tpu_reasm_slot_t holds a message reassembly buffer.
   Carefully tuned to 32 byte size. */

struct fd_tpu_reasm_key {
  ulong conn_uid; /* ULONG_MAX means invalid */
  ulong stream_id : 48;
  ulong sz        : 13;
  ulong state     :  2;
  ulong mapped    :  1;
};

#define FD_TPU_REASM_SID_MASK (0xffffffffffffUL)
#define FD_TPU_REASM_SZ_MASK  (0x1fffUL)

typedef struct fd_tpu_reasm_key fd_tpu_reasm_key_t;

struct __attribute__((aligned(16))) fd_tpu_reasm_slot {
  fd_tpu_reasm_key_t k; /* FIXME ugly: the compound key has to be a single struct member */
  uint lru_prev;
  uint lru_next;
  uint chain_next;
  uint chain_prev;
};

typedef struct fd_tpu_reasm_slot fd_tpu_reasm_slot_t;

struct __attribute__((aligned(FD_TPU_REASM_ALIGN))) fd_tpu_reasm {
  ulong magic;  /* ==FD_TPU_REASM_MAGIC */

  ulong slots_off;     /* slots mem     */
  ulong pub_slots_off; /* pub_slots mem */
  ulong chunks_off;    /* payload mem   */
  ulong map_off;       /* map mem */

  uint   depth;       /* mcache depth */
  uint   burst;       /* max concurrent reassemblies */

  uint   head;        /* least recent reassembly */
  uint   tail;        /* most  recent reassembly */

  uint   slot_cnt;
  ushort orig;        /* tango orig */
};

typedef struct fd_tpu_reasm fd_tpu_reasm_t;

FD_PROTOTYPES_BEGIN

/* Private accessors */

static inline FD_FN_PURE fd_tpu_reasm_slot_t *
fd_tpu_reasm_slots_laddr( fd_tpu_reasm_t * reasm ) {
  return (fd_tpu_reasm_slot_t *)( (ulong)reasm + reasm->slots_off );
}

static inline FD_FN_PURE fd_tpu_reasm_slot_t const *
fd_tpu_reasm_slots_laddr_const( fd_tpu_reasm_t const * reasm ) {
  return (fd_tpu_reasm_slot_t const *)( (ulong)reasm + reasm->slots_off );
}

static inline FD_FN_PURE uint *
fd_tpu_reasm_pub_slots_laddr( fd_tpu_reasm_t * reasm ) {
  return (uint *)( (ulong)reasm + reasm->pub_slots_off );
}

static inline FD_FN_PURE uchar *
fd_tpu_reasm_chunks_laddr( fd_tpu_reasm_t * reasm ) {
  return (uchar *)( (ulong)reasm + reasm->chunks_off );
}

static inline FD_FN_PURE uchar const *
fd_tpu_reasm_chunks_laddr_const( fd_tpu_reasm_t const * reasm ) {
  return (uchar const *)( (ulong)reasm + reasm->chunks_off );
}

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
   tpu_reasm. */

void *
fd_tpu_reasm_new( void * shmem,
                  ulong  depth,  /* Assumed in {2^0,2^1,2^2,...,2^32} */
                  ulong  burst,  /* Assumed in [1,2^32) */
                  ulong  orig    /* Assumed in [0,FD_FRAG_META_ORIG_MAX) */ );

fd_tpu_reasm_t *
fd_tpu_reasm_join( void * shreasm );

void *
fd_tpu_reasm_leave( fd_tpu_reasm_t * reasm );

void *
fd_tpu_reasm_delete( void * shreasm );

/* fd_tpu_reasm_{chunk0,wmark} returns the chunk index of the {lowest,
   highest} possible chunk value that fd_tpu_reasm_publish will write to
   an mcache. */

FD_FN_CONST ulong
fd_tpu_reasm_chunk0( fd_tpu_reasm_t const * reasm,
                     void const *           base );


FD_FN_CONST ulong
fd_tpu_reasm_wmark( fd_tpu_reasm_t const * reasm,
                    void const *           base );

/* Accessor API */

fd_tpu_reasm_slot_t *
fd_tpu_reasm_query( fd_tpu_reasm_t * reasm,
                    ulong            conn_uid,
                    ulong            stream_id );

FD_FN_PURE static inline fd_tpu_reasm_slot_t *
fd_tpu_reasm_peek_tail( fd_tpu_reasm_t * reasm ) {
  uint                  tail_idx = reasm->tail;
  fd_tpu_reasm_slot_t * tail     = fd_tpu_reasm_slots_laddr( reasm ) + tail_idx;
  return tail;
}

fd_tpu_reasm_slot_t *
fd_tpu_reasm_prepare( fd_tpu_reasm_t * reasm,
                      ulong            conn_uid,
                      ulong            stream_id,
                      long             tspub );

static inline fd_tpu_reasm_slot_t *
fd_tpu_reasm_acquire( fd_tpu_reasm_t * reasm,
                      ulong            conn_uid,
                      ulong            stream_id,
                      long             tspub ) {
  fd_tpu_reasm_slot_t * slot = fd_tpu_reasm_query( reasm, conn_uid, stream_id );
  if( !slot ) {
    slot = fd_tpu_reasm_prepare( reasm, conn_uid, stream_id, tspub );
  }
  return slot;
}

/* fd_tpu_reasm_frag appends a new stream frag to the reasm slot.
   [data,data+data_sz) is the memory region containing the stream data.
   data_off is the offset of this stream data.  Slot reassembly buffer
   is appended with copy of [data,data+data_sz) on success.  On failure,
   cancels the reassembly.

   Return values one of:

     FD_TPU_REASM_SUCCESS:   success, fragment added to reassembly
     FD_TPU_REASM_EAGAIN:    incomplete
     FD_TPU_REASM_ERR_SZ:    fail, data_off + data_sz  > mtu
     FD_TPU_REASM_ERR_SKIP:  fail, data_off - slot->sz > 0

   Note on SKIP error:  RFC 9000 Section 2.2 specifies "QUIC makes no
   specific allowances for delivery of stream data out of order." */

int
fd_tpu_reasm_frag( fd_tpu_reasm_t *      reasm,
                   fd_tpu_reasm_slot_t * slot,
                   uchar const *         data,
                   ulong                 sz,
                   ulong                 off );

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
                      long                  tspub );

/* fd_tpu_reasm_publish_fast is a streamlined version of acquire/frag/
   publish. */

int
fd_tpu_reasm_publish_fast( fd_tpu_reasm_t * reasm,
                           uchar const *    data,
                           ulong            sz,
                           fd_frag_meta_t * mcache,
                           void *           base,  /* Assumed aligned FD_CHUNK_ALIGN */
                           ulong            seq,
                           long             tspub );

/* fd_tpu_reasm_cancel cancels the given stream reassembly. */

void
fd_tpu_reasm_cancel( fd_tpu_reasm_t *      reasm,
                     fd_tpu_reasm_slot_t * slot );

/* fd_tpu_reasm_key_hash is an unrolled version of fd_hash (xxhash-r39) */

#define C1 (11400714785074694791UL)
#define C2 (14029467366897019727UL)
#define C3 ( 1609587929392839161UL)
#define C4 ( 9650029242287828579UL)
#define C5 ( 2870177450012600261UL)

static inline ulong
fd_tpu_reasm_key_hash( fd_tpu_reasm_key_t const * k,
                       ulong                      seed ) {

  ulong h  = seed + C5 + 16UL;
  ulong w0 = k->conn_uid;
  ulong w1 = k->stream_id;

  w0 *= C2; w0 = fd_ulong_rotate_left( w0, 31 ); w0 *= C1; h ^= w0; h = fd_ulong_rotate_left( h, 27 )*C1 + C4;
  w1 *= C2; w1 = fd_ulong_rotate_left( w1, 31 ); w1 *= C1; h ^= w1; h = fd_ulong_rotate_left( h, 27 )*C1 + C4;

  /* Final avalanche */
  h ^= h >> 33;
  h *= C2;
  h ^= h >> 29;
  h *= C3;
  h ^= h >> 32;

  return h;
}

#undef C1
#undef C2
#undef C3
#undef C4
#undef C5

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_quic_fd_tpu_h */
