#ifndef HEADER_fd_src_disco_tpu_fd_tpu_defrag_h
#define HEADER_fd_src_disco_tpu_fd_tpu_defrag_h

/* fd_tpu_defrag implements a defragmenter for incoming TPU/QUIC data.
   The Solana TPU/QUIC protocol is simple unidirectional transmission of
   txns over stream-oriented transports.  Each txn is sent over one QUIC
   stream.  A QUIC stream is comparable to a TCP conn minus the overhead
   of a three-way handshake.  Because each QUIC tile will handle many
   incoming streams at once, txns can be fragmented and interleaved
   across the sequence of incoming frames. */

/* FIXME: Directly copy into dcache and skip buffering in chunk. */

#include "fd_tpu.h"

/* FD_TPU_DEFRAG_ALIGN: Byte alignment of fd_tpu_defrag_t */

#define FD_TPU_DEFRAG_ALIGN (64UL)

/* FD_TPU_DEFRAG_ENTRY_ALIGN: Byte alignment of fd_tpu_defrag_entry_t */

#define FD_TPU_DEFRAG_ENTRY_ALIGN (64UL)

/* FD_TPU_DEFRAG_TTL is the time-to-live of a defrag process in
   nanoseconds. */

#define FD_TPU_DEFRAG_TTL (3000000000UL) /* 3000ms */

/* fd_tpu_defrag_t manages defragmentation processes. */

struct fd_tpu_defrag_private;
typedef struct fd_tpu_defrag_private fd_tpu_defrag_t;

/* fd_tpu_defrag_entry_t contains the defragmented content of a TPU
   stream.  This is usually a serialized txn.  Accessing any fields is
   U.B. unless stated otherwise. */

struct __attribute__((aligned(FD_TPU_DEFRAG_ENTRY_ALIGN))) fd_tpu_defrag_entry {
  /* 64 byte aligned */

  ushort sz;
  ulong  _reserved_0x08;
  ulong  conn_id;
  ulong  stream_id;  /* ULONG_MAX if not allocated */

  /* 64 byte aligned */

  uchar chunk[ FD_TPU_MTU ] __attribute__((aligned(64UL)));
};
typedef struct fd_tpu_defrag_entry fd_tpu_defrag_entry_t;

FD_PROTOTYPES_BEGIN

/* fd_tpu_defrag_{align,footprint} return the memory alignment and size
   requirements for an fd_tpu_defrag_t. */

ulong
fd_tpu_defrag_align( void );

ulong
fd_tpu_defrag_footprint( ulong entry_cnt );

/* fd_tpu_defrag_new formats an unused memory region for use as an
   fd_tpu_defrag_t.  mem is a non-NULL pointer to a memory region in the
   local address space with the required footprint and alignment. */

void *
fd_tpu_defrag_new( void * mem,
                   ulong  entry_cnt );

/* fd_tpu_defrag_{join,leave} joins/leaves the caller to/from the
   defragger memory region.  Only one join to a defragger may be active
   at a time. */

static inline fd_tpu_defrag_t *
fd_tpu_defrag_join( void * mem ) {
  return (fd_tpu_defrag_t *)mem;
}

static inline void *
fd_tpu_defrag_leave( fd_tpu_defrag_t * defragger ) {
  return (void *)defragger;
}

/* fd_tpu_defrag_delete unformats a memory region used as a defragger. */

void *
fd_tpu_defrag_delete( void * );

/* fd_tpu_defrag_entry_{start,exists,append,fini} are used to manage a
   defrag entry.

   fd_tpu_defrag_entry_{start,exists,append} return the in-progress
   defrag entry on success or NULL on expiry.  If a non-NULL entry is
   returned, this entry is safe to access until a call to one of
   fd_tpu_defrag_{housekeep,leave} or a matching call to
   fd_defrag_entry_fini.  Params {conn,stream}_id uniquely identify the
   stream being defragmented.  U.B. if stream_id is ULONG_MAX.

   fd_tpu_defrag_entry_start allocates and initializes a new defrag entry
   in the memory region managed by the given defragger.  Returns a defrag
   entry on success and NULL if allocation failed.

   fd_tpu_defrag_entry_exists checks whether the given defrag entry is
   still alive after a call to fd_tpu_defrag_housekeep.

   fd_tpu_defrag_entry_append copies a fragment payload to the end of the
   defrag entry buffer.  frag points to the first byte of the payload of
   size frag_sz.  Caller may deallocate frag after return.  Deallocates
   the entry and returns NULL if the total size exceeds FD_TPU_MTU.

   fd_tpu_defrag_entry_fini deallocates the given defrag entry. */

fd_tpu_defrag_entry_t *
fd_tpu_defrag_entry_start( fd_tpu_defrag_t * defragger,
                           ulong             conn_id,
                           ulong             stream_id );

static inline fd_tpu_defrag_entry_t *
fd_tpu_defrag_entry_exists( fd_tpu_defrag_entry_t * entry,
                            ulong                   conn_id,
                            ulong                   stream_id ) {
  if( FD_UNLIKELY( entry->conn_id   != conn_id
                || entry->stream_id != stream_id ) )
    return NULL; /* deallocated */

  return entry;
}

fd_tpu_defrag_entry_t *
fd_tpu_defrag_entry_append( fd_tpu_defrag_t *       defragger,
                            fd_tpu_defrag_entry_t * entry,
                            ulong                   conn_id,
                            ulong                   stream_id,
                            uchar *                 frag,
                            ulong                   frag_sz );

void
fd_tpu_defrag_entry_fini( fd_tpu_defrag_t *       defragger,
                          fd_tpu_defrag_entry_t * entry,
                          ulong                   conn_id,
                          ulong                   stream_id );

/* fd_tpu_defrag_housekeep evicts stale defrag entries.  This function
   should be called periodically.  After a call to this function,
   dereferencing any fd_tpu_defrag_entry_t pointer returned by this API
   is U.B.

   If more than FD_TPU_DEFRAG_TTL has passed since the creation of a
   defrag entry, defrag entry is aborted and deallocated.  For those
   affected defrag entries, subsequent calls to
   fd_tpu_defrag_entry_{exists,append,fini} for this entry will return
   NULL. */

void
fd_tpu_defrag_housekeep( fd_tpu_defrag_t * defrag );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_tpu_fd_tpu_defrag_h */
