#ifndef HEADER_fd_src_flamenco_runtime_fd_bpf_ser_arena_h
#define HEADER_fd_src_flamenco_runtime_fd_bpf_ser_arena_h

/* fd_bpf_ser_arena is a shared pool of full-size BPF loader
   serialization bundles.  A bundle backs the CPI-depth frames (depths
   2..FD_MAX_INSTRUCTION_STACK_DEPTH) of one in-flight transaction at
   the full per-frame worst case.  Exec tiles keep a small per-tile
   window for typical CPI frames (see fd_runtime.h) and fall back to a
   bundle from this arena for the rare transaction whose CPI frames
   exceed the window.

   Acquisition is an all-or-nothing FIFO ticket: a caller takes a
   ticket, waits until the pool has a free bundle for its turn, and
   holds exactly one bundle until release.  Holders never wait on
   anything while holding, so the scheme is deadlock free; exhaustion
   is a bounded wait behind bundle_cnt concurrently executing
   transactions, never an abort. */

#include "fd_runtime_const.h"

#define FD_BPF_SER_ARENA_ALIGN      (128UL)
#define FD_BPF_SER_ARENA_MAGIC      (0xF17EDA2CEB5E7A3EUL)
#define FD_BPF_SER_ARENA_BUNDLE_MAX (8UL)

/* Frames for depths 2..FD_MAX_INSTRUCTION_STACK_DEPTH */
#define FD_BPF_SER_ARENA_BUNDLE_FOOTPRINT ((FD_MAX_INSTRUCTION_STACK_DEPTH-1UL)*BPF_LOADER_SERIALIZATION_FOOTPRINT)

struct __attribute__((aligned(FD_BPF_SER_ARENA_ALIGN))) fd_bpf_ser_arena {
  ulong magic;
  ulong bundle_cnt;
  uchar pad0[ 112 ];

  ulong next_ticket; /* tickets issued */
  uchar pad1[ 120 ];

  ulong done_cnt;    /* bundles released */
  uchar pad2[ 120 ];

  struct { ulong used; uchar pad[ 120 ]; } slot[ FD_BPF_SER_ARENA_BUNDLE_MAX ];

  /* bundle_cnt bundles of FD_BPF_SER_ARENA_BUNDLE_FOOTPRINT follow */
};
typedef struct fd_bpf_ser_arena fd_bpf_ser_arena_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong fd_bpf_ser_arena_align( void ) { return FD_BPF_SER_ARENA_ALIGN; }

FD_FN_CONST static inline ulong
fd_bpf_ser_arena_footprint( ulong bundle_cnt ) {
  if( FD_UNLIKELY( !bundle_cnt || bundle_cnt>FD_BPF_SER_ARENA_BUNDLE_MAX ) ) return 0UL;
  return sizeof(fd_bpf_ser_arena_t) + bundle_cnt*FD_BPF_SER_ARENA_BUNDLE_FOOTPRINT;
}

void *
fd_bpf_ser_arena_new( void * shmem,
                      ulong  bundle_cnt );

fd_bpf_ser_arena_t *
fd_bpf_ser_arena_join( void * shmem );

/* fd_bpf_ser_arena_ticket takes a FIFO ticket.  Every ticket MUST be
   redeemed with fd_bpf_ser_arena_wait (else later tickets stall). */

ulong
fd_bpf_ser_arena_ticket( fd_bpf_ser_arena_t * arena );

/* fd_bpf_ser_arena_ready returns 1 if wait( ticket ) would not block */

int
fd_bpf_ser_arena_ready( fd_bpf_ser_arena_t const * arena,
                        ulong                      ticket );

/* fd_bpf_ser_arena_wait spins until ticket's turn, claims a free
   bundle and returns its base (FD_RUNTIME_EBPF_HOST_ALIGN aligned) */

uchar *
fd_bpf_ser_arena_wait( fd_bpf_ser_arena_t * arena,
                       ulong                ticket );

static inline uchar *
fd_bpf_ser_arena_acquire( fd_bpf_ser_arena_t * arena ) {
  return fd_bpf_ser_arena_wait( arena, fd_bpf_ser_arena_ticket( arena ) );
}

void
fd_bpf_ser_arena_release( fd_bpf_ser_arena_t * arena,
                          uchar *              bundle );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_bpf_ser_arena_h */
