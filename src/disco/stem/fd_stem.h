#ifndef HEADER_fd_src_disco_stem_fd_stem_h
#define HEADER_fd_src_disco_stem_fd_stem_h

#include "../fd_disco_base.h"
#include <sys/syscall.h>
#include <linux/futex.h>

#define FD_STEM_SCRATCH_ALIGN (128UL)

struct fd_stem_context {
   fd_frag_meta_t ** mcaches;
   ulong *           seqs;
   ulong *           depths;

   ulong *           cr_avail;
   ulong             cr_decrement_amount;
};

typedef struct fd_stem_context fd_stem_context_t;

struct __attribute__((aligned(64))) fd_stem_tile_in {
  fd_frag_meta_t const * mcache;   /* local join to this in's mcache */
  uint                   depth;    /* == fd_mcache_depth( mcache ), depth of this in's cache (const) */
  uint                   idx;      /* index of this in in the list of providers, [0, in_cnt) */
  ulong                  seq;      /* sequence number of next frag expected from the upstream producer,
                                      updated when frag from this in is published */
  fd_frag_meta_t const * mline;    /* == mcache + fd_mcache_line_idx( seq, depth ), location to poll next */
  ulong *                fseq;     /* local join to the fseq used to return flow control credits to the in */
  uint                   accum[6]; /* local diagnostic accumulators.  These are drained during in housekeeping. */
                                   /* Assumes FD_FSEQ_DIAG_{PUB_CNT,PUB_SZ,FILT_CNT,FILT_SZ,OVRNP_CNT,OVRNP_FRAG_CNT} are 0:5 */
};

typedef struct fd_stem_tile_in fd_stem_tile_in_t;

long syscall(long number, ...);

static inline long futex_wait(const uint32_t *addr, uint32_t val) {
    return syscall(SYS_futex, addr, FUTEX_WAIT, val, NULL, NULL, 0);
}

static inline long futex_wake(uint32_t *addr, uint32_t n) {
    return syscall(SYS_futex, addr, FUTEX_WAKE, n, NULL, NULL, 0);
}

static inline long futex_waitv(struct futex_waitv *waiters, unsigned int nr_futexes) {
    return syscall(SYS_futex_waitv, waiters, nr_futexes, 0, NULL, 0);
}

static inline void
fd_stem_publish( fd_stem_context_t * stem,
                 ulong               out_idx,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub ) {
  ulong * seqp = &stem->seqs[ out_idx ];
  ulong   seq  = *seqp;
  fd_mcache_publish( stem->mcaches[ out_idx ], stem->depths[ out_idx ], seq, sig, chunk, sz, ctl, tsorig, tspub );
  uint * futex_flag = fd_mcache_futex_flag( stem->mcaches[out_idx] );
  FD_LOG_NOTICE(("Producer: futex_flag address: %p", (void*) futex_flag));
  FD_LOG_NOTICE(("Producer: futex_flag value: %d", (int) *futex_flag));
  // logic like if need_to_wake_up [out_idx]
  futex_wake( (uint32_t*) futex_flag, 1);
  // is this okay? writing to header every time? -- only the producer should be pulling a writable version anyways
  *futex_flag += 1;
  
  *stem->cr_avail -= stem->cr_decrement_amount;
  *seqp = fd_seq_inc( seq, 1UL );
}

static inline ulong
fd_stem_advance( fd_stem_context_t * stem,
                 ulong               out_idx ) {
  ulong * seqp = &stem->seqs[ out_idx ];
  ulong   seq  = *seqp;
  *stem->cr_avail -= stem->cr_decrement_amount;
  *seqp = fd_seq_inc( seq, 1UL );
  return seq;
}

#endif /* HEADER_fd_src_disco_stem_fd_stem_h */
