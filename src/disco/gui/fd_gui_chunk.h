#ifndef HEADER_fd_src_disco_gui_fd_gui_chunk_h
#define HEADER_fd_src_disco_gui_fd_gui_chunk_h

/* fd_gui_chunk caches compressed timeline query responses so that
   many clients following the live edge share one serialization and one
   compression of the same data.

   Time is cut into absolute, FD_GUI_CHUNK_NS aligned chunks.  Chunk k
   of a query kind is the response for [k*FD_GUI_CHUNK_NS,
   (k+1)*FD_GUI_CHUNK_NS).  A chunk is final, so may be cached, once
   now is at least FD_GUI_CHUNK_FINAL_NS past its end: rows are
   assigned to a window by timestamps that are at most that old when
   they are recorded.  Cached chunks are frozen: a row that arrives
   later anyway is recorded in the history but never added to a cached
   chunk (fd_gui_chunk_note only counts it), so every client receives
   the same bytes for a chunk.

   Each cached chunk is one complete zstd frame holding a JSON object,
   kept in a FD_GUI_CHUNK_CACHE_SZ byte ring.  A response is the
   concatenation of a header frame, the chunk frames separated by ","
   frames, and a closing frame, which decodes to a single JSON message.

   The cache only holds bytes and an index; building and sending
   responses is in fd_gui_printf.c. */

#include "../../util/bits/fd_bits.h"

#define FD_GUI_CHUNK_NS          (100000000L)   /* 100 ms */
#define FD_GUI_CHUNK_CACHE_SZ    (64UL<<20)     /* 64 MiB of compressed chunks */
#define FD_GUI_CHUNK_IDX_CNT     (4096UL)       /* chunks indexed per kind, ~410 s */
#define FD_GUI_CHUNK_SZ_MAX      (4UL<<20)      /* larger chunks are not cached */
#define FD_GUI_CHUNK_QUERY_MAX   (300UL)        /* chunks per cached response */
#define FD_GUI_CHUNK_BUILD_MAX   (20UL)         /* chunks built per cached response */
#define FD_GUI_CHUNK_RESPONSE_MAX (16UL<<20)    /* compressed bytes per cached response */

#define FD_GUI_CHUNK_KIND_TILE_STATES_TXN   (0)
#define FD_GUI_CHUNK_KIND_TILE_STATES_BATCH (1)
#define FD_GUI_CHUNK_KIND_TXN_META          (2)
#define FD_GUI_CHUNK_KIND_REVENUE_TXN       (3)
#define FD_GUI_CHUNK_KIND_REVENUE_BATCH     (4)
#define FD_GUI_CHUNK_KIND_SHREDS            (5)
#define FD_GUI_CHUNK_KIND_FEC               (6)
#define FD_GUI_CHUNK_KIND_CNT               (7)

#define FD_GUI_CHUNK_MASK( kind ) (1UL<<(kind))

/* Replay transactions, slot states, lthash tasks and shred/FEC events
   are recorded as their frags arrive, a transaction's tile states when
   it completes, and transaction / lthash batches within
   FD_GUI_TXN_BATCH_IDLE_NS / FD_GUI_LTHASH_BATCH_IDLE_NS of their last
   member, so the oldest timestamp a new row can carry is at most one
   transaction duration plus link latency old (traced on mainnet: worst
   2 ms for shreds, FEC events and transactions, 75 ms for tile
   states).  A chunk is final FD_GUI_CHUNK_FINAL_NS after its end.  Rows
   recorded later anyway are counted by late_cnt. */

#define FD_GUI_CHUNK_FINAL_NS       (200000000L)

struct fd_gui_chunk_entry {
  ulong chunk; /* chunk index, ULONG_MAX if empty */
  ulong pos;   /* monotonic ring position of the first byte */
  ulong len;
};
typedef struct fd_gui_chunk_entry fd_gui_chunk_entry_t;

struct fd_gui_chunk {
  uchar * data;  /* FD_GUI_CHUNK_CACHE_SZ bytes, NULL disables the cache */
  ulong   wr;    /* monotonic position of the next write */
  ulong   hi;    /* monotonic end of everything ever (possibly) written */
  long    now;   /* updated by fd_gui_poll */

  int     mode;  /* printers stage a bare chunk object, not a response */
  int     limit; /* set by a printer in chunk mode on a row limit */

  ulong   hit_cnt;
  ulong   miss_cnt;
  ulong   late_cnt;
  ulong   fallback_cnt;

  ulong   sep_sz;   uchar sep  [ 32 ]; /* compressed "," */
  ulong   close_sz; uchar close[ 32 ]; /* compressed "]}}" */

  fd_gui_chunk_entry_t idx[ FD_GUI_CHUNK_KIND_CNT ][ FD_GUI_CHUNK_IDX_CNT ];
};
typedef struct fd_gui_chunk fd_gui_chunk_t;

FD_PROTOTYPES_BEGIN

static inline long
fd_gui_chunk_final_ns( fd_gui_chunk_t const * c,
                       int                    kind ) {
  (void)c; (void)kind;
  return FD_GUI_CHUNK_FINAL_NS;
}

/* fd_gui_chunk_edge returns the index of the first chunk of kind that
   is not final yet. */

static inline ulong
fd_gui_chunk_edge( fd_gui_chunk_t const * c,
                   int                    kind ) {
  long t = c->now - fd_gui_chunk_final_ns( c, kind );
  return t>0L ? (ulong)(t/FD_GUI_CHUNK_NS) : 0UL;
}

/* fd_gui_chunk_init sets up c to cache in data (FD_GUI_CHUNK_CACHE_SZ
   bytes, or NULL to disable caching). */

void
fd_gui_chunk_init( fd_gui_chunk_t * c,
                   void *           data );

/* fd_gui_chunk_get returns the cached entry for chunk k of kind, or NULL
   if it is not cached or its bytes were overwritten.  Its bytes are at
   fd_gui_chunk_bytes( c, e ). */

static inline fd_gui_chunk_entry_t const *
fd_gui_chunk_get( fd_gui_chunk_t const * c,
                  int                    kind,
                  ulong                  k ) {
  fd_gui_chunk_entry_t const * e = &c->idx[ kind ][ k%FD_GUI_CHUNK_IDX_CNT ];
  if( e->chunk!=k || e->pos+FD_GUI_CHUNK_CACHE_SZ<c->hi ) return NULL;
  return e;
}

static inline uchar const *
fd_gui_chunk_bytes( fd_gui_chunk_t const *       c,
                    fd_gui_chunk_entry_t const * e ) {
  return c->data + e->pos%FD_GUI_CHUNK_CACHE_SZ;
}

/* fd_gui_chunk_prepare returns where to write the next chunk, which
   may be up to FD_GUI_CHUNK_SZ_MAX bytes.  Entries the write may
   overwrite stop being returned by fd_gui_chunk_get.
   fd_gui_chunk_publish indexes the len bytes written there as chunk k
   of kind. */

uchar *
fd_gui_chunk_prepare( fd_gui_chunk_t * c );

void
fd_gui_chunk_publish( fd_gui_chunk_t * c,
                      int              kind,
                      ulong            k,
                      ulong            len );

/* fd_gui_chunk_note is called when a row whose window position is
   [lo,hi] (ns, inclusive) is recorded for the kinds in kind_mask.  If
   any of those chunks are already cached (so final), the row is late:
   the frozen cached copies don't include it and late_cnt counts each
   such copy. */

void
fd_gui_chunk_note( fd_gui_chunk_t * c,
                   ulong            kind_mask,
                   long             lo,
                   long             hi );

/* fd_gui_chunk_lo returns the earlier of two optional row times
   (non-positive or LONG_MAX if absent), for fd_gui_chunk_note. */

static inline long
fd_gui_chunk_lo( long a,
                 long b ) {
  if( a<=0L ) return b;
  if( b<=0L ) return a;
  return fd_long_min( a, b );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_chunk_h */
