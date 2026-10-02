#ifndef HEADER_fd_src_discof_motor_fd_motor_shred_h
#define HEADER_fd_src_discof_motor_fd_motor_shred_h

#include "../poh/fd_poh.h"
#include "../../disco/fd_disco_base.h"
#include "../../disco/shred/fd_shred_batch.h"
#include "../../disco/stem/fd_stem.h"

/* fd_motor_shred_t coalesces the entries motor sends to shred into
   poh_shred frags.  Entries append to the frag open at out->chunk,
   which is published once it holds FD_POH_SHRED_BATCH_SZ bytes of
   them, when the input runs dry, or where shred closes a batch.  The
   frags then cut the block into the same shred batches, FEC sets and
   block id as one frag per entry would (see fd_shred_batch_step):

   - an entry on which shred closes the open batch (it would take the
     batch past the watermark) starts a new frag;
   - an entry that closes a batch on its own (it completes the block or
     is the first of its slot) ends its frag;
   - markers and ticks are frags of their own (fd_motor_shred_prepare).

   batch_slot and batch_pos track shred's open batch as it will be once
   the open frag is published. */

struct fd_motor_shred {
  fd_poh_out_t out[ 1 ];

  ulong pend_sz;    /* entry bytes in the open frag, 0 if none */
  ulong pend_slot;
  ulong pend_pos;   /* batch_pos before the open frag */
  ulong next_sz;    /* the entry being written (see append) */
  int   next_close;

  ulong batch_slot; /* ULONG_MAX before the first frag */
  ulong batch_pos;

  ulong idle_cnt;   /* stem loops since the last frag in */
};

typedef struct fd_motor_shred fd_motor_shred_t;

static inline void
fd_motor_shred_init( fd_motor_shred_t *   s,
                     fd_poh_out_t const * out ) {
  *s->out       = *out;
  s->pend_sz    = 0UL;
  s->pend_slot  = 0UL;
  s->pend_pos   = 0UL;
  s->next_sz    = 0UL;
  s->next_close = 0;
  s->batch_slot = ULONG_MAX;
  s->batch_pos  = 0UL;
  s->idle_cnt   = 0UL;
}

/* fd_motor_shred_flush publishes the open frag, if any. */

static inline void
fd_motor_shred_flush( fd_motor_shred_t *  s,
                      fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( !s->pend_sz ) ) return;
  ulong sz    = sizeof(fd_entry_batch_meta_t)+s->pend_sz;
  ulong sig   = fd_disco_poh_sig( s->pend_slot, POH_PKT_TYPE_MICROBLOCK, 0UL );
  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, s->out->idx, sig, s->out->chunk, sz, 0UL, 0UL, tspub );
  s->out->chunk = fd_dcache_compact_next( s->out->chunk, sz, s->out->chunk0, s->out->wmark );
  s->pend_sz    = 0UL;
}

/* fd_motor_shred_append returns where to write an entry_sz byte entry of
   slot, at the end of the open frag.  meta is the frag meta for the
   entry (block_complete 0 or 1, entry_cnt and txn_cnt ignored); an
   open frag with another slot, parent_offset or reference_tick is
   published first.  The caller writes the entry, then calls
   fd_motor_shred_commit with its transaction count.  The pair publishes
   at most two frags. */

static inline uchar *
fd_motor_shred_append( fd_motor_shred_t *            s,
                       fd_stem_context_t *           stem,
                       ulong                         slot,
                       fd_entry_batch_meta_t const * meta,
                       ulong                         entry_sz ) {
  int   new_slot = slot!=s->batch_slot;
  ulong pos      = fd_ulong_if( new_slot, 0UL, s->batch_pos );
  int   step     = fd_shred_batch_step( pos, entry_sz, meta->block_complete, new_slot );

  fd_entry_batch_meta_t * pend = fd_chunk_to_laddr( s->out->mem, s->out->chunk );
  if( FD_LIKELY( s->pend_sz ) ) {
    int differs = (slot!=s->pend_slot) | (meta->parent_offset!=pend->parent_offset) | (meta->reference_tick!=pend->reference_tick);
    if( FD_UNLIKELY( differs | (step & FD_SHRED_BATCH_SHRED) ) ) {
      fd_motor_shred_flush( s, stem );
      pend = fd_chunk_to_laddr( s->out->mem, s->out->chunk );
    }
  }
  if( FD_UNLIKELY( !s->pend_sz ) ) {
    *pend           = *meta;
    pend->entry_cnt = 0;
    pend->txn_cnt   = 0;
    s->pend_slot    = slot;
    s->pend_pos     = pos;
  }
  s->next_sz    = entry_sz;
  s->next_close = step==(FD_SHRED_BATCH_INCLUDE|FD_SHRED_BATCH_SHRED);
  s->batch_slot = slot;
  s->batch_pos  = fd_shred_batch_pos( pos, entry_sz, meta->block_complete, new_slot );
  return (uchar *)(pend+1)+s->pend_sz;
}

static inline void
fd_motor_shred_commit( fd_motor_shred_t *  s,
                       fd_stem_context_t * stem,
                       ulong               txn_cnt ) {
  fd_entry_batch_meta_t * pend = fd_chunk_to_laddr( s->out->mem, s->out->chunk );
  pend->entry_cnt = (ushort)( pend->entry_cnt+1U );
  pend->txn_cnt   = (ushort)( pend->txn_cnt+txn_cnt );
  s->pend_sz += s->next_sz;
  if( FD_UNLIKELY( s->next_close | (s->pend_sz>=FD_POH_SHRED_BATCH_SZ) ) ) fd_motor_shred_flush( s, stem );
}

/* fd_motor_shred_prepare publishes the open frag and returns where to
   write a frag of its own: its meta followed by one entry or marker of
   entry_sz bytes, published by fd_motor_shred_publish.  The pair
   publishes at most two frags. */

static inline fd_entry_batch_meta_t *
fd_motor_shred_prepare( fd_motor_shred_t *  s,
                        fd_stem_context_t * stem ) {
  fd_motor_shred_flush( s, stem );
  return fd_chunk_to_laddr( s->out->mem, s->out->chunk );
}

static inline void
fd_motor_shred_publish( fd_motor_shred_t *  s,
                        fd_stem_context_t * stem,
                        ulong               slot,
                        ulong               entry_sz ) {
  fd_entry_batch_meta_t const * meta = fd_chunk_to_laddr_const( s->out->mem, s->out->chunk );
  int new_slot  = slot!=s->batch_slot;
  s->batch_pos  = fd_shred_batch_pos( fd_ulong_if( new_slot, 0UL, s->batch_pos ), entry_sz, meta->block_complete, new_slot );
  s->batch_slot = slot;

  ulong sz    = sizeof(fd_entry_batch_meta_t)+entry_sz;
  ulong sig   = fd_disco_poh_sig( slot, POH_PKT_TYPE_MICROBLOCK, 0UL );
  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, s->out->idx, sig, s->out->chunk, sz, 0UL, 0UL, tspub );
  s->out->chunk = fd_dcache_compact_next( s->out->chunk, sz, s->out->chunk0, s->out->wmark );
}

/* The open frag also goes out when the input runs dry: idle_max stem
   loops since a frag was last taken, in_cnt (the tile's polled in
   count) when the stem can park, 2*in_cnt (every in polled empty
   since) when it cannot.  A parking stem
   parks only after in_cnt loops in a row that took no frag, so the open
   frag is published (and charge_busy keeps the stem awake) in the loop
   before any park: no entry waits behind one.  Call fd_motor_shred_loop
   from before_credit, which runs every loop, fd_motor_shred_busy from
   after_frag, which runs for every frag taken, and fd_motor_shred_idle
   from after_credit.  fd_motor_shred_idle publishes at most one frag. */

static inline void fd_motor_shred_loop( fd_motor_shred_t * s ) { s->idle_cnt++;      }
static inline void fd_motor_shred_busy( fd_motor_shred_t * s ) { s->idle_cnt = 0UL; }

static inline void
fd_motor_shred_idle( fd_motor_shred_t *  s,
                     fd_stem_context_t * stem,
                     ulong               in_cnt,
                     int *               charge_busy ) {
  ulong idle_max = fd_ulong_if( !!stem->sleep, in_cnt, 2UL*in_cnt );
  if( FD_LIKELY( !s->pend_sz || s->idle_cnt<idle_max ) ) return;
  fd_motor_shred_flush( s, stem );
  *charge_busy = 1;
}

#endif /* HEADER_fd_src_discof_motor_fd_motor_shred_h */
