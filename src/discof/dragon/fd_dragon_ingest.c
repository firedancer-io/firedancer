#include "fd_dragon_ingest.h"

#define FD_DRAGON_INGEST_MAGIC (0xf17eda2547d2a602UL) /* firedancer geyser ingest */

struct dragon_link {
  uchar * buf;      /* FD_EVENT_INTERNAL_SZ_MAX bytes */
  ulong   next_seq; /* sequence number the next fragment must have, ULONG_MAX before the first */
  ulong   sz;       /* bytes of the record in progress accumulated so far */
  ulong   total;    /* size the record's first fragment declared */
  ulong   type;     /* type the record's first fragment declared */
  ulong   rec_sz;   /* size of the last completed record */
  ulong   rec_type; /* type of the last completed record */
  int     open;     /* a record is in progress */
  int     drop;     /* the record in progress is being dropped */
};

typedef struct dragon_link dragon_link_t;

struct fd_dragon_ingest {
  ulong magic;
  ulong link_cnt;
  int   gap;

  dragon_link_t * link;

  fd_dragon_ingest_metrics_t metrics;
};

FD_FN_CONST ulong
fd_dragon_ingest_align( void ) {
  return FD_DRAGON_INGEST_ALIGN;
}

FD_FN_CONST ulong
fd_dragon_ingest_footprint( ulong link_cnt ) {
  if( FD_UNLIKELY( !link_cnt || link_cnt>FD_DRAGON_INGEST_LINK_MAX ) ) return 0UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_DRAGON_INGEST_ALIGN,   sizeof(fd_dragon_ingest_t)     );
  l = FD_LAYOUT_APPEND( l, alignof(dragon_link_t),   link_cnt*sizeof(dragon_link_t) );
  l = FD_LAYOUT_APPEND( l, 128UL,                    link_cnt*FD_EVENT_INTERNAL_SZ_MAX );
  return FD_LAYOUT_FINI( l, FD_DRAGON_INGEST_ALIGN );
}

void *
fd_dragon_ingest_new( void * mem,
                      ulong  link_cnt ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_DRAGON_INGEST_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_dragon_ingest_footprint( link_cnt ) ) ) {
    FD_LOG_WARNING(( "bad link_cnt %lu", link_cnt ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_dragon_ingest_t * ing  = FD_SCRATCH_ALLOC_APPEND( l, FD_DRAGON_INGEST_ALIGN, sizeof(fd_dragon_ingest_t)     );
  dragon_link_t *      link = FD_SCRATCH_ALLOC_APPEND( l, alignof(dragon_link_t), link_cnt*sizeof(dragon_link_t) );
  uchar *              buf  = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                  link_cnt*FD_EVENT_INTERNAL_SZ_MAX );
  FD_SCRATCH_ALLOC_FINI( l, FD_DRAGON_INGEST_ALIGN );

  fd_memset( ing, 0, sizeof(fd_dragon_ingest_t) );
  ing->link_cnt = link_cnt;
  ing->link     = link;

  for( ulong i=0UL; i<link_cnt; i++ ) {
    fd_memset( link+i, 0, sizeof(dragon_link_t) );
    link[ i ].buf      = buf + i*FD_EVENT_INTERNAL_SZ_MAX;
    link[ i ].next_seq = ULONG_MAX;
  }

  FD_COMPILER_MFENCE();
  ing->magic = FD_DRAGON_INGEST_MAGIC;
  FD_COMPILER_MFENCE();
  return mem;
}

fd_dragon_ingest_t *
fd_dragon_ingest_join( void * mem ) {
  fd_dragon_ingest_t * ing = mem;
  if( FD_UNLIKELY( !ing ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( ing->magic!=FD_DRAGON_INGEST_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return ing;
}

/* dragon_link_reset forgets the record in progress. */

static void
dragon_link_reset( dragon_link_t * l ) {
  l->open = 0;
  l->drop = 0;
  l->sz   = 0UL;
}

int
fd_dragon_ingest_frag( fd_dragon_ingest_t * ing,
                       ulong                link_idx,
                       ulong                seq,
                       ulong                sig,
                       ulong                ctl,
                       void const *         data,
                       ulong                sz ) {
  if( FD_UNLIKELY( link_idx>=ing->link_cnt ) ) return 0;
  dragon_link_t * l = ing->link + link_idx;

  if( FD_UNLIKELY( l->next_seq!=ULONG_MAX && seq!=l->next_seq ) ) {
    ing->metrics.overrun_cnt++;
    ing->gap = 1;
    if( FD_UNLIKELY( l->open ) ) ing->metrics.gap_drop_cnt++;
    dragon_link_reset( l );
  }
  l->next_seq = fd_seq_inc( seq, 1UL );

  if( FD_UNLIKELY( sz>FD_EVENT_INTERNAL_FRAG_MAX ) ) {
    if( FD_UNLIKELY( l->open ) ) ing->metrics.malformed_cnt++;
    dragon_link_reset( l );
    return 0;
  }

  if( FD_UNLIKELY( fd_frag_meta_ctl_som( ctl ) ) ) {
    l->open  = 1;
    l->drop  = 0;
    l->sz    = 0UL;
    l->type  = FD_EVENT_SIG_TYPE( sig );
    l->total = FD_EVENT_SIG_SZ  ( sig );
    if( FD_UNLIKELY( !l->total || l->total>FD_EVENT_INTERNAL_SZ_MAX ) ) {
      ing->metrics.malformed_cnt++;
      l->drop = 1;
    }
  } else if( FD_UNLIKELY( !l->open ) ) {
    return 0; /* a continuation of a record whose start was lost */
  }

  if( FD_LIKELY( !l->drop ) ) {
    if( FD_UNLIKELY( sz>l->total-l->sz ) ) {
      ing->metrics.malformed_cnt++;
      l->drop = 1;
    } else {
      fd_memcpy( l->buf+l->sz, data, sz );
    }
  }
  l->sz += sz;

  if( FD_LIKELY( !fd_frag_meta_ctl_eom( ctl ) ) ) return 0;

  if( FD_UNLIKELY( !l->drop && l->sz!=l->total ) ) {
    ing->metrics.malformed_cnt++;
    l->drop = 1;
  }

  int ready = !l->drop;
  if( FD_LIKELY( ready ) ) {
    l->rec_sz   = l->sz;
    l->rec_type = l->type;
    ing->metrics.record_cnt++;
    if( FD_UNLIKELY( l->sz>FD_EVENT_INTERNAL_FRAG_MAX ) ) ing->metrics.multi_frag_cnt++;
  }
  dragon_link_reset( l );
  return ready;
}

void
fd_dragon_ingest_record( fd_dragon_ingest_t const * ing,
                         ulong                      link_idx,
                         ulong *                    opt_type,
                         void const **              opt_rec,
                         ulong *                    opt_rec_sz ) {
  dragon_link_t const * l = ing->link + link_idx;
  if( opt_type   ) *opt_type   = l->rec_type;
  if( opt_rec    ) *opt_rec    = l->buf;
  if( opt_rec_sz ) *opt_rec_sz = l->rec_sz;
}

FD_FN_PURE ulong
fd_dragon_ingest_next_seq( fd_dragon_ingest_t const * ing,
                           ulong                      link_idx ) {
  return ing->link[ link_idx ].next_seq;
}

int
fd_dragon_ingest_gap_clear( fd_dragon_ingest_t * ing ) {
  int gap  = ing->gap;
  ing->gap = 0;
  return gap;
}

FD_FN_PURE fd_dragon_ingest_metrics_t const *
fd_dragon_ingest_metrics( fd_dragon_ingest_t const * ing ) {
  return &ing->metrics;
}
