#include "fd_motor_shred.h"
#include "../../disco/shred/fd_shredder.h"

/* The coalesced poh_shred frags must cut a block into the same shred
   batches, FEC sets and block id as one frag per entry.  Each stream
   below is shredded twice by the shred tile's leader batching (the
   model here follows during_frag in fd_shred_tile.c, with the same
   fd_shred_batch_step), once from one frag per entry and once from the
   fd_motor_shred_t frags, and the merkle root of every FEC set is
   compared. */

#define DEPTH   (4096UL)
#define SET_MAX (8192UL)

static uchar * dcache_mem;
static ulong   chunk0;
static ulong   wmark;

/* The FEC set merkle roots a stream shreds to, in order */

struct roots {
  ulong     cnt;
  ulong     batch_cnt;
  fd_hash_t root[ SET_MAX ];
  ulong     data_cnt;
};
typedef struct roots roots_t;

static roots_t       roots_a[1];
static roots_t       roots_b[1];
static fd_shredder_t _shredder[1];
static fd_fec_set_t  _set[1];

struct shred_model {
  ulong slot;
  ulong pos;
  ulong entry_cnt;
  uchar chained_root[ 32 ];
  union {
    struct {
      ulong cnt;
      uchar payload[ FD_SHRED_BATCH_RAW_BUF_SZ - 8UL ];
    };
    uchar raw[ FD_SHRED_BATCH_RAW_BUF_SZ ];
  };
};
typedef struct shred_model shred_model_t;

static shred_model_t model[1];

static void
model_init( shred_model_t * m ) {
  m->slot      = ULONG_MAX;
  m->pos       = 0UL;
  m->entry_cnt = 0UL;
  memset( m->chained_root, 0, 32UL );
}

static void
model_shred( shred_model_t *               m,
             fd_entry_batch_meta_t const * meta,
             roots_t *                     out ) {
  ulong load      = FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ;
  ulong batch_sz  = sizeof(ulong)+m->pos;
  ulong padded_sz = load*( ( batch_sz+load-1UL )/load );
  memset( m->payload+m->pos, 0, padded_sz-batch_sz );
  m->cnt = m->entry_cnt;

  fd_shredder_t * shredder = fd_shredder_join( _shredder );
  FD_TEST( fd_shredder_init_batch( shredder, m->raw, padded_sz, m->slot, meta ) );
  ulong set_cnt = 0UL;
  while( fd_shredder_next_fec_set( shredder, _set, m->chained_root ) ) {
    FD_TEST( out->cnt<SET_MAX );
    memcpy( out->root[ out->cnt++ ].uc, m->chained_root, 32UL );
    set_cnt++;
  }
  FD_TEST( set_cnt && set_cnt<=FD_SHRED_BATCH_FEC_SETS_MAX );
  FD_TEST( fd_shredder_fini_batch( shredder ) );
  out->batch_cnt++;
  out->data_cnt += 32UL*set_cnt;

  m->pos       = 0UL;
  m->entry_cnt = 0UL;
}

static void
model_frag( shred_model_t * m,
            ulong           slot,
            uchar const *   frag,
            ulong           sz,
            roots_t *       out ) {
  fd_entry_batch_meta_t const * meta = (fd_entry_batch_meta_t const *)frag;
  uchar const * entry    = frag+sizeof(fd_entry_batch_meta_t);
  ulong         entry_sz = sz-sizeof(fd_entry_batch_meta_t);
  FD_TEST( entry_sz+m->pos<=sizeof(m->payload) );

  int new_slot = slot!=m->slot;
  if( new_slot ) {
    FD_TEST( !m->pos ); /* streams never abandon a batch */
    m->slot = slot;
    memcpy( m->chained_root, meta->parent_block_id, 32UL );
  }

  int is_marker = meta->block_complete==-1;
  int step      = fd_shred_batch_step( m->pos, entry_sz, meta->block_complete, new_slot );
  if( step & FD_SHRED_BATCH_INCLUDE ) {
    memcpy( m->payload+m->pos, entry, entry_sz );
    m->pos       += entry_sz;
    m->entry_cnt += meta->entry_cnt;
  }
  if( step & FD_SHRED_BATCH_SHRED ) model_shred( m, meta, out );
  if( !(step & FD_SHRED_BATCH_INCLUDE) ) {
    if( is_marker ) {
      memcpy( m->raw, entry, entry_sz );
      m->pos = entry_sz-sizeof(ulong);
      model_shred( m, meta, out );
    } else {
      memcpy( m->payload, entry, entry_sz );
      m->pos       = entry_sz;
      m->entry_cnt = meta->entry_cnt;
    }
  }
}

/* A mock stem context with one reliable out of DEPTH credits, which the
   test returns as it drains frags. */

static fd_frag_meta_t * mcache;
static ulong            out_seq;
static ulong            cr_avail;
static ulong            min_cr_avail;
static ulong            depth_;
static int              reliable = 1;
static fd_stem_context_t stem[1];

static ulong
drain( roots_t * out,
       ulong     seq0 ) {
  ulong seq = seq0;
  for( ; seq<out_seq; seq++ ) {
    fd_frag_meta_t const * m = mcache + fd_mcache_line_idx( seq, DEPTH );
    FD_TEST( m->seq==seq );
    ulong sz = m->sz;
    FD_TEST( sz>=sizeof(fd_entry_batch_meta_t)+1UL && sz<=FD_POH_SHRED_MTU );
    model_frag( model, fd_disco_poh_sig_slot( m->sig ), fd_chunk_to_laddr_const( dcache_mem, m->chunk ), sz, out );
  }
  cr_avail     = DEPTH;
  min_cr_avail = DEPTH;
  return seq;
}

static void
stem_init( fd_wksp_t * wksp ) {
  void * mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( DEPTH, 0UL ), 1UL );
  mcache = fd_mcache_join( fd_mcache_new( mem, DEPTH, 0UL, 0UL ) );
  FD_TEST( mcache );
  ulong data_sz = fd_dcache_req_data_sz( FD_POH_SHRED_MTU, DEPTH, 1UL, 1 );
  mem = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ), 1UL );
  uchar * dcache = fd_dcache_join( fd_dcache_new( mem, data_sz, 0UL ) );
  FD_TEST( dcache );
  dcache_mem = (uchar *)wksp;
  chunk0     = fd_dcache_compact_chunk0( wksp, dcache );
  wmark      = fd_dcache_compact_wmark ( wksp, dcache, FD_POH_SHRED_MTU );
  depth_     = DEPTH;
  cr_avail     = DEPTH;
  min_cr_avail = DEPTH;

  static fd_frag_meta_t * mcaches[1];
  mcaches[0] = mcache;
  *stem = (fd_stem_context_t){
    .mcaches             = mcaches,
    .seqs                = &out_seq,
    .depths              = &depth_,
    .cr_avail            = &cr_avail,
    .min_cr_avail        = &min_cr_avail,
    .cr_decrement_amount = 1UL,
    .out_reliable        = &reliable,
  };
}

/* A random block: a header marker, entries of 1..5 transactions of
   random sizes, a footer marker and the alpentick.  Entries are written
   byte-identically in both encodings. */

struct entry_desc {
  int   kind; /* 0 entry, 1 marker, 2 tick */
  int   block_complete;
  ulong sz;
  ulong txn_cnt;
  uint  seed;
};
typedef struct entry_desc entry_desc_t;

#define ENTRY_MAX (40000UL)
static entry_desc_t entries[ ENTRY_MAX ];

static ulong
gen_block( fd_rng_t * rng,
           ulong      entry_cnt,
           ulong      max_txn,
           int        big ) {
  ulong n = 0UL;
  entries[ n++ ] = (entry_desc_t){ .kind=1, .block_complete=-1, .sz=54UL, .seed=fd_rng_uint( rng ) };
  for( ulong i=0UL; i<entry_cnt; i++ ) {
    ulong txn_cnt = 1UL+fd_rng_ulong_roll( rng, max_txn );
    ulong sz      = sizeof(fd_entry_batch_header_t);
    for( ulong t=0UL; t<txn_cnt; t++ ) sz += big ? FD_TPU_MTU-fd_rng_ulong_roll( rng, 16UL ) : 150UL+fd_rng_ulong_roll( rng, 1100UL );
    entries[ n++ ] = (entry_desc_t){ .kind=0, .sz=sz, .txn_cnt=txn_cnt, .seed=fd_rng_uint( rng ) };
    FD_TEST( n<ENTRY_MAX-4UL );
  }
  entries[ n++ ] = (entry_desc_t){ .kind=1, .block_complete=-1, .sz=200UL+fd_rng_ulong_roll( rng, 1500UL ), .seed=fd_rng_uint( rng ) };
  entries[ n++ ] = (entry_desc_t){ .kind=2, .block_complete=1, .sz=sizeof(fd_entry_batch_header_t), .seed=fd_rng_uint( rng ) };
  return n;
}

static void
write_entry( uchar *              dst,
             entry_desc_t const * e ) {
  fd_rng_t _r[1]; fd_rng_t * r = fd_rng_join( fd_rng_new( _r, e->seed, 0UL ) );
  for( ulong i=0UL; i<e->sz; i++ ) dst[ i ] = (uchar)fd_rng_uint( r );
  if( e->kind!=1 ) ((fd_entry_batch_header_t *)dst)->txn_cnt = e->txn_cnt;
  fd_rng_delete( fd_rng_leave( r ) );
}

static void
fill_meta( fd_entry_batch_meta_t * meta,
           entry_desc_t const *    e,
           uchar const *           parent ) {
  memset( meta, 0, sizeof(*meta) );
  meta->parent_offset         = 1UL;
  meta->block_complete        = e->kind==0 ? 0 : e->block_complete;
  meta->parent_block_id_valid = 1;
  memcpy( meta->parent_block_id, parent, 32UL );
}

/* Per entry: every entry and marker a frag of its own.  Coalesced:
   entries through fd_motor_shred_append/commit, markers and the
   alpentick through fd_motor_shred_prepare/publish, with idle flushes at random
   points (idle_pct percent of entries). */

static void
run( ulong     slot,
     ulong     n,
     int       coalesce,
     uint      idle_pct,
     fd_rng_t * rng,
     roots_t *  out,
     uchar const * parent ) {
  static fd_motor_shred_t s[1];
  fd_poh_out_t o = { .idx=0UL, .mem=(fd_wksp_t *)dcache_mem, .chunk0=chunk0, .wmark=wmark, .chunk=chunk0 };
  fd_motor_shred_init( s, &o );
  model_init( model );
  FD_TEST( fd_shredder_new( _shredder ) ); /* shred indices restart */
  fd_shredder_set_shred_version( fd_shredder_join( _shredder ), (ushort)1 );
  ulong seq = out_seq;

  for( ulong i=0UL; i<n; i++ ) {
    entry_desc_t const * e = entries+i;
    ulong seq_entry = out_seq;
    if( !coalesce || e->kind!=0 ) {
      fd_entry_batch_meta_t * meta = fd_motor_shred_prepare( s, stem );
      fill_meta( meta, e, parent );
      meta->entry_cnt = (ushort)( e->kind!=1 );
      meta->txn_cnt   = (ushort)e->txn_cnt;
      write_entry( (uchar *)(meta+1), e );
      fd_motor_shred_publish( s, stem, slot, e->sz );
    } else {
      fd_entry_batch_meta_t meta[1];
      fill_meta( meta, e, parent );
      uchar * dst = fd_motor_shred_append( s, stem, slot, meta, e->sz );
      write_entry( dst, e );
      fd_motor_shred_commit( s, stem, e->txn_cnt );
      if( fd_rng_uint_roll( rng, 100U )<idle_pct ) {
        fd_motor_shred_busy( s );
        int busy = 0;
        int open = !!s->pend_sz;
        fd_motor_shred_loop( s ); fd_motor_shred_idle( s, stem, 1UL, &busy );
        FD_TEST( !busy && !!s->pend_sz==open );
        fd_motor_shred_loop( s ); fd_motor_shred_idle( s, stem, 1UL, &busy );
        FD_TEST( busy==open && !s->pend_sz ); /* a spinning stem waits 2*in_cnt loops */
      }
    }
    FD_TEST( out_seq-seq_entry<=2UL ); /* the open frag and this entry */
    if( out_seq-seq>=DEPTH/2UL ) seq = drain( out, seq );
  }
  FD_TEST( !s->pend_sz );
  drain( out, seq );
  FD_TEST( !model->pos ); /* the block completed */
}

/* Shreds the n entries both ways, checks that each takes at most
   data_max data shreds and compares.  Returns the frag count of the
   coalesced stream. */

static ulong
check_entries( ulong      slot,
               ulong      n,
               uint       idle_pct,
               fd_rng_t * rng,
               ulong      data_max ) {
  uchar parent[ 32 ];
  for( ulong i=0UL; i<32UL; i++ ) parent[ i ] = (uchar)fd_rng_uint( rng );

  memset( roots_a, 0, sizeof(roots_t) );
  memset( roots_b, 0, sizeof(roots_t) );
  ulong seq_b = out_seq; run( slot, n, 1, idle_pct, rng, roots_b, parent ); ulong frag_b = out_seq-seq_b;
  ulong seq_a = out_seq; run( slot, n, 0, 0U,       rng, roots_a, parent ); ulong frag_a = out_seq-seq_a;
  FD_TEST( roots_a->data_cnt<=data_max );
  FD_TEST( roots_b->data_cnt<=data_max );

  FD_TEST( roots_a->cnt==roots_b->cnt );
  FD_TEST( roots_a->batch_cnt==roots_b->batch_cnt );
  for( ulong i=0UL; i<roots_a->cnt; i++ ) FD_TEST( fd_memeq( roots_a->root[ i ].uc, roots_b->root[ i ].uc, 32UL ) );
  FD_TEST( frag_b<=frag_a );
  return frag_b;
}

static void
check( ulong      slot,
       ulong      entry_cnt,
       ulong      max_txn,
       int        big,
       uint       idle_pct,
       fd_rng_t * rng ) {
  ulong n = gen_block( rng, entry_cnt, max_txn, big );
  ulong frag_cnt = check_entries( slot, n, idle_pct, rng, ULONG_MAX );
  if( !idle_pct && entry_cnt>=1000UL && !big && max_txn==1UL ) FD_TEST( frag_cnt*4UL<n ); /* it coalesces */
}

/* A block of one-transaction entries holding as many entry bytes as
   fd_shred_batch_pack_data_max allows for 32k shreds, ended by the
   alpentick, must fit in 32k shreds.  The sizes repeat pattern.  With frags cut at 8 KiB alone
   (4047, 4144, 4144) makes 12335 byte frags, and shred would close
   batches at 4 of them, 49340 bytes, well under the 57480 the bound
   assumes. */

static void
check_budget( ulong         slot,
              ulong const * pattern,
              ulong         pattern_cnt,
              fd_rng_t *    rng ) {
  ulong const M      = sizeof(fd_entry_batch_header_t)+FD_TPU_MTU;
  ulong const shreds = 32768UL;
  ulong       budget = fd_shred_batch_pack_data_max( shreds, M );
  FD_TEST( budget );

  ulong n   = 0UL;
  ulong tot = 0UL;
  for( ulong i=0UL;; i++ ) {
    ulong sz = pattern[ i%pattern_cnt ];
    FD_TEST( sz>sizeof(fd_entry_batch_header_t) && sz<=M );
    if( tot+sz>budget ) break;
    entries[ n++ ] = (entry_desc_t){ .kind=0, .sz=sz, .txn_cnt=1UL, .seed=fd_rng_uint( rng ) };
    tot += sz;
    FD_TEST( n<ENTRY_MAX-1UL );
  }
  entries[ n++ ] = (entry_desc_t){ .kind=2, .block_complete=1, .sz=sizeof(fd_entry_batch_header_t), .seed=fd_rng_uint( rng ) };

  check_entries( slot, n, 0U, rng, shreds );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1234U, 0UL ) );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 65536UL, fd_shmem_cpu_idx( 0UL ), "test_motor_shred", 0UL );
  FD_TEST( wksp );
  stem_init( wksp );
  FD_TEST( fd_shredder_new( _shredder ) );
  fd_shredder_set_shred_version( fd_shredder_join( _shredder ), (ushort)1 );

  ulong slot = 10UL;
  check( slot++,     1UL, 1UL, 0,  0U, rng );
  check( slot++,    50UL, 1UL, 1,  0U, rng );
  check( slot++,  2000UL, 1UL, 0,  0U, rng );
  check( slot++,  2000UL, 5UL, 0, 10U, rng );
  check( slot++,   500UL, 5UL, 1,  0U, rng );
  check( slot++,   500UL, 3UL, 1, 30U, rng );
  for( ulong i=0UL; i<40UL; i++ ) {
    check( slot++, 1UL+fd_rng_ulong_roll( rng, 3000UL ), 1UL+fd_rng_ulong_roll( rng, 5UL ), (int)fd_rng_uint_roll( rng, 2U ), fd_rng_uint_roll( rng, 3U )*10U, rng );
  }

  ulong const pat0[] = { 4047UL, 4144UL, 4144UL };
  ulong const pat1[] = { 4144UL };
  ulong const pat2[] = { 49UL, 4144UL, 4144UL, 4144UL, 1000UL, 4144UL, 4143UL };
  check_budget( slot++, pat0, 3UL, rng );
  check_budget( slot++, pat1, 1UL, rng );
  check_budget( slot++, pat2, 7UL, rng );

  /* The first entry of a slot goes alone */
  fd_motor_shred_t s[1];
  fd_poh_out_t o = { .idx=0UL, .mem=(fd_wksp_t *)dcache_mem, .chunk0=chunk0, .wmark=wmark, .chunk=chunk0 };
  fd_motor_shred_init( s, &o );
  entry_desc_t e = { .kind=0, .sz=1000UL, .txn_cnt=1UL };
  fd_entry_batch_meta_t meta[1];
  uchar parent[ 32 ] = {0};
  fill_meta( meta, &e, parent );
  ulong seq = out_seq;
  write_entry( fd_motor_shred_append( s, stem, 99UL, meta, e.sz ), &e ); fd_motor_shred_commit( s, stem, 1UL );
  FD_TEST( out_seq==seq+1UL && !s->pend_sz && s->batch_pos==0UL ); /* the first entry of a slot goes alone */

  /* The idle flush waits for 2*in_cnt loops (in_cnt when the stem can
     park, see test_motor_tile) with no frag in */
  write_entry( fd_motor_shred_append( s, stem, 99UL, meta, e.sz ), &e ); fd_motor_shred_commit( s, stem, 1UL );
  int busy = 0;
  for( ulong i=0UL; i<8UL; i++ ) {
    fd_motor_shred_loop( s ); fd_motor_shred_idle( s, stem, 3UL, &busy ); FD_TEST( !busy && s->pend_sz );
    if( i==2UL ) fd_motor_shred_busy( s ); /* a frag came in */
  }
  fd_motor_shred_loop( s ); fd_motor_shred_idle( s, stem, 3UL, &busy ); FD_TEST(  busy && !s->pend_sz && out_seq==seq+2UL );
  busy = 0;
  fd_motor_shred_loop( s ); fd_motor_shred_idle( s, stem, 3UL, &busy ); FD_TEST( !busy && out_seq==seq+2UL );

  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
