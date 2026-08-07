#define _GNU_SOURCE
#define FD_TILE_TEST 1
#include "fd_snapmk_tile.c"
#include "../../disco/topo/fd_topob.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

static fd_wksp_t *
fd_wksp_new_lazy( ulong footprint ) {
  footprint = fd_ulong_align_up( footprint, FD_SHMEM_NORMAL_PAGE_SZ );
  void * mem = mmap( NULL, footprint, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) {
    FD_LOG_ERR(( "mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS) failed (%i-%s)",
                 footprint>>10, errno, fd_io_strerror( errno ) ));
  }

  ulong part_max = fd_wksp_part_max_est( footprint, 64UL<<10 ); FD_TEST( part_max );
  ulong data_max = fd_wksp_data_max_est( footprint, part_max ); FD_TEST( data_max );
  fd_wksp_t * wksp = fd_wksp_join( fd_wksp_new( mem, "wksp", 1U, part_max, data_max ) );
  FD_TEST( wksp );

  FD_TEST( 0==fd_shmem_join_anonymous(
      "wksp", FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, mem,
      FD_SHMEM_NORMAL_PAGE_SZ, footprint>>FD_SHMEM_NORMAL_LG_PAGE_SZ ) );
  return wksp;
}

static fd_topo_link_t *
create_link( fd_topo_t *  topo,
             fd_wksp_t *  wksp,
             char const * name,
             ulong        depth,
             ulong        mtu,
             ulong        burst ) {
  fd_topo_link_t * link = fd_topob_link( topo, name, wksp->name, depth, mtu, burst );

  void *           mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( depth, mtu ), 1UL );
  FD_TEST( mcache_mem );
  fd_frag_meta_t * mcache     = fd_mcache_join( fd_mcache_new( mcache_mem, depth, mtu, 0UL ) );
  FD_TEST( mcache );
  link->mcache = mcache;

  if( mtu ) {
    ulong   dcache_data_sz = fd_dcache_req_data_sz( mtu, depth, burst, 1 );
    FD_TEST( dcache_data_sz );
    void *  dcache_mem     = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( dcache_data_sz, 0UL ), 1UL );
    FD_TEST( dcache_mem );
    uchar * dcache         = fd_dcache_join( fd_dcache_new( dcache_mem, dcache_data_sz, 0UL ) );
    FD_TEST( dcache );
    link->dcache = dcache;
  }

  return link;
}

typedef struct {
  fd_wksp_t *      wksp;
  fd_topo_t *      topo;     /* heap allocated, kept alive for the harness's lifetime */
  fd_topo_link_t * link_in;  /* snaprd_out */
  fd_topo_link_t * link_zp;  /* snapmk_zp */

  ulong in_chunk0;
  ulong in_wmark;
  ulong in_chunk; /* write cursor into link_in's dcache */
} harness_t;

static void
harness_new( harness_t * h,
             fd_wksp_t * wksp ) {
  FD_TEST( wksp );
  h->wksp = wksp;

  h->topo = malloc( sizeof(fd_topo_t) );
  FD_TEST( h->topo );
  fd_topob_new( h->topo, "test_snapmk" );
  fd_topo_wksp_t * topo_wksp = fd_topob_wksp( h->topo, wksp->name );
  topo_wksp->wksp = wksp;

  h->link_in = create_link( h->topo, wksp, "snaprd_out", 4UL, FD_BACKUP_RD_MTU, 1UL );
  h->link_zp = create_link( h->topo, wksp, "snapmk_zp",  FD_SNAPMK_ZP_DEPTH, sizeof(fd_backup_frag_t), 1UL );

  h->in_chunk0 = fd_dcache_compact_chunk0( wksp, h->link_in->dcache );
  h->in_wmark  = fd_dcache_compact_wmark ( wksp, h->link_in->dcache, h->link_in->mtu );
  h->in_chunk  = h->in_chunk0;
}

typedef struct {
  uint *               acc_map;   /* chain heads, size chain_cnt (power of 2) */
  fd_accdb_accmeta_t * acc_pool;  /* size pool_max */
  ulong                pool_max;
  ulong                pool_used;
  uint                 chain_mask;
  ulong                seed;
} fake_index_t;

static void
fake_index_new( fake_index_t * idx,
                 ulong          pool_max,
                 ulong          seed ) {
  ulong chain_cnt = 1UL;
  while( chain_cnt<pool_max ) chain_cnt <<= 1;
  if( FD_UNLIKELY( !chain_cnt ) ) chain_cnt = 1UL;

  idx->acc_map  = malloc( chain_cnt*sizeof(uint) );
  idx->acc_pool = aligned_alloc( alignof(fd_accdb_accmeta_t), pool_max*sizeof(fd_accdb_accmeta_t) );
  FD_TEST( idx->acc_map && idx->acc_pool );
  for( ulong i=0UL; i<chain_cnt; i++ ) idx->acc_map[ i ] = UINT_MAX;
  memset( idx->acc_pool, 0, pool_max*sizeof(fd_accdb_accmeta_t) );

  idx->pool_max   = pool_max;
  idx->pool_used  = 0UL;
  idx->chain_mask = (uint)( chain_cnt-1UL );
  idx->seed       = seed;
}

static void
fake_index_delete( fake_index_t * idx ) {
  free( idx->acc_map );
  free( idx->acc_pool );
  idx->acc_map  = NULL;
  idx->acc_pool = NULL;
}

static uint
fake_index_insert( fake_index_t *       idx,
                    fd_pubkey_t const * pubkey,
                    uint                generation,
                    ulong               lamports,
                    ulong               file_off ) {
  FD_TEST( idx->pool_used<idx->pool_max );
  uint acc_idx = (uint)idx->pool_used++;
  fd_accdb_accmeta_t * acc = &idx->acc_pool[ acc_idx ];
  memcpy( acc->key.pubkey, pubkey->uc, sizeof(fd_pubkey_t) );
  acc->key.generation = generation;
  acc->lamports       = lamports;
  acc->offset_fork    = fd_accdb_acc_pack_offset_fork( file_off, 0 );

  ulong chain_idx = fd_accdb_hash( pubkey->uc, idx->seed ) & idx->chain_mask;
  acc->map.next             = idx->acc_map[ chain_idx ];
  idx->acc_map[ chain_idx ] = acc_idx;
  return acc_idx;
}

#define MAX_ACC_DATA (8192UL)

typedef enum {
  ACC_KEEP,
  ACC_DROP_NOT_INDEXED,
  ACC_DROP_TOMBSTONE,
  ACC_DROP_FUTURE_GEN,
  ACC_DROP_STALE_OFFSET,
} acc_kind_t;

typedef struct {
  ulong       acc_no;
  fd_pubkey_t pubkey;
  fd_pubkey_t owner;
  ulong       file_off;
  ulong       data_len;
  acc_kind_t  kind;
  int         expect_keep;
  int         seen;
} gen_acc_t;

typedef struct {
  uchar * buf;
  ulong   len;
  ulong   cap;
} byte_buf_t;

static void
byte_buf_new( byte_buf_t * bb,
              ulong        cap ) {
  bb->buf = malloc( cap );
  FD_TEST( bb->buf );
  bb->len = 0UL;
  bb->cap = cap;
}

static void
byte_buf_delete( byte_buf_t * bb ) {
  free( bb->buf );
  bb->buf = NULL;
}

static void
byte_buf_append( byte_buf_t * bb,
                  void const * data,
                  ulong        sz ) {
  FD_TEST( bb->len+sz<=bb->cap );
  memcpy( bb->buf+bb->len, data, sz );
  bb->len += sz;
}

static uchar
expected_byte( ulong acc_no,
               ulong j ) {
  return (uchar)( acc_no*131UL + j*7UL + 13UL );
}

static void
make_pubkey( fd_pubkey_t * pk,
             ulong         salt ) {
  memset( pk, 0, sizeof(fd_pubkey_t) );
  ulong h = fd_ulong_hash( salt*0x9E3779B97F4A7C15UL + 0xabcdef01UL );
  memcpy( pk->uc,   &h,    sizeof(ulong) );
  memcpy( pk->uc+8, &salt, sizeof(ulong) );
}

/* append_account writes [fd_accdb_disk_meta_t][data] for acc into bb,
   filling data bytes with expected_byte( acc->acc_no, j ). */

static void
append_account( byte_buf_t *       bb,
                gen_acc_t const *  acc ) {
  FD_TEST( acc->data_len<=MAX_ACC_DATA );
  fd_accdb_disk_meta_t meta;
  memcpy( meta.pubkey, acc->pubkey.uc, 32UL );
  memcpy( meta.owner,  acc->owner.uc,  32UL );
  meta.size = FD_ACCDB_SIZE_PACK( acc->data_len, 0 );
  byte_buf_append( bb, &meta, sizeof(meta) );
  if( acc->data_len ) {
    uchar * tmp = malloc( acc->data_len );
    FD_TEST( tmp );
    for( ulong j=0UL; j<acc->data_len; j++ ) tmp[ j ] = expected_byte( acc->acc_no, j );
    byte_buf_append( bb, tmp, acc->data_len );
    free( tmp );
  }
}

/* gen_accounts appends acc_cnt accounts (with the given kinds/lengths)
   into bb, inserting index entries into idx as appropriate, and fills
   in accs[i].{pubkey,owner,file_off,expect_keep}. */

static void
gen_accounts( byte_buf_t *         bb,
               fake_index_t *      idx,
               gen_acc_t *          accs,
               ulong                acc_cnt,
               acc_kind_t const *  kinds,
               ulong const *       data_lens,
               uint                 root_gen ) {
  for( ulong i=0UL; i<acc_cnt; i++ ) {
    gen_acc_t * a = &accs[ i ];
    a->acc_no   = i;
    a->kind     = kinds[ i ];
    a->data_len = data_lens[ i ];
    a->seen     = 0;
    make_pubkey( &a->pubkey, i*2UL+1UL );
    make_pubkey( &a->owner,  i*2UL+2UL );
    a->file_off = bb->len;
    append_account( bb, a );

    switch( a->kind ) {
    case ACC_KEEP:
      fake_index_insert( idx, &a->pubkey, root_gen, 1UL, a->file_off );
      a->expect_keep = 1;
      break;
    case ACC_DROP_NOT_INDEXED:
      a->expect_keep = 0;
      break;
    case ACC_DROP_TOMBSTONE:
      fake_index_insert( idx, &a->pubkey, root_gen, 0UL, a->file_off );
      a->expect_keep = 0;
      break;
    case ACC_DROP_FUTURE_GEN:
      fake_index_insert( idx, &a->pubkey, root_gen+1U, 1UL, a->file_off );
      a->expect_keep = 0;
      break;
    case ACC_DROP_STALE_OFFSET:
      fake_index_insert( idx, &a->pubkey, root_gen, 1UL, a->file_off + (1UL<<40) );
      a->expect_keep = 0;
      break;
    default:
      FD_LOG_ERR(( "bad acc_kind" ));
    }
  }
}

typedef struct {
  fd_snapmk_t * ctx;
  ulong         rd_shadow_buf[ FD_SNAPMK_ZP_DEPTH ];

  fd_frag_meta_t * zp_mcache[1];
  ulong            zp_depth [1];
  ulong            zp_seq   [1];
  ulong            zp_cr_avail[1];
  ulong            zp_min_cr_avail;
  fd_stem_context_t stem;

  ulong epoch_val;
  ulong epoch_slot_val;

  ulong rd_seq;
} scenario_t;

static void
scenario_wire( scenario_t *   sc,
               harness_t *    h,
               fake_index_t * idx,
               visited_set_t * visited_set,
               uint            root_gen ) {
  if( FD_UNLIKELY( !sc->ctx ) ) {
    sc->ctx = aligned_alloc( alignof(fd_snapmk_t), sizeof(fd_snapmk_t) );
    FD_TEST( sc->ctx );
  }
  fd_snapmk_t * ctx = sc->ctx;
  memset( ctx, 0, sizeof(fd_snapmk_t) );

  ctx->state     = SNAPMK_STATE_ACCDB_DISK;
  ctx->rd_in_mem = h->wksp;
  ctx->rd_in_mtu = FD_BACKUP_RD_MTU;

  ctx->zp_cnt              = 1UL;
  ctx->zp_out[0].mem       = h->wksp;
  ctx->zp_out[0].chunk0    = fd_dcache_compact_chunk0( h->wksp, h->link_zp->dcache );
  ctx->zp_out[0].wmark     = fd_dcache_compact_wmark ( h->wksp, h->link_zp->dcache, h->link_zp->mtu );
  ctx->zp_out[0].chunk     = ctx->zp_out[0].chunk0;
  ctx->zp_ready            = 1UL;
  ctx->zp_rr_idx           = 0UL;
  ctx->disk_out_idx        = -1;
  ctx->disk_batch_pending  = 0;
  ctx->rd_shadow[0]        = sc->rd_shadow_buf;

  *ctx->accparse = (fd_snapmk_accparse_t){
    .acc_keep        = 1U,
    .acc_map         = idx->acc_map,
    .acc_pool        = idx->acc_pool,
    .visited_set     = visited_set,
    .max_accounts    = idx->pool_max,
    .acc_map_seed    = idx->seed,
    .chain_mask      = idx->chain_mask,
    .epoch_slot      = &sc->epoch_slot_val,
    .epoch           = &sc->epoch_val,
    .root_generation = root_gen,
  };
  sc->epoch_val      = 1UL;
  sc->epoch_slot_val = ULONG_MAX;

  sc->zp_mcache[0]    = h->link_zp->mcache;
  sc->zp_depth [0]    = FD_SNAPMK_ZP_DEPTH;
  sc->zp_seq   [0]    = 0UL;
  sc->zp_cr_avail[0]  = FD_SNAPMK_ZP_DEPTH;
  sc->zp_min_cr_avail = FD_SNAPMK_ZP_DEPTH;
  sc->stem = (fd_stem_context_t){
    .mcaches             = sc->zp_mcache,
    .depths              = sc->zp_depth,
    .seqs                = sc->zp_seq,
    .cr_avail            = sc->zp_cr_avail,
    .min_cr_avail        = &sc->zp_min_cr_avail,
    .cr_decrement_amount = 1UL,
  };

  sc->rd_seq = 0UL;
  h->in_chunk = h->in_chunk0;
}

typedef struct {
  gen_acc_t * accs;
  ulong       acc_cnt;

  ulong zp_seq_cursor;

  fd_pubkey_t cur_pubkey;
  fd_pubkey_t cur_owner;
  ulong       cur_len;
  uchar       cur_buf[ MAX_ACC_DATA ];
} verify_ctx_t;

static void
verify_init( verify_ctx_t * v,
             gen_acc_t *    accs,
             ulong          acc_cnt ) {
  v->accs          = accs;
  v->acc_cnt       = acc_cnt;
  v->zp_seq_cursor = 0UL;
  v->cur_len       = 0UL;
}

static void
record_kept( verify_ctx_t *       v,
             fd_pubkey_t const *  pubkey,
             fd_pubkey_t const *  owner,
             uchar const *        data,
             ulong                data_len ) {
  gen_acc_t * acc = NULL;
  for( ulong i=0UL; i<v->acc_cnt; i++ ) {
    if( 0==memcmp( v->accs[ i ].pubkey.uc, pubkey->uc, sizeof(fd_pubkey_t) ) ) { acc = &v->accs[ i ]; break; }
  }
  FD_TEST( acc );
  FD_TEST( acc->expect_keep );
  FD_TEST( !acc->seen );
  acc->seen = 1;
  FD_TEST( acc->data_len==data_len );
  FD_TEST( 0==memcmp( acc->owner.uc, owner->uc, sizeof(fd_pubkey_t) ) );
  for( ulong j=0UL; j<data_len; j++ ) {
    FD_TEST( data[ j ]==expected_byte( acc->acc_no, j ) );
  }
}

static void
drain_zp( harness_t *    h,
          scenario_t *   sc,
          verify_ctx_t * v ) {
  ulong seq = v->zp_seq_cursor;
  while( seq!=sc->stem.seqs[0] ) {
    fd_frag_meta_t const * line = h->link_zp->mcache + ( seq & (FD_SNAPMK_ZP_DEPTH-1UL) );
    ulong ctl   = line->ctl;
    ulong chunk = line->chunk;
    ulong tspub = line->tspub;
    ulong sig   = line->sig;
    ulong orig  = fd_frag_meta_ctl_orig( ctl );
    int   som   = fd_frag_meta_ctl_som ( ctl );
    int   eom   = fd_frag_meta_ctl_eom ( ctl );

    if( orig==FD_BACKUP_ORIG_ACC_DISK_BATCH ) {
      fd_backup_disk_batch_msg_t const * b = fd_chunk_to_laddr_const( h->wksp, chunk );
      uchar const * frag_base = fd_wksp_laddr_fast( h->wksp, sig );
      for( ulong i=0UL; i<FD_BACKUP_DISK_PARA; i++ ) {
        if( b->acc_idx[ i ]==UINT_MAX ) continue;
        fd_accdb_disk_meta_t const * dm = (fd_accdb_disk_meta_t const *)( frag_base + b->frag_off[ i ] );
        ulong data_len = FD_ACCDB_SIZE_DATA( dm->size );
        FD_TEST( 0==memcmp( dm->pubkey, b->pubkey[ i ].uc, sizeof(fd_pubkey_t) ) );
        record_kept( v, &b->pubkey[ i ], (fd_pubkey_t const *)dm->owner, (uchar const *)dm+sizeof(*dm), data_len );
      }
    } else if( orig==FD_BACKUP_ORIG_ACC_DISK ) {
      if( som ) {
        fd_backup_disk_msg_t const * hdr = fd_chunk_to_laddr_const( h->wksp, chunk );
        v->cur_pubkey = hdr->pubkey;
        v->cur_owner  = hdr->owner;
        v->cur_len    = 0UL;
      }
      if( tspub ) {
        uchar const * data = fd_wksp_laddr_fast( h->wksp, sig );
        FD_TEST( v->cur_len+tspub<=sizeof(v->cur_buf) );
        memcpy( v->cur_buf+v->cur_len, data, tspub );
        v->cur_len += tspub;
      }
      if( eom ) {
        record_kept( v, &v->cur_pubkey, &v->cur_owner, v->cur_buf, v->cur_len );
      }
    } else {
      FD_LOG_ERR(( "unexpected snapmk_zp frag orig=%lu", orig ));
    }

    seq = fd_seq_inc( seq, 1UL );
  }
  v->zp_seq_cursor = seq;
}

static void
verify_done( verify_ctx_t * v ) {
  for( ulong i=0UL; i<v->acc_cnt; i++ ) {
    FD_TEST( v->accs[ i ].seen==v->accs[ i ].expect_keep );
  }
}

/* Frag feeder: chops [0,total_len) per frag_lens[], writes each slice
   into the snaprd_out dcache, and drives snaprd_frag() to completion
   for each frag (retrying with identical args until it returns 0),
   draining newly published snapmk_zp frags after every call. */

static void
feed_frags( harness_t *      h,
            scenario_t *     sc,
            verify_ctx_t *   v,
            uchar const *    buf,
            ulong const *    frag_lens,
            ulong            n_frags ) {
  ulong off = 0UL;
  for( ulong f=0UL; f<n_frags; f++ ) {
    ulong len     = frag_lens[ f ];
    int   is_last = ( f==n_frags-1UL );
    FD_TEST( len<=FD_BACKUP_RD_MTU );
    FD_TEST( len || is_last );

    ulong chunk = h->in_chunk;
    if( len ) memcpy( fd_chunk_to_laddr( h->wksp, chunk ), buf+off, len );
    ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_DISK_FRAG, 0, is_last, 0 );

    for(;;) {
      int more = snaprd_frag( sc->ctx, &sc->stem, sc->rd_seq, off, chunk, ctl, len );
      drain_zp( h, sc, v );
      if( !more ) break;
    }
    sc->rd_seq++;
    h->in_chunk = fd_dcache_compact_next( chunk, len, h->in_chunk0, h->in_wmark );
    off += len;
  }
}

/* frags_fixed splits [0,total_len) into chunk_sz pieces (last partial)
   plus a trailing 0-length EOM slice. */

static ulong
frags_fixed( ulong   total_len,
             ulong   chunk_sz,
             ulong * out,
             ulong   out_max ) {
  ulong n = 0UL, rem = total_len;
  while( rem>0UL ) {
    FD_TEST( n<out_max );
    ulong len = fd_ulong_min( chunk_sz, rem );
    out[ n++ ] = len;
    rem -= len;
  }
  FD_TEST( n<out_max );
  out[ n++ ] = 0UL; /* EOM */
  return n;
}

/* frags_random splits [0,total_len) into pieces of random size in
   [min_len,max_len] (min_len>=1) plus a trailing 0-length EOM slice. */

static ulong
frags_random( fd_rng_t * rng,
              ulong      total_len,
              ulong      min_len,
              ulong      max_len,
              ulong *    out,
              ulong      out_max ) {
  ulong n = 0UL, rem = total_len;
  while( rem>0UL ) {
    FD_TEST( n<out_max );
    ulong span = max_len-min_len+1UL;
    ulong len  = min_len + ( span>1UL ? fd_rng_ulong( rng ) % span : 0UL );
    len = fd_ulong_min( len, rem );
    out[ n++ ] = len;
    rem -= len;
  }
  FD_TEST( n<out_max );
  out[ n++ ] = 0UL; /* EOM */
  return n;
}

/* frags_from_cuts splits [0,total_len) at the given sorted interior
   cut offsets (each in (0,total_len)) plus a trailing 0-length EOM
   slice. */

static ulong
frags_from_cuts( ulong const * cuts,
                  ulong         n_cuts,
                  ulong         total_len,
                  ulong *       out,
                  ulong         out_max ) {
  ulong n = 0UL, prev = 0UL;
  for( ulong i=0UL; i<n_cuts; i++ ) {
    FD_TEST( cuts[ i ]>prev && cuts[ i ]<total_len );
    FD_TEST( n<out_max );
    out[ n++ ] = cuts[ i ]-prev;
    prev = cuts[ i ];
  }
  FD_TEST( n<out_max );
  out[ n++ ] = total_len-prev;
  FD_TEST( n<out_max );
  out[ n++ ] = 0UL; /* EOM */
  return n;
}

/* Scenario 1: degenerate frags (1-byte-at-a-time, zero-length data
   account, valid 0-byte EOM terminator). */

static void
test_degenerate_frags( harness_t * h ) {
  ulong const acc_cnt = 5UL;
  acc_kind_t kinds[5]     = { ACC_KEEP, ACC_DROP_NOT_INDEXED, ACC_KEEP, ACC_KEEP, ACC_DROP_TOMBSTONE };
  ulong      data_lens[5] = { 10UL, 7UL, 0UL /* zero-length data account */, 25UL, 5UL };

  byte_buf_t bb; byte_buf_new( &bb, 4096UL );
  fake_index_t idx; fake_index_new( &idx, acc_cnt, 0x1234UL );
  gen_acc_t accs[5];
  gen_accounts( &bb, &idx, accs, acc_cnt, kinds, data_lens, 0U );

  ulong visited_max = fd_ulong_max( idx.pool_max, 64UL );
  void * vs_mem = aligned_alloc( visited_set_align(), visited_set_footprint( visited_max ) );
  FD_TEST( vs_mem );
  visited_set_t * vs = visited_set_join( visited_set_new( vs_mem, visited_max ) );
  visited_set_null( vs );

  scenario_t sc = {0};
  scenario_wire( &sc, h, &idx, vs, 0U );

  verify_ctx_t v; verify_init( &v, accs, acc_cnt );

  ulong frag_lens[ 4096 ];
  ulong n_frags = frags_fixed( bb.len, 1UL /* 1 byte at a time */, frag_lens, 4096UL );
  feed_frags( h, &sc, &v, bb.buf, frag_lens, n_frags );
  verify_done( &v );

  free( sc.ctx );
  visited_set_delete( visited_set_leave( vs ) );
  free( vs_mem );
  fake_index_delete( &idx );
  byte_buf_delete( &bb );

  FD_LOG_NOTICE(( "test_degenerate_frags: ok" ));
}

/* Scenario 2: boundary-exact straddles across the accdb disk meta
   header and account data. */

static void
test_boundary_straddles( harness_t * h ) {
  ulong const acc_cnt = 3UL;
  acc_kind_t kinds[3]     = { ACC_KEEP, ACC_KEEP, ACC_KEEP };
  ulong      data_lens[3] = { 40UL, 40UL, 40UL };

  byte_buf_t bb; byte_buf_new( &bb, 4096UL );
  fake_index_t idx; fake_index_new( &idx, acc_cnt, 0x5678UL );
  gen_acc_t accs[3];
  gen_accounts( &bb, &idx, accs, acc_cnt, kinds, data_lens, 0U );

  ulong const meta_sz = sizeof(fd_accdb_disk_meta_t);
  ulong const rec_sz  = meta_sz+40UL; /* 108 bytes/record */
  FD_TEST( accs[1].file_off==rec_sz );
  FD_TEST( accs[2].file_off==2UL*rec_sz );

  /* Cuts: 1 byte before/after the rec0/rec1 meta boundary, exactly at
     the rec0/rec1 record boundary, 1 byte into rec1's data, and mid
     rec1's data. */
  ulong cuts[6] = {
    meta_sz-1UL,          /* inside rec0 meta, 1 byte before it ends */
    meta_sz+1UL,          /* inside rec0 data, 1 byte after meta ends */
    rec_sz-1UL,            /* 1 byte before rec0/rec1 boundary */
    rec_sz,                /* exactly at rec0/rec1 boundary */
    rec_sz+meta_sz-1UL,   /* 1 byte before rec1's data starts */
    rec_sz+meta_sz+20UL,  /* mid rec1 data */
  };

  ulong visited_max = fd_ulong_max( idx.pool_max, 64UL );
  void * vs_mem = aligned_alloc( visited_set_align(), visited_set_footprint( visited_max ) );
  FD_TEST( vs_mem );
  visited_set_t * vs = visited_set_join( visited_set_new( vs_mem, visited_max ) );
  visited_set_null( vs );

  scenario_t sc = {0};
  scenario_wire( &sc, h, &idx, vs, 0U );

  verify_ctx_t v; verify_init( &v, accs, acc_cnt );

  ulong frag_lens[ 32 ];
  ulong n_frags = frags_from_cuts( cuts, 6UL, bb.len, frag_lens, 32UL );
  feed_frags( h, &sc, &v, bb.buf, frag_lens, n_frags );
  verify_done( &v );

  free( sc.ctx );
  visited_set_delete( visited_set_leave( vs ) );
  free( vs_mem );
  fake_index_delete( &idx );
  byte_buf_delete( &bb );

  FD_LOG_NOTICE(( "test_boundary_straddles: ok" ));
}

/* Scenario 3: random chopping with a mix of keep/drop reasons,
   repeated across several seeds; also exercises zp_ready backpressure. */

static void
test_random_mixed_keep_drop( harness_t * h,
                              ulong        rng_seed ) {
  ulong const acc_cnt = 300UL;
  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, (uint)rng_seed, 0UL ) );

  acc_kind_t kinds[300];
  ulong      data_lens[300];
  for( ulong i=0UL; i<acc_cnt; i++ ) {
    kinds[ i ]     = (acc_kind_t)( fd_rng_ulong( rng )%5UL );
    data_lens[ i ] = fd_rng_ulong( rng )%301UL; /* [0,300] */
  }

  byte_buf_t bb; byte_buf_new( &bb, acc_cnt*(sizeof(fd_accdb_disk_meta_t)+300UL)+16UL );
  fake_index_t idx; fake_index_new( &idx, acc_cnt, 0x9abcUL^rng_seed );
  gen_acc_t * accs = malloc( acc_cnt*sizeof(gen_acc_t) );
  FD_TEST( accs );
  gen_accounts( &bb, &idx, accs, acc_cnt, kinds, data_lens, 0U );

  ulong visited_max = fd_ulong_max( idx.pool_max, 64UL );
  void * vs_mem = aligned_alloc( visited_set_align(), visited_set_footprint( visited_max ) );
  FD_TEST( vs_mem );
  visited_set_t * vs = visited_set_join( visited_set_new( vs_mem, visited_max ) );
  visited_set_null( vs );

  scenario_t sc = {0};
  scenario_wire( &sc, h, &idx, vs, 0U );

  /* Exercise credit-blocked backpressure: with zp_ready cleared,
     snaprd_frag must return 1 without making progress; setting it
     resumes exactly where it left off. */
  {
    ulong chunk = h->in_chunk;
    ulong probe_len = fd_ulong_min( bb.len, 16UL );
    memcpy( fd_chunk_to_laddr( h->wksp, chunk ), bb.buf, probe_len );
    ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_DISK_FRAG, 0, 0, 0 );
    sc.ctx->zp_ready = 0UL;
    ulong before_seq = sc.stem.seqs[0];
    int more = snaprd_frag( sc.ctx, &sc.stem, sc.rd_seq, 0UL, chunk, ctl, probe_len );
    FD_TEST( more==1 );
    FD_TEST( sc.stem.seqs[0]==before_seq ); /* no progress while blocked */
    sc.ctx->zp_ready = 1UL;
    /* Re-wire cleanly and re-run the full scenario below (the probe
       above only checked the blocked/unblocked transition). */
  }
  scenario_wire( &sc, h, &idx, vs, 0U );
  visited_set_null( vs );

  verify_ctx_t v; verify_init( &v, accs, acc_cnt );

  ulong frag_lens[ 65536 ];
  ulong n_frags = frags_random( rng, bb.len, 1UL, 4096UL, frag_lens, 65536UL );
  feed_frags( h, &sc, &v, bb.buf, frag_lens, n_frags );
  verify_done( &v );

  free( sc.ctx );
  visited_set_delete( visited_set_leave( vs ) );
  free( vs_mem );
  fake_index_delete( &idx );
  free( accs );
  byte_buf_delete( &bb );

  FD_LOG_NOTICE(( "test_random_mixed_keep_drop(seed=%lu): ok", rng_seed ));
}

/* Scenario 4: one full-MTU frag packed with the maximum number of
   minimal (0-byte-data) accounts, forcing many full prestage batches. */

static void
test_full_mtu_max_tiny_accounts( harness_t * h ) {
  ulong const meta_sz = sizeof(fd_accdb_disk_meta_t);
  ulong const acc_cnt = FD_BACKUP_RD_MTU/meta_sz; /* all accounts are meta-only */
  FD_TEST( acc_cnt>4UL*FD_BACKUP_DISK_PARA ); /* forces several full 128-entry batches */

  acc_kind_t * kinds     = malloc( acc_cnt*sizeof(acc_kind_t) );
  ulong *      data_lens = malloc( acc_cnt*sizeof(ulong) );
  FD_TEST( kinds && data_lens );
  for( ulong i=0UL; i<acc_cnt; i++ ) { kinds[ i ] = ACC_KEEP; data_lens[ i ] = 0UL; }

  byte_buf_t bb; byte_buf_new( &bb, acc_cnt*meta_sz+16UL );
  fake_index_t idx; fake_index_new( &idx, acc_cnt, 0xdeadUL );
  gen_acc_t * accs = malloc( acc_cnt*sizeof(gen_acc_t) );
  FD_TEST( accs );
  gen_accounts( &bb, &idx, accs, acc_cnt, kinds, data_lens, 0U );
  FD_TEST( bb.len<=FD_BACKUP_RD_MTU );

  ulong visited_max = fd_ulong_max( idx.pool_max, 64UL );
  void * vs_mem = aligned_alloc( visited_set_align(), visited_set_footprint( visited_max ) );
  FD_TEST( vs_mem );
  visited_set_t * vs = visited_set_join( visited_set_new( vs_mem, visited_max ) );
  visited_set_null( vs );

  scenario_t sc = {0};
  scenario_wire( &sc, h, &idx, vs, 0U );

  verify_ctx_t v; verify_init( &v, accs, acc_cnt );

  ulong frag_lens[2] = { bb.len, 0UL };
  feed_frags( h, &sc, &v, bb.buf, frag_lens, 2UL );
  verify_done( &v );

  free( sc.ctx );
  visited_set_delete( visited_set_leave( vs ) );
  free( vs_mem );
  fake_index_delete( &idx );
  free( accs );
  free( kinds );
  free( data_lens );
  byte_buf_delete( &bb );

  FD_LOG_NOTICE(( "test_full_mtu_max_tiny_accounts(%lu accounts): ok", acc_cnt ));
}

/* Scenario 5: visited-set dedup, calling keep_inner/keep_batch
   directly for the same acc_idx twice. */

static void
test_visited_dedup( void ) {
  fake_index_t idx; fake_index_new( &idx, 4UL, 0xf00dUL );
  fd_pubkey_t pk; make_pubkey( &pk, 999UL );
  ulong file_off = 12345UL;
  uint acc_idx = fake_index_insert( &idx, &pk, 0U, 1UL, file_off );

  ulong visited_max = 16UL;
  void * vs_mem = aligned_alloc( visited_set_align(), visited_set_footprint( visited_max ) );
  FD_TEST( vs_mem );
  visited_set_t * vs = visited_set_join( visited_set_new( vs_mem, visited_max ) );
  visited_set_null( vs );

  ulong epoch = 1UL, epoch_slot = ULONG_MAX;
  fd_snapmk_accparse_t parse = {0};
  parse.acc_map         = idx.acc_map;
  parse.acc_pool        = idx.acc_pool;
  parse.visited_set     = vs;
  parse.max_accounts    = idx.pool_max;
  parse.acc_map_seed    = idx.seed;
  parse.chain_mask      = idx.chain_mask;
  parse.epoch_slot      = &epoch_slot;
  parse.epoch           = &epoch;
  parse.root_generation = 0U;
  parse.acc_file_off    = file_off;
  memcpy( parse.meta.pubkey, pk.uc, sizeof(fd_pubkey_t) );

  FD_TEST(  fd_snapmk_accparse_keep_inner( &parse ) );
  FD_TEST( !fd_snapmk_accparse_keep_inner( &parse ) ); /* dedup via visited_set */

  /* Defensive out-of-bounds guard: a chain head pointing past
     max_accounts (e.g. index corruption) must be rejected, not
     dereferenced. */
  {
    fd_pubkey_t pk2; make_pubkey( &pk2, 1000UL );
    ulong chain_idx2 = fd_accdb_hash( pk2.uc, idx.seed ) & idx.chain_mask;
    idx.acc_map[ chain_idx2 ] = (uint)idx.pool_max; /* out of [0,max_accounts) */
    memcpy( parse.meta.pubkey, pk2.uc, sizeof(fd_pubkey_t) );
    FD_TEST( !fd_snapmk_accparse_keep_inner( &parse ) );
  }

  visited_set_null( vs );
  /* fd_snapmk_accparse_keep_batch always writes FD_BACKUP_DISK_PARA
     entries to acc_idx (only the first cnt entries of file_off/hash
     are read), matching how ctx->disk_batch is sized in production. */
  ulong file_offs[ FD_BACKUP_DISK_PARA ] = { file_off };
  ulong hashes[ FD_BACKUP_DISK_PARA ]    = { fd_accdb_hash( pk.uc, idx.seed ) & idx.chain_mask };
  uint  acc_idxs[ FD_BACKUP_DISK_PARA ];
  fd_snapmk_accparse_keep_batch( &parse, file_offs, hashes, acc_idxs, 1UL );
  FD_TEST( acc_idxs[0]==acc_idx );
  fd_snapmk_accparse_keep_batch( &parse, file_offs, hashes, acc_idxs, 1UL );
  FD_TEST( acc_idxs[0]==UINT_MAX ); /* dedup via visited_set */

  visited_set_delete( visited_set_leave( vs ) );
  free( vs_mem );
  fake_index_delete( &idx );

  FD_LOG_NOTICE(( "test_visited_dedup: ok" ));
}

/* Scenario 6: throughput benchmark over a pinned wksp. */

static void
bench_prestage( harness_t * h ) {
  ulong const acc_cnt = 50000UL;
  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 7U, 0UL ) );

  acc_kind_t * kinds     = malloc( acc_cnt*sizeof(acc_kind_t) );
  ulong *      data_lens = malloc( acc_cnt*sizeof(ulong) );
  FD_TEST( kinds && data_lens );
  ulong total_data = 0UL;
  for( ulong i=0UL; i<acc_cnt; i++ ) {
    kinds[ i ]     = ACC_KEEP;
    data_lens[ i ] = 64UL + fd_rng_ulong( rng )%449UL; /* [64,512] */
    total_data    += data_lens[ i ];
  }

  byte_buf_t bb; byte_buf_new( &bb, total_data+acc_cnt*sizeof(fd_accdb_disk_meta_t)+16UL );
  fake_index_t idx; fake_index_new( &idx, acc_cnt, 0xb00bUL );
  gen_acc_t * accs = malloc( acc_cnt*sizeof(gen_acc_t) );
  FD_TEST( accs );
  gen_accounts( &bb, &idx, accs, acc_cnt, kinds, data_lens, 0U );

  ulong visited_max = fd_ulong_max( idx.pool_max, 64UL );
  void * vs_mem = aligned_alloc( visited_set_align(), visited_set_footprint( visited_max ) );
  FD_TEST( vs_mem );
  visited_set_t * vs = visited_set_join( visited_set_new( vs_mem, visited_max ) );
  visited_set_null( vs );

  scenario_t sc = {0};
  scenario_wire( &sc, h, &idx, vs, 0U );

  verify_ctx_t v; verify_init( &v, accs, acc_cnt );

  ulong frag_lens[ 4096 ];
  ulong n_frags = frags_fixed( bb.len, FD_BACKUP_RD_MTU, frag_lens, 4096UL );

  long t0 = fd_log_wallclock();
  feed_frags( h, &sc, &v, bb.buf, frag_lens, n_frags );
  long t1 = fd_log_wallclock();

  verify_done( &v );

  double ns_per_acc = (double)( t1-t0 )/(double)acc_cnt;
  double mb_per_sec  = ( (double)bb.len/(1024.0*1024.0) )/( (double)( t1-t0 )*1e-9 );
  FD_LOG_NOTICE(( "BENCH prestage: %.1f ns/acc (%lu accounts, %.1f MB/s)", ns_per_acc, acc_cnt, mb_per_sec ));

  free( sc.ctx );
  visited_set_delete( visited_set_leave( vs ) );
  free( vs_mem );
  fake_index_delete( &idx );
  free( accs );
  free( kinds );
  free( data_lens );
  byte_buf_delete( &bb );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  (void)privileged_init;
  (void)unprivileged_init;
  (void)populate_allowed_fds;
  (void)populate_allowed_seccomp;
  (void)snapmk_run;

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"               );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL                      );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t * wksp_bench = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp_bench", 0UL );
  FD_TEST( wksp_bench );
  harness_t hb;
  harness_new( &hb, wksp_bench );
  bench_prestage( &hb );
  fd_wksp_delete_anonymous( wksp_bench );

  harness_t h;
  harness_new( &h, fd_wksp_new_lazy( 128UL<<20 ) );

  test_degenerate_frags( &h );
  test_boundary_straddles( &h );
  test_random_mixed_keep_drop( &h, 1UL );
  test_random_mixed_keep_drop( &h, 2UL );
  test_random_mixed_keep_drop( &h, 3UL );
  test_full_mtu_max_tiny_accounts( &h );
  test_visited_dedup();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
