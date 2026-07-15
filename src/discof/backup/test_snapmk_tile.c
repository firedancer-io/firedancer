/* test_snapmk_tile.c tests snapmk tile disk-account parsing. */

#define _GNU_SOURCE

#define fd_tile_snapmk fd_tile_snapmk_test
#include "fd_snapmk_tile.c"
#undef fd_tile_snapmk

#include "../../util/fd_util.h"
#include "../../util/tmpl/fd_unit_test.c"

#define MAP_CNT 16UL
#define POOL_CNT 8UL
#define MAX_OUT 16UL

typedef struct {
  fd_frag_meta_t meta;
  ulong          sig;
  ulong          sz;
  uint           acc_idx;
  uint           snap_sz;
  uint           size;
  fd_pubkey_t    pubkey;
  fd_pubkey_t    owner;
  int            som;
  int            eom;
} out_frag_t;

static void
fill_key( fd_pubkey_t * key,
          uchar         seed ) {
  for( ulong i=0UL; i<sizeof(fd_pubkey_t); i++ ) key->uc[ i ] = (uchar)( seed + i );
}

static ulong
append_record( uchar *             buf,
               ulong               off,
               fd_pubkey_t const * pubkey,
               fd_pubkey_t const * owner,
               uint                size,
               uchar               data_seed ) {
  fd_accdb_disk_meta_t * meta = (fd_accdb_disk_meta_t *)( buf+off );
  memcpy( meta->pubkey, pubkey->uc, sizeof(fd_pubkey_t) );
  meta->size = size;
  memcpy( meta->owner, owner->uc, sizeof(fd_pubkey_t) );

  ulong data_sz = (ulong)FD_ACCDB_SIZE_DATA( size );
  for( ulong i=0UL; i<data_sz; i++ ) buf[ off+sizeof(fd_accdb_disk_meta_t)+i ] = (uchar)( data_seed+i );
  return off + sizeof(fd_accdb_disk_meta_t) + data_sz;
}

static void
insert_acc( uint *                map,
            fd_accdb_accmeta_t *  pool,
            ulong                 seed,
            ulong                 mask,
            uint                  acc_idx,
            fd_pubkey_t const *   pubkey,
            uint                  generation,
            ulong                 off ) {
  ulong hash = fd_accdb_hash( pubkey->uc, seed ) & mask;
  memcpy( pool[ acc_idx ].key.pubkey, pubkey->uc, sizeof(fd_pubkey_t) );
  pool[ acc_idx ].key.generation = generation;
  pool[ acc_idx ].map.next       = map[ hash ];
  pool[ acc_idx ].offset_fork    = off;
  map[ hash ] = acc_idx;
}

static visited_set_t *
new_visited_set( ulong max ) {
  void * mem = aligned_alloc( visited_set_align(), visited_set_footprint( max ) );
  FD_TEST( mem );
  visited_set_t * set = visited_set_join( visited_set_new( mem, max ) );
  FD_TEST( set );
  return set;
}

static ulong
collect_publish( fd_snapmk_accparse_t * parse,
                 out_frag_t *           out,
                 ulong                  out_cnt ) {
  for(;;) {
    FD_TEST( out_cnt<MAX_OUT );
    fd_frag_meta_t meta[1];
    if( !fd_snapmk_accparse_publish( parse, meta ) ) return out_cnt;

    out[ out_cnt ] = (out_frag_t) {
      .meta    = *meta,
      .sig     = meta->sig,
      .sz      = (ulong)meta->tspub,
      .acc_idx = parse->pub_acc_idx,
      .snap_sz = parse->pub_snap_sz,
      .size    = parse->pub_size,
      .pubkey  = parse->pub_pubkey,
      .owner   = parse->pub_owner,
      .som     = fd_frag_meta_ctl_som( meta->ctl ),
      .eom     = fd_frag_meta_ctl_eom( meta->ctl )
    };
    out_cnt++;
  }
}

static ulong
feed_frag( fd_snapmk_accparse_t * parse,
           uchar const *          base,
           ulong                  off,
           ulong                  sz,
           out_frag_t *           out,
           ulong                  out_cnt ) {
  fd_snapmk_accparse_insert( parse, base+off, sz, 0x100000UL+off, off );
  out_cnt = collect_publish( parse, out, out_cnt );
  parse->input_active = 0;
  return out_cnt;
}

static ulong
feed_frag_at( fd_snapmk_accparse_t * parse,
              uchar const *          data,
              ulong                  sz,
              ulong                  src_off,
              out_frag_t *           out,
              ulong                  out_cnt ) {
  fd_snapmk_accparse_insert( parse, data, sz, 0x100000UL+src_off, src_off );
  out_cnt = collect_publish( parse, out, out_cnt );
  parse->input_active = 0;
  return out_cnt;
}

/* split handles fragmented headers, skipped accounts, and large records. */
FD_UNIT_TEST( split ) {
  uint map[ MAP_CNT ];
  fd_accdb_accmeta_t pool[ POOL_CNT ];
  for( ulong i=0UL; i<MAP_CNT; i++ ) map[ i ] = UINT_MAX;
  memset( pool, 0, sizeof(pool) );
  for( ulong i=0UL; i<POOL_CNT; i++ ) pool[ i ].map.next = UINT_MAX;

  ulong seed = 0x1234UL;
  uint  mask = MAP_CNT-1U;
  uint  root_gen = 7U;

  fd_pubkey_t pk_a, pk_b, pk_c, pk_d, pk_e, owner_a, owner_b, owner_c, owner_d, owner_e;
  fill_key( &pk_a,    0x10 ); fill_key( &owner_a, 0x90 );
  fill_key( &pk_b,    0x20 ); fill_key( &owner_b, 0xa0 );
  fill_key( &pk_c,    0x30 ); fill_key( &owner_c, 0xb0 );
  fill_key( &pk_d,    0x40 ); fill_key( &owner_d, 0xc0 );
  fill_key( &pk_e,    0x50 ); fill_key( &owner_e, 0xd0 );

  uchar stream[ (2UL*FD_BACKUP_RD_MTU) + 512UL ];
  ulong off_a = 0UL;
  ulong off_b = append_record( stream, off_a, &pk_a, &owner_a, FD_ACCDB_SIZE_PACK( 5U, 1 ), 0x01 );
  ulong off_c = append_record( stream, off_b, &pk_b, &owner_b, FD_ACCDB_SIZE_PACK( 0U, 0 ), 0x11 );
  ulong off_d = append_record( stream, off_c, &pk_c, &owner_c, FD_ACCDB_SIZE_PACK( 4U, 0 ), 0x21 );
  ulong off_e = append_record( stream, off_d, &pk_d, &owner_d, FD_ACCDB_SIZE_PACK( 3U, 0 ), 0x31 );
  ulong end   = append_record( stream, off_e, &pk_e, &owner_e, FD_ACCDB_SIZE_PACK( (uint)(FD_BACKUP_RD_MTU+13UL), 0 ), 0x41 );

  insert_acc( map, pool, seed, mask, 1U, &pk_a, 5U, off_a );
  insert_acc( map, pool, seed, mask, 2U, &pk_b, 5U, off_b );
  insert_acc( map, pool, seed, mask, 3U, &pk_c, root_gen+1U, off_c ); /* skipped: too new */
  insert_acc( map, pool, seed, mask, 4U, &pk_d, 5U, off_d+1UL );      /* skipped: stale offset */
  insert_acc( map, pool, seed, mask, 5U, &pk_e, 5U, off_e );

  fd_snapmk_accparse_t parse[1];
  visited_set_t * visited = new_visited_set( POOL_CNT );
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen, 0UL, 1 );

  out_frag_t out[ MAX_OUT ];
  ulong out_cnt = 0UL;

  out_cnt = feed_frag( parse, stream, 0UL, 10UL, out, out_cnt );
  FD_TEST( out_cnt==0UL );

  out_cnt = feed_frag( parse, stream, 10UL, sizeof(fd_accdb_disk_meta_t)-10UL+2UL, out, out_cnt );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].som && !out[0].eom );
  FD_TEST( out[0].sz==2UL );
  FD_TEST( out[0].sig==0x100000UL+sizeof(fd_accdb_disk_meta_t) );
  FD_TEST( out[0].acc_idx==1U );
  FD_TEST( visited_set_test( visited, 1UL ) );
  FD_TEST( out[0].snap_sz==sizeof(snap_acc_hdr_t)+8UL );
  FD_TEST( !memcmp( out[0].pubkey.uc, pk_a.uc, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( out[0].owner .uc, owner_a.uc, sizeof(fd_pubkey_t) ) );

  out_cnt = feed_frag( parse, stream, sizeof(fd_accdb_disk_meta_t)+2UL, 3UL, out, out_cnt );
  FD_TEST( out_cnt==2UL );
  FD_TEST( !out[1].som && out[1].eom );
  FD_TEST( out[1].sz==3UL );
  FD_TEST( out[1].acc_idx==1U );

  out_cnt = feed_frag( parse, stream, off_b, off_e-off_b, out, out_cnt );
  FD_TEST( out_cnt==3UL );
  FD_TEST( out[2].som && out[2].eom );
  FD_TEST( out[2].sz==0UL ); /* zero-data control fragment */
  FD_TEST( out[2].sig==0UL );
  FD_TEST( out[2].acc_idx==2U );
  FD_TEST( visited_set_test( visited, 2UL ) );
  FD_TEST( out[2].snap_sz==sizeof(snap_acc_hdr_t) );
  FD_TEST( !memcmp( out[2].pubkey.uc, pk_b.uc, sizeof(fd_pubkey_t) ) );

  out_cnt = feed_frag( parse, stream, off_e, sizeof(fd_accdb_disk_meta_t)+10UL, out, out_cnt );
  FD_TEST( out_cnt==4UL );
  FD_TEST( out[3].som && !out[3].eom );
  FD_TEST( out[3].sz==10UL );
  FD_TEST( out[3].acc_idx==5U );
  FD_TEST( visited_set_test( visited, 5UL ) );
  FD_TEST( out[3].snap_sz==sizeof(snap_acc_hdr_t)+fd_ulong_align_up( FD_BACKUP_RD_MTU+13UL, 8UL ) );

  out_cnt = feed_frag( parse, stream, off_e+sizeof(fd_accdb_disk_meta_t)+10UL, FD_BACKUP_RD_MTU, out, out_cnt );
  FD_TEST( out_cnt==5UL );
  FD_TEST( !out[4].som && !out[4].eom );
  FD_TEST( out[4].sz==FD_BACKUP_RD_MTU );
  FD_TEST( out[4].meta.sz==0U );
  FD_TEST( out[4].meta.tspub==FD_BACKUP_RD_MTU );

  ulong final_off = off_e+sizeof(fd_accdb_disk_meta_t)+10UL+FD_BACKUP_RD_MTU;
  out_cnt = feed_frag( parse, stream, final_off, end-final_off, out, out_cnt );
  FD_TEST( out_cnt==6UL );
  FD_TEST( !out[5].som && out[5].eom );
  FD_TEST( out[5].sz==end-final_off );
  FD_TEST( out[5].acc_idx==5U );
}

/* offsets handles account partitions with non-contiguous file offsets. */
FD_UNIT_TEST( offsets ) {
  uint map[ MAP_CNT ];
  fd_accdb_accmeta_t pool[ POOL_CNT ];
  for( ulong i=0UL; i<MAP_CNT; i++ ) map[ i ] = UINT_MAX;
  memset( pool, 0, sizeof(pool) );
  for( ulong i=0UL; i<POOL_CNT; i++ ) pool[ i ].map.next = UINT_MAX;

  ulong seed = 0x1234UL;
  uint  mask = MAP_CNT-1U;
  uint  root_gen = 7U;

  fd_pubkey_t pk_a, pk_b, owner_a, owner_b;
  fill_key( &pk_a,    0x10 ); fill_key( &owner_a, 0x90 );
  fill_key( &pk_b,    0x20 ); fill_key( &owner_b, 0xa0 );

  uchar part_a[ 256UL ];
  uchar part_b[ 256UL ];
  ulong end_a = append_record( part_a, 0UL, &pk_a, &owner_a, FD_ACCDB_SIZE_PACK( 5U, 0 ), 0x01 );
  ulong end_b = append_record( part_b, 0UL, &pk_b, &owner_b, FD_ACCDB_SIZE_PACK( 6U, 0 ), 0x11 );

  ulong part_b_file_off = 4096UL;
  insert_acc( map, pool, seed, mask, 1U, &pk_a, 5U, 0UL             );
  insert_acc( map, pool, seed, mask, 2U, &pk_b, 5U, part_b_file_off );

  fd_snapmk_accparse_t parse[1];
  visited_set_t * visited = new_visited_set( POOL_CNT );
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen, 0UL, 1 );

  out_frag_t out[ MAX_OUT ];
  ulong out_cnt = 0UL;
  out_cnt = feed_frag_at( parse, part_a, end_a, 0UL,             out, out_cnt );
  out_cnt = feed_frag_at( parse, part_b, end_b, part_b_file_off, out, out_cnt );

  FD_TEST( out_cnt==2UL );
  FD_TEST( out[0].som && out[0].eom );
  FD_TEST( out[1].som && out[1].eom );
  FD_TEST( out[0].acc_idx==1U );
  FD_TEST( out[1].acc_idx==2U );
  FD_TEST( out[0].sig==0x100000UL+sizeof(fd_accdb_disk_meta_t) );
  FD_TEST( out[1].sig==0x100000UL+part_b_file_off+sizeof(fd_accdb_disk_meta_t) );
  FD_TEST( visited_set_test( visited, 1UL ) );
  FD_TEST( visited_set_test( visited, 2UL ) );
}

/* visited skips already published disk accounts. */
FD_UNIT_TEST( visited ) {
  uint map[ MAP_CNT ];
  fd_accdb_accmeta_t pool[ POOL_CNT ];
  for( ulong i=0UL; i<MAP_CNT; i++ ) map[ i ] = UINT_MAX;
  memset( pool, 0, sizeof(pool) );
  for( ulong i=0UL; i<POOL_CNT; i++ ) pool[ i ].map.next = UINT_MAX;

  ulong seed = 0x1234UL;
  uint  mask = MAP_CNT-1U;
  uint  root_gen = 7U;

  fd_pubkey_t pk_a, owner_a;
  fill_key( &pk_a,    0x10 );
  fill_key( &owner_a, 0x90 );

  uchar stream[ 256UL ];
  ulong off_a = 0UL;
  ulong end   = append_record( stream, off_a, &pk_a, &owner_a, FD_ACCDB_SIZE_PACK( 5U, 1 ), 0x01 );
  insert_acc( map, pool, seed, mask, 1U, &pk_a, 5U, off_a );

  visited_set_t * visited = new_visited_set( POOL_CNT );
  visited_set_insert( visited, 1UL );

  fd_snapmk_accparse_t parse[1];
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen, 0UL, 1 );

  out_frag_t out[ MAX_OUT ];
  ulong out_cnt = feed_frag( parse, stream, 0UL, end, out, 0UL );
  FD_TEST( out_cnt==0UL );

  visited_set_null( visited );
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen, 0UL, 1 );

  out_cnt = feed_frag( parse, stream, 0UL, end, out, 0UL );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].som && out[0].eom );
  FD_TEST( out[0].acc_idx==1U );
  FD_TEST( visited_set_test( visited, 1UL ) );

  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen, 0UL, 1 );
  out_cnt = feed_frag( parse, stream, 0UL, end, out, 0UL );
  FD_TEST( out_cnt==0UL );
}

/* incremental_filter checks the generation lower bound and tombstone
   gates used for incremental snapshot production. */
FD_UNIT_TEST( incremental_filter ) {
  uint map[ MAP_CNT ];
  fd_accdb_accmeta_t pool[ POOL_CNT ];
  for( ulong i=0UL; i<MAP_CNT; i++ ) map[ i ] = UINT_MAX;
  memset( pool, 0, sizeof(pool) );
  for( ulong i=0UL; i<POOL_CNT; i++ ) pool[ i ].map.next = UINT_MAX;

  ulong seed = 0x1234UL;
  uint  mask = MAP_CNT-1U;
  uint  root_gen = 7U;
  ulong min_gen  = 5UL;

  fd_pubkey_t pk_a, pk_b, pk_c, pk_d, owner;
  fill_key( &pk_a, 0x10 ); fill_key( &pk_b, 0x20 );
  fill_key( &pk_c, 0x30 ); fill_key( &pk_d, 0x40 );
  fill_key( &owner, 0x90 );

  uchar stream[ 512UL ];
  ulong off_a = 0UL;
  ulong off_b = append_record( stream, off_a, &pk_a, &owner, FD_ACCDB_SIZE_PACK( 5U, 0 ), 0x01 );
  ulong off_c = append_record( stream, off_b, &pk_b, &owner, FD_ACCDB_SIZE_PACK( 4U, 0 ), 0x11 );
  ulong off_d = append_record( stream, off_c, &pk_c, &owner, FD_ACCDB_SIZE_PACK( 3U, 0 ), 0x21 );
  ulong end   = append_record( stream, off_d, &pk_d, &owner, FD_ACCDB_SIZE_PACK( 0U, 0 ), 0x31 );

  insert_acc( map, pool, seed, mask, 1U, &pk_a, 4U, off_a ); /* below min_gen: skipped */
  insert_acc( map, pool, seed, mask, 2U, &pk_b, 5U, off_b ); /* at min_gen: kept */
  insert_acc( map, pool, seed, mask, 3U, &pk_c, 7U, off_c ); /* at root_gen: kept */
  insert_acc( map, pool, seed, mask, 4U, &pk_d, 6U, off_d ); /* tombstone (lamports=0) */
  pool[ 1 ].lamports = 100UL;
  pool[ 2 ].lamports = 100UL;
  pool[ 3 ].lamports = 100UL;

  fd_snapmk_accparse_t parse[1];
  visited_set_t * visited = new_visited_set( POOL_CNT );

  /* Incremental mode: min_gen filter active, tombstones kept. */
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen, min_gen, 1 );
  out_frag_t out[ MAX_OUT ];
  ulong out_cnt = feed_frag( parse, stream, 0UL, end, out, 0UL );
  FD_TEST( out_cnt==3UL );
  FD_TEST( out[0].acc_idx==2U );
  FD_TEST( out[1].acc_idx==3U );
  FD_TEST( out[2].acc_idx==4U );

  /* Full mode: no generation floor, tombstone skipped. */
  visited_set_null( visited );
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen, 0UL, 0 );
  out_cnt = feed_frag( parse, stream, 0UL, end, out, 0UL );
  FD_TEST( out_cnt==3UL );
  FD_TEST( out[0].acc_idx==1U );
  FD_TEST( out[1].acc_idx==2U );
  FD_TEST( out[2].acc_idx==3U );
}

/* incremental_filter_batch checks the same gates through the batched
   disk-scan path (fd_snapmk_accparse_keep_batch), which is the primary
   path in production. */
FD_UNIT_TEST( incremental_filter_batch ) {
  uint map[ MAP_CNT ];
  fd_accdb_accmeta_t pool[ POOL_CNT ];
  for( ulong i=0UL; i<MAP_CNT; i++ ) map[ i ] = UINT_MAX;
  memset( pool, 0, sizeof(pool) );
  for( ulong i=0UL; i<POOL_CNT; i++ ) pool[ i ].map.next = UINT_MAX;

  ulong seed = 0x1234UL;
  uint  mask = MAP_CNT-1U;
  uint  root_gen = 7U;
  ulong min_gen  = 5UL;

  fd_pubkey_t pk_a, pk_b, pk_c, pk_d, owner;
  fill_key( &pk_a, 0x10 ); fill_key( &pk_b, 0x20 );
  fill_key( &pk_c, 0x30 ); fill_key( &pk_d, 0x40 );
  fill_key( &owner, 0x90 );

  uchar stream[ 512UL ];
  ulong off_a = 0UL;
  ulong off_b = append_record( stream, off_a, &pk_a, &owner, FD_ACCDB_SIZE_PACK( 5U, 0 ), 0x01 );
  ulong off_c = append_record( stream, off_b, &pk_b, &owner, FD_ACCDB_SIZE_PACK( 4U, 0 ), 0x11 );
  ulong off_d = append_record( stream, off_c, &pk_c, &owner, FD_ACCDB_SIZE_PACK( 3U, 0 ), 0x21 );
  ulong end   = append_record( stream, off_d, &pk_d, &owner, FD_ACCDB_SIZE_PACK( 0U, 0 ), 0x31 );

  insert_acc( map, pool, seed, mask, 1U, &pk_a, 4U, off_a ); /* below min_gen: skipped */
  insert_acc( map, pool, seed, mask, 2U, &pk_b, 5U, off_b ); /* at min_gen: kept */
  insert_acc( map, pool, seed, mask, 3U, &pk_c, 7U, off_c ); /* at root_gen: kept */
  insert_acc( map, pool, seed, mask, 4U, &pk_d, 6U, off_d ); /* tombstone (lamports=0) */
  pool[ 1 ].lamports = 100UL;
  pool[ 2 ].lamports = 100UL;
  pool[ 3 ].lamports = 100UL;

  fd_snapmk_accparse_t parse[1];
  visited_set_t * visited = new_visited_set( POOL_CNT );

  /* Incremental mode: min_gen filter active, tombstones kept. */
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen, min_gen, 1 );
  fd_snapmk_accparse_insert( parse, stream, end, 0x100000UL, 0UL );

  fd_backup_disk_batch_msg_t batch[1];
  ulong base_gaddr = 0UL;
  ulong n = fd_snapmk_accparse_publish_batch( parse, batch, &base_gaddr );
  FD_TEST( n==4UL );
  FD_TEST( batch->acc_idx[ 0 ]==UINT_MAX ); /* below min_gen */
  FD_TEST( batch->acc_idx[ 1 ]==2U        );
  FD_TEST( batch->acc_idx[ 2 ]==3U        );
  FD_TEST( batch->acc_idx[ 3 ]==4U        ); /* tombstone kept */

  /* Full mode: no generation floor, tombstone skipped. */
  visited_set_null( visited );
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen, 0UL, 0 );
  fd_snapmk_accparse_insert( parse, stream, end, 0x100000UL, 0UL );

  n = fd_snapmk_accparse_publish_batch( parse, batch, &base_gaddr );
  FD_TEST( n==4UL );
  FD_TEST( batch->acc_idx[ 0 ]==1U        );
  FD_TEST( batch->acc_idx[ 1 ]==2U        );
  FD_TEST( batch->acc_idx[ 2 ]==3U        );
  FD_TEST( batch->acc_idx[ 3 ]==UINT_MAX ); /* tombstone skipped */
}

/* state keeps the disk-account state alive after credit. */
FD_UNIT_TEST( state ) {
  static fd_snapmk_t ctx[1];
  memset( ctx, 0, sizeof(fd_snapmk_t) );
  ctx->state = SNAPMK_STATE_ACCOUNTS_DISK;

  fd_stem_context_t stem[1];
  memset( stem, 0, sizeof(fd_stem_context_t) );

  int poll_in = 0;
  int charge_busy = 0;
  after_credit( ctx, stem, &poll_in, &charge_busy );

  FD_TEST( ctx->state==SNAPMK_STATE_ACCOUNTS_DISK );
  FD_TEST( !charge_busy );
}

FD_UNIT_TEST( idle_sleep_only_between_snapshots ) {
  fd_snapmk_t ctx[1];
  fd_stem_context_t stem[1];
  memset( ctx,  0, sizeof(fd_snapmk_t)       );
  memset( stem, 0, sizeof(fd_stem_context_t) );

  int charge_busy = 0;
  int is_backpressured = 0;

  ctx->state       = SNAPMK_STATE_TAR_HEADERS;
  ctx->in_idle_cnt = 16385UL;
  check_credit( ctx, stem, &charge_busy, &is_backpressured );
  FD_TEST( ctx->in_idle_cnt==0UL );

  ctx->state = SNAPMK_STATE_IDLE;
  check_credit( ctx, stem, &charge_busy, &is_backpressured );
  FD_TEST( ctx->in_idle_cnt==1UL );
}

FD_UNIT_TEST( snapshot_pool_slot_selection ) {
  static fd_snapmk_t ctx[1];
  memset( ctx, 0, sizeof(fd_snapmk_t) );
  ctx->full_slot_cnt = 2U;
  ctx->pool_cnt      = 7U;

  for( uint i=0U; i<ctx->full_slot_cnt; i++ ) {
    ctx->pool[ i ].full_slot = 100UL + (ulong)i;
    ctx->pool[ i ].incr_slot = ULONG_MAX;
    FD_TEST( fd_cstr_printf_check( ctx->pool[ i ].name, sizeof(ctx->pool[ i ].name), NULL,
                                  "snapshot-%lu-hash.tar.zst", ctx->pool[ i ].full_slot ) );
  }
  for( uint i=ctx->full_slot_cnt; i<ctx->pool_cnt; i++ ) {
    ctx->pool[ i ].full_slot = 100UL;
    ctx->pool[ i ].incr_slot = 190UL + (ulong)i;
    FD_TEST( fd_cstr_printf_check( ctx->pool[ i ].name, sizeof(ctx->pool[ i ].name), NULL,
                                  "incremental-snapshot-100-%lu-hash.tar.zst", ctx->pool[ i ].incr_slot ) );
  }

  /* The target already belongs to slot 5.  Select it even though slot 2
     is the oldest and slot 3 is free.  This avoids renaming a different
     inode over the existing target name. */
  fd_cstr_ncpy( ctx->final_name, ctx->pool[ 5 ].name, sizeof(ctx->final_name) );
  ctx->pool[ 3 ].full_slot = ULONG_MAX;
  ctx->pool[ 3 ].incr_slot = ULONG_MAX;
  FD_TEST( snap_select_slot( ctx, ctx->full_slot_cnt, ctx->pool_cnt, 1 )==5U );

  fd_cstr_ncpy( ctx->final_name, "incremental-snapshot-100-999-hash.tar.zst", sizeof(ctx->final_name) );
  FD_TEST( snap_select_slot( ctx, ctx->full_slot_cnt, ctx->pool_cnt, 1 )==3U ); /* free */

  ctx->pool[ 3 ].full_slot = 100UL;
  ctx->pool[ 3 ].incr_slot = 193UL;
  FD_TEST( snap_select_slot( ctx, ctx->full_slot_cnt, ctx->pool_cnt, 1 )==2U ); /* oldest */

  fd_cstr_ncpy( ctx->final_name, ctx->pool[ 1 ].name, sizeof(ctx->final_name) );
  FD_TEST( snap_select_slot( ctx, 0U, ctx->full_slot_cnt, 0 )==1U );
}

FD_UNIT_TEST( abort_recycles_published_incremental ) {
  char dir[] = "/tmp/fd_snapmk_abort_XXXXXX";
  FD_TEST( mkdtemp( dir ) );
  int dir_fd = open( dir, O_RDONLY|O_DIRECTORY );
  FD_TEST( dir_fd>=0 );

  char const * final_name = "incremental-snapshot-100-200-hash.tar.zst";
  int fd = openat( dir_fd, final_name, O_CREAT|O_EXCL|O_RDWR, 0600 );
  FD_TEST( fd>=0 );
  FD_TEST( write( fd, "partial snapshot bytes", 22UL )==22L );
  FD_TEST( dup2( fd, FD_BACKUP_POOL_FD( 0 ) )==FD_BACKUP_POOL_FD( 0 ) );
  FD_TEST( !close( fd ) );

  static fd_snapmk_t ctx[1];
  memset( ctx, 0, sizeof(ctx) );
  ctx->snap_dir_fd = dir_fd;
  ctx->pool_cnt    = 1U;
  fd_cstr_ncpy( ctx->pool[ 0 ].name, final_name, sizeof(ctx->pool[ 0 ].name) );
  ctx->pool[ 0 ].full_slot = 100UL;
  ctx->pool[ 0 ].incr_slot = 200UL;

  snap_abort_slot( ctx, 0U );

  char partial_name[ FD_BACKUP_POOL_PARTIAL_NAME_MAX ];
  fd_backup_pool_partial_name( partial_name, 0U );
  FD_TEST( !strcmp( ctx->pool[ 0 ].name, partial_name ) );
  FD_TEST( ctx->pool[ 0 ].full_slot==ULONG_MAX );
  FD_TEST( ctx->pool[ 0 ].incr_slot==ULONG_MAX );
  struct stat st[1];
  FD_TEST( !fstatat( dir_fd, partial_name, st, 0 ) );
  FD_TEST( st->st_size==0L );
  FD_TEST( fstatat( dir_fd, final_name, st, 0 ) && errno==ENOENT );

  FD_TEST( !close( FD_BACKUP_POOL_FD( 0 ) ) );
  FD_TEST( !unlinkat( dir_fd, partial_name, 0 ) );
  FD_TEST( !close( dir_fd ) );
  FD_TEST( !rmdir( dir ) );
}

/* flow_control uses consumer fseqs, not stale stem credits, for flush
   barriers. */
FD_UNIT_TEST( flow_control ) {
  static fd_snapmk_t ctx[1];
  memset( ctx, 0, sizeof(fd_snapmk_t) );
  ctx->zp_cnt = 2UL;

  ulong cons_seq[ 2 ] = { 200UL, 500UL };
  ctx->zp_cons_fseq[ 0 ] = &cons_seq[ 0 ];
  ctx->zp_cons_fseq[ 1 ] = &cons_seq[ 1 ];
  ctx->out_catchup_seq[ 0 ] = 200UL;
  ctx->out_catchup_seq[ 1 ] = 500UL;
  ctx->out_flush_seq  [ 0 ] = 201UL;
  ctx->out_flush_seq  [ 1 ] = 501UL;

  ulong seqs    [ 2 ] = { 200UL, 500UL };
  ulong depths  [ 2 ] = { 1024UL, 1024UL };
  ulong cr_avail[ 2 ] = { 0UL, 7UL }; /* deliberately stale */
  ulong min_cr_avail = 0UL;

  fd_stem_context_t stem[1];
  memset( stem, 0, sizeof(fd_stem_context_t) );
  stem->seqs         = seqs;
  stem->depths       = depths;
  stem->cr_avail     = cr_avail;
  stem->min_cr_avail = &min_cr_avail;

  int charge_busy = 0;
  int is_backpressured = 1;
  ctx->state = SNAPMK_STATE_ACCOUNTS_FLUSH1;
  check_credit( ctx, stem, &charge_busy, &is_backpressured );
  FD_TEST( !is_backpressured );
  FD_TEST( cr_avail[ 0 ]==1024UL );
  FD_TEST( cr_avail[ 1 ]==1024UL );

  cons_seq[ 1 ] = 499UL;
  is_backpressured = 0;
  check_credit( ctx, stem, &charge_busy, &is_backpressured );
  FD_TEST( is_backpressured );

  cons_seq[ 0 ] = 201UL;
  cons_seq[ 1 ] = 500UL;
  is_backpressured = 0;
  ctx->state = SNAPMK_STATE_ACCOUNTS_DRAIN;
  check_credit( ctx, stem, &charge_busy, &is_backpressured );
  FD_TEST( is_backpressured );

  cons_seq[ 1 ] = 501UL;
  is_backpressured = 1;
  check_credit( ctx, stem, &charge_busy, &is_backpressured );
  FD_TEST( !is_backpressured );
}

/* batch stages wholly-contained accounts and resolves their indices in
   bulk, applying the same keep predicate as the streaming path. */
FD_UNIT_TEST( batch ) {
  uint map[ MAP_CNT ];
  fd_accdb_accmeta_t pool[ POOL_CNT ];
  for( ulong i=0UL; i<MAP_CNT; i++ ) map[ i ] = UINT_MAX;
  memset( pool, 0, sizeof(pool) );
  for( ulong i=0UL; i<POOL_CNT; i++ ) pool[ i ].map.next = UINT_MAX;

  ulong seed = 0x1234UL;
  uint  mask = MAP_CNT-1U;
  uint  root_gen = 7U;

  fd_pubkey_t pk_a, pk_b, pk_c, pk_d, owner_a, owner_b, owner_c, owner_d;
  fill_key( &pk_a, 0x10 ); fill_key( &owner_a, 0x90 );
  fill_key( &pk_b, 0x20 ); fill_key( &owner_b, 0xa0 );
  fill_key( &pk_c, 0x30 ); fill_key( &owner_c, 0xb0 );
  fill_key( &pk_d, 0x40 ); fill_key( &owner_d, 0xc0 );

  uchar stream[ 1024UL ];
  ulong off_a = 0UL;
  ulong off_b = append_record( stream, off_a, &pk_a, &owner_a, FD_ACCDB_SIZE_PACK( 5U, 1 ), 0x01 );
  ulong off_c = append_record( stream, off_b, &pk_b, &owner_b, FD_ACCDB_SIZE_PACK( 0U, 0 ), 0x11 );
  ulong off_d = append_record( stream, off_c, &pk_c, &owner_c, FD_ACCDB_SIZE_PACK( 4U, 0 ), 0x21 );
  ulong end   = append_record( stream, off_d, &pk_d, &owner_d, FD_ACCDB_SIZE_PACK( 3U, 0 ), 0x31 );

  insert_acc( map, pool, seed, mask, 1U, &pk_a, 5U,          off_a      );
  insert_acc( map, pool, seed, mask, 2U, &pk_b, 5U,          off_b      );
  insert_acc( map, pool, seed, mask, 3U, &pk_c, root_gen+1U, off_c      ); /* skipped: too new */
  insert_acc( map, pool, seed, mask, 4U, &pk_d, 5U,          off_d+1UL  ); /* skipped: stale offset */

  fd_snapmk_accparse_t parse[1];
  visited_set_t * visited = new_visited_set( POOL_CNT );
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen, 0UL, 1 );
  fd_snapmk_accparse_insert( parse, stream, end, 0x100000UL, 0UL );

  fd_backup_disk_batch_msg_t batch[1];
  ulong base_gaddr = 0UL;
  ulong n = fd_snapmk_accparse_publish_batch( parse, batch, &base_gaddr );
  FD_TEST( n==4UL );
  FD_TEST( base_gaddr==0x100000UL );

  FD_TEST( batch->acc_idx[ 0 ]==1U       );
  FD_TEST( batch->acc_idx[ 1 ]==2U       );
  FD_TEST( batch->acc_idx[ 2 ]==UINT_MAX );
  FD_TEST( batch->acc_idx[ 3 ]==UINT_MAX );

  FD_TEST( batch->frag_off[ 0 ]==(uint)off_a );
  FD_TEST( batch->frag_off[ 1 ]==(uint)off_b );
  FD_TEST( batch->frag_off[ 2 ]==(uint)off_c );
  FD_TEST( batch->frag_off[ 3 ]==(uint)off_d );

  FD_TEST( !memcmp( batch->pubkey[ 0 ].uc, pk_a.uc, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( batch->pubkey[ 1 ].uc, pk_b.uc, sizeof(fd_pubkey_t) ) );

  FD_TEST(  visited_set_test( visited, 1UL ) );
  FD_TEST(  visited_set_test( visited, 2UL ) );
  FD_TEST( !visited_set_test( visited, 3UL ) );
  FD_TEST( !visited_set_test( visited, 4UL ) );

  /* fully consumed: no more batches */
  FD_TEST( fd_snapmk_accparse_publish_batch( parse, batch, &base_gaddr )==0UL );
}

FD_UNIT_TEST( batch_large_frag_offset ) {
  uint map[ MAP_CNT ];
  fd_accdb_accmeta_t pool[ POOL_CNT ];
  for( ulong i=0UL; i<MAP_CNT; i++ ) map[ i ] = UINT_MAX;
  memset( pool, 0, sizeof(pool) );
  for( ulong i=0UL; i<POOL_CNT; i++ ) pool[ i ].map.next = UINT_MAX;

  ulong seed = 4321UL;
  uint  mask = MAP_CNT-1U;
  uint  root_gen = 7U;

  fd_pubkey_t pk_a, owner_a;
  fill_key( &pk_a, 0xa1 );
  fill_key( &owner_a, 0xb1 );

  static uchar stream[ 80000UL ];
  memset( stream, 0, sizeof(stream) );
  ulong off_a = 70000UL;
  ulong end   = append_record( stream, off_a, &pk_a, &owner_a, FD_ACCDB_SIZE_PACK( 5U, 0 ), 0x01 );
  insert_acc( map, pool, seed, mask, 1U, &pk_a, root_gen, off_a );

  fd_snapmk_accparse_t parse[1];
  visited_set_t * visited = new_visited_set( POOL_CNT );
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen, 0UL, 1 );
  fd_snapmk_accparse_insert( parse, stream+off_a, end-off_a, 0x100000UL+off_a, off_a );
  parse->frag_base_gaddr = 0x100000UL;

  fd_backup_disk_batch_msg_t batch[1];
  ulong base_gaddr = 0UL;
  ulong n = fd_snapmk_accparse_publish_batch( parse, batch, &base_gaddr );
  FD_TEST( n==1UL );
  FD_TEST( base_gaddr==0x100000UL );
  FD_TEST( batch->acc_idx [ 0 ]==1U );
  FD_TEST( batch->frag_off[ 0 ]==(uint)off_a );
}

/* batch_straddle stops the batch at the account whose data crosses the
   frag boundary and leaves it for the streaming single-account path. */
FD_UNIT_TEST( batch_straddle ) {
  uint map[ MAP_CNT ];
  fd_accdb_accmeta_t pool[ POOL_CNT ];
  for( ulong i=0UL; i<MAP_CNT; i++ ) map[ i ] = UINT_MAX;
  memset( pool, 0, sizeof(pool) );
  for( ulong i=0UL; i<POOL_CNT; i++ ) pool[ i ].map.next = UINT_MAX;

  ulong seed = 0x1234UL;
  uint  mask = MAP_CNT-1U;
  uint  root_gen = 7U;

  fd_pubkey_t pk_a, pk_b, pk_c, owner_a, owner_b, owner_c;
  fill_key( &pk_a, 0x10 ); fill_key( &owner_a, 0x90 );
  fill_key( &pk_b, 0x20 ); fill_key( &owner_b, 0xa0 );
  fill_key( &pk_c, 0x30 ); fill_key( &owner_c, 0xb0 );

  uchar stream[ 1024UL ];
  ulong off_a = 0UL;
  ulong off_b = append_record( stream, off_a, &pk_a, &owner_a, FD_ACCDB_SIZE_PACK( 5U, 0 ), 0x01 );
  ulong off_c = append_record( stream, off_b, &pk_b, &owner_b, FD_ACCDB_SIZE_PACK( 0U, 0 ), 0x11 );
  ulong end   = append_record( stream, off_c, &pk_c, &owner_c, FD_ACCDB_SIZE_PACK( 100U, 0 ), 0x21 );

  insert_acc( map, pool, seed, mask, 1U, &pk_a, 5U, off_a );
  insert_acc( map, pool, seed, mask, 2U, &pk_b, 5U, off_b );
  insert_acc( map, pool, seed, mask, 3U, &pk_c, 5U, off_c );

  fd_snapmk_accparse_t parse[1];
  visited_set_t * visited = new_visited_set( POOL_CNT );
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen, 0UL, 1 );

  /* frag only covers acc_c's meta + 40 of its 100 data bytes */
  ulong frag_sz = off_c + sizeof(fd_accdb_disk_meta_t) + 40UL;
  FD_TEST( frag_sz < end );
  fd_snapmk_accparse_insert( parse, stream, frag_sz, 0x100000UL, 0UL );

  fd_backup_disk_batch_msg_t batch[1];
  ulong base_gaddr = 0UL;
  ulong n = fd_snapmk_accparse_publish_batch( parse, batch, &base_gaddr );
  FD_TEST( n==2UL );
  FD_TEST( batch->acc_idx[ 0 ]==1U );
  FD_TEST( batch->acc_idx[ 1 ]==2U );

  /* the straddling acc_c is handled by the streaming path */
  fd_frag_meta_t meta[1];
  FD_TEST( fd_snapmk_accparse_publish( parse, meta ) );
  FD_TEST(  fd_frag_meta_ctl_som( meta->ctl ) );
  FD_TEST( !fd_frag_meta_ctl_eom( meta->ctl ) );
  FD_TEST( (ulong)meta->tspub==40UL );
  FD_TEST( parse->pub_acc_idx==3U );
}

static int
new_tmp_fd( char * path,
            ulong  path_sz ) {
  static char const tmpl[] = "/tmp/test_snapmk_tile_zstd_XXXXXX";
  FD_TEST( path_sz>=sizeof(tmpl) );
  memcpy( path, tmpl, sizeof(tmpl) );
  int fd = mkstemp( path );
  FD_TEST( fd>=0 );
  return fd;
}

static fd_snapmk_t *
new_snapmk_writer( int              fd,
                   ulong volatile * file_off,
                   void **          zstd_mem ) {
  ulong ctx_mem_sz = fd_ulong_align_up( sizeof(fd_snapmk_t), alignof(fd_snapmk_t) );
  fd_snapmk_t * ctx = aligned_alloc( alignof(fd_snapmk_t), ctx_mem_sz );
  FD_TEST( ctx );
  memset( ctx, 0, sizeof(fd_snapmk_t) );

  ulong zstd_mem_sz = fd_ulong_align_up( ZSTD_estimateCStreamSize( FD_ZSTD_LEVEL ), 32UL );
  *zstd_mem = aligned_alloc( 32UL, zstd_mem_sz );
  FD_TEST( *zstd_mem );

  ctx->zst = ZSTD_initStaticCStream( *zstd_mem, zstd_mem_sz );
  FD_TEST( ctx->zst );
  ulong zst_err = ZSTD_CCtx_setParameter( ctx->zst, ZSTD_c_compressionLevel, FD_ZSTD_LEVEL );
  FD_TEST( !ZSTD_isError( zst_err ) );

  ctx->out_fd      = fd;
  ctx->zp_file_off = file_off;
  ctx->raw_buf     = (ZSTD_inBuffer ){ .src = ctx->raw,  .size = 0UL,         .pos = 0UL };
  ctx->comp_buf    = (ZSTD_outBuffer){ .dst = ctx->comp, .size = COMP_BUF_SZ, .pos = 0UL };
  return ctx;
}

static void
snapmk_write_raw( fd_snapmk_t *     ctx,
                  void const *      data,
                  ulong             data_sz,
                  ZSTD_EndDirective directive ) {
  FD_TEST( data_sz<=RAW_BUF_SZ );
  FD_TEST( !ctx->raw_buf.pos  );
  FD_TEST( !ctx->raw_buf.size );
  memcpy( ctx->raw, data, data_sz );
  ctx->raw_buf.size = data_sz;
  flush_buffer( ctx, directive );
  FD_TEST( !ctx->raw_buf.pos  );
  FD_TEST( !ctx->raw_buf.size );
}

static void
write_skippable_frame( int   fd,
                       ulong frame_sz ) {
  FD_TEST( frame_sz>=8UL );
  FD_TEST( frame_sz-8UL<=UINT_MAX );

  uchar hdr[ 8 ];
  FD_STORE( uint, hdr,   ZSTD_MAGIC_SKIPPABLE_START );
  FD_STORE( uint, hdr+4, (uint)( frame_sz-8UL ) );

  long wr = write( fd, hdr, sizeof(hdr) );
  FD_TEST( wr==(long)sizeof(hdr) );

  static uchar const zero[ 4096UL ] = {0};
  for( ulong rem=frame_sz-8UL; rem; ) {
    ulong chunk = fd_ulong_min( rem, sizeof(zero) );
    wr = write( fd, zero, chunk );
    FD_TEST( wr==(long)chunk );
    rem -= chunk;
  }
}

static ulong
read_fd_all( int      fd,
             uchar ** out ) {
  long file_sz = lseek( fd, 0L, SEEK_END );
  FD_TEST( file_sz>=0L );
  FD_TEST( lseek( fd, 0L, SEEK_SET )==0L );

  uchar * buf = malloc( (ulong)file_sz );
  FD_TEST( buf || !file_sz );
  for( ulong off=0UL; off<(ulong)file_sz; ) {
    long rd = read( fd, buf+off, (ulong)file_sz-off );
    FD_TEST( rd>0L );
    off += (ulong)rd;
  }

  *out = buf;
  return (ulong)file_sz;
}

static ulong
zstd_decompress_all( uchar const * comp,
                     ulong         comp_sz,
                     uchar *       out,
                     ulong         out_cap ) {
  ZSTD_DCtx * dctx = ZSTD_createDCtx();
  FD_TEST( dctx );

  ZSTD_inBuffer  in  = { .src = comp, .size = comp_sz, .pos = 0UL };
  ZSTD_outBuffer dec = { .dst = out,  .size = out_cap, .pos = 0UL };
  ulong last_ret = 0UL;
  while( in.pos<in.size ) {
    ulong old_in  = in .pos;
    ulong old_out = dec.pos;
    last_ret = ZSTD_decompressStream( dctx, &dec, &in );
    FD_TEST( !ZSTD_isError( last_ret ) );
    FD_TEST( in.pos>old_in || dec.pos>old_out || !last_ret );
  }
  FD_TEST( !last_ret );

  FD_TEST( ZSTD_freeDCtx( dctx )==0UL );
  return dec.pos;
}

static void
verify_zstd_file( int           fd,
                  uchar const * expected,
                  ulong         expected_sz ) {
  uchar * comp = NULL;
  ulong comp_sz = read_fd_all( fd, &comp );
  FD_TEST( comp_sz );

  uchar * dec = malloc( expected_sz );
  FD_TEST( dec || !expected_sz );
  ulong dec_sz = zstd_decompress_all( comp, comp_sz, dec, expected_sz );
  FD_TEST( dec_sz==expected_sz );
  FD_TEST( !memcmp( dec, expected, expected_sz ) );

  free( dec );
  free( comp );
}

/* zstd_roundtrip verifies that snapmk's compressed byte stream is a valid
   concatenation of zstd frames, including an align_stream skippable frame. */
FD_UNIT_TEST( zstd_roundtrip ) {
  char path[ sizeof("/tmp/test_snapmk_tile_zstd_XXXXXX") ];
  int fd = new_tmp_fd( path, sizeof(path) );

  ulong volatile file_off = ULONG_MAX;
  void * zstd_mem = NULL;
  fd_snapmk_t * ctx = new_snapmk_writer( fd, &file_off, &zstd_mem );

  static uchar const part0[] = "snapmk zstd frame 0: header bytes\n";
  static uchar const part1[] = "snapmk zstd frame 0: payload bytes\n";
  static uchar const part2[] = "snapmk zstd frame 1: after skippable alignment\n";

  snapmk_write_raw( ctx, part0, sizeof(part0)-1UL, ZSTD_e_continue );
  snapmk_write_raw( ctx, part1, sizeof(part1)-1UL, ZSTD_e_end      );

  long off_before = lseek( fd, 0L, SEEK_CUR );
  FD_TEST( off_before>0L );
  ulong pad_sz = fd_ulong_align_up( (ulong)off_before, 4096UL ) - (ulong)off_before;
  FD_TEST( pad_sz>8UL );

  align_stream( ctx );
  long off_after = lseek( fd, 0L, SEEK_CUR );
  FD_TEST( off_after>off_before );
  FD_TEST( fd_ulong_is_aligned( (ulong)off_after, 4096UL ) );
  FD_TEST( file_off==(ulong)off_after );

  snapmk_write_raw( ctx, part2, sizeof(part2)-1UL, ZSTD_e_end );

  uchar expected[ (sizeof(part0)-1UL) + (sizeof(part1)-1UL) + (sizeof(part2)-1UL) ];
  uchar * p = expected;
  memcpy( p, part0, sizeof(part0)-1UL ); p += sizeof(part0)-1UL;
  memcpy( p, part1, sizeof(part1)-1UL ); p += sizeof(part1)-1UL;
  memcpy( p, part2, sizeof(part2)-1UL ); p += sizeof(part2)-1UL;
  FD_TEST( p==expected+sizeof(expected) );
  verify_zstd_file( fd, expected, sizeof(expected) );

  FD_TEST( close( fd )==0 );
  FD_TEST( unlink( path )==0 );
  free( zstd_mem );
  free( ctx );
}

/* zstd_short_pad forces align_stream's pad_sz<8 branch */
FD_UNIT_TEST( zstd_short_pad ) {
  char path[ sizeof("/tmp/test_snapmk_tile_zstd_XXXXXX") ];
  int fd = new_tmp_fd( path, sizeof(path) );

  ulong volatile file_off = ULONG_MAX;
  void * zstd_mem = NULL;
  fd_snapmk_t * ctx = new_snapmk_writer( fd, &file_off, &zstd_mem );

  write_skippable_frame( fd, 4091UL );
  FD_TEST( lseek( fd, 0L, SEEK_CUR )==4091L );

  align_stream( ctx );
  long off_after = lseek( fd, 0L, SEEK_CUR );
  FD_TEST( off_after==8192L );
  FD_TEST( file_off==8192UL );

  static uchar const payload[] = "snapmk zstd frame after short padding\n";
  snapmk_write_raw( ctx, payload, sizeof(payload)-1UL, ZSTD_e_end );
  verify_zstd_file( fd, payload, sizeof(payload)-1UL );

  FD_TEST( close( fd )==0 );
  FD_TEST( unlink( path )==0 );
  free( zstd_mem );
  free( ctx );
}

/* release exercises the snaprd shadow-ring watermark, in particular the
   caught-up (no-floor) deadlock guard. */
FD_UNIT_TEST( release ) {
  static fd_snapmk_t ctx[1];
  memset( ctx, 0, sizeof(fd_snapmk_t) );
  ctx->zp_cnt = 2UL;

  ulong shadow0[ 8 ], shadow1[ 8 ];
  ctx->rd_shadow[ 0 ] = shadow0; ctx->zp_depth[ 0 ] = 8UL;
  ctx->rd_shadow[ 1 ] = shadow1; ctx->zp_depth[ 1 ] = 8UL;

  ulong relfseq = 0UL;
  ctx->snaprd_release_fseq = &relfseq;
  ctx->snaprd_release_seq  = ULONG_MAX;
  ctx->snaprd_parse_seq    = 10UL;

  ulong cons0 = 0UL, cons1 = 0UL;
  ctx->zp_cons_fseq[ 0 ] = &cons0;
  ctx->zp_cons_fseq[ 1 ] = &cons1;

  ulong seqs[ 2 ] = { 0UL, 0UL };
  fd_stem_context_t stem[1];
  memset( stem, 0, sizeof(fd_stem_context_t) );
  stem->seqs = seqs;

  /* both tiles caught up -> release clamps to parse cursor */
  snapmk_update_release( ctx, stem );
  FD_TEST( relfseq==10UL );

  /* tile 0 lags: oldest unconsumed frag (cons=1) references snaprd seq 4 */
  seqs[ 0 ] = 3UL; cons0 = 1UL; shadow0[ 1 ] = 4UL;
  seqs[ 1 ] = 2UL; cons1 = 2UL; /* tile 1 caught up */
  snapmk_update_release( ctx, stem );
  FD_TEST( relfseq==4UL );

  /* tile 1 now also lags referencing an older seq 2 -> min wins */
  cons1 = 0UL; shadow1[ 0 ] = 2UL;
  snapmk_update_release( ctx, stem );
  FD_TEST( relfseq==2UL );

  /* both caught up again: watermark jumps forward to the parse cursor
     instead of staying pinned (the deadlock guard) */
  cons0 = 3UL; cons1 = 2UL;
  snapmk_update_release( ctx, stem );
  FD_TEST( relfseq==10UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_unit_tests( argc, argv );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
