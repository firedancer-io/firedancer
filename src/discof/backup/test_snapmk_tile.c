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
  ulong mask = MAP_CNT-1UL;
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
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen );

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
  ulong mask = MAP_CNT-1UL;
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
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen );

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
  ulong mask = MAP_CNT-1UL;
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
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen );

  out_frag_t out[ MAX_OUT ];
  ulong out_cnt = feed_frag( parse, stream, 0UL, end, out, 0UL );
  FD_TEST( out_cnt==0UL );

  visited_set_null( visited );
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen );

  out_cnt = feed_frag( parse, stream, 0UL, end, out, 0UL );
  FD_TEST( out_cnt==1UL );
  FD_TEST( out[0].som && out[0].eom );
  FD_TEST( out[0].acc_idx==1U );
  FD_TEST( visited_set_test( visited, 1UL ) );

  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen );
  out_cnt = feed_frag( parse, stream, 0UL, end, out, 0UL );
  FD_TEST( out_cnt==0UL );
}

/* state keeps the disk-account state alive after credit. */
FD_UNIT_TEST( state ) {
  fd_snapmk_t ctx[1];
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
  ulong mask = MAP_CNT-1UL;
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
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen );
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
  ulong mask = MAP_CNT-1UL;
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
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen );
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
  ulong mask = MAP_CNT-1UL;
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
  fd_snapmk_accparse_reset( parse, map, pool, visited, POOL_CNT, seed, mask, root_gen );

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
