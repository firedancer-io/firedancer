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
      .sz      = (ulong)meta->sz + 1UL,
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
  FD_TEST( out[2].sz==1UL ); /* zero-data control fragment */
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
  FD_TEST( out[4].meta.sz==USHORT_MAX );

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

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_unit_tests( argc, argv );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
