/* test_backup_disk.c exercises fd_snapmk_accparse_lookup, the accdb
   index lookup that decides which on-disk account records make it into
   a snapshot.  Drives it against a hand-built acc_map/acc_pool rather
   than a live accdb, so chain shapes and stale versions that are hard
   to provoke in situ can be set up directly. */

#include "fd_backup_disk.h"

#define MAX_ACCOUNTS  256UL
#define CHAIN_CNT      64UL /* power of 2 */
#define ROOT_GEN       10U

FD_STATIC_ASSERT( MAX_ACCOUNTS>FD_BACKUP_DISK_PARA, need_a_full_batch );

static uint               acc_map [ CHAIN_CNT    ];
static fd_accdb_accmeta_t acc_pool[ MAX_ACCOUNTS ];

static uchar visited_mem[ 4096 ] __attribute__((aligned(128)));

static fd_snapmk_accparse_t parse[1];

/* env_reset clears the index and the visited set.  Every case starts
   from a clean slate so a leftover visited bit cannot mask a bug. */

static void
env_reset( void ) {
  for( ulong i=0UL; i<CHAIN_CNT; i++ ) acc_map[ i ] = UINT_MAX;
  memset( acc_pool, 0, sizeof(acc_pool) );

  visited_set_t * visited = visited_set_join( visited_set_new( visited_mem, MAX_ACCOUNTS ) );
  FD_TEST( visited );
  visited_set_null( visited );

  parse->visited_set = visited;
}

/* pubkey_n returns a distinct address for n. */

static uchar const *
pubkey_n( ulong n ) {
  static uchar pk[ 32 ];
  memset( pk, 0, sizeof(pk) );
  pk[ 0 ] = (uchar)  n;
  pk[ 1 ] = (uchar)( n>>8 );
  pk[ 2 ] = 0xa5;
  return pk;
}

/* index_add prepends an index entry onto chain, describing an account
   version stored at file_off.  Returns the pool index. */

static uint
index_add( uint          ele,
           ulong         chain,
           uchar const * pubkey,
           uint          generation,
           ulong         lamports,
           ulong         file_off ) {
  FD_TEST( (ulong)ele<MAX_ACCOUNTS );
  FD_TEST( chain<CHAIN_CNT         );

  fd_accdb_accmeta_t * m = &acc_pool[ ele ];
  memcpy( m->key.pubkey, pubkey, 32UL );
  m->key.generation = generation;
  m->lamports       = lamports;
  /* nonzero fork_id so a lookup that forgets FD_ACCDB_OFF_MASK fails */
  m->offset_fork    = fd_accdb_acc_pack_offset_fork( file_off, 0x1234 );

  m->map.next   = acc_map[ chain ];
  acc_map[ chain ] = ele;
  return ele;
}

/* lookup1 resolves a single record and returns the index entry that
   claimed it, or UINT_MAX. */

static uint
lookup1( ulong chain,
         ulong file_off ) {
  uint acc_idx[ 2 ] = { 0xdeadbeefU, 0xfeedfaceU };
  fd_snapmk_accparse_lookup( parse, &chain, &file_off, acc_idx, 1UL );
  FD_TEST( acc_idx[ 1 ]==0xfeedfaceU ); /* must not write past cnt */
  return acc_idx[ 0 ];
}

static void
test_single_hop( void ) {
  env_reset();
  uint ele = index_add( 7U, 3UL, pubkey_n( 1UL ), 5U, 1000UL, 0x1000UL );
  FD_TEST( lookup1( 3UL, 0x1000UL )==ele );
}

static void
test_multi_hop( void ) {
  env_reset();
  /* three versions of unrelated accounts ahead of the one we want */
  uint want = index_add( 1U, 0UL, pubkey_n( 1UL ), 5U, 1000UL, 0x1000UL );
              index_add( 2U, 0UL, pubkey_n( 2UL ), 5U, 1000UL, 0x2000UL );
              index_add( 3U, 0UL, pubkey_n( 3UL ), 5U, 1000UL, 0x3000UL );
  FD_TEST( lookup1( 0UL, 0x1000UL )==want ); /* walks to the chain tail */
}

static void
test_collision_resolved_by_offset( void ) {
  env_reset();
  /* Two different accounts sharing a chain.  The lookup compares only
     the file offset, so each record must still find its own entry. */
  uint a = index_add( 4U, 9UL, pubkey_n( 10UL ), 5U, 1000UL, 0x4000UL );
  uint b = index_add( 5U, 9UL, pubkey_n( 11UL ), 5U, 1000UL, 0x5000UL );
  FD_TEST( lookup1( 9UL, 0x4000UL )==a );
  env_reset();
  index_add( 4U, 9UL, pubkey_n( 10UL ), 5U, 1000UL, 0x4000UL );
  b = index_add( 5U, 9UL, pubkey_n( 11UL ), 5U, 1000UL, 0x5000UL );
  FD_TEST( lookup1( 9UL, 0x5000UL )==b );
}

static void
test_superseded_version( void ) {
  env_reset();
  /* The index points at 0x6000; the record we parsed at 0x1000 is an
     older copy still on disk and must not be emitted. */
  index_add( 6U, 2UL, pubkey_n( 20UL ), 5U, 1000UL, 0x6000UL );
  FD_TEST( lookup1( 2UL, 0x1000UL )==UINT_MAX );
}

static void
test_generation_above_root( void ) {
  env_reset();
  index_add( 8U, 1UL, pubkey_n( 30UL ), ROOT_GEN+1U, 1000UL, 0x7000UL );
  FD_TEST( lookup1( 1UL, 0x7000UL )==UINT_MAX );

  /* exactly at the root generation is in */
  env_reset();
  uint ele = index_add( 8U, 1UL, pubkey_n( 30UL ), ROOT_GEN, 1000UL, 0x7000UL );
  FD_TEST( lookup1( 1UL, 0x7000UL )==ele );
}

static void
test_tombstone( void ) {
  env_reset();
  index_add( 9U, 4UL, pubkey_n( 40UL ), 5U, 0UL, 0x8000UL );
  FD_TEST( lookup1( 4UL, 0x8000UL )==UINT_MAX );
}

static void
test_empty_chain( void ) {
  env_reset();
  FD_TEST( lookup1( 11UL, 0x9000UL )==UINT_MAX );
}

static void
test_visited_dedup( void ) {
  env_reset();
  uint ele = index_add( 12U, 5UL, pubkey_n( 50UL ), 5U, 1000UL, 0xa000UL );
  FD_TEST( lookup1( 5UL, 0xa000UL )==ele      ); /* first sighting wins */
  FD_TEST( lookup1( 5UL, 0xa000UL )==UINT_MAX ); /* second is dropped */
}

/* A batch resolves every lane independently and agrees with resolving
   the same records one at a time. */

static void
test_full_batch( void ) {
  ulong chain   [ FD_BACKUP_DISK_PARA ];
  ulong file_off[ FD_BACKUP_DISK_PARA ];
  uint  expected[ FD_BACKUP_DISK_PARA ];
  uint  batched [ FD_BACKUP_DISK_PARA ];

  env_reset();
  for( ulong i=0UL; i<FD_BACKUP_DISK_PARA; i++ ) {
    chain   [ i ] = i & (CHAIN_CNT-1UL); /* 2 records per chain */
    file_off[ i ] = 0x10000UL + i*0x100UL;

    /* every 5th record is stale (index points elsewhere), every 7th is
       a tombstone, every 11th is unrooted */
    ulong off_in_index = ( i%5UL==4UL ) ? 0xdead0000UL+i : file_off[ i ];
    ulong lamports     = ( i%7UL==6UL ) ? 0UL            : 1000UL;
    uint  generation   = ( i%11UL==10UL ) ? ROOT_GEN+3U  : 5U;

    uint ele = index_add( (uint)i, chain[ i ], pubkey_n( 100UL+i ),
                          generation, lamports, off_in_index );
    int  keep = ( off_in_index==file_off[ i ] ) & ( lamports!=0UL ) & ( generation<=ROOT_GEN );
    expected[ i ] = keep ? ele : UINT_MAX;
  }

  /* one at a time */
  for( ulong i=0UL; i<FD_BACKUP_DISK_PARA; i++ ) {
    FD_TEST( lookup1( chain[ i ], file_off[ i ] )==expected[ i ] );
  }

  /* same records, one batch, fresh visited set */
  visited_set_null( parse->visited_set );
  fd_snapmk_accparse_lookup( parse, chain, file_off, batched, FD_BACKUP_DISK_PARA );
  for( ulong i=0UL; i<FD_BACKUP_DISK_PARA; i++ ) FD_TEST( batched[ i ]==expected[ i ] );

  /* replaying the batch must now find everything already claimed */
  fd_snapmk_accparse_lookup( parse, chain, file_off, batched, FD_BACKUP_DISK_PARA );
  for( ulong i=0UL; i<FD_BACKUP_DISK_PARA; i++ ) FD_TEST( batched[ i ]==UINT_MAX );
}

/* fd_snapmk_accparse_keep derives the chain from the record header
   rather than from a prestaged chain index.  It must land on the same
   entry as an explicit lookup. */

static void
test_keep_derives_chain( void ) {
  env_reset();

  uchar const * pubkey = pubkey_n( 777UL );
  ulong chain    = fd_backup_accidx_chain( &parse->idx, pubkey );
  ulong file_off = 0xb000UL;
  uint  ele      = index_add( 33U, chain, pubkey, 5U, 1000UL, file_off );

  memcpy( parse->meta.pubkey, pubkey, 32UL );
  parse->acc_file_off = file_off;
  parse->acc_idx      = UINT_MAX;

  FD_TEST( fd_snapmk_accparse_keep( parse )==1 );
  FD_TEST( parse->acc_idx==ele );

  /* already visited: keep must report 0 and clear acc_idx */
  FD_TEST( fd_snapmk_accparse_keep( parse )==0 );
  FD_TEST( parse->acc_idx==UINT_MAX );
}

/* A record header above the root generation is dropped without ever
   reaching the index, so the entry it would have hit stays unclaimed. */

static void
test_keep_skips_too_new( void ) {
  env_reset();

  uchar const * pubkey   = pubkey_n( 888UL );
  ulong         chain    = fd_backup_accidx_chain( &parse->idx, pubkey );
  ulong         file_off = 0xc000UL;
  uint          ele      = index_add( 44U, chain, pubkey, 5U, 1000UL, file_off );

  memcpy( parse->meta.pubkey, pubkey, 32UL );
  parse->acc_file_off   = file_off;
  parse->acc_idx        = UINT_MAX;
  parse->meta.generation = ROOT_GEN+1U;

  FD_TEST( fd_snapmk_accparse_keep( parse )==0 );
  FD_TEST( parse->acc_idx==UINT_MAX );

  /* the skip must not have burned the visited bit */
  parse->meta.generation = ROOT_GEN;
  FD_TEST( fd_snapmk_accparse_keep( parse )==1 );
  FD_TEST( parse->acc_idx==ele );
}

/* Same skip on the whole-record path: too-new records are consumed off
   the frag but never staged into the batch. */

static void
test_prestage_skips_too_new( void ) {
  env_reset();

  ulong const rec_sz  = sizeof(fd_accdb_disk_meta_t); /* data_len 0 */
  ulong const off_base = 0x20000UL;

  static fd_accdb_disk_meta_t recs[ 3 ];
  uint expected[ 3 ];
  for( ulong i=0UL; i<3UL; i++ ) {
    uchar const * pubkey = pubkey_n( 200UL+i );
    ulong chain = fd_backup_accidx_chain( &parse->idx, pubkey );
    uint  gen   = ( i==1UL ) ? ROOT_GEN+1U : 5U;

    memset( &recs[ i ], 0, sizeof(recs[ i ]) );
    memcpy( recs[ i ].pubkey, pubkey, 32UL );
    recs[ i ].size       = 0U;
    recs[ i ].generation = gen;

    uint ele = index_add( (uint)(50UL+i), chain, pubkey, gen, 1000UL, off_base + i*rec_sz );
    expected[ i ] = ( gen<=ROOT_GEN ) ? ele : UINT_MAX;
  }

  parse->data            = (uchar const *)recs;
  parse->data_sz         = 3UL*rec_sz;
  parse->src_gaddr       = 0x900000UL;
  parse->frag_base_gaddr = 0x900000UL;
  parse->src_off         = off_base;
  parse->pf_cursor       = NULL;
  parse->ps_cnt          = 0U;
  parse->pub_pending     = 0;
  parse->acc_active      = 0;
  parse->meta_sz         = 0U;

  fd_backup_disk_batch_msg_t batch[1];
  ulong n = fd_snapmk_accparse_publish_batch( parse, batch );

  FD_TEST( n==2UL );                                   /* middle one dropped */
  FD_TEST( batch->acc_idx [ 0 ]==expected[ 0 ] );
  FD_TEST( batch->frag_off[ 0 ]==0U             );
  FD_TEST( batch->acc_idx [ 1 ]==expected[ 2 ] );      /* record 2, not 1 */
  FD_TEST( batch->frag_off[ 1 ]==(uint)(2UL*rec_sz) );
  for( ulong i=n; i<FD_BACKUP_DISK_PARA; i++ ) FD_TEST( batch->acc_idx[ i ]==UINT_MAX );

  FD_TEST( !parse->data_sz ); /* every record consumed, skipped ones too */
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( visited_set_footprint( MAX_ACCOUNTS )<=sizeof(visited_mem) );
  FD_TEST( visited_set_align()<=128UL );

  static ulong epoch      = 42UL;
  static ulong epoch_slot = ULONG_MAX;

  parse->idx = (fd_backup_accidx_t){
    .acc_map         = acc_map,
    .acc_pool        = acc_pool,
    .max_accounts    = MAX_ACCOUNTS,
    .seed            = 0x1234abcdUL,
    .chain_mask      = (uint)( CHAIN_CNT-1UL ),
    .epoch_slot      = &epoch_slot,
    .epoch           = &epoch,
    .root_generation = ROOT_GEN
  };

  test_single_hop();
  test_multi_hop();
  test_collision_resolved_by_offset();
  test_superseded_version();
  test_generation_above_root();
  test_tombstone();
  test_empty_chain();
  test_visited_dedup();
  test_full_batch();
  test_keep_derives_chain();
  test_keep_skips_too_new();
  test_prestage_skips_too_new();

  /* every lookup must have released its epoch announcement */
  FD_TEST( epoch_slot==ULONG_MAX );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
