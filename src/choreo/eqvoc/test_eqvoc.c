#include "fd_eqvoc.c"

FD_IMPORT_BINARY( id,       "src/choreo/eqvoc/fixtures/id.bin"       );
FD_IMPORT_BINARY( pay1,     "src/choreo/eqvoc/fixtures/pay1.bin"     );
FD_IMPORT_BINARY( pay2,     "src/choreo/eqvoc/fixtures/pay2.bin"     );
FD_IMPORT_BINARY( mr1,      "src/choreo/eqvoc/fixtures/mr1.bin"      );
FD_IMPORT_BINARY( mr2,      "src/choreo/eqvoc/fixtures/mr2.bin"      );
FD_IMPORT_BINARY( meta1,    "src/choreo/eqvoc/fixtures/meta1.bin"    );
FD_IMPORT_BINARY( meta2,    "src/choreo/eqvoc/fixtures/meta2.bin"    );
FD_IMPORT_BINARY( last1,    "src/choreo/eqvoc/fixtures/last1.bin"    );
FD_IMPORT_BINARY( last2,    "src/choreo/eqvoc/fixtures/last2.bin"    );
FD_IMPORT_BINARY( overlap1, "src/choreo/eqvoc/fixtures/overlap1.bin" );
FD_IMPORT_BINARY( overlap2, "src/choreo/eqvoc/fixtures/overlap2.bin" );
FD_IMPORT_BINARY( chained1, "src/choreo/eqvoc/fixtures/chained1.bin" );
FD_IMPORT_BINARY( chained2, "src/choreo/eqvoc/fixtures/chained2.bin" );

#define FEC_MAX       4
#define SLOT_MAX      4
#define VTR_MAX       4
#define SHRED_VERSION 42
#define ROOT          0UL

static uchar __attribute__((aligned(128UL))) eqvoc_mem [ 131072 ];
static uchar __attribute__((aligned(128UL))) voters_mem[ 131072 ];


static fd_pubkey_t        from [1]   = { { .uc = { 242, 97, 238, 195, 95, 84,  158, 41, 211, 104, 141, 25, 22,  233, 147, 28, 8,   50, 225, 227, 88, 116, 4,   29, 207, 7,   22,  4,  141, 136, 237, 132 } } };
static uint               sched[100] = { 0 };
static fd_epoch_leaders_t leaders    = { .slot0 = 0, .slot_cnt = 100, .pub = from, .pub_cnt = 1, .sched = sched, .sched_cnt = 4 };

static fd_gossip_duplicate_shred_t chunks_out[ FD_EQVOC_CHUNK_CNT ];

static uchar proof_mem[ 2 * sizeof(ulong) + 2 * FD_SHRED_MAX_SZ ];

static void
vtr_insert( fd_eqvoc_t *        eqvoc,
            fd_pubkey_t const * from ) {
  vtr_t * vtr = vtr_map_ele_query( eqvoc->vtr_map, from, NULL, eqvoc->vtr_pool );
  if( FD_LIKELY( vtr ) ) return;
  vtr                = vtr_pool_ele_acquire( eqvoc->vtr_pool );
  vtr->from          = *from;
  vtr->prf_dlist_cnt = 0;
  vtr_map_ele_insert( eqvoc->vtr_map, vtr, eqvoc->vtr_pool );
  vtr_dlist_ele_push_tail( eqvoc->vtr_dlist, vtr, eqvoc->vtr_pool );
}

fd_eqvoc_t *
setup( void ) {
  FD_TEST( fd_eqvoc_footprint( SLOT_MAX, FEC_MAX, VTR_MAX ) < sizeof(eqvoc_mem) );

  fd_eqvoc_t * eqvoc = fd_eqvoc_join( fd_eqvoc_new( eqvoc_mem, SLOT_MAX, FEC_MAX, VTR_MAX, 0UL ) );
  return eqvoc;
}

void
teardown( fd_eqvoc_t * eqvoc ) {
  eqvoc = fd_eqvoc_delete( fd_eqvoc_leave( eqvoc ) );
  memset( eqvoc_mem, 0, sizeof(eqvoc_mem) );
}

void
test_proof( uchar const * shred1_bytes, uchar const * shred2_bytes, int err_expected, int skip_shred_insert ) {
  fd_eqvoc_t * eqvoc = setup();

  fd_shred_t const * shred1 = (fd_shred_t const *)fd_type_pun_const( shred1_bytes );
  fd_shred_t const * shred2 = (fd_shred_t const *)fd_type_pun_const( shred2_bytes );

  /* Test verify_proof */

  FD_TEST( verify_proof( eqvoc, SHRED_VERSION, &leaders, shred1, shred2 )==err_expected );

  /* Test construct_proof */

  construct_proof( shred1, shred2, chunks_out );
  ulong sz = 0;
  for( ulong i = 0; i < FD_EQVOC_CHUNK_CNT; i++ ) {
    memcpy( proof_mem + sz, chunks_out[i].chunk, chunks_out[i].chunk_len );
    sz += chunks_out[i].chunk_len;
  }

  FD_TEST( fd_ulong_load_8( proof_mem )==fd_shred_sz( shred1 ) );
  FD_TEST( 0==memcmp( proof_mem + sizeof(ulong), shred1, fd_shred_sz( shred1 ) ) );
  FD_TEST( fd_ulong_load_8( proof_mem + sizeof(ulong) + fd_shred_sz( shred1 ) )==fd_shred_sz( shred2 ) );
  FD_TEST( 0==memcmp( proof_mem + sizeof(ulong) + fd_shred_sz( shred1 ) + sizeof(ulong), shred2, fd_shred_sz( shred2 ) ) );

  /* Test chunk_insert */

  vtr_insert( eqvoc, from );
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, from, &chunks_out[0], chunks_out )==FD_EQVOC_SUCCESS );
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, from, &chunks_out[1], chunks_out )==FD_EQVOC_SUCCESS );
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, from, &chunks_out[0], chunks_out )==FD_EQVOC_SUCCESS ); /* inserting again no-op */
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, from, &chunks_out[2], chunks_out )==err_expected     );

  teardown( eqvoc );
  memset( chunks_out, 0, sizeof(chunks_out) );

  if( skip_shred_insert ) return;

  eqvoc = setup();

  /* Test shred_insert */

  int err_actual = FD_EQVOC_SUCCESS;
  err_actual = fd_eqvoc_shred_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, shred1, chunks_out );
  FD_TEST( err_actual==FD_EQVOC_SUCCESS );

  err_actual = fd_eqvoc_shred_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, shred1, chunks_out );
  FD_TEST( err_actual==FD_EQVOC_SUCCESS ); /* same shred twice isn't equivocating */

  err_actual = fd_eqvoc_shred_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, shred2, chunks_out );
  FD_TEST( err_actual==err_expected );

  teardown( eqvoc );
}

void
test_evict( void ) {

  /* Shred eviction by (slot, fec_set_idx) */

  fd_eqvoc_t * eqvoc = setup();
  uchar        shred_bytes[FD_SHRED_MIN_SZ] = { 12, 20, 88, 140, 221, 68, 111, 148, 187, 119, 30, 22, 42, 221, 65, 43, 93, 170, 201, 121, 37, 87, 253, 68, 228, 161, 159, 159, 149, 93, 96, 134, 155, 92, 2, 73, 33, 46, 100, 22, 245, 94, 0, 144, 43, 171, 120, 101, 93, 222, 110, 116, 17, 96, 149, 145, 33, 119, 0, 163, 70, 166, 206, 6, 149, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 0, 0, 1, 0, 42, 47, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 247, 131, 90, 55, 245, 41, 73, 211, 141, 173, 29, 87, 159, 58, 136, 18, 205, 115, 200, 64, 195, 242, 252, 120, 220, 58, 254, 31, 67, 199, 42, 81, 109, 14, 250, 128, 50, 24, 176, 41, 132, 8, 60, 164, 149, 81, 6, 236, 49, 238, 200, 131, 75, 27, 146, 57, 2, 85, 228, 37, 131, 223, 245, 89, 100, 51, 148, 245, 134, 194, 194, 110, 240, 25, 201, 234, 239, 3, 62, 134, 94, 74, 139, 131, 28, 116, 160, 239, 153, 61, 58, 57, 122, 55, 56, 220, 88, 16, 105, 185 };
  fd_shred_t * shred                        = (fd_shred_t *)fd_type_pun( shred_bytes );
  fd_gossip_duplicate_shred_t chunks[ FD_EQVOC_CHUNK_CNT ];

  ulong k = 10;
  for( ulong i = 0; i < FEC_MAX * k; i++ ) {
    ulong slot  = shred->slot;
    shred->slot = shred->slot + i;
    fd_eqvoc_shred_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, shred, chunks );
    shred->slot = slot;
  }
  FD_TEST( fec_pool_used( eqvoc->fec_pool )==FEC_MAX );
  for( ulong i = 0; i < FEC_MAX; i++ ) {
    for( ulong j = 0; j < (k-1); j++ ) {
      ulong key = (shred->slot + FEC_MAX * (j) + i) << 32 | shred->fec_set_idx;
      FD_TEST( !fec_map_ele_query( eqvoc->fec_map, &key, NULL, eqvoc->fec_pool ) );
    }
    ulong key = (shred->slot + FEC_MAX * (k-1) + i) << 32 | shred->fec_set_idx;
    FD_TEST( fec_map_ele_query( eqvoc->fec_map, &key, NULL, eqvoc->fec_pool ) );
  }
  teardown( eqvoc );

  /* Proof eviction by (from, [slot]) */

  eqvoc = setup();
  fd_pubkey_t from = { .uc = { 42 } };
  fd_pubkey_t from2 = { .uc = { 43 } };
  vtr_insert( eqvoc, &from );
  vtr_insert( eqvoc, &from2 );
  for( ulong i = 0; i < SLOT_MAX; i++ ) {
    fd_gossip_duplicate_shred_t chunk = { .slot = i, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
    fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &from, &chunk, chunks_out );
  }
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==SLOT_MAX );

  fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &from, &(fd_gossip_duplicate_shred_t){ .slot = SLOT_MAX, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==SLOT_MAX ); /* still SLOT_MAX, one evicted */

  fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &from2, &(fd_gossip_duplicate_shred_t){ .slot = SLOT_MAX, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==SLOT_MAX + 1 ); /* new pubkey, so now SLOT_MAX + 1 */

  teardown( eqvoc );
}

void
test_update_voters( void ) {
  fd_eqvoc_t * eqvoc = setup();

  fd_pubkey_t a = { .uc = { 1 } };
  fd_pubkey_t b = { .uc = { 2 } };
  fd_pubkey_t c = { .uc = { 3 } };

  /* Chunk insert returns ERR_FROM for unknown pubkeys. */

  fd_gossip_duplicate_shred_t chunk = { .slot = 0, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &a, &chunk, chunks_out )==FD_EQVOC_ERR_IGNORED_FROM );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==0 ); /* no proof created */

  /* After update_voters with {a, b}, chunks from a and b are accepted. */

  fd_tower_voters_t * tv = fd_tower_voters_join( fd_tower_voters_new( voters_mem, VTR_MAX ) );
  fd_tower_voters_push_tail( tv, (fd_tower_voters_t){ .id = a } );
  fd_tower_voters_push_tail( tv, (fd_tower_voters_t){ .id = b } );
  fd_eqvoc_update_voters( eqvoc, tv );

  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==2 );

  fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &a, &(fd_gossip_duplicate_shred_t){ .slot = 10, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==1 ); /* proof created for a */

  fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &b, &(fd_gossip_duplicate_shred_t){ .slot = 20, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==2 ); /* proof created for b */

  /* c is not a voter, chunk from c returns ERR_FROM. */

  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &c, &(fd_gossip_duplicate_shred_t){ .slot = 30, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out )==FD_EQVOC_ERR_IGNORED_FROM );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==2 ); /* still 2 */

  /* Reindex with {b, c}: a should be removed (and its proof evicted),
     c should be added.  b's proof should be preserved. */

  fd_tower_voters_t * tv2 = fd_tower_voters_join( fd_tower_voters_new( voters_mem, VTR_MAX ) );
  fd_tower_voters_push_tail( tv2, (fd_tower_voters_t){ .id = b } );
  fd_tower_voters_push_tail( tv2, (fd_tower_voters_t){ .id = c } );
  fd_eqvoc_update_voters( eqvoc, tv2 );

  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==2 );
  FD_TEST( !vtr_map_ele_query( eqvoc->vtr_map, &a, NULL, eqvoc->vtr_pool ) ); /* a removed */
  FD_TEST(  vtr_map_ele_query( eqvoc->vtr_map, &b, NULL, eqvoc->vtr_pool ) ); /* b still present */
  FD_TEST(  vtr_map_ele_query( eqvoc->vtr_map, &c, NULL, eqvoc->vtr_pool ) ); /* c added */

  FD_TEST( prf_pool_used( eqvoc->prf_pool )==1 ); /* a's proof evicted, b's proof preserved */

  /* c can now submit chunks. */

  fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &c, &(fd_gossip_duplicate_shred_t){ .slot = 30, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==2 ); /* now 2 again */

  /* Calling update_voters with same set is a no-op (proofs preserved). */

  fd_tower_voters_t * tv3 = fd_tower_voters_join( fd_tower_voters_new( voters_mem, VTR_MAX ) );
  fd_tower_voters_push_tail( tv3, (fd_tower_voters_t){ .id = b } );
  fd_tower_voters_push_tail( tv3, (fd_tower_voters_t){ .id = c } );
  fd_eqvoc_update_voters( eqvoc, tv3 );

  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==2 );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==2 ); /* unchanged */

  /* Re-add a (who was removed).  a should come back with zero proofs;
     its old proof for slot 10 must not be in the map. */

  fd_tower_voters_t * tv4 = fd_tower_voters_join( fd_tower_voters_new( voters_mem, VTR_MAX ) );
  fd_tower_voters_push_tail( tv4, (fd_tower_voters_t){ .id = a } );
  fd_tower_voters_push_tail( tv4, (fd_tower_voters_t){ .id = b } );
  fd_tower_voters_push_tail( tv4, (fd_tower_voters_t){ .id = c } );
  fd_eqvoc_update_voters( eqvoc, tv4 );

  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==3 );
  FD_TEST( vtr_map_ele_query( eqvoc->vtr_map, &a, NULL, eqvoc->vtr_pool ) );
  FD_TEST( vtr_map_ele_query( eqvoc->vtr_map, &b, NULL, eqvoc->vtr_pool ) );
  FD_TEST( vtr_map_ele_query( eqvoc->vtr_map, &c, NULL, eqvoc->vtr_pool ) );

  /* a's old proof (slot 10) must be gone. */

  xid_t a_old = { .slot = 10, .from = a };
  FD_TEST( !prf_map_ele_query( eqvoc->prf_map, &a_old, NULL, eqvoc->prf_pool ) );

  vtr_t * vtr_a = vtr_map_ele_query( eqvoc->vtr_map, &a, NULL, eqvoc->vtr_pool );
  FD_TEST( vtr_a->prf_dlist_cnt==0 ); /* no proofs carried over */

  FD_TEST( prf_pool_used( eqvoc->prf_pool )==2 ); /* b and c's proofs still there */

  /* a can submit new chunks now. */

  fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &a, &(fd_gossip_duplicate_shred_t){ .slot = 50, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==3 );
  FD_TEST( vtr_a->prf_dlist_cnt==1 );

  /* Add a brand new voter d.  Existing proofs for a, b, c preserved    . */

  fd_pubkey_t d = { .uc = { 4 } };

  fd_tower_voters_t * tv5 = fd_tower_voters_join( fd_tower_voters_new( voters_mem, VTR_MAX ) );
  fd_tower_voters_push_tail( tv5, (fd_tower_voters_t){ .id = a } );
  fd_tower_voters_push_tail( tv5, (fd_tower_voters_t){ .id = b } );
  fd_tower_voters_push_tail( tv5, (fd_tower_voters_t){ .id = c } );
  fd_tower_voters_push_tail( tv5, (fd_tower_voters_t){ .id = d } );
  fd_eqvoc_update_voters( eqvoc, tv5 );

  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==4 );
  FD_TEST( vtr_map_ele_query( eqvoc->vtr_map, &d, NULL, eqvoc->vtr_pool ) );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==3 ); /* unchanged */

  /* d can submit chunks. */

  fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &d, &(fd_gossip_duplicate_shred_t){ .slot = 60, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==4 );

  vtr_t * vtr_d = vtr_map_ele_query( eqvoc->vtr_map, &d, NULL, eqvoc->vtr_pool );
  FD_TEST( vtr_d->prf_dlist_cnt==1 );

  /* Calling update_voters with empty set removes all. */

  fd_tower_voters_t * tv6 = fd_tower_voters_join( fd_tower_voters_new( voters_mem, VTR_MAX ) );
  fd_eqvoc_update_voters( eqvoc, tv6 );

  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==0 );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==0 );

  teardown( eqvoc );
}

void
test_bad_actor( void ) {
  fd_eqvoc_t * eqvoc = setup();

  fd_pubkey_t a = { .uc = { 10 } };
  fd_pubkey_t b = { .uc = { 11 } };
  fd_pubkey_t c = { .uc = { 12 } };
  fd_pubkey_t unknown = { .uc = { 99 } };

  fd_tower_voters_t * tv = fd_tower_voters_join( fd_tower_voters_new( voters_mem, VTR_MAX ) );
  fd_tower_voters_push_tail( tv, (fd_tower_voters_t){ .id = a } );
  fd_tower_voters_push_tail( tv, (fd_tower_voters_t){ .id = b } );
  fd_tower_voters_push_tail( tv, (fd_tower_voters_t){ .id = c } );
  fd_eqvoc_update_voters( eqvoc, tv );

  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==3 );

  /* Chunks from an unknown pubkey return ERR_FROM. */

  for( ulong i = 0; i < 10; i++ ) {
    fd_gossip_duplicate_shred_t chunk = { .slot = i, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
    FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &unknown, &chunk, chunks_out )==FD_EQVOC_ERR_IGNORED_FROM );
  }
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==0 );

  /* Bad num_chunks is rejected. */

  fd_gossip_duplicate_shred_t bad_cnt = { .slot = 0, .num_chunks = 5, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &a, &bad_cnt, chunks_out )==FD_EQVOC_ERR_CHUNK_CNT );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==0 );

  /* Bad chunk_index is rejected. */

  fd_gossip_duplicate_shred_t bad_idx = { .slot = 0, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = FD_EQVOC_CHUNK_CNT, .chunk_len = FD_EQVOC_CHUNK0_LEN };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &a, &bad_idx, chunks_out )==FD_EQVOC_ERR_CHUNK_IDX );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==0 );

  /* Bad chunk_len for chunk 0 is rejected. */

  fd_gossip_duplicate_shred_t bad_len0 = { .slot = 0, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = 1 };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &a, &bad_len0, chunks_out )==FD_EQVOC_ERR_CHUNK_LEN );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==0 );

  /* Bad chunk_len for chunk 1 is rejected. */

  fd_gossip_duplicate_shred_t bad_len1 = { .slot = 0, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 1, .chunk_len = 1 };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &a, &bad_len1, chunks_out )==FD_EQVOC_ERR_CHUNK_LEN );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==0 );

  /* Bad chunk_len for chunk 2 is rejected. */

  fd_gossip_duplicate_shred_t bad_len2 = { .slot = 0, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 2, .chunk_len = 1 };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &a, &bad_len2, chunks_out )==FD_EQVOC_ERR_CHUNK_LEN );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==0 );

  /* Attacker 'a' spams SLOT_MAX distinct proofs (one chunk per slot).
     Each first chunk for a new slot creates a new proof entry. */

  for( ulong i = 0; i < SLOT_MAX; i++ ) {
    fd_gossip_duplicate_shred_t chunk = { .slot = i, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
    FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &a, &chunk, chunks_out )==FD_EQVOC_SUCCESS );
  }
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==SLOT_MAX );

  vtr_t * vtr_a = vtr_map_ele_query( eqvoc->vtr_map, &a, NULL, eqvoc->vtr_pool );
  FD_TEST( vtr_a );
  FD_TEST( vtr_a->prf_dlist_cnt==SLOT_MAX );

  /* Verify all SLOT_MAX proofs are in the map. */

  for( ulong i = 0; i < SLOT_MAX; i++ ) {
    xid_t key = { .slot = i, .from = a };
    FD_TEST( prf_map_ele_query( eqvoc->prf_map, &key, NULL, eqvoc->prf_pool ) );
  }

  /* Attacker 'a' sends one more proof for slot SLOT_MAX.  This should
     FIFO-evict the oldest proof (slot 0). */

  fd_gossip_duplicate_shred_t evict_chunk = { .slot = SLOT_MAX, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &a, &evict_chunk, chunks_out )==FD_EQVOC_SUCCESS );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==SLOT_MAX ); /* still SLOT_MAX, oldest evicted */

  vtr_a = vtr_map_ele_query( eqvoc->vtr_map, &a, NULL, eqvoc->vtr_pool );
  FD_TEST( vtr_a->prf_dlist_cnt==SLOT_MAX );

  /* Slot 0 proof should be gone; slots 1..SLOT_MAX should be present. */

  xid_t evicted_key = { .slot = 0, .from = a };
  FD_TEST( !prf_map_ele_query( eqvoc->prf_map, &evicted_key, NULL, eqvoc->prf_pool ) );
  for( ulong i = 1; i <= SLOT_MAX; i++ ) {
    xid_t key = { .slot = i, .from = a };
    FD_TEST( prf_map_ele_query( eqvoc->prf_map, &key, NULL, eqvoc->prf_pool ) );
  }

  /* Continue spamming: send 3 more proofs from 'a', evicting slots
     1, 2, 3 in order. */

  for( ulong i = SLOT_MAX + 1; i < SLOT_MAX + 4; i++ ) {
    fd_gossip_duplicate_shred_t chunk = { .slot = i, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
    FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &a, &chunk, chunks_out )==FD_EQVOC_SUCCESS );
  }
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==SLOT_MAX );

  vtr_a = vtr_map_ele_query( eqvoc->vtr_map, &a, NULL, eqvoc->vtr_pool );
  FD_TEST( vtr_a->prf_dlist_cnt==SLOT_MAX );

  /* Slots 0..3 should all be evicted; slots 4..7 should remain. */

  for( ulong i = 0; i < SLOT_MAX; i++ ) {
    xid_t key = { .slot = i, .from = a };
    FD_TEST( !prf_map_ele_query( eqvoc->prf_map, &key, NULL, eqvoc->prf_pool ) );
  }
  for( ulong i = SLOT_MAX; i < SLOT_MAX + 4; i++ ) {
    xid_t key = { .slot = i, .from = a };
    FD_TEST( prf_map_ele_query( eqvoc->prf_map, &key, NULL, eqvoc->prf_pool ) );
  }

  /* Attacker 'b' fills up independently.  Total pool usage should
     increase since 'b' has its own per-voter limit. */

  for( ulong i = 0; i < SLOT_MAX; i++ ) {
    fd_gossip_duplicate_shred_t chunk = { .slot = 100 + i, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
    FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &b, &chunk, chunks_out )==FD_EQVOC_SUCCESS );
  }
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==2 * SLOT_MAX );

  vtr_t * vtr_b = vtr_map_ele_query( eqvoc->vtr_map, &b, NULL, eqvoc->vtr_pool );
  FD_TEST( vtr_b->prf_dlist_cnt==SLOT_MAX );

  /* 'b' overflows => only 'b's oldest proof evicted, 'a' unaffected. */

  fd_gossip_duplicate_shred_t b_overflow = { .slot = 200, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &b, &b_overflow, chunks_out )==FD_EQVOC_SUCCESS );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==2 * SLOT_MAX );
  FD_TEST( vtr_b->prf_dlist_cnt==SLOT_MAX );

  /* 'b' slot 100 should be evicted. */

  xid_t b_evicted = { .slot = 100, .from = b };
  FD_TEST( !prf_map_ele_query( eqvoc->prf_map, &b_evicted, NULL, eqvoc->prf_pool ) );

  /* 'a' slots 4..7 should still be there. */

  for( ulong i = SLOT_MAX; i < SLOT_MAX + 4; i++ ) {
    xid_t key = { .slot = i, .from = a };
    FD_TEST( prf_map_ele_query( eqvoc->prf_map, &key, NULL, eqvoc->prf_pool ) );
  }

  /* 'c' fills up its own quota too. */

  for( ulong i = 0; i < SLOT_MAX; i++ ) {
    fd_gossip_duplicate_shred_t chunk = { .slot = 300 + i, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
    FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &c, &chunk, chunks_out )==FD_EQVOC_SUCCESS );
  }
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==3 * SLOT_MAX );

  vtr_t * vtr_c = vtr_map_ele_query( eqvoc->vtr_map, &c, NULL, eqvoc->vtr_pool );
  FD_TEST( vtr_c->prf_dlist_cnt==SLOT_MAX );

  /* 'c' overflows while 'a' and 'b' remain at their limits. */

  fd_gossip_duplicate_shred_t c_overflow = { .slot = 400, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &c, &c_overflow, chunks_out )==FD_EQVOC_SUCCESS );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==3 * SLOT_MAX );

  xid_t c_evicted = { .slot = 300, .from = c };
  FD_TEST( !prf_map_ele_query( eqvoc->prf_map, &c_evicted, NULL, eqvoc->prf_pool ) );

  /* Duplicate chunk for existing proof should not create a new entry. */

  fd_gossip_duplicate_shred_t dup_chunk = { .slot = SLOT_MAX, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &a, &dup_chunk, chunks_out )==FD_EQVOC_SUCCESS );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==3 * SLOT_MAX ); /* unchanged */

  /* Removing voter 'a' should free all of 'a's proofs. */

  fd_tower_voters_t * tv2 = fd_tower_voters_join( fd_tower_voters_new( voters_mem, VTR_MAX ) );
  fd_tower_voters_push_tail( tv2, (fd_tower_voters_t){ .id = b } );
  fd_tower_voters_push_tail( tv2, (fd_tower_voters_t){ .id = c } );
  fd_eqvoc_update_voters( eqvoc, tv2 );

  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==2 );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==2 * SLOT_MAX );
  FD_TEST( !vtr_map_ele_query( eqvoc->vtr_map, &a, NULL, eqvoc->vtr_pool ) );

  /* 'a' proofs should all be gone from the map. */

  for( ulong i = SLOT_MAX; i < SLOT_MAX + 4; i++ ) {
    xid_t key = { .slot = i, .from = a };
    FD_TEST( !prf_map_ele_query( eqvoc->prf_map, &key, NULL, eqvoc->prf_pool ) );
  }

  /* Removing all voters frees everything. */

  fd_tower_voters_t * tv3 = fd_tower_voters_join( fd_tower_voters_new( voters_mem, VTR_MAX ) );
  fd_eqvoc_update_voters( eqvoc, tv3 );

  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==0 );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==0 );

  teardown( eqvoc );
}

void
test_verify_proof_errors( void ) {

  uchar base[FD_SHRED_MIN_SZ]; memcpy( base, id, FD_SHRED_MIN_SZ );

  fd_eqvoc_t * eqvoc = setup();

  /* ERR_SLOT: shreds with different slots. */
  {
    uchar s1[FD_SHRED_MIN_SZ]; memcpy( s1, base, FD_SHRED_MIN_SZ );
    uchar s2[FD_SHRED_MIN_SZ]; memcpy( s2, base, FD_SHRED_MIN_SZ );
    fd_shred_t * sh2 = (fd_shred_t *)fd_type_pun( s2 );
    sh2->slot = 99;
    FD_TEST( verify_proof( eqvoc, SHRED_VERSION, &leaders, (fd_shred_t const *)s1, (fd_shred_t const *)s2 )==FD_EQVOC_ERR_SLOT );
  }

  /* ERR_VERSION: shred1 has wrong version. */
  {
    uchar s1[FD_SHRED_MIN_SZ]; memcpy( s1, base, FD_SHRED_MIN_SZ );
    uchar s2[FD_SHRED_MIN_SZ]; memcpy( s2, base, FD_SHRED_MIN_SZ );
    fd_shred_t * sh1 = (fd_shred_t *)fd_type_pun( s1 );
    sh1->version = 99;
    FD_TEST( verify_proof( eqvoc, SHRED_VERSION, &leaders, (fd_shred_t const *)s1, (fd_shred_t const *)s2 )==FD_EQVOC_ERR_VERSION );
  }

  /* ERR_VERSION: shred2 has wrong version. */
  {
    uchar s1[FD_SHRED_MIN_SZ]; memcpy( s1, base, FD_SHRED_MIN_SZ );
    uchar s2[FD_SHRED_MIN_SZ]; memcpy( s2, base, FD_SHRED_MIN_SZ );
    fd_shred_t * sh2 = (fd_shred_t *)fd_type_pun( s2 );
    sh2->version = 99;
    FD_TEST( verify_proof( eqvoc, SHRED_VERSION, &leaders, (fd_shred_t const *)s1, (fd_shred_t const *)s2 )==FD_EQVOC_ERR_VERSION );
  }

  /* ERR_TYPE: shred with legacy variant (not chained, not resigned). */
  {
    uchar s1[FD_SHRED_MIN_SZ]; memcpy( s1, base, FD_SHRED_MIN_SZ );
    uchar s2[FD_SHRED_MIN_SZ]; memcpy( s2, base, FD_SHRED_MIN_SZ );
    fd_shred_t * sh1 = (fd_shred_t *)fd_type_pun( s1 );
    sh1->variant = FD_SHRED_TYPE_LEGACY_DATA | 5;
    FD_TEST( verify_proof( eqvoc, SHRED_VERSION, &leaders, (fd_shred_t const *)s1, (fd_shred_t const *)s2 )==FD_EQVOC_ERR_TYPE );
  }

  /* ERR_MERKLE: shred idx too large for merkle tree inclusion proof. */
  {
    uchar s1[FD_SHRED_MIN_SZ]; memcpy( s1, base, FD_SHRED_MIN_SZ );
    uchar s2[FD_SHRED_MIN_SZ]; memcpy( s2, base, FD_SHRED_MIN_SZ );
    fd_shred_t * sh1 = (fd_shred_t *)fd_type_pun( s1 );
    sh1->idx = 200;
    FD_TEST( verify_proof( eqvoc, SHRED_VERSION, &leaders, (fd_shred_t const *)s1, (fd_shred_t const *)s2 )==FD_EQVOC_ERR_MERKLE );
  }

  /* ERR_SIG: valid merkle roots but signature doesn't match leader. */
  {
    uchar s1[FD_SHRED_MIN_SZ]; memcpy( s1, base, FD_SHRED_MIN_SZ );
    uchar s2[FD_SHRED_MIN_SZ]; memcpy( s2, base, FD_SHRED_MIN_SZ );
    /* Use a different leader schedule so the leader pubkey doesn't
       match the signer of the shred. */
    fd_pubkey_t  wrong_pub = { .uc = { 99 } };
    uint         wrong_sched[100] = { 0 };
    fd_epoch_leaders_t wrong_leaders = { .slot0 = 0, .slot_cnt = 100, .pub = &wrong_pub, .pub_cnt = 1, .sched = wrong_sched, .sched_cnt = 4 };
    FD_TEST( verify_proof( eqvoc, SHRED_VERSION, &wrong_leaders, (fd_shred_t const *)s1, (fd_shred_t const *)s2 )==FD_EQVOC_ERR_SIG );
  }

  teardown( eqvoc );
}

void
test_ignored_slot( void ) {
  fd_eqvoc_t * eqvoc = setup();

  uchar base[FD_SHRED_MIN_SZ]; memcpy( base, id, FD_SHRED_MIN_SZ );
  fd_shred_t * shred = (fd_shred_t *)fd_type_pun( base );
  shred->slot = 5;

  fd_gossip_duplicate_shred_t chunk = { .slot = 5, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
  fd_pubkey_t any = { .uc = { 1 } };

  /* NULL leader schedule: both shred_insert and chunk_insert return ERR_IGNORED_SLOT. */

  FD_TEST( fd_eqvoc_shred_insert( eqvoc, SHRED_VERSION, ROOT, NULL, (fd_shred_t const *)base, chunks_out )==FD_EQVOC_ERR_IGNORED_SLOT );
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, NULL, &any, &chunk, chunks_out )==FD_EQVOC_ERR_IGNORED_SLOT );

  /* Slot older than root: both return ERR_IGNORED_SLOT. */

  FD_TEST( fd_eqvoc_shred_insert( eqvoc, SHRED_VERSION, 10UL, &leaders, (fd_shred_t const *)base, chunks_out )==FD_EQVOC_ERR_IGNORED_SLOT );
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, 10UL, &leaders, &any, &chunk, chunks_out )==FD_EQVOC_ERR_IGNORED_SLOT );

  teardown( eqvoc );
}

/* test_voter_removal verifies that removing a voter preserves other
   voters' in-progress proofs and that newly inserted voters start with
   an empty prf_dlist. */

void
test_voter_removal( void ) {
  fd_eqvoc_t * eqvoc = setup();

  fd_pubkey_t a = { .uc = { 20 } };
  fd_pubkey_t b = { .uc = { 21 } };
  fd_pubkey_t c = { .uc = { 22 } };

  /* Register a and b; both hash to the same bucket so b probes to slot 1. */

  fd_tower_voters_t * tv = fd_tower_voters_join( fd_tower_voters_new( voters_mem, VTR_MAX ) );
  fd_tower_voters_push_tail( tv, (fd_tower_voters_t){ .id = a } );
  fd_tower_voters_push_tail( tv, (fd_tower_voters_t){ .id = b } );
  fd_eqvoc_update_voters( eqvoc, tv );

  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==2 );

  /* Give b one in-progress proof (chunk 0 only, so proof stays open). */

  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &b, &(fd_gossip_duplicate_shred_t){ .slot = 10, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out )==FD_EQVOC_SUCCESS );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==1 );

  vtr_t * vtr_b = vtr_map_ele_query( eqvoc->vtr_map, &b, NULL, eqvoc->vtr_pool );
  FD_TEST( vtr_b );
  FD_TEST( vtr_b->prf_dlist_cnt==1 );

  /* Remove a: b's proofs must survive. */

  fd_tower_voters_t * tv2 = fd_tower_voters_join( fd_tower_voters_new( voters_mem, VTR_MAX ) );
  fd_tower_voters_push_tail( tv2, (fd_tower_voters_t){ .id = b } );
  fd_eqvoc_update_voters( eqvoc, tv2 );

  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==1 );
  FD_TEST( !vtr_map_ele_query( eqvoc->vtr_map, &a, NULL, eqvoc->vtr_pool ) );

  /* b's proof survived the removal. */

  vtr_b = vtr_map_ele_query( eqvoc->vtr_map, &b, NULL, eqvoc->vtr_pool );
  FD_TEST( vtr_b );
  FD_TEST( vtr_b->prf_dlist_cnt==1 );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==1 );

  /* b can accept new proofs after a's removal. */

  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &b, &(fd_gossip_duplicate_shred_t){ .slot = 11, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out )==FD_EQVOC_SUCCESS );
  FD_TEST( vtr_b->prf_dlist_cnt==2 );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==2 );

  /* Add c alongside b.  c starts with an empty prf_dlist. */

  fd_tower_voters_t * tv3 = fd_tower_voters_join( fd_tower_voters_new( voters_mem, VTR_MAX ) );
  fd_tower_voters_push_tail( tv3, (fd_tower_voters_t){ .id = b } );
  fd_tower_voters_push_tail( tv3, (fd_tower_voters_t){ .id = c } );
  fd_eqvoc_update_voters( eqvoc, tv3 );

  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==2 );
  vtr_t * vtr_c = vtr_map_ele_query( eqvoc->vtr_map, &c, NULL, eqvoc->vtr_pool );
  FD_TEST( vtr_c );
  FD_TEST( vtr_c->prf_dlist_cnt==0 );

  /* c's chunk goes to c's prf_dlist; b's proofs are unaffected. */

  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &c, &(fd_gossip_duplicate_shred_t){ .slot = 20, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out )==FD_EQVOC_SUCCESS );
  FD_TEST( vtr_c->prf_dlist_cnt==1 );
  FD_TEST( vtr_b->prf_dlist_cnt==2 ); /* b unaffected */
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==3 );

  teardown( eqvoc );
}

int
main( void ) {

  test_proof( id,       id,       FD_EQVOC_SUCCESS,         0 /* don't skip shred insert */ );
  test_proof( pay1,     pay2,     FD_EQVOC_SUCCESS_MERKLE,  0 /* don't skip shred insert */ );
  test_proof( mr1,      mr2,      FD_EQVOC_SUCCESS_MERKLE,  0 /* don't skip shred insert */ );
  test_proof( meta1,    meta2,    FD_EQVOC_SUCCESS_META,    0 /* don't skip shred insert */ );
  test_proof( last1,    last2,    FD_EQVOC_SUCCESS_LAST,    0 /* don't skip shred insert */ );
  test_proof( overlap1, overlap2, FD_EQVOC_SUCCESS_OVERLAP, 1 /* skip shred insert */       );
  test_proof( chained1, chained2, FD_EQVOC_SUCCESS_CHAINED, 1 /* skip shred insert */       );

  test_evict();
  test_update_voters();
  test_bad_actor();
  test_verify_proof_errors();
  test_ignored_slot();
  test_voter_removal();

  /* Unverifiable proofs should not leak.  When all chunks arrive but
     verify_proof returns <= FD_EQVOC_SUCCESS (e.g. FD_EQVOC_ERR_SERDE),
     the proof must be released.  Repeat to confirm no pool leak. */

  {
    fd_eqvoc_t * eqvoc = setup();

    fd_pubkey_t voter = { .uc = { 77 } };
    fd_tower_voters_t * tv = fd_tower_voters_join( fd_tower_voters_new( voters_mem, VTR_MAX ) );
    fd_tower_voters_push_tail( tv, (fd_tower_voters_t){ .id = voter } );
    fd_eqvoc_update_voters( eqvoc, tv );

    for( ulong round = 0; round < 3; round++ ) {
      /* Send all 3 chunks with garbage data for the same (slot, from).
         The assembled proof will fail deserialization. */

      for( uchar ci = 0; ci < FD_EQVOC_CHUNK_CNT; ci++ ) {
        fd_gossip_duplicate_shred_t chunk = { .slot = 42, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = ci };
        if( ci==0 )      chunk.chunk_len = FD_EQVOC_CHUNK0_LEN;
        else if( ci==1 ) chunk.chunk_len = FD_EQVOC_CHUNK1_LEN;
        else             chunk.chunk_len = FD_EQVOC_CHUNK2_LEN_DD;
        int err = fd_eqvoc_chunk_insert( eqvoc, SHRED_VERSION, ROOT, &leaders, &voter, &chunk, chunks_out );
        if( ci < FD_EQVOC_CHUNK_CNT - 1 ) {
          FD_TEST( err==FD_EQVOC_SUCCESS );       /* not yet complete */
          FD_TEST( prf_pool_used( eqvoc->prf_pool )==1 );
        } else {
          FD_TEST( err==FD_EQVOC_ERR_SERDE );      /* garbage data fails deser */
          FD_TEST( prf_pool_used( eqvoc->prf_pool )==0 ); /* proof freed, no leak */
        }
      }

      vtr_t * vtr = vtr_map_ele_query( eqvoc->vtr_map, &voter, NULL, eqvoc->vtr_pool );
      FD_TEST( vtr );
      FD_TEST( vtr->prf_dlist_cnt==0 );
    }

    teardown( eqvoc );
  }

  return 0;
}
