#include "fd_eqvoc.c"
#include "fd_eqvoc.h"

FD_IMPORT_BINARY( id,       "src/choreo/eqvoc/fixtures/id.bin"       );
FD_IMPORT_BINARY( pay1,     "src/choreo/eqvoc/fixtures/pay1.bin"     );
FD_IMPORT_BINARY( pay2,     "src/choreo/eqvoc/fixtures/pay2.bin"     );

#define FEC_MAX       4
#define SLOT_MAX      4
#define VTR_MAX       4
#define SHRED_VERSION 42
#define ROOT          0UL

static uchar __attribute__((aligned(128UL))) eqvoc_mem [ 131072 ];

static fd_pubkey_t        from [1]   = { { .uc = { 242, 97, 238, 195, 95, 84,  158, 41, 211, 104, 141, 25, 22,  233, 147, 28, 8,   50, 225, 227, 88, 116, 4,   29, 207, 7,   22,  4,  141, 136, 237, 132 } } };
static uint               sched[100] = { 0 };
static fd_epoch_leaders_t leaders    = { .slot0 = 0, .slot_cnt = 100, .pub = from, .pub_cnt = 1, .sched = sched, .sched_cnt = 4 };

static fd_gossip_duplicate_shred_t chunks_out[ FD_EQVOC_CHUNK_CNT ];

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
  FD_TEST( fd_eqvoc_footprint( SLOT_MAX, FEC_MAX, SLOT_MAX, VTR_MAX ) < sizeof(eqvoc_mem) );

  fd_eqvoc_t * eqvoc = fd_eqvoc_join( fd_eqvoc_new( eqvoc_mem, SLOT_MAX, FEC_MAX, SLOT_MAX, VTR_MAX, 0UL ) );
  return eqvoc;
}

void
teardown( fd_eqvoc_t * eqvoc ) {
  eqvoc = fd_eqvoc_delete( fd_eqvoc_leave( eqvoc ) );
  memset( eqvoc_mem, 0, sizeof(eqvoc_mem) );
}

void
test_shred_insert( void ) {
  fd_eqvoc_t * eqvoc = setup();

  uchar base[FD_SHRED_MIN_SZ]; memcpy( base, id, FD_SHRED_MIN_SZ );
  fd_shred_t * shred = (fd_shred_t *)fd_type_pun( base );

  /* Already-known equivocation short-circuits. */

  memcpy( base, id, FD_SHRED_MIN_SZ );
  dup_insert( eqvoc, shred->slot );
  FD_TEST( fd_eqvoc_shred_insert( eqvoc, 0, shred, chunks_out )==0 );

  /* First shred in FEC set (no sibling) returns 0. */

  memcpy( base, id, FD_SHRED_MIN_SZ );
  shred->slot = 99;
  ulong fec_used = fec_pool_used( eqvoc->fec_pool );
  FD_TEST( fd_eqvoc_shred_insert( eqvoc, 0, shred, chunks_out )==0 );
  FD_TEST( fec_pool_used( eqvoc->fec_pool ) > fec_used );

  teardown( eqvoc );

  /* FEC eviction by (slot, fec_set_idx). */

  eqvoc = setup();
  uchar shred_bytes[FD_SHRED_MIN_SZ] = { 12, 20, 88, 140, 221, 68, 111, 148, 187, 119, 30, 22, 42, 221, 65, 43, 93, 170, 201, 121, 37, 87, 253, 68, 228, 161, 159, 159, 149, 93, 96, 134, 155, 92, 2, 73, 33, 46, 100, 22, 245, 94, 0, 144, 43, 171, 120, 101, 93, 222, 110, 116, 17, 96, 149, 145, 33, 119, 0, 163, 70, 166, 206, 6, 149, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 0, 0, 1, 0, 42, 47, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 247, 131, 90, 55, 245, 41, 73, 211, 141, 173, 29, 87, 159, 58, 136, 18, 205, 115, 200, 64, 195, 242, 252, 120, 220, 58, 254, 31, 67, 199, 42, 81, 109, 14, 250, 128, 50, 24, 176, 41, 132, 8, 60, 164, 149, 81, 6, 236, 49, 238, 200, 131, 75, 27, 146, 57, 2, 85, 228, 37, 131, 223, 245, 89, 100, 51, 148, 245, 134, 194, 194, 110, 240, 25, 201, 234, 239, 3, 62, 134, 94, 74, 139, 131, 28, 116, 160, 239, 153, 61, 58, 57, 122, 55, 56, 220, 88, 16, 105, 185 };
  fd_shred_t * evict_shred = (fd_shred_t *)fd_type_pun( shred_bytes );
  fd_gossip_duplicate_shred_t chunks[ FD_EQVOC_CHUNK_CNT ];

  ulong n = 10;
  ulong base_slot = evict_shred->slot;
  for( ulong i = 0; i < n; i++ ) {
    evict_shred->slot = base_slot + i;
    fd_eqvoc_shred_insert( eqvoc, 0, evict_shred, chunks );
  }
  evict_shred->slot = base_slot;
  FD_TEST( fec_pool_used( eqvoc->fec_pool )==FEC_MAX );

  /* Each shred_insert creates 2 fec entries (UINT_MAX + fec_set_idx),
     so only the last FEC_MAX/2 slots survive eviction. */

  ulong surviving = FEC_MAX / 2;
  for( ulong i = 0; i < n - surviving; i++ ) {
    ulong key = (base_slot + i) << 32 | evict_shred->fec_set_idx;
    FD_TEST( !fec_map_ele_query( eqvoc->fec_map, &key, NULL, eqvoc->fec_pool ) );
  }
  for( ulong i = n - surviving; i < n; i++ ) {
    ulong key = (base_slot + i) << 32 | evict_shred->fec_set_idx;
    FD_TEST( fec_map_ele_query( eqvoc->fec_map, &key, NULL, eqvoc->fec_pool ) );
  }
  teardown( eqvoc );
}

void
test_chunk_insert( void ) {
  fd_eqvoc_t * eqvoc = setup();

  fd_pubkey_t a       = { .uc = { 10 } };
  fd_pubkey_t b       = { .uc = { 11 } };
  fd_pubkey_t c       = { .uc = { 12 } };
  fd_pubkey_t unknown = { .uc = { 99 } };

  fd_pubkey_t tv[] = { a, b, c };
  fd_eqvoc_update_voters( eqvoc, tv, 3UL );

  /* ERR_CHUNK_SLOT: slot older than root. */

  fd_gossip_duplicate_shred_t chunk_slot = { .slot = 5, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, 10UL, SHRED_VERSION, &leaders, &a, &chunk_slot, chunks_out )==FD_EQVOC_ERR_CHUNK_SLOT );

  /* ERR_CHUNK_FROM: chunks from an unknown pubkey. */

  for( ulong i = 0; i < 10; i++ ) {
    fd_gossip_duplicate_shred_t chunk = { .slot = i + 1, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
    FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &unknown, &chunk, chunks_out )==FD_EQVOC_ERR_CHUNK_FROM );
  }
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==0 );

  /* ERR_CHUNK_CNT: bad num_chunks. */

  fd_gossip_duplicate_shred_t bad_cnt = { .slot = 1, .num_chunks = 5, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &a, &bad_cnt, chunks_out )==FD_EQVOC_ERR_CHUNK_CNT );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==0 );

  /* ERR_CHUNK_IDX: bad chunk_index. */

  fd_gossip_duplicate_shred_t bad_idx = { .slot = 1, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = FD_EQVOC_CHUNK_CNT, .chunk_len = FD_EQVOC_CHUNK0_LEN };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &a, &bad_idx, chunks_out )==FD_EQVOC_ERR_CHUNK_IDX );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==0 );

  /* ERR_CHUNK_LEN: bad chunk_len for each chunk index. */

  fd_gossip_duplicate_shred_t bad_len0 = { .slot = 1, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = 1 };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &a, &bad_len0, chunks_out )==FD_EQVOC_ERR_CHUNK_LEN );

  fd_gossip_duplicate_shred_t bad_len1 = { .slot = 1, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 1, .chunk_len = 1 };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &a, &bad_len1, chunks_out )==FD_EQVOC_ERR_CHUNK_LEN );

  fd_gossip_duplicate_shred_t bad_len2 = { .slot = 1, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 2, .chunk_len = 1 };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &a, &bad_len2, chunks_out )==FD_EQVOC_ERR_CHUNK_LEN );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==0 );

  /* Chunk dedup: reinserting same chunk index does not overwrite data. */

  fd_gossip_duplicate_shred_t chunk0a = { .slot = 5, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
  memset( chunk0a.chunk, 0xAA, FD_EQVOC_CHUNK0_LEN );
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &a, &chunk0a, chunks_out )==FD_EQVOC_IGNORED );

  vtr_t * vtr = vtr_map_ele_query( eqvoc->vtr_map, &a, NULL, eqvoc->vtr_pool );
  prf_t * prf = prf_query( eqvoc, vtr, 5 );
  FD_TEST( prf );
  FD_TEST( prf->buf_sz==FD_EQVOC_CHUNK0_LEN );
  FD_TEST( prf->buf[0]==0xAA );

  fd_gossip_duplicate_shred_t chunk0b = { .slot = 5, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
  memset( chunk0b.chunk, 0xBB, FD_EQVOC_CHUNK0_LEN );
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &a, &chunk0b, chunks_out )==FD_EQVOC_IGNORED );

  prf = prf_query( eqvoc, vtr, 5 );
  FD_TEST( prf->buf[0]==0xAA ); /* original data preserved */
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==1 );

  /* Reinserting chunk 2 with different length is also ignored. */

  fd_gossip_duplicate_shred_t chunk2_cc = { .slot = 5, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 2, .chunk_len = FD_EQVOC_CHUNK2_LEN_CC };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &a, &chunk2_cc, chunks_out )==FD_EQVOC_IGNORED );
  prf = prf_query( eqvoc, vtr, 5 );
  FD_TEST( prf->buf_sz==FD_EQVOC_CHUNK0_LEN + FD_EQVOC_CHUNK2_LEN_CC );

  fd_gossip_duplicate_shred_t chunk2_dd = { .slot = 5, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 2, .chunk_len = FD_EQVOC_CHUNK2_LEN_DD };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &a, &chunk2_dd, chunks_out )==FD_EQVOC_IGNORED );
  prf = prf_query( eqvoc, vtr, 5 );
  FD_TEST( prf->buf_sz==FD_EQVOC_CHUNK0_LEN + FD_EQVOC_CHUNK2_LEN_CC ); /* unchanged */

  teardown( eqvoc );

  /* Slot mismatch: chunk slot != reassembled shred slot => ERR_SERDE. */

  eqvoc = setup();

  fd_shred_t const * shred1 = (fd_shred_t const *)fd_type_pun_const( pay1 );
  fd_shred_t const * shred2 = (fd_shred_t const *)fd_type_pun_const( pay2 );
  construct_proof( shred1, shred2, chunks_out );

  for( ulong i = 0; i < FD_EQVOC_CHUNK_CNT; i++ ) chunks_out[i].slot = 43;

  vtr_insert( eqvoc, from );
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, from, &chunks_out[0], chunks_out )==FD_EQVOC_IGNORED );
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, from, &chunks_out[1], chunks_out )==FD_EQVOC_IGNORED );
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, from, &chunks_out[2], chunks_out )==FD_EQVOC_ERR_SERDE );

  FD_TEST( prf_pool_used( eqvoc->prf_pool )==0 );
  FD_TEST( !fd_eqvoc_proof_verified( eqvoc, 43 ) );

  teardown( eqvoc );
  memset( chunks_out, 0, sizeof(chunks_out) );

  /* Per-voter proof eviction: attacker spams proofs, oldest evicted. */

  eqvoc = setup();
  fd_eqvoc_update_voters( eqvoc, tv, 3UL );

  for( ulong i = 1; i <= SLOT_MAX; i++ ) {
    fd_gossip_duplicate_shred_t chunk = { .slot = i, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
    FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &a, &chunk, chunks_out )==FD_EQVOC_IGNORED );
  }
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==SLOT_MAX );

  vtr_t * vtr_a = vtr_map_ele_query( eqvoc->vtr_map, &a, NULL, eqvoc->vtr_pool );
  FD_TEST( vtr_a->prf_dlist_cnt==SLOT_MAX );

  for( ulong i = 1; i <= SLOT_MAX; i++ ) {
    xid_t key = { .slot = i, .from = a };
    FD_TEST( prf_map_ele_query( eqvoc->prf_map, &key, NULL, eqvoc->prf_pool ) );
  }

  fd_gossip_duplicate_shred_t evict_chunk = { .slot = SLOT_MAX + 1, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &a, &evict_chunk, chunks_out )==FD_EQVOC_IGNORED );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==SLOT_MAX );

  xid_t evicted_key = { .slot = 1, .from = a };
  FD_TEST( !prf_map_ele_query( eqvoc->prf_map, &evicted_key, NULL, eqvoc->prf_pool ) );
  for( ulong i = 2; i <= SLOT_MAX + 1; i++ ) {
    xid_t key = { .slot = i, .from = a };
    FD_TEST( prf_map_ele_query( eqvoc->prf_map, &key, NULL, eqvoc->prf_pool ) );
  }

  /* Independent voters: b fills up without affecting a. */

  for( ulong i = 0; i < SLOT_MAX; i++ ) {
    fd_gossip_duplicate_shred_t chunk = { .slot = 100 + i, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
    FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &b, &chunk, chunks_out )==FD_EQVOC_IGNORED );
  }
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==2 * SLOT_MAX );

  fd_gossip_duplicate_shred_t b_overflow = { .slot = 200, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &b, &b_overflow, chunks_out )==FD_EQVOC_IGNORED );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==2 * SLOT_MAX );

  xid_t b_evicted = { .slot = 100, .from = b };
  FD_TEST( !prf_map_ele_query( eqvoc->prf_map, &b_evicted, NULL, eqvoc->prf_pool ) );

  /* Duplicate chunk for existing proof should not create a new entry. */

  fd_gossip_duplicate_shred_t dup_chunk = { .slot = SLOT_MAX + 1, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &a, &dup_chunk, chunks_out )==FD_EQVOC_IGNORED );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==2 * SLOT_MAX );

  teardown( eqvoc );

  /* Unverifiable proofs should not leak.  When all chunks arrive but
     verify_proof returns FD_EQVOC_IGNORED or FD_EQVOC_ERR_{...},
     the proof must be released.  Repeat to confirm no pool leak. */

  eqvoc = setup();

  fd_pubkey_t voter = { .uc = { 77 } };
  fd_pubkey_t tv_leak[] = { voter };
  fd_eqvoc_update_voters( eqvoc, tv_leak, 1UL );

  for( ulong round = 0; round < 3; round++ ) {
    for( uchar ci = 0; ci < FD_EQVOC_CHUNK_CNT; ci++ ) {
      fd_gossip_duplicate_shred_t chunk = { .slot = 42, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = ci };
      if( ci==0 )      chunk.chunk_len = FD_EQVOC_CHUNK0_LEN;
      else if( ci==1 ) chunk.chunk_len = FD_EQVOC_CHUNK1_LEN;
      else             chunk.chunk_len = FD_EQVOC_CHUNK2_LEN_DD;
      int err = fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &voter, &chunk, chunks_out );
      if( ci < FD_EQVOC_CHUNK_CNT - 1 ) {
        FD_TEST( err==FD_EQVOC_IGNORED );
        FD_TEST( prf_pool_used( eqvoc->prf_pool )==1 );
      } else {
        FD_TEST( err==FD_EQVOC_ERR_SERDE );
        FD_TEST( prf_pool_used( eqvoc->prf_pool )==0 );
      }
    }
    vtr_t * v = vtr_map_ele_query( eqvoc->vtr_map, &voter, NULL, eqvoc->vtr_pool );
    FD_TEST( v->prf_dlist_cnt==0 );
  }

  teardown( eqvoc );
}

void
test_proof_verified( void ) {
  fd_eqvoc_t * eqvoc = setup();

  FD_TEST( !fd_eqvoc_proof_verified( eqvoc, 42 ) );

  dup_insert( eqvoc, 42 );

  FD_TEST( fd_eqvoc_proof_verified( eqvoc, 42 ) );
  FD_TEST( !fd_eqvoc_proof_verified( eqvoc, 43 ) );

  teardown( eqvoc );
}

void
test_update_voters( void ) {
  fd_eqvoc_t * eqvoc = setup();

  fd_pubkey_t a = { .uc = { 1 } };
  fd_pubkey_t b = { .uc = { 2 } };
  fd_pubkey_t c = { .uc = { 3 } };
  fd_pubkey_t d = { .uc = { 4 } };

  /* Chunk insert returns ERR_FROM for unknown pubkeys. */

  fd_gossip_duplicate_shred_t chunk = { .slot = 1, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN };
  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &a, &chunk, chunks_out )==FD_EQVOC_ERR_CHUNK_FROM );

  /* After update_voters with {a, b}, chunks from a and b are accepted. */

  fd_pubkey_t tv[] = { a, b };
  fd_eqvoc_update_voters( eqvoc, tv, 2UL );
  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==2 );

  fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &a, &(fd_gossip_duplicate_shred_t){ .slot = 10, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==1 );

  fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &b, &(fd_gossip_duplicate_shred_t){ .slot = 20, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==2 );

  /* c is not a voter, chunk from c returns ERR_FROM. */

  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &c, &(fd_gossip_duplicate_shred_t){ .slot = 30, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out )==FD_EQVOC_ERR_CHUNK_FROM );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==2 );

  /* Reindex with {b, c}: a removed (proof evicted), c added, b preserved. */

  fd_pubkey_t tv2[] = { b, c };
  fd_eqvoc_update_voters( eqvoc, tv2, 2UL );
  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==2 );
  FD_TEST( !vtr_map_ele_query( eqvoc->vtr_map, &a, NULL, eqvoc->vtr_pool ) );
  FD_TEST(  vtr_map_ele_query( eqvoc->vtr_map, &b, NULL, eqvoc->vtr_pool ) );
  FD_TEST(  vtr_map_ele_query( eqvoc->vtr_map, &c, NULL, eqvoc->vtr_pool ) );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==1 ); /* a's proof evicted */

  /* Removing a voter preserves other voters' proofs. */

  vtr_t * vtr_b = vtr_map_ele_query( eqvoc->vtr_map, &b, NULL, eqvoc->vtr_pool );
  FD_TEST( vtr_b->prf_dlist_cnt==1 );

  /* b can accept new proofs after a's removal. */

  FD_TEST( fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &b, &(fd_gossip_duplicate_shred_t){ .slot = 11, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out )==FD_EQVOC_IGNORED );
  FD_TEST( vtr_b->prf_dlist_cnt==2 );

  /* Newly added voter c starts with empty prf_dlist. */

  vtr_t * vtr_c = vtr_map_ele_query( eqvoc->vtr_map, &c, NULL, eqvoc->vtr_pool );
  FD_TEST( vtr_c->prf_dlist_cnt==0 );

  fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &c, &(fd_gossip_duplicate_shred_t){ .slot = 30, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==3 );
  FD_TEST( vtr_c->prf_dlist_cnt==1 );
  FD_TEST( vtr_b->prf_dlist_cnt==2 ); /* b unaffected */

  /* No-op with same set preserves proofs. */

  fd_pubkey_t tv3[] = { b, c };
  fd_eqvoc_update_voters( eqvoc, tv3, 2UL );
  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==2 );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==3 );

  /* Re-add a: comes back fresh with no old proofs. */

  fd_pubkey_t tv4[] = { a, b, c };
  fd_eqvoc_update_voters( eqvoc, tv4, 3UL );
  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==3 );

  xid_t a_old = { .slot = 10, .from = a };
  FD_TEST( !prf_map_ele_query( eqvoc->prf_map, &a_old, NULL, eqvoc->prf_pool ) );

  vtr_t * vtr_a = vtr_map_ele_query( eqvoc->vtr_map, &a, NULL, eqvoc->vtr_pool );
  FD_TEST( vtr_a->prf_dlist_cnt==0 );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==3 ); /* b and c preserved */

  /* a can submit new chunks. */

  fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &a, &(fd_gossip_duplicate_shred_t){ .slot = 50, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out );
  FD_TEST( vtr_a->prf_dlist_cnt==1 );

  /* Add d: existing proofs preserved. */

  fd_pubkey_t tv5[] = { a, b, c, d };
  fd_eqvoc_update_voters( eqvoc, tv5, 4UL );
  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==4 );
  FD_TEST( vtr_map_ele_query( eqvoc->vtr_map, &d, NULL, eqvoc->vtr_pool ) );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==4 );

  fd_eqvoc_chunk_insert( eqvoc, ROOT, SHRED_VERSION, &leaders, &d, &(fd_gossip_duplicate_shred_t){ .slot = 60, .num_chunks = FD_EQVOC_CHUNK_CNT, .chunk_index = 0, .chunk_len = FD_EQVOC_CHUNK0_LEN }, chunks_out );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==5 );

  vtr_t * vtr_d = vtr_map_ele_query( eqvoc->vtr_map, &d, NULL, eqvoc->vtr_pool );
  FD_TEST( vtr_d->prf_dlist_cnt==1 );

  /* Empty set removes all voters and proofs. */

  fd_eqvoc_update_voters( eqvoc, NULL, 0UL );
  FD_TEST( vtr_pool_used( eqvoc->vtr_pool )==0 );
  FD_TEST( prf_pool_used( eqvoc->prf_pool )==0 );

  teardown( eqvoc );
}

int
main( void ) {
  test_shred_insert();
  test_chunk_insert();
  test_proof_verified();
  test_update_voters();
  return 0;
}
