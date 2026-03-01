#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <string.h>

#include "fd_eqvoc.h"
#include "fd_eqvoc_private.h"
#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"

#define SHRED_MAX 4
#define SLOT_MAX  4
#define FROM_MAX  4

static fd_pubkey_t        leader[1]  = {{{ 0 }}};
static uint               sched[100] = { 0 };
static fd_epoch_leaders_t leaders    = { .slot0 = 0, .slot_cnt = 100, .pub = leader, .pub_cnt = 1, .sched = sched, .sched_cnt = 4 };

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  ulong chunk_sz = sizeof(fd_gossip_duplicate_shred_t);
  if( FD_UNLIKELY( size < 32UL + 3UL * chunk_sz ) ) return -1;

  ulong   footprint = fd_eqvoc_footprint( SHRED_MAX, SLOT_MAX, FROM_MAX );
  uchar * mem       = aligned_alloc( fd_eqvoc_align(), footprint );

  fd_eqvoc_t * eqvoc = fd_eqvoc_join( fd_eqvoc_new( mem, SHRED_MAX, SLOT_MAX, FROM_MAX, 0UL ) );
  fd_eqvoc_set_shred_version( eqvoc, 42 );
  fd_eqvoc_set_leader_schedule( eqvoc, &leaders );

  fd_pubkey_t from;
  memcpy( &from, data, 32UL );
  data += 32UL;
  size -= 32UL;

  while( size >= sizeof(fd_gossip_duplicate_shred_t) ) {
    fd_gossip_duplicate_shred_t chunk;
    memcpy( &chunk, data, sizeof(fd_gossip_duplicate_shred_t) );
    fd_eqvoc_chunk_insert( eqvoc, &from, &chunk );
    data += sizeof(fd_gossip_duplicate_shred_t);
    size -= sizeof(fd_gossip_duplicate_shred_t);
  }

  fd_eqvoc_delete( fd_eqvoc_leave( eqvoc ) );
  free( mem );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}

ulong
LLVMFuzzerCustomMutator( uchar * data,
                         ulong   size,
                         ulong   max_size,
                         uint    seed ) {
  (void)seed;

  ulong chunk_sz = sizeof(fd_gossip_duplicate_shred_t);
  ulong min_sz   = 32UL + 3UL * chunk_sz;

  if( FD_UNLIKELY( max_size < min_sz ) ) return 0;

  if( size < min_sz ) {
    memset( data + size, 0, min_sz - size );
    size = min_sz;
  }

  size = LLVMFuzzerMutate( data, size, max_size );

  if( size < min_sz ) {
    memset( data + size, 0, min_sz - size );
    size = min_sz;
  }

  /* Fix up structural invariants so chunks reach the reassembly path. */

  fd_gossip_duplicate_shred_t chunk;
  memcpy( &chunk, data + 32UL, chunk_sz );
  ulong slot = chunk.slot;

  for( uchar i = 0; i < 3; i++ ) {
    memcpy( &chunk, data + 32UL + (ulong)i * chunk_sz, chunk_sz );
    chunk.slot        = slot;
    chunk.chunk_index = i;
    chunk.num_chunks  = FD_EQVOC_CHUNK_CNT;
    if( chunk.chunk_len > sizeof(chunk.chunk) ) chunk.chunk_len = sizeof(chunk.chunk);
    memcpy( data + 32UL + (ulong)i * chunk_sz, &chunk, chunk_sz );
  }

  return size;
}
