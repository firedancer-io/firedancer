#include "fd_accdb_delta.h"

FD_FN_CONST ulong
fd_accdb_delta_align( void ) {
  return FD_ACCDB_DELTA_ALIGN;
}

FD_FN_CONST ulong
fd_accdb_delta_footprint( ulong max ) {
  if( FD_UNLIKELY( !max || max>(ulong)UINT_MAX ) ) return 0UL;
  ulong chain_cnt = fd_ulong_pow2_up( (max+1UL)>>1 );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_ACCDB_DELTA_ALIGN, sizeof(fd_accdb_delta_t) );
  l = FD_LAYOUT_APPEND( l, alignof(uint), chain_cnt*sizeof(uint) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_delta_ele_t), max*sizeof(fd_accdb_delta_ele_t) );
  return FD_LAYOUT_FINI( l, FD_ACCDB_DELTA_ALIGN );
}

void *
fd_accdb_delta_new( void * shmem,
                    ulong  max,
                    ulong  seed ) {
  if( FD_UNLIKELY( !shmem || !fd_ulong_is_aligned( (ulong)shmem, FD_ACCDB_DELTA_ALIGN ) ) ) return NULL;
  if( FD_UNLIKELY( !fd_accdb_delta_footprint( max ) ) ) return NULL;

  ulong chain_cnt = fd_ulong_pow2_up( (max+1UL)>>1 );
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_accdb_delta_t * delta = FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_DELTA_ALIGN, sizeof(fd_accdb_delta_t) );
  uint * chain = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint), chain_cnt*sizeof(uint) );
  fd_accdb_delta_ele_t * ele = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_delta_ele_t), max*sizeof(fd_accdb_delta_ele_t) );

  fd_memset( delta, 0, sizeof(fd_accdb_delta_t) );
  fd_memset( chain, 0xff, chain_cnt*sizeof(uint) );
  (void)ele;
  delta->max       = max;
  delta->chain_cnt = chain_cnt;
  delta->seed      = seed;
  delta->chain_off = (ulong)( (uchar *)chain - (uchar *)delta );
  delta->ele_off   = (ulong)( (uchar *)ele   - (uchar *)delta );
  FD_COMPILER_MFENCE();
  delta->magic = FD_ACCDB_DELTA_MAGIC;
  FD_COMPILER_MFENCE();
  return shmem;
}

fd_accdb_delta_t *
fd_accdb_delta_join( void * shmem ) {
  fd_accdb_delta_t * delta = (fd_accdb_delta_t *)shmem;
  if( FD_UNLIKELY( !delta || delta->magic!=FD_ACCDB_DELTA_MAGIC ) ) return NULL;
  return delta;
}

int
fd_accdb_delta_insert( fd_accdb_delta_t * delta,
                       uchar const         pubkey[ 32 ] ) {
  ulong hash = fd_hash( delta->seed, pubkey, 32UL );
  ulong chain_idx = hash & (delta->chain_cnt-1UL);
  uint * chain = fd_accdb_delta_chain( delta );
  fd_accdb_delta_ele_t * pool = fd_accdb_delta_ele( delta );
  uint cur = __atomic_load_n( &chain[ chain_idx ], __ATOMIC_ACQUIRE );
  while( cur!=UINT_MAX ) {
    fd_accdb_delta_ele_t const * ele = &pool[ cur ];
    if( FD_LIKELY( !memcmp( ele->pubkey, pubkey, 32UL ) ) ) {
      return 1;
    }
    cur = __atomic_load_n( &ele->next, __ATOMIC_RELAXED );
  }

  ulong idx = __atomic_fetch_add( &delta->head, 1UL, __ATOMIC_RELAXED );
  if( FD_UNLIKELY( idx>=delta->max ) ) {
    return -1;
  }

  fd_accdb_delta_ele_t * ele = &pool[ idx ];
  fd_memcpy( ele->pubkey, pubkey, 32UL );
  for(;;) {
    /* Another inserter may have published this pubkey after our first
       lookup but before we reserved idx.  Re-scan on every CAS attempt;
       a failed CAS means the chain changed and must be checked again.
       Losing duplicate reservations remain harmless, unreachable holes
       in the bump allocation. */
    uint old = __atomic_load_n( &chain[ chain_idx ], __ATOMIC_ACQUIRE );
    uint cur = old;
    while( cur!=UINT_MAX ) {
      fd_accdb_delta_ele_t const * cur_ele = &pool[ cur ];
      if( FD_UNLIKELY( !memcmp( cur_ele->pubkey, pubkey, 32UL ) ) ) return 1;
      cur = __atomic_load_n( &cur_ele->next, __ATOMIC_RELAXED );
    }
    ele->next = old;
    if( FD_LIKELY( __atomic_compare_exchange_n( &chain[ chain_idx ], &old, (uint)idx, 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED ) ) ) break;
    FD_SPIN_PAUSE();
  }
  return 1;
}

void
fd_accdb_delta_writer_enter( fd_accdb_delta_t * delta ) {
  for(;;) {
    while( FD_UNLIKELY( __atomic_load_n( &delta->reset_pending, __ATOMIC_ACQUIRE ) ) ) FD_SPIN_PAUSE();
    __atomic_fetch_add( &delta->active, 1UL, __ATOMIC_ACQUIRE );
    if( FD_LIKELY( !__atomic_load_n( &delta->reset_pending, __ATOMIC_ACQUIRE ) ) ) return;
    __atomic_fetch_sub( &delta->active, 1UL, __ATOMIC_RELEASE );
  }
}

void
fd_accdb_delta_writer_leave( fd_accdb_delta_t * delta ) {
  __atomic_fetch_sub( &delta->active, 1UL, __ATOMIC_RELEASE );
}

void
fd_accdb_delta_reset_begin( fd_accdb_delta_t * delta ) {
  __atomic_store_n( &delta->reset_pending, 1UL, __ATOMIC_RELEASE );
}

int
fd_accdb_delta_reset_try( fd_accdb_delta_t * delta ) {
  if( FD_UNLIKELY( __atomic_load_n( &delta->active, __ATOMIC_ACQUIRE ) ) ) return 0;
  fd_memset( fd_accdb_delta_chain( delta ), 0xff, delta->chain_cnt*sizeof(uint) );
  __atomic_store_n( &delta->head, 0UL, __ATOMIC_RELEASE );
  __atomic_store_n( &delta->reset_pending, 0UL, __ATOMIC_RELEASE );
  return 1;
}
