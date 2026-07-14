#include "fd_accdb_delta.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  fd_accdb_delta_t * delta;
  ulong              begin;
  ulong              cnt;
} insert_thread_ctx_t;

static void *
insert_thread_main( void * _ctx ) {
  insert_thread_ctx_t * ctx = (insert_thread_ctx_t *)_ctx;
  fd_accdb_delta_writer_enter( ctx->delta );
  for( ulong i=0UL; i<ctx->cnt; i++ ) {
    uchar pubkey[ 32 ] = {0};
    ulong value = ctx->begin+i;
    memcpy( pubkey, &value, sizeof(value) );
    FD_TEST( fd_accdb_delta_insert( ctx->delta, pubkey )==1 );
  }
  fd_accdb_delta_writer_leave( ctx->delta );
  return NULL;
}

static void
test_layout_and_insert( void ) {
  FD_TEST( fd_accdb_delta_align()==128UL );
  FD_TEST( sizeof(fd_accdb_delta_ele_t)==36UL );
  FD_TEST( !fd_accdb_delta_footprint( 0UL ) );

  ulong footprint = fd_accdb_delta_footprint( 4UL );
  FD_TEST( footprint );
  FD_TEST( !(footprint & (fd_accdb_delta_align()-1UL)) );

  void * mem = aligned_alloc( fd_accdb_delta_align(), footprint );
  FD_TEST( mem );
  memset( mem, 0xa5, footprint );
  FD_TEST( !fd_accdb_delta_new( (uchar *)mem+1UL, 4UL, 1234UL ) );

  fd_accdb_delta_t * delta = fd_accdb_delta_join( fd_accdb_delta_new( mem, 4UL, 1234UL ) );
  FD_TEST( delta );
  FD_TEST( delta->max==4UL );
  FD_TEST( delta->chain_cnt==2UL );
  FD_TEST( fd_accdb_delta_head( delta )==0UL );
  for( ulong i=0UL; i<sizeof(fd_accdb_delta_ele_t); i++ )
    FD_TEST( ((uchar *)fd_accdb_delta_ele( delta ))[ i ]==0xa5U );

  uchar pubkey[ 5 ][ 32 ] = {{0}};
  for( ulong i=0UL; i<5UL; i++ ) pubkey[ i ][ 0 ] = (uchar)(i+1UL);

  fd_accdb_delta_writer_enter( delta );
  FD_TEST( fd_accdb_delta_insert( delta, pubkey[ 0 ] )==1 );
  FD_TEST( fd_accdb_delta_head( delta )==1UL );

  /* A non-racing duplicate is suppressed and consumes no bump slot. */
  FD_TEST( fd_accdb_delta_insert( delta, pubkey[ 0 ] )==1 );
  FD_TEST( fd_accdb_delta_head( delta )==1UL );

  FD_TEST( fd_accdb_delta_insert( delta, pubkey[ 1 ] )==1 );
  FD_TEST( fd_accdb_delta_insert( delta, pubkey[ 2 ] )==1 );
  FD_TEST( fd_accdb_delta_insert( delta, pubkey[ 3 ] )==1 );
  fd_accdb_delta_writer_leave( delta );
  FD_TEST( fd_accdb_delta_head( delta )==4UL );
  FD_TEST( !fd_accdb_delta_overflowed( delta ) );

  fd_accdb_delta_ele_t * ele = fd_accdb_delta_ele( delta );
  for( ulong i=0UL; i<4UL; i++ ) {
    FD_TEST( !memcmp( ele[ i ].pubkey, pubkey[ i ], 32UL ) );
  }

  /* The first allocation past max moves head into the persistent,
     graceful overflow state.  Existing keys remain queryable. */
  fd_accdb_delta_writer_enter( delta );
  FD_TEST( fd_accdb_delta_insert( delta, pubkey[ 4 ] )==-1 );
  FD_TEST( fd_accdb_delta_overflowed( delta ) );
  FD_TEST( fd_accdb_delta_head( delta )==5UL );
  FD_TEST( fd_accdb_delta_insert( delta, pubkey[ 0 ] )==1 );
  FD_TEST( fd_accdb_delta_head( delta )==5UL );
  fd_accdb_delta_writer_leave( delta );

  free( mem );
}

static void
test_reset_drains_writers( void ) {
  ulong footprint = fd_accdb_delta_footprint( 8UL );
  void * mem = aligned_alloc( fd_accdb_delta_align(), footprint );
  FD_TEST( mem );
  fd_accdb_delta_t * delta = fd_accdb_delta_join( fd_accdb_delta_new( mem, 8UL, 5678UL ) );
  FD_TEST( delta );

  uchar pubkey[ 32 ] = { 9 };
  fd_accdb_delta_writer_enter( delta );
  FD_TEST( fd_accdb_delta_insert( delta, pubkey )==1 );

  fd_accdb_delta_reset_begin( delta );
  FD_TEST( !fd_accdb_delta_reset_try( delta ) );
  FD_TEST( fd_accdb_delta_head( delta )==1UL );

  fd_accdb_delta_writer_leave( delta );
  FD_TEST( fd_accdb_delta_reset_try( delta ) );
  FD_TEST( fd_accdb_delta_head( delta )==0UL );
  FD_TEST( !fd_accdb_delta_overflowed( delta ) );
  for( ulong i=0UL; i<delta->chain_cnt; i++ )
    FD_TEST( fd_accdb_delta_chain( delta )[ i ]==UINT_MAX );

  /* Reset reuses the backing bump entry without needing to clear it. */
  fd_accdb_delta_writer_enter( delta );
  FD_TEST( fd_accdb_delta_insert( delta, pubkey )==1 );
  fd_accdb_delta_writer_leave( delta );
  FD_TEST( fd_accdb_delta_head( delta )==1UL );
  FD_TEST( !memcmp( fd_accdb_delta_ele( delta )->pubkey, pubkey, 32UL ) );

  free( mem );
}

static void
test_concurrent_insert( void ) {
  ulong const thread_cnt = 4UL;
  ulong const per_thread = 512UL;
  ulong const max        = thread_cnt*per_thread;
  ulong footprint = fd_accdb_delta_footprint( max );
  void * mem = aligned_alloc( fd_accdb_delta_align(), footprint );
  FD_TEST( mem );
  fd_accdb_delta_t * delta = fd_accdb_delta_join( fd_accdb_delta_new( mem, max, 9876UL ) );
  FD_TEST( delta );

  pthread_t threads[ 4 ];
  insert_thread_ctx_t ctx[ 4 ];
  for( ulong i=0UL; i<thread_cnt; i++ ) {
    /* All threads race to insert the same key set. */
    ctx[ i ] = (insert_thread_ctx_t){ .delta=delta, .begin=0UL, .cnt=per_thread };
    FD_TEST( !pthread_create( &threads[ i ], NULL, insert_thread_main, &ctx[ i ] ) );
  }
  for( ulong i=0UL; i<thread_cnt; i++ ) FD_TEST( !pthread_join( threads[ i ], NULL ) );

  /* Losing racers may consume bump slots, but cannot link duplicates. */
  FD_TEST( fd_accdb_delta_head( delta )>=per_thread );
  FD_TEST( fd_accdb_delta_head( delta )<=max );
  FD_TEST( !fd_accdb_delta_overflowed( delta ) );

  /* Every logical key is reachable exactly once despite concurrent CAS
     prepends.  Unreachable bump holes are intentionally ignored. */
  uchar seen[ 2048 ] = {0};
  uchar key_seen[ 512 ] = {0};
  fd_accdb_delta_ele_t * ele = fd_accdb_delta_ele( delta );
  ulong found = 0UL;
  for( ulong chain_idx=0UL; chain_idx<delta->chain_cnt; chain_idx++ ) {
    uint idx = fd_accdb_delta_chain( delta )[ chain_idx ];
    while( idx!=UINT_MAX ) {
      FD_TEST( (ulong)idx<max );
      FD_TEST( !seen[ idx ] );
      seen[ idx ] = 1U;
      ulong key;
      memcpy( &key, ele[ idx ].pubkey, sizeof(key) );
      FD_TEST( key<per_thread );
      FD_TEST( !key_seen[ key ] );
      key_seen[ key ] = 1U;
      found++;
      idx = ele[ idx ].next;
    }
  }
  FD_TEST( found==per_thread );
  for( ulong i=0UL; i<per_thread; i++ ) FD_TEST( key_seen[ i ] );

  free( mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_layout_and_insert();
  test_reset_drains_writers();
  test_concurrent_insert();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
