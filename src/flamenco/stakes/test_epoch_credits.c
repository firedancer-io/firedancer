#define _GNU_SOURCE
#include "fd_epoch_credits.h"
#include "../runtime/fd_runtime_const.h"

#include <stdlib.h> /* aligned_alloc */
#include <sys/mman.h> /* memfd_create */
#include <sys/stat.h>
#include <unistd.h>

#define CACHE_CNT (4UL)

static ulong
spill_sz( int fd ) {
  struct stat st;
  FD_TEST( !fstat( fd, &st ) );
  return (ulong)st.st_size;
}

static fd_epoch_credits_store_t *
store_create( void ** mem_out,
              int     fd,
              ulong   max_live_slots,
              ulong   cache_cnt ) {
  ulong footprint = fd_epoch_credits_store_footprint( max_live_slots, cache_cnt );
  FD_TEST( footprint );
  void * mem = aligned_alloc( fd_epoch_credits_store_align(), footprint );
  FD_TEST( mem );
  FD_TEST( !ftruncate( fd, 0L ) );
  fd_epoch_credits_store_t * store = fd_epoch_credits_store_join( fd_epoch_credits_store_new( mem, fd, max_live_slots, cache_cnt ), fd );
  FD_TEST( store );
  *mem_out = mem;
  return store;
}

static void
set_write( fd_epoch_credits_store_t * store,
           ushort                     fork_id,
           ulong                      base,
           ulong                      len ) {
  fd_epoch_credits_view_t view[1];
  FD_TEST( fd_epoch_credits_view_init( view, store, fork_id ) );
  for( ulong i=0UL; i<len; i++ ) view->credits[i].base_credits = base+i;
  view->len = len;
  fd_epoch_credits_view_fini( view );
}

static void
set_check( fd_epoch_credits_store_t * store,
           ushort                     fork_id,
           ulong                      base,
           ulong                      len ) {
  fd_epoch_credits_view_t view[1];
  FD_TEST( fd_epoch_credits_view_init( view, store, fork_id ) );
  FD_TEST( view->len==len );
  for( ulong i=0UL; i<len; i++ ) FD_TEST( view->credits[i].base_credits==base+i );
  fd_epoch_credits_view_fini( view );
}

/* Only the per-set metadata grows with max_live_slots.  Each cache
   entry holds one full set, and the cache never exceeds max_live_slots
   entries. */

static void
test_footprint( void ) {
  ulong set_sz = sizeof(fd_epoch_credits_t)*FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS;

  FD_TEST( !fd_epoch_credits_store_footprint( 0UL,        CACHE_CNT ) );
  FD_TEST( !fd_epoch_credits_store_footprint( USHORT_MAX, CACHE_CNT ) );
  FD_TEST( !fd_epoch_credits_store_footprint( 8UL,        0UL       ) );

  ulong fp1    = fd_epoch_credits_store_footprint( 1UL,       CACHE_CNT );
  ulong fp8_1  = fd_epoch_credits_store_footprint( 8UL,       1UL       );
  ulong fp8_2  = fd_epoch_credits_store_footprint( 8UL,       2UL       );
  ulong fp_c   = fd_epoch_credits_store_footprint( CACHE_CNT, CACHE_CNT );
  ulong fp_max = fd_epoch_credits_store_footprint( 4096UL,    CACHE_CNT );
  FD_TEST( fp1>=set_sz && fp1<2UL*set_sz );
  FD_TEST( fp8_2-fp8_1>=set_sz && fp8_2-fp8_1<=set_sz+FD_EPOCH_CREDITS_STORE_ALIGN );
  FD_TEST( fp_c>=CACHE_CNT*set_sz );
  FD_TEST( fp_max-fp_c < 4096UL*3UL*sizeof(ulong)+FD_EPOCH_CREDITS_STORE_ALIGN );
}

static void
test_new_join( int fd ) {
  ulong  footprint = fd_epoch_credits_store_footprint( 4UL, CACHE_CNT );
  uchar * mem      = aligned_alloc( fd_epoch_credits_store_align(), footprint+fd_epoch_credits_store_align() );
  FD_TEST( mem );

  FD_TEST( !fd_epoch_credits_store_new( NULL,    fd, 4UL, CACHE_CNT ) );
  FD_TEST( !fd_epoch_credits_store_new( mem+1UL, fd, 4UL, CACHE_CNT ) );
  FD_TEST( !fd_epoch_credits_store_new( mem,     -1, 4UL, CACHE_CNT ) );
  FD_TEST( !fd_epoch_credits_store_new( mem,     fd, 0UL, CACHE_CNT ) );
  FD_TEST( !fd_epoch_credits_store_new( mem,     fd, 4UL, 0UL       ) );

  FD_TEST( fd_epoch_credits_store_new( mem, fd, 4UL, CACHE_CNT )==mem );
  FD_TEST( !fd_epoch_credits_store_join( NULL, fd    ) );
  FD_TEST( !fd_epoch_credits_store_join( mem,  fd+1  ) );
  FD_TEST(  fd_epoch_credits_store_join( mem,  fd    ) );

  fd_memset( mem, 0, sizeof(ulong) );
  FD_TEST( !fd_epoch_credits_store_join( mem, fd ) );
  free( mem );
}

/* Fresh sets reuse the most recently freed id, are empty, and are
   zeroed when first viewed.  Releasing the last reference frees the
   id. */

static void
test_refcnt( int fd ) {
  void * mem;
  fd_epoch_credits_store_t * store = store_create( &mem, fd, 4UL, CACHE_CNT );

  ushort a = fd_epoch_credits_store_new_fork( store, USHORT_MAX );
  FD_TEST( a==0 );
  set_write( store, a, 100UL, 3UL );

  fd_epoch_credits_store_acquire( store, a );
  ushort b = fd_epoch_credits_store_new_fork( store, a );
  FD_TEST( b==1 );
  set_check( store, a, 100UL, 3UL );
  set_check( store, b, 0UL,   0UL );

  ushort c = fd_epoch_credits_store_new_fork( store, a );
  FD_TEST( c==a );
  set_check( store, c, 0UL, 0UL );

  fd_epoch_credits_view_t view[1];
  FD_TEST( fd_epoch_credits_view_init( view, store, c ) );
  for( ulong i=0UL; i<3UL; i++ ) FD_TEST( !view->credits[i].base_credits );
  view->len = 0UL;
  fd_epoch_credits_view_fini( view );

  free( mem );
}

/* More live sets than cache entries spill to the backing file and
   reload intact.  A pinned set is never evicted. */

static void
test_spill_reload( int   fd,
                   ulong cache_cnt ) {
  ulong const set_cnt = cache_cnt+2UL;
  void * mem;
  fd_epoch_credits_store_t * store = store_create( &mem, fd, set_cnt, cache_cnt );

  ushort ids[ CACHE_CNT+2UL ];
  FD_TEST( set_cnt<=sizeof(ids)/sizeof(ids[0]) );
  for( ulong i=0UL; i<set_cnt; i++ ) {
    ids[i] = fd_epoch_credits_store_new_fork( store, USHORT_MAX );
    set_write( store, ids[i], 1000UL*(i+1UL), i+1UL );
    if( i<cache_cnt ) FD_TEST( !spill_sz( fd ) );
    else              FD_TEST(  spill_sz( fd ) );
  }

  fd_epoch_credits_view_t pinned[1];
  FD_TEST( fd_epoch_credits_view_init( pinned, store, ids[0] ) );
  FD_TEST( pinned->credits[0].base_credits==1000UL );

  for( ulong round=0UL; round<2UL; round++ ) {
    for( ulong i=1UL; i<set_cnt; i++ ) set_check( store, ids[i], 1000UL*(i+1UL), i+1UL );
  }

  FD_TEST( pinned->credits[0].base_credits==1000UL );
  fd_epoch_credits_view_fini( pinned );
  set_check( store, ids[0], 1000UL, 1UL );

  free( mem );
}

/* A single cache entry works when no other set is pinned. */

static void
test_single_entry_cache( int fd ) {
  ulong const set_cnt = 3UL;
  void * mem;
  fd_epoch_credits_store_t * store = store_create( &mem, fd, set_cnt, 1UL );

  for( ulong i=0UL; i<set_cnt; i++ ) {
    ushort id = fd_epoch_credits_store_new_fork( store, USHORT_MAX );
    set_write( store, id, 100UL*(i+1UL), i+1UL );
  }
  for( ulong round=0UL; round<2UL; round++ ) {
    for( ulong i=0UL; i<set_cnt; i++ ) set_check( store, (ushort)i, 100UL*(i+1UL), i+1UL );
  }

  free( mem );
}

/* With every id in use, replacing a uniquely held set must release it
   before acquiring the replacement. */

static void
test_new_fork_full( int fd ) {
  ulong const set_cnt = CACHE_CNT+1UL;
  void * mem;
  fd_epoch_credits_store_t * store = store_create( &mem, fd, set_cnt, CACHE_CNT );

  for( ulong i=0UL; i<set_cnt; i++ ) {
    ushort id = fd_epoch_credits_store_new_fork( store, USHORT_MAX );
    FD_TEST( id==(ushort)i );
    set_write( store, id, 10UL*(i+1UL), 1UL );
  }

  ushort tip = (ushort)(set_cnt-1UL);
  ushort id  = fd_epoch_credits_store_new_fork( store, tip );
  FD_TEST( id==tip );
  set_check( store, id, 0UL, 0UL );
  set_write( store, id, 2000UL, 1UL );
  set_check( store, id, 2000UL, 1UL );

  free( mem );
}

/* Peek returns the pinned set without changing the store, even when
   other sets cycle through the rest of the cache. */

static void
test_peek( int fd ) {
  ulong const set_cnt = CACHE_CNT+2UL;
  void * mem;
  fd_epoch_credits_store_t * store = store_create( &mem, fd, set_cnt, CACHE_CNT );

  for( ulong i=0UL; i<set_cnt; i++ ) {
    ushort id = fd_epoch_credits_store_new_fork( store, USHORT_MAX );
    set_write( store, id, 1000UL*(i+1UL), i+1UL );
  }

  fd_epoch_credits_view_t pinned[1];
  FD_TEST( fd_epoch_credits_view_init( pinned, store, 0 ) );
  for( ulong i=1UL; i<set_cnt; i++ ) set_check( store, (ushort)i, 1000UL*(i+1UL), i+1UL );

  ulong                      len = 0UL;
  fd_epoch_credits_t const * ec  = fd_epoch_credits_store_peek( store, 0, &len );
  FD_TEST( ec==pinned->credits );
  FD_TEST( len==1UL );
  FD_TEST( ec[0].base_credits==1000UL );
  fd_epoch_credits_view_fini( pinned );

  free( mem );
}

/* Reset drops every set, including spilled ones. */

static void
test_reset( int fd ) {
  ulong const set_cnt = CACHE_CNT+1UL;
  void * mem;
  fd_epoch_credits_store_t * store = store_create( &mem, fd, set_cnt, CACHE_CNT );

  for( ulong i=0UL; i<set_cnt; i++ ) {
    ushort id = fd_epoch_credits_store_new_fork( store, USHORT_MAX );
    set_write( store, id, 50UL, 1UL );
  }
  FD_TEST( spill_sz( fd ) );

  fd_epoch_credits_store_reset( store );
  FD_TEST( fd_epoch_credits_store_new_fork( store, USHORT_MAX )==0 );
  set_check( store, 0, 0UL, 0UL );

  free( mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  int fd = memfd_create( "test_epoch_credits", 0 );
  FD_TEST( fd>=0 );

  test_footprint();
  test_new_join( fd );
  test_refcnt( fd );
  for( ulong cache_cnt=2UL; cache_cnt<=CACHE_CNT; cache_cnt++ ) test_spill_reload( fd, cache_cnt );
  test_single_entry_cache( fd );
  test_new_fork_full( fd );
  test_peek( fd );
  test_reset( fd );

  FD_TEST( !close( fd ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
