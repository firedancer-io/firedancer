/* Deterministic two-fetch publication race.  Include the implementation so
   the test can fetch an allocated, empty page without inserting into it. */
#define _GNU_SOURCE
#include "fd_txncache.c"
#include "../../util/racesan/fd_racesan.h"
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct {
  fd_txncache_t * tc;
  fd_txncache_fork_id_t fork;
  fd_hash_t blockhash;
  fd_hash_t hash[2];
  ulong page;
  ulong seq;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  int first_io;
  int resume;
  int published;
  int inserted;
  uint first_frame;
} ctx_t;

static void
first_io( void * arg, ulong name ) {
  (void)name;
  ctx_t * c = arg;
  FD_TEST( !pthread_mutex_lock( &c->mutex ) );
  c->first_io = 1;
  FD_TEST( !pthread_cond_broadcast( &c->cond ) );
  while( !c->resume ) FD_TEST( !pthread_cond_wait( &c->cond, &c->mutex ) );
  FD_TEST( !pthread_mutex_unlock( &c->mutex ) );
}

static void *
fetch_first( void * arg ) {
  ctx_t * c = arg;
  fd_racesan_t rs[1];
  fd_racesan_new( rs, c );
  fd_racesan_inject( rs, "txncache:fetch_io", first_io );
  FD_RACESAN_INJECT_BEGIN( rs ) {
    page_fetch( c->tc, c->page, c->seq );
  } FD_RACESAN_INJECT_END;
  FD_TEST( !pthread_mutex_lock( &c->mutex ) );
  c->first_frame = c->tc->page_meta[c->page].frame;
  c->published = 1;
  FD_TEST( !pthread_cond_broadcast( &c->cond ) );
  FD_TEST( !pthread_mutex_unlock( &c->mutex ) );
  return NULL;
}

static void
publish_between_checks( void * arg, ulong name ) {
  (void)name;
  ctx_t * c = arg;
  FD_TEST( !pthread_mutex_lock( &c->mutex ) );
  c->resume = 1;
  FD_TEST( !pthread_cond_broadcast( &c->cond ) );
  while( !c->published ) FD_TEST( !pthread_cond_wait( &c->cond, &c->mutex ) );
  FD_TEST( !pthread_mutex_unlock( &c->mutex ) );
}

static void
insert_during_second_io( void * arg, ulong name ) {
  (void)name;
  ctx_t * c = arg;
  /* The second fetch has dropped the write lock.  The first frame is
     still published, so an ordinary insert can use it. */
  fd_txncache_insert( c->tc, c->fork, c->blockhash.uc, c->hash[0].uc );
  c->inserted = 1;
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  alarm( 20U );
  ulong shsz = fd_txncache_shmem_footprint( 4UL, 256UL, 2UL*sizeof(fd_txncache_txnpage_t) );
  ulong sz = shsz+fd_txncache_footprint( 4UL );
  uchar * mem = mmap( NULL, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( mem!=MAP_FAILED );
  fd_txncache_shmem_t * sh = fd_txncache_shmem_join( fd_txncache_shmem_new( mem, 4UL, 256UL, 2UL*sizeof(fd_txncache_txnpage_t), 0UL ) );
  /* Keep all generated state inside the caller's working directory. */
  char path[] = "./fd-txncache-publish-XXXXXX";
  int fd = mkstemp( path );
  FD_TEST( fd>=0 );
  FD_TEST( !fcntl( fd, F_SETFL, O_DIRECT ) );
  FD_TEST( !unlink( path ) );
  fd_txncache_t * tc = fd_txncache_join( fd_txncache_new( mem+shsz, sh, fd ) );
  fd_hash_t bh[3] = { { .ul={1UL} }, { .ul={2UL} }, { .ul={3UL} } };
  fd_txncache_fork_id_t a = fd_txncache_attach_child( tc, (fd_txncache_fork_id_t){ .val=USHORT_MAX } );
  fd_txncache_finalize_fork( tc, a, 0UL, bh[0].uc );
  fd_txncache_fork_id_t b = fd_txncache_attach_child( tc, a );
  fd_txncache_finalize_fork( tc, b, 0UL, bh[1].uc );
  fd_txncache_fork_id_t target = fd_txncache_attach_child( tc, b );
  fd_txncache_finalize_fork( tc, target, 0UL, bh[2].uc );
  fd_txncache_fork_id_t child = fd_txncache_attach_child( tc, target );
  fd_hash_t other = { .ul={42UL} };
  fd_txncache_insert( tc, child, bh[0].uc, other.uc );
  fd_txncache_insert( tc, child, bh[1].uc, other.uc );
  FD_TEST( !sh->frames_free_cnt );

  ctx_t c = { .tc=tc, .fork=child, .blockhash=bh[2],
              .hash={ { .ul={7UL,1UL} }, { .ul={7UL,2UL} } },
              .mutex=PTHREAD_MUTEX_INITIALIZER, .cond=PTHREAD_COND_INITIALIZER };
  lock_read( tc );
  FD_TEST( !fd_txncache_ensure_txnpage( tc, &tc->blockcache_pool[target.val], 0, &c.page ) );
  c.seq = sh->release_seq;
  fd_rwlock_unread( sh->lock );
  FD_TEST( c.page!=ULONG_MAX && tc->page_meta[c.page].frame==UINT_MAX );

  pthread_t first;
  FD_TEST( !pthread_create( &first, NULL, fetch_first, &c ) );
  FD_TEST( !pthread_mutex_lock( &c.mutex ) );
  while( !c.first_io ) FD_TEST( !pthread_cond_wait( &c.cond, &c.mutex ) );
  FD_TEST( !pthread_mutex_unlock( &c.mutex ) );
  fd_racesan_t rs[1];
  fd_racesan_new( rs, &c );
  fd_racesan_inject( rs, "txncache:fetch_pre_io_check", publish_between_checks );
  fd_racesan_inject( rs, "txncache:fetch_io", insert_during_second_io );
  FD_RACESAN_INJECT_BEGIN( rs ) {
    page_fetch( tc, c.page, c.seq );
  } FD_RACESAN_INJECT_END;
  FD_TEST( !pthread_join( first, NULL ) );

  uint frame = tc->page_meta[c.page].frame;
  ulong owners = 0UL;
  for( ulong i=0UL; i<sh->frames_max; i++ ) owners += tc->frame_page[i]==c.page;
  printf( "second_io=%d first_frame=%u final_frame=%u frame_owners=%lu free_after_fetch=%hu dirty=%u disk_valid=%d\n",
          c.inserted, c.first_frame, frame, owners, tc->txnpages[frame].free,
          tc->page_meta[c.page].dirty, tc->page_meta[c.page].disk_valid );
  if( !c.inserted ) fd_txncache_insert( tc, child, bh[2].uc, c.hash[0].uc );
  fd_txncache_insert( tc, child, bh[2].uc, c.hash[1].uc );
  uint head = tc->blockcache_pool[target.val].heads[fd_txncache_bucket( tc, c.hash[0].uc )];
  uint next = tc->txnpages[frame].txns[head%FD_TXNCACHE_TXNS_PER_PAGE]->blockcache_next;
  printf( "page=%lu head=%u next=%u self_cycle=%d used=%lu\n", c.page, head, next, head==next,
          FD_TXNCACHE_TXNS_PER_PAGE-tc->txnpages[frame].free );
  fflush( stdout );
  FD_TEST( owners==1UL );
  FD_TEST( !c.inserted );
  FD_TEST( head!=next );
  FD_TEST( tc->txnpages[frame].free==FD_TXNCACHE_TXNS_PER_PAGE-2UL );
  FD_TEST( fd_txncache_query( tc, child, bh[2].uc, c.hash[0].uc ) );
  FD_TEST( fd_txncache_query( tc, child, bh[2].uc, c.hash[1].uc ) );
  ulong cnt = 0UL;
  fd_txncache_blockcache_iter_t iter[1];
  for( fd_txncache_blockcache_iter_init( iter, tc, target.val );
       !fd_txncache_blockcache_iter_done( iter ); fd_txncache_blockcache_iter_next( iter ) ) {
    FD_TEST( ++cnt<=2UL );
  }
  fd_txncache_blockcache_iter_fini( iter );
  FD_TEST( cnt==2UL );
  FD_TEST( !close( fd ) );
  FD_TEST( !munmap( mem, sz ) );
  alarm( 0U );
  FD_LOG_NOTICE(( "pass: one published frame, both inserts and snapshot iteration preserved" ));
  fd_halt();
  return 0;
}
