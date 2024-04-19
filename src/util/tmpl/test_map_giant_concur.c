#include "../fd_util.h"
#include "pthread.h"

struct pair {
  ulong mykey;
  ulong mynext;
  ulong val;
};

typedef struct pair pair_t;

#define MAP_NAME map
#define MAP_T    pair_t
#define MAP_KEY  mykey
#define MAP_NEXT mynext
#include "fd_map_giant.c"

static uchar mem[ 32768 ] __attribute__((aligned(128)));

static const ulong max = 512UL;
static volatile ulong queue[512];
static pair_t * map;

static volatile int stop_flag = 0;
static void * read_thread(void * arg) {
  (void)arg;
  ulong rights = 0;
  ulong wrongs = 0;
  ulong blanks = 0;
  while( !stop_flag ) {
    for( ulong i = 0; i < max; ++i ) {
      ulong key = queue[i];
      const pair_t * rec = map_query_safe( map, &key, NULL );
      if( rec == NULL ) {
        blanks++;
      } else {
        /* The result should always be a valid map entry even if it's wrong */
        long idx = rec - map;
        FD_TEST( idx >= 0 && idx < (long)max && rec == map + idx );
        if( rec->mykey == key ) rights++;
        else                    wrongs++;
      }
    }
  }
  FD_LOG_NOTICE(( "rights=%lu wrongs=%lu blanks=%lu", rights, wrongs, blanks ));
  FD_TEST( rights>0 );
  return NULL;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong seed     = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed",     NULL,      1234UL );
  ulong iter_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-max", NULL, 500000000UL );

  FD_LOG_NOTICE(( "Testing with --max %lu --seed %lu --iter-max %lu", max, seed, iter_max ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  for( ulong i = 0; i < max; ++i ) queue[i] = fd_rng_ulong( rng );
  ulong queue_head = 0;
  ulong queue_len = 0;

  ulong align     = map_align();
  ulong footprint = map_footprint( max );
  if( FD_UNLIKELY( (footprint>32768UL) | (align>128UL) ) ) {
    FD_LOG_WARNING(( "skip: adjust mem to support this test" ));
    return 0;
  }
  map = map_join( map_new( mem, max, seed ) ); FD_TEST( map );

  FD_TEST( map_key_cnt ( map )==0UL  );
  FD_TEST( map_key_max ( map )==max  );
  FD_TEST( map_seed    ( map )==seed );

  pthread_t thr = 0;
  FD_TEST( pthread_create(&thr, NULL, read_thread, NULL) == 0 );
  
  for( ulong iter=0UL; iter<iter_max; iter++ ) {
    
    if( iter%200 == 0 ) {
      FD_TEST( !map_verify( map ) );
      
      ulong cnt = 0UL;
      for( map_iter_t iter = map_iter_init( map ); !map_iter_done( map, iter ); iter = map_iter_next( map, iter ) ) {
        pair_t *       p0 = map_iter_ele(       map, iter );
        pair_t const * p1 = map_iter_ele_const( map, iter );
        FD_TEST( p0 );
        FD_TEST( p1 );
        FD_TEST( p1==(pair_t const *)p0 );
        FD_TEST( p0->mykey==p0->val );
        FD_TEST( p1==map_query( map, &p1->mykey, NULL ) );
        FD_TEST( p1==map_query_const( map, &p1->mykey, NULL ) );
        FD_TEST( p1==map_query_safe( map, &p1->mykey, NULL ) );
        cnt++;
      }
      FD_TEST( cnt==map_key_cnt( map ) );
      FD_TEST( cnt==queue_len );
    }

    if( map_is_full( map ) ) {
      ulong k = queue[(queue_head - (queue_len - 1)) & (max - 1)];
      pair_t * p = map_remove( map, &k );
      FD_TEST( p->mykey == k );
      queue_len--;
    }
    FD_TEST( !map_is_full( map ) );

    ulong k = fd_rng_ulong( rng );
    pair_t * p = map_insert( map, &k );
    FD_TEST( p->mykey == k );
    p->val = k;
    queue[(++queue_head) & (max - 1)] = k;
    ++queue_len;
  }

  stop_flag = 1;
  pthread_join( thr, NULL );

  FD_TEST( map_delete( map_leave( map ) )==mem );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
