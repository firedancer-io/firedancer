#include "../fd_util.h"

struct myele {
  uint  mykey;
  int   used;
  uint  val;
  uint  mod;
  ulong mymemo;
};

typedef struct myele myele_t;

/* Note: macros are deliberately written sloppy (generator should be
   robust against this) */

#define MAP_NAME             mymap
#define MAP_ELE_T            myele_t
#define MAP_KEY_T            uint
#define MAP_KEY              mykey
#define MAP_KEY_HASH(k,s)    fd_ulong_hash( s ^ (ulong)*k )
#define MAP_KEY_EQ(k0,k1)    *k0==*k1
#define MAP_MEMOIZE          0
#define MAP_MEMO             mymemo
#define MAP_KEY_EQ_IS_SLOW   0
#define MAP_ELE_IS_FREE(c,e) (!e->used)
#define MAP_ELE_FREE(c,e)    FD_TEST( *(ulong *)c==0x0123456789abcdefUL ); e->used = 0
#define MAP_ELE_MOVE(c,d,s)  FD_TEST( *(ulong *)c==0x0123456789abcdefUL ); *d = *s; s->used = 0
#define MAP_IMPL_STYLE       0
#include "fd_map_slot_para.c"

FD_STATIC_ASSERT( FD_MAP_SUCCESS  == 0, unit_test );
FD_STATIC_ASSERT( FD_MAP_ERR_INVAL==-1, unit_test );
FD_STATIC_ASSERT( FD_MAP_ERR_AGAIN==-2, unit_test );
FD_STATIC_ASSERT( FD_MAP_ERR_FULL ==-5, unit_test );
FD_STATIC_ASSERT( FD_MAP_ERR_KEY  ==-6, unit_test );

FD_STATIC_ASSERT( FD_MAP_FLAG_BLOCKING     ==(1<<0), unit_test );
FD_STATIC_ASSERT( FD_MAP_FLAG_USE_HINT     ==(1<<2), unit_test );
FD_STATIC_ASSERT( FD_MAP_FLAG_PREFETCH_NONE==(0<<3), unit_test );
FD_STATIC_ASSERT( FD_MAP_FLAG_PREFETCH_META==(1<<3), unit_test );
FD_STATIC_ASSERT( FD_MAP_FLAG_PREFETCH_DATA==(2<<3), unit_test );
FD_STATIC_ASSERT( FD_MAP_FLAG_PREFETCH     ==(3<<3), unit_test );

#define SHMEM_MAX (1UL<<20)

static FD_TL uchar shmem[ SHMEM_MAX ];
static FD_TL ulong shmem_cnt = 0UL;

static void *
shmem_alloc( ulong a,
             ulong s ) {
  uchar * m  = (uchar *)fd_ulong_align_up( (ulong)(shmem + shmem_cnt), a );
  shmem_cnt = (ulong)((m + s) - shmem);
  FD_TEST( shmem_cnt <= SHMEM_MAX );
  return (void *)m;
}

static mymap_t * tile_map;
static ulong     tile_iter_cnt;
static ulong     tile_go;

static int
tile_main( int     argc,
           char ** argv ) {

  /* Init local tile context */

  mymap_t *  map      = tile_map;
  ulong      iter_cnt = tile_iter_cnt;
  ulong      tile_idx = (ulong)(uint)argc;
  ulong      tile_cnt = (ulong)argv;

  myele_t * ele0    = (myele_t *)mymap_shele( map );
  ulong     ele_max = mymap_ele_max( map );
  ulong     seed    = mymap_seed( map );

  myele_t   sentinel[1];

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)tile_idx, fd_ulong_hash( tile_cnt ) ) );

  /* Need to upgrade this if using more than 256 tiles or ~16.7M iterations */

  FD_TEST( tile_cnt<(1UL<< 8) );
  FD_TEST( iter_cnt<(1UL<<24) );
  uint local_prefix = (uint)(tile_idx << 24);
  uint local_key    = 0U;

  ulong  save    = shmem_cnt;
  uint * map_key = shmem_alloc( alignof(uint), ele_max*sizeof(uint) );
  ulong  map_cnt = 0UL;

  ulong lock_max = mymap_lock_max();
  ulong lock_cnt = mymap_lock_cnt( map );

  /* Wait for the go code */

  while( !FD_VOLATILE_CONST( tile_go ) ) FD_SPIN_PAUSE();

  /* Hammer the map with all manners of concurrent operations */

  ulong diag_rem = 0UL;
  for( ulong iter_idx=0UL; iter_idx<iter_cnt; iter_idx++ ) {
    if( FD_UNLIKELY( !diag_rem ) ) {
      if( !tile_idx ) FD_LOG_NOTICE(( "Iteration %lu of %lu (local map_cnt %lu)", iter_idx, iter_cnt, map_cnt ));
      if( tile_cnt==1UL ) FD_TEST( !mymap_verify( map ) );
      diag_rem = 1000000UL;
    }
    diag_rem--;

    ulong r = fd_rng_ulong( rng );

    int op       = (int)(r & 15UL);           r >>= 4;
    int flags    = (int)r;                    r >>= 32;
    int blocking = !!(flags & FD_MAP_FLAG_BLOCKING);
    int use_hint = !!(flags & FD_MAP_FLAG_USE_HINT);
    int rdonly   = !!(flags & FD_MAP_FLAG_RDONLY);

    mymap_query_t query[1];

    switch( op ) {

    case 0: { /* blocking read / bad insert (i.e. key already in map) */

      if( FD_UNLIKELY( !map_cnt ) ) break;
      ulong idx  = fd_rng_ulong_roll( rng, map_cnt );
      uint  key  = map_key[ idx ];
      ulong memo = mymap_key_hash( &key, seed );

      if( use_hint ) {
        mymap_hint( map, &key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==mymap_query_memo( query ) );
      }

      int       err = mymap_prepare( map, &key, sentinel, query, flags );
      myele_t * ele = mymap_query_ele( query ); FD_TEST( memo==mymap_query_memo( query ) );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( ele==sentinel         );
        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );
      } else {
        FD_TEST( (ulong)(ele-ele0)<ele_max     );
        FD_TEST( ele->mykey ==key              );
        FD_TEST( ele->mymemo==memo             );
        FD_TEST( ele->val   ==(key ^ ele->mod) );
        FD_TEST( ele->used                     );

        mymap_cancel( query );
      }

      break;
    }

    case 1: { /* good insert (i.e. key not already in map) */

      uint  key  = (uint)(local_prefix | local_key);
      ulong memo = mymap_key_hash( &key, seed );
      uint  mod  = 0U;

      if( use_hint ) {
        mymap_hint( map, &key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==mymap_query_memo( query ) );
      }

      int       err = mymap_prepare( map, &key, sentinel, query, flags );
      myele_t * ele = mymap_query_ele( query ); FD_TEST( memo==mymap_query_memo( query ) );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( ele==sentinel );
        if( err==FD_MAP_ERR_AGAIN ) { FD_TEST( !blocking ); FD_TEST( tile_cnt>1UL ); }
        else                        FD_TEST( err==FD_MAP_ERR_FULL );
      } else {
        FD_TEST( (ulong)(ele-ele0)<ele_max );
        FD_TEST( !ele->used );

        ele->mykey  = key;
        ele->mymemo = memo;
        ele->val    = key ^ mod;
        ele->mod    = mod;
        ele->used   = 1;

        mymap_publish( query );

        map_key[ map_cnt++ ] = key;
        local_key++;
      }

      break;
    }

    case 2: { /* bad remove (i.e. key not already in map) */
      uint  key  = (uint)(local_prefix | local_key); /* not yet inserted */
      ulong memo = mymap_key_hash( &key, seed );

      if( use_hint ) {
        mymap_hint( map, &key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==mymap_query_memo( query ) );
      }

      int err = mymap_remove( map, &key, query, flags );

      if( FD_LIKELY( err ) ) {
        if( err==FD_MAP_ERR_AGAIN ) { FD_TEST( !blocking ); FD_TEST( tile_cnt>1UL ); }
        else                        FD_TEST( err==FD_MAP_ERR_KEY );
      }

      break;
    }

    case 3: { /* good remove (i.e. key already in map) */
      if( FD_UNLIKELY( !map_cnt ) ) break;
      ulong idx  = fd_rng_ulong_roll( rng, map_cnt );
      uint  key  = map_key[ idx ];
      ulong memo = mymap_key_hash( &key, seed );

      if( use_hint ) {
        mymap_hint( map, &key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==mymap_query_memo( query ) );
      }

      int err = mymap_remove( map, &key, query, flags );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );
      } else {
        map_key[ idx ] = map_key[ --map_cnt ];
      }

      break;
    }

    case 4: { /* bad modify (i.e. key not already in map) */

      uint  key  = (uint)(local_prefix | local_key);
      ulong memo = mymap_key_hash( &key, seed );

      if( use_hint ) {
        mymap_hint( map, &key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==mymap_query_memo( query ) );
      }

      int       err = mymap_prepare( map, &key, sentinel, query, flags );
      myele_t * ele = mymap_query_ele( query ); FD_TEST( memo==mymap_query_memo( query ) );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( ele==sentinel );
        if( err==FD_MAP_ERR_AGAIN ) { FD_TEST( !blocking ); FD_TEST( tile_cnt>1UL ); }
        else                        FD_TEST( err==FD_MAP_ERR_FULL );
      } else {
        FD_TEST( (ulong)(ele-ele0)<ele_max );
        FD_TEST( !ele->used );

        mymap_cancel( query );
      }

      break;
    }

    case 5: { /* good modify (i.e. key already in map) */

      if( FD_UNLIKELY( !map_cnt ) ) break;
      ulong idx  = fd_rng_ulong_roll( rng, map_cnt );
      uint  key  = map_key[ idx ];
      ulong memo = mymap_key_hash( &key, seed );

      if( use_hint ) {
        mymap_hint( map, &key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==mymap_query_memo( query ) );
      }

      int       err = mymap_prepare( map, &key, sentinel, query, flags );
      myele_t * ele = mymap_query_ele( query ); FD_TEST( memo==mymap_query_memo( query ) );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( ele==sentinel         );
        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );
      } else {
        FD_TEST( (ulong)(ele-ele0)<ele_max );
        uint mod = ele->mod;
        FD_TEST( ele->mykey ==key          );
        FD_TEST( ele->mymemo==memo         );
        FD_TEST( ele->val   ==(key ^ mod)  );
        FD_TEST( ele->used                 );

        mod++;

        ele->val = key ^ mod;
        ele->mod = mod;

        mymap_publish( query );
      }

      break;
    }

    case 6: { /* bad query (i.e. key not already in map) */

      uint  key  = (uint)(local_prefix | local_key);
      ulong memo = mymap_key_hash( &key, seed );

      if( use_hint ) {
        mymap_hint( map, &key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==mymap_query_memo( query ) );
      }

      int             err = mymap_query_try( map, &key, sentinel, query, flags );
      myele_t const * ele = mymap_query_ele_const( query ); FD_TEST( memo==mymap_query_memo( query ) );

      FD_TEST( ele==sentinel );
      if( err==FD_MAP_ERR_AGAIN ) { FD_TEST( !blocking ); FD_TEST( tile_cnt>1UL ); }
      else                        FD_TEST( err==FD_MAP_ERR_KEY );

      break;
    }

    case 7: { /* good query */

      if( FD_UNLIKELY( !map_cnt ) ) break;
      ulong idx  = fd_rng_ulong_roll( rng, map_cnt );
      uint  key  = map_key[ idx ];
      ulong memo = mymap_key_hash( &key, seed );

      if( use_hint ) {
        mymap_hint( map, &key, query, flags & (~FD_MAP_FLAG_USE_HINT) );
        FD_TEST( memo==mymap_query_memo( query ) );
      }

      int             err = mymap_query_try( map, &key, sentinel, query, flags );
      myele_t const * ele = mymap_query_ele_const( query ); FD_TEST( memo==mymap_query_memo( query ) );

      if( FD_UNLIKELY( err ) ) {
        FD_TEST( ele==sentinel         );
        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );
      } else {
        FD_TEST( (ulong)(ele-ele0)<ele_max );

        uint spec_key = ele->mykey;
        uint spec_mod = ele->mod;
        uint spec_val = ele->val;

        err = mymap_query_test( query );

        if( FD_UNLIKELY( err ) ) {
          FD_TEST( err==FD_MAP_ERR_AGAIN );
          FD_TEST( tile_cnt>1UL          );
        } else {
          FD_TEST( spec_key== key             );
          FD_TEST( spec_val==(key ^ spec_mod) );
        }
      }

      break;
    }

    case 8: { /* parallel iteration */
      ulong version[ lock_max ];

      ulong range_start = fd_rng_ulong_roll( rng, lock_cnt );
      ulong range_cnt   = fd_ulong_min( fd_rng_coin_tosses( rng ), lock_cnt );

      int err = mymap_lock_range( map, range_start, range_cnt, flags, version );

      if( FD_UNLIKELY( err ) ) {

        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );

      } else {

        ulong lock_idx = range_start;
        for( ulong lock_rem=range_cnt; lock_rem; lock_rem-- ) {
          ulong e0 = mymap_lock_ele0( map, lock_idx );
          ulong e1 = mymap_lock_ele1( map, lock_idx );

          FD_TEST( e0< e1      );
          FD_TEST( e1<=ele_max );

          for( ulong ele_idx=e0; ele_idx<e1; ele_idx++ ) {
            myele_t * ele = ele0 + ele_idx;
            if( !ele->used ) continue;

            uint  key  = ele->mykey;
            uint  mod  = ele->mod;
            ulong memo = mymap_key_hash( &key, seed );

            FD_TEST( ele->mymemo==memo         );
            FD_TEST( ele->val   ==(key ^ mod)  );

            if( !rdonly ) {
              mod++;
              ele->mod = mod;
              ele->val = key ^ mod;
            }
          }

          lock_idx = (lock_idx+1UL) & (lock_cnt-1UL);
        }

        mymap_unlock_range( map, range_start, range_cnt, version );

      }

      break;
    }

    case 9: { /* parallel memo iteration */
      ulong memo;
      ulong iter_min;
      if( FD_UNLIKELY( !map_cnt ) ) { /* pick a memo not likely in map */
        memo     = fd_rng_ulong( rng );
        iter_min = 0UL;
      } else { /* pick a memo in map at least once */
        ulong idx = fd_rng_ulong_roll( rng, map_cnt );
        uint  key = map_key[ idx ];
        memo      = mymap_key_hash( &key, seed );
        iter_min  = 1UL;
      }

      mymap_iter_t iter[1];
      int err = mymap_iter_init( map, memo, flags, iter );

      if( FD_UNLIKELY( err ) ) {

        FD_TEST( err==FD_MAP_ERR_AGAIN );
        FD_TEST( !blocking             );
        FD_TEST( tile_cnt>1UL          );

      } else {

        ulong iter_cnt = 0UL;
        while( !mymap_iter_done( iter ) ) {
          myele_t * ele = mymap_iter_ele( iter );

          FD_TEST( (ulong)(ele-ele0)<ele_max );

          uint  key   = ele->mykey;
          uint  mod   = ele->mod;

          FD_TEST( mymap_key_hash( &key, seed )==memo );
          FD_TEST( ele->mymemo==memo                  );
          FD_TEST( ele->val   ==(key ^ mod)           );
          FD_TEST( ele->used                          );

          if( !rdonly ) {
            mod++;
            ele->mod = mod;
            ele->val = key ^ mod;
          }

          iter_cnt++;

          FD_TEST( mymap_iter_next( iter )==iter );
        }

        FD_TEST( mymap_iter_fini( iter )==iter );

        FD_TEST( iter_cnt>=iter_min );
      }

      break;
    }

    default:
      break;
    }
  }

  /* Clean up for the next text battery */

  for( ulong map_idx=0UL; map_idx<map_cnt; map_idx++ )
    FD_TEST( !mymap_remove( map, map_key + map_idx, NULL, FD_MAP_FLAG_BLOCKING ) );

  shmem_cnt = save;

  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong ele_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--ele-max",   NULL, 4096UL                         );
  ulong lock_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--lock-cnt",  NULL, mymap_lock_cnt_est ( ele_max ) );
  ulong probe_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--probe-max", NULL, mymap_probe_max_est( ele_max ) );
  ulong seed      = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed",      NULL, 1234UL                         );
  ulong iter_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-cnt",  NULL, 10000000UL                     );

  FD_LOG_NOTICE(( "Testing (--ele-max %lu --lock-cnt %lu --probe-max %lu --seed %lu --iter-cnt %lu)",
                  ele_max, lock_cnt, probe_max, seed, iter_cnt ));

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  /* Create the shared element store and initialize it to free */

  void * shele = shmem_alloc( alignof(myele_t), sizeof(myele_t)*ele_max );
  memset( shele, 0, sizeof(myele_t)*ele_max );

  FD_LOG_NOTICE(( "Testing misc" ));

  ulong lock_max = mymap_lock_max();
  FD_TEST( fd_ulong_is_pow2( lock_max ) );

  for( ulong rem=1000000UL; rem; rem-- ) {
    uint  r  = fd_rng_uint( rng );
    ulong em = 1UL << (r&63U);                     r >>= 6;
    uint  k0 = fd_rng_uint( rng ) >> (int)(r&31U); r >>= 5;
    uint  k1 = fd_rng_uint( rng ) >> (int)(r&31U); r >>= 5;

    ulong lock_cnt_est = mymap_lock_cnt_est( em );
    FD_TEST( fd_ulong_is_pow2( lock_cnt_est ) && lock_cnt_est<=em );

    ulong probe_max_est = mymap_probe_max_est( em );
    FD_TEST( fd_ulong_is_pow2( probe_max_est ) && probe_max_est<=em );

    int eq = (k0==k1);
    FD_TEST( mymap_key_eq(&k0,&k0)==1 && mymap_key_eq(&k1,&k0)==eq && mymap_key_eq(&k0,&k1)==eq && mymap_key_eq(&k1,&k1)==1 );

    ulong s = fd_rng_ulong( rng );
    ulong h = mymap_key_hash( &k0, s ); FD_COMPILER_FORGET( h ); /* All values possible and hash quality depends on the user */
  }

  FD_LOG_NOTICE(( "Testing construction" ));

  ulong align = mymap_align();
  FD_TEST( fd_ulong_is_pow2( align ) );

  FD_TEST( !mymap_footprint( 0UL,     lock_cnt,                              probe_max   ) ); /* ele_max  not a power of 2 */
  FD_TEST( !mymap_footprint( ele_max, 0UL,                                   probe_max   ) ); /* lock_cnt not a power of 2 */
  FD_TEST( !mymap_footprint( ele_max, 2UL*fd_ulong_min( lock_max, ele_max ), probe_max   ) ); /* too large lock_cnt */
  FD_TEST( !mymap_footprint( ele_max, lock_cnt,                              0UL         ) ); /* too small probe_max */
  FD_TEST( !mymap_footprint( ele_max, lock_cnt,                              ele_max+1UL ) ); /* too large probe_max */

  ulong footprint = mymap_footprint( ele_max, lock_cnt, probe_max );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  void * shmap = shmem_alloc( align, footprint );
  mymap_t map[1];

  FD_TEST( !mymap_new( NULL,        ele_max, lock_cnt,                              probe_max,   seed ) ); /* NULL       shmem */
  FD_TEST( !mymap_new( (void *)1UL, ele_max, lock_cnt,                              probe_max,   seed ) ); /* misaligned shmem */
  FD_TEST( !mymap_new( shmap,       0UL,     lock_cnt,                              probe_max,   seed ) ); /* ele_max  not a power of 2   */
  FD_TEST( !mymap_new( shmap,       ele_max, 0UL,                                   probe_max,   seed ) ); /* lock_cnt not a power of 2   */
  FD_TEST( !mymap_new( shmap,       ele_max, 2UL*fd_ulong_min( lock_max, ele_max ), probe_max,   seed ) ); /* too large lock_cnt */
  FD_TEST( !mymap_new( shmap,       ele_max, lock_cnt,                              0UL,         seed ) ); /* too small probe_max */
  FD_TEST( !mymap_new( shmap,       ele_max, lock_cnt,                              ele_max+1UL, seed ) ); /* too large probe_max */
  /* seed is arbitrary */

  FD_TEST(  mymap_new( shmap, ele_max, lock_cnt, probe_max, seed )==shmap );

  FD_TEST( !mymap_join( NULL,        shmap,       shele       )      ); /* NULL       ljoin */
  FD_TEST( !mymap_join( (void *)1UL, shmap,       shele       )      ); /* misaligned ljoin */
  FD_TEST( !mymap_join( map,         NULL,        shele       )      ); /* NULL       shmap */
  FD_TEST( !mymap_join( map,         (void *)1UL, shele       )      ); /* misaligned shmap */
  FD_TEST( !mymap_join( map,         shmap,       NULL        )      ); /* NULL       shele */
  FD_TEST( !mymap_join( map,         shmap,       (void *)1UL )      ); /* misaligned shele */
  FD_TEST(  mymap_join( map,         shmap,       shele       )==map );

  FD_LOG_NOTICE(( "Initializing context" ));

  FD_TEST( mymap_ctx_max( map )>=8UL );
  ulong * ctx = (ulong *)mymap_ctx( map );
  FD_TEST( ctx );
  FD_TEST( fd_ulong_is_aligned( (ulong)ctx, alignof(ulong) ) );

  ctx[0] = 0x0123456789abcdefUL;

  FD_TEST( ctx==(ulong *)mymap_ctx_const( map ) );

  FD_LOG_NOTICE(( "Testing accessors" ));

  FD_TEST( mymap_ele_max  ( map )==ele_max   );
  FD_TEST( mymap_lock_cnt ( map )==lock_cnt  );
  FD_TEST( mymap_probe_max( map )==probe_max );
  FD_TEST( mymap_seed     ( map )==seed      );

  FD_TEST( mymap_shmap_const( map )==shmap );
  FD_TEST( mymap_shele_const( map )==shele );

  FD_TEST( mymap_shmap( map )==shmap );
  FD_TEST( mymap_shele( map )==shele );

  for( ulong ele_idx=0UL; ele_idx<ele_max; ele_idx++ ) {
    ulong lock_idx = mymap_ele_lock ( map, ele_idx  ); FD_TEST( lock_idx<lock_cnt );
    ulong ele0     = mymap_lock_ele0( map, lock_idx ); FD_TEST( ele0<=ele_idx );
    ulong ele1     = mymap_lock_ele1( map, lock_idx ); FD_TEST( ele_idx< ele1 );
  }

  ulong test_ele1 = 0UL;
  for( ulong lock_idx=0UL; lock_idx<lock_cnt; lock_idx++ ) {
    ulong test_ele0 = test_ele1;
    /**/  test_ele1 = mymap_lock_ele1( map, lock_idx );
    FD_TEST( mymap_lock_ele0( map, lock_idx )==test_ele0 );
    FD_TEST( test_ele0<test_ele1 );
  }
  FD_TEST( test_ele1==ele_max );

  /* FIXME: use tpool here */

  tile_map      = map;
  tile_iter_cnt = iter_cnt;

  ulong tile_max = fd_tile_cnt();
  for( ulong tile_cnt=1UL; tile_cnt<=tile_max; tile_cnt++ ) {

    FD_LOG_NOTICE(( "Testing concurrent operation on %lu tiles", tile_cnt ));

    FD_COMPILER_MFENCE();
    FD_VOLATILE( tile_go ) = 0;
    FD_COMPILER_MFENCE();

    for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ )
      fd_tile_exec_new( tile_idx, tile_main, (int)(uint)tile_idx, (char **)tile_cnt );

    fd_log_sleep( (long)0.1e9 );

    FD_COMPILER_MFENCE();
    FD_VOLATILE( tile_go ) = 1;
    FD_COMPILER_MFENCE();

    tile_main( 0, (char **)tile_cnt );

    for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) fd_tile_exec_delete( fd_tile_exec( tile_idx ), NULL );

    FD_TEST( !mymap_verify( map ) );
  }

  FD_LOG_NOTICE(( "Testing destruction" ));

  FD_TEST( !mymap_leave( NULL )      ); /* NULL join */
  FD_TEST(  mymap_leave( map  )==map );

  FD_TEST( !mymap_delete( NULL        )        ); /* NULL shmap */
  FD_TEST( !mymap_delete( (void *)1UL )        ); /* misaligned shmap */
  FD_TEST(  mymap_delete( shmap       )==shmap );

  FD_TEST( !mymap_delete( shmap )           ); /* bad magic */
  FD_TEST( !mymap_join( map, shmap, shele ) ); /* bad magic */

  FD_LOG_NOTICE(( "bad error code   (%i-%s)", 1,                mymap_strerror( 1                ) ));
  FD_LOG_NOTICE(( "FD_MAP_SUCCESS   (%i-%s)", FD_MAP_SUCCESS,   mymap_strerror( FD_MAP_SUCCESS   ) ));
  FD_LOG_NOTICE(( "FD_MAP_ERR_INVAL (%i-%s)", FD_MAP_ERR_INVAL, mymap_strerror( FD_MAP_ERR_INVAL ) ));
  FD_LOG_NOTICE(( "FD_MAP_ERR_AGAIN (%i-%s)", FD_MAP_ERR_AGAIN, mymap_strerror( FD_MAP_ERR_AGAIN ) ));
  FD_LOG_NOTICE(( "FD_MAP_ERR_FULL  (%i-%s)", FD_MAP_ERR_FULL,  mymap_strerror( FD_MAP_ERR_FULL  ) ));
  FD_LOG_NOTICE(( "FD_MAP_ERR_KEY   (%i-%s)", FD_MAP_ERR_KEY,   mymap_strerror( FD_MAP_ERR_KEY   ) ));

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
