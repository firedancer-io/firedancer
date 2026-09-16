#include "../fd_util.h"

struct myele {
  uint mynext;
  uint val;
};

typedef struct myele myele_t;

#define POOL_NAME          mypool
#define POOL_ELE_T         myele_t
#define POOL_IDX_T         uint
#define POOL_NEXT          mynext
#define POOL_IMPL_STYLE    0
#define POOL_LAZY          1
#include "fd_pool_para.c"

FD_STATIC_ASSERT( FD_POOL_SUCCESS    == 0, unit_test );
FD_STATIC_ASSERT( FD_POOL_ERR_AGAIN  ==-1, unit_test );
FD_STATIC_ASSERT( FD_POOL_ERR_CORRUPT==-2, unit_test );

#define SHMEM_MAX (131072UL)

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

static void
test_acquire_nolock( mypool_t * pool,
                     myele_t *  ele,
                     ulong      ele_max ) {
  if( FD_UNLIKELY( !ele_max ) ) return;

  mypool_reset( pool );

  ulong top0  = pool->pool->ver_top;
  ulong lazy0 = pool->pool->ver_lazy;
  myele_t * ele0 = mypool_acquire_nolock( pool );
  FD_TEST( ele0==ele );
  FD_TEST( pool->pool->ver_top==top0 );
  FD_TEST( mypool_private_vidx_ver( pool->pool->ver_lazy )==mypool_private_vidx_ver( lazy0 )+2UL );
  FD_TEST( mypool_private_vidx_idx( pool->pool->ver_lazy )==(ele_max>1UL ? 1UL : mypool_idx_null()) );

  mypool_release( pool, ele0 );
  ulong top1  = pool->pool->ver_top;
  ulong lazy1 = pool->pool->ver_lazy;
  FD_TEST( mypool_private_vidx_idx( top1 )==0UL );
  FD_TEST( mypool_acquire_nolock( pool )==ele0 );
  FD_TEST( mypool_private_vidx_ver( pool->pool->ver_top )==mypool_private_vidx_ver( top1 )+2UL );
  FD_TEST( mypool_private_vidx_idx( pool->pool->ver_top )==mypool_idx_null() );
  FD_TEST( pool->pool->ver_lazy==lazy1 );

  mypool_reset( pool );
  for( ulong i=0UL; i<ele_max; i++ ) FD_TEST( mypool_acquire_nolock( pool )==ele+i );
  ulong top_empty = pool->pool->ver_top;
  ulong lazy_empty = pool->pool->ver_lazy;
  FD_TEST( !mypool_acquire_nolock( pool ) );
  FD_TEST( pool->pool->ver_top ==top_empty  );
  FD_TEST( pool->pool->ver_lazy==lazy_empty );
  for( ulong i=0UL; i<ele_max; i++ ) mypool_release( pool, ele+i );
  FD_TEST( !mypool_verify( pool ) );

  mypool_reset( pool );
  FD_TEST( !mypool_lock( pool, 1 ) );
  ulong top_locked  = pool->pool->ver_top;
  ulong lazy_locked = pool->pool->ver_lazy;
  ele0 = mypool_acquire_nolock( pool );
  FD_TEST( ele0==ele );
  FD_TEST( pool->pool->ver_top==top_locked );
  FD_TEST( mypool_private_vidx_ver( pool->pool->ver_lazy )==mypool_private_vidx_ver( lazy_locked )+2UL );
  mypool_unlock( pool );
  mypool_release( pool, ele0 );
  FD_TEST( !mypool_verify( pool ) );
}

static myele_t canary[1]; /* sentinel for out[cnt] */

/* acquire_batch with a canary at out[cnt] */

static void
batch( mypool_t * pool,
       ulong      cnt,
       myele_t ** out ) {
  out[ cnt ] = canary;
  myele_t ** result = mypool_acquire_batch( pool, cnt, out );
  FD_TEST( result==(cnt ? out : NULL) );
  FD_TEST( out[ cnt ]==canary );
}

static void
test_acquire_batch( mypool_t * pool,
                    myele_t *  ele,
                    ulong      ele_max,
                    fd_rng_t * rng ) {
  ulong      save = shmem_cnt;
  myele_t ** out  = shmem_alloc( alignof(myele_t *), (ele_max+1UL)*sizeof(myele_t *) );
  myele_t ** out2 = shmem_alloc( alignof(myele_t *), (ele_max+1UL)*sizeof(myele_t *) );

  mypool_reset( pool );

  /* cnt==0 is a no-op, even on an empty element store */

  ulong top0  = pool->pool->ver_top;
  ulong lazy0 = pool->pool->ver_lazy;
  batch( pool, 0UL, out );
  FD_TEST( pool->pool->ver_top ==top0  );
  FD_TEST( pool->pool->ver_lazy==lazy0 );

  if( FD_UNLIKELY( !ele_max ) ) { shmem_cnt = save; return; }

  /* Lazy only: ascending, one CAS on ver_lazy, ver_top untouched */

  ulong k = fd_ulong_min( ele_max, 3UL );
  batch( pool, k, out );
  for( ulong i=0UL; i<k; i++ ) FD_TEST( out[ i ]==ele+i );
  FD_TEST( pool->pool->ver_top==top0 );
  FD_TEST( mypool_private_vidx_ver( pool->pool->ver_lazy )==mypool_private_vidx_ver( lazy0 )+2UL );
  FD_TEST( mypool_private_vidx_idx( pool->pool->ver_lazy )==(k<ele_max ? k : mypool_idx_null()) );

  /* Stack only: LIFO, one CAS on ver_top, ver_lazy untouched */

  for( ulong i=0UL; i<k; i++ ) mypool_release( pool, ele+i );
  ulong top1  = pool->pool->ver_top;
  ulong lazy1 = pool->pool->ver_lazy;
  FD_TEST( mypool_private_vidx_idx( top1 )==k-1UL );

  /* cnt==0 is also a no-op on a non-empty free stack */

  batch( pool, 0UL, out2 );
  FD_TEST( pool->pool->ver_top ==top1  );
  FD_TEST( pool->pool->ver_lazy==lazy1 );

  batch( pool, k, out );
  for( ulong i=0UL; i<k; i++ ) FD_TEST( out[ i ]==ele+(k-1UL-i) );
  FD_TEST( mypool_private_vidx_ver( pool->pool->ver_top )==mypool_private_vidx_ver( top1 )+2UL );
  FD_TEST( mypool_private_vidx_idx( pool->pool->ver_top )==mypool_idx_null() );
  FD_TEST( pool->pool->ver_lazy==lazy1 );

  /* Split: stack first (LIFO) then lazy (ascending), one CAS each */

  ulong m = fd_ulong_min( ele_max-k, 2UL );
  if( m ) {
    for( ulong i=0UL; i<k; i++ ) mypool_release( pool, ele+i );
    ulong top2  = pool->pool->ver_top;
    ulong lazy2 = pool->pool->ver_lazy;
    batch( pool, k+m, out );
    for( ulong i=0UL; i<k; i++ ) FD_TEST( out[ i   ]==ele+(k-1UL-i) );
    for( ulong i=0UL; i<m; i++ ) FD_TEST( out[ k+i ]==ele+k+i        );
    FD_TEST( mypool_private_vidx_ver( pool->pool->ver_top  )==mypool_private_vidx_ver( top2  )+2UL );
    FD_TEST( mypool_private_vidx_idx( pool->pool->ver_top  )==mypool_idx_null() );
    FD_TEST( mypool_private_vidx_ver( pool->pool->ver_lazy )==mypool_private_vidx_ver( lazy2 )+2UL );
    FD_TEST( mypool_private_vidx_idx( pool->pool->ver_lazy )==(k+m<ele_max ? k+m : mypool_idx_null()) );
  }

  /* Any subset can go back with release and comes back LIFO */

  ulong held = k+m;
  ulong rel  = 0UL;
  for( ulong i=1UL; i<held; i+=2UL ) { mypool_release( pool, out[ i ] ); rel++; }
  FD_TEST( !mypool_verify( pool ) );
  if( rel ) {
    batch( pool, rel, out2 );
    for( ulong i=0UL; i<rel; i++ ) FD_TEST( out2[ i ]==out[ 1UL+2UL*(rel-1UL-i) ] );
  }
  for( ulong i=0UL; i<held; i++ ) mypool_release( pool, out[ i ] );
  FD_TEST( !mypool_verify( pool ) );

  /* Full drain from reset: all lazy, ascending, pool then empty */

  mypool_reset( pool );
  batch( pool, ele_max, out );
  for( ulong i=0UL; i<ele_max; i++ ) FD_TEST( out[ i ]==ele+i );
  FD_TEST(  mypool_is_empty( pool ) );
  FD_TEST( !mypool_peek    ( pool ) );

  /* Failure returns any partially acquired elements */

  if( ele_max>1UL ) {
    mypool_release( pool, out[ 0 ] );
    FD_TEST( !mypool_acquire_batch( pool, 2UL, out2 ) );
    FD_TEST( mypool_acquire( pool )==out[ 0 ] );
  } else {
    FD_TEST( !mypool_acquire_batch( pool, 1UL, out2 ) );
  }

  /* Long random chain: one batch returns it in reverse release order */

  for( ulong i=ele_max-1UL; i>0UL; i-- ) {
    ulong j = fd_rng_ulong_roll( rng, i+1UL );
    myele_t * tmp = out[ i ]; out[ i ] = out[ j ]; out[ j ] = tmp;
  }
  for( ulong i=0UL; i<ele_max; i++ ) mypool_release( pool, out[ i ] );
  FD_TEST( !mypool_verify( pool ) );
  ulong top3  = pool->pool->ver_top;
  ulong lazy3 = pool->pool->ver_lazy;
  FD_TEST( mypool_private_vidx_idx( lazy3 )==mypool_idx_null() );
  batch( pool, ele_max, out2 );
  for( ulong i=0UL; i<ele_max; i++ ) FD_TEST( out2[ i ]==out[ ele_max-1UL-i ] );
  FD_TEST( mypool_private_vidx_ver( pool->pool->ver_top )==mypool_private_vidx_ver( top3 )+2UL );
  FD_TEST( mypool_private_vidx_idx( pool->pool->ver_top )==mypool_idx_null() );
  FD_TEST( pool->pool->ver_lazy==lazy3 );
  for( ulong i=0UL; i<ele_max; i++ ) mypool_release( pool, out2[ i ] );
  FD_TEST( !mypool_verify( pool ) );

  shmem_cnt = save;
}

/* test_acquire_batch_refill: a batch sees an empty stack, then another
   thread releases an element while a third drains the lazy region.
   The batch must recheck the stack instead of CRITing.  The batch tile
   is frozen between its phases with the lazy lock bit. */

static mypool_t * refill_pool;
static myele_t *  refill_out[ 3 ]; /* 2 elements + canary */

static int
refill_tile_main( int     argc,
                  char ** argv ) {
  (void)argc; (void)argv;
  batch( refill_pool, 2UL, refill_out );
  return 0;
}

static void
test_acquire_batch_refill( mypool_t * pool,
                           myele_t *  ele,
                           ulong      ele_max,
                           int        argc,
                           char **    argv ) {
  if( FD_UNLIKELY( (ele_max<3UL) | (fd_tile_cnt()<2UL) ) ) {
    FD_LOG_NOTICE(( "Skipping batch refill test (needs --ele-max>=3 and at least 2 tiles)" ));
    return;
  }

  mypool_reset( pool );
  myele_t * x = mypool_acquire( pool ); FD_TEST( x==ele     ); /* lazy now starts at 1 */
  myele_t * y = mypool_acquire( pool ); FD_TEST( y==ele+1UL ); /* lazy now starts at 2 */
  mypool_release( pool, x );                                   /* free stack is {x} */

  /* Lock lazy so the batch tile stops after its stack phase */

  ulong ver_lazy = pool->pool->ver_lazy;
  FD_TEST( mypool_private_vidx_idx( ver_lazy )==2UL );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( pool->pool->ver_lazy ) = mypool_private_vidx( mypool_private_vidx_ver( ver_lazy )|1UL, 2UL );
  FD_COMPILER_MFENCE();

  refill_pool = pool;
  fd_tile_exec_new( 1UL, refill_tile_main, argc, argv );

  /* Wait for the batch tile to pop x and drain the stack */

  while( !mypool_idx_is_null( mypool_private_vidx_idx( FD_VOLATILE_CONST( pool->pool->ver_top ) ) ) ) FD_SPIN_PAUSE();

  /* Second thread releases y ... */

  mypool_release( pool, y );

  /* ... third thread drains lazy, then unlock */

  FD_COMPILER_MFENCE();
  FD_VOLATILE( pool->pool->ver_lazy ) = mypool_private_vidx( mypool_private_vidx_ver( ver_lazy )+2UL, mypool_idx_null() );
  FD_COMPILER_MFENCE();

  fd_tile_exec_delete( fd_tile_exec( 1UL ), NULL );

  FD_TEST( refill_out[ 0 ]==x );
  FD_TEST( refill_out[ 1 ]==y );

  /* Hand back what the third thread and the batch took */

  for( ulong i=2UL; i<ele_max; i++ ) mypool_release( pool, ele+i );
  mypool_release( pool, x );
  mypool_release( pool, y );
  FD_TEST( !mypool_verify( pool ) );
}

/* tile_batch_max: 0 for acquire / release only (pool may run dry), else
   the largest batch to request (per tile quota applies).
   tile_active_cnt: tiles in this round (fd_tile_cnt() is the configured
   count). */

static mypool_t * tile_pool;
static ulong      tile_ele_max;
static ulong      tile_iter_cnt;
static ulong      tile_batch_max;
static ulong      tile_active_cnt;
static ulong      tile_go;

/* tile_owner[i]: 0 if free, tile_idx+1 if held.  Atomic claims catch an
   element handed to two tiles at once. */

static ulong * tile_owner;

static void
tile_claim( mypool_t * pool,
            myele_t *  ele,
            ulong      tile_idx ) {
  ulong idx = mypool_idx( pool, ele );
  FD_TEST( idx<tile_ele_max );
  FD_TEST( FD_ATOMIC_CAS( &tile_owner[ idx ], 0UL, tile_idx+1UL )==0UL );
}

static void
tile_unclaim( mypool_t * pool,
              myele_t *  ele,
              ulong      tile_idx ) {
  ulong idx = mypool_idx( pool, ele );
  FD_TEST( FD_ATOMIC_CAS( &tile_owner[ idx ], tile_idx+1UL, 0UL )==tile_idx+1UL );
}

/* Repurpose a held element's next (out of bounds or random in bounds)
   like a real user would.  A stale walker must retry, not trust it.
   release rewrites next. */

static void
tile_scribble( myele_t *  ele,
               ulong      ele_max,
               fd_rng_t * rng ) {
  ele->mynext = (fd_rng_uint( rng ) & 1U) ? (uint)ele_max : (uint)fd_rng_ulong_roll( rng, ele_max );
}

/* Mixes acquire, release and (if tile_batch_max) acquire_batch.  Without
   batches the pool may run dry.  With batches each tile holds at most
   ele_max/tile_cnt so acquire_batch can never run short. */

static int
tile_main( int     argc,
           char ** argv ) {
  (void)argc; (void)argv;
  mypool_t * pool      = tile_pool;
  ulong      ele_max   = tile_ele_max;
  ulong      iter_cnt  = tile_iter_cnt;
  ulong      batch_max = tile_batch_max;
  ulong      tile_idx  = fd_tile_idx();
  ulong      tile_cnt  = tile_active_cnt;

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)tile_idx, 0UL ) );

  ulong      quota   = batch_max ? ele_max/tile_cnt : ULONG_MAX;
  ulong      save    = shmem_cnt;
  myele_t ** acq_ele = shmem_alloc( alignof(myele_t *), ele_max*sizeof(myele_t *) );
  ulong      acq_cnt = 0UL;

  batch_max = fd_ulong_min( batch_max, quota );

  while( !FD_VOLATILE_CONST( tile_go ) ) FD_SPIN_PAUSE();

  for( ulong iter_idx=0UL; iter_idx<iter_cnt; iter_idx++ ) {
    switch( fd_rng_uint_roll( rng, batch_max ? 3U : 2U ) ) {

    case 0: { /* acquire one */
      if( FD_UNLIKELY( acq_cnt>=quota ) ) break;
      myele_t * ele = mypool_acquire( pool );
      if( FD_LIKELY( ele ) ) {
        tile_claim( pool, ele, tile_idx );
        tile_scribble( ele, ele_max, rng );
        acq_ele[ acq_cnt++ ] = ele;
      } else {
        FD_TEST( !batch_max );                           /* never runs dry under quota */
        if( tile_cnt==1UL ) FD_TEST( acq_cnt==ele_max ); /* a lone tile only runs dry when it holds everything */
      }
      break;
    }

    case 1: { /* release one */
      if( acq_cnt ) {
        ulong acq_idx = fd_rng_ulong_roll( rng, acq_cnt );
        tile_unclaim( pool, acq_ele[ acq_idx ], tile_idx );
        mypool_release( pool, acq_ele[ acq_idx ] );
        acq_ele[ acq_idx ] = acq_ele[ --acq_cnt ];
      }
      break;
    }

    case 2: { /* acquire batch */
      ulong n = fd_ulong_min( 1UL+fd_rng_ulong_roll( rng, batch_max ), quota-acq_cnt );
      if( FD_LIKELY( n ) ) {
        FD_TEST( mypool_acquire_batch( pool, n, acq_ele+acq_cnt )==acq_ele+acq_cnt );
        for( ulong j=0UL; j<n; j++ ) {
          tile_claim( pool, acq_ele[ acq_cnt+j ], tile_idx );
          tile_scribble( acq_ele[ acq_cnt+j ], ele_max, rng );
        }
        acq_cnt += n;
      }
      break;
    }

    default: /* never get here */
      break;
    }
  }

  for( ulong acq_idx=0UL; acq_idx<acq_cnt; acq_idx++ ) {
    tile_unclaim( pool, acq_ele[ acq_idx ], tile_idx );
    mypool_release( pool, acq_ele[ acq_idx ] );
  }
  shmem_cnt = save;

  fd_rng_delete( fd_rng_leave( rng ) );

  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong ele_max  = fd_env_strip_cmdline_ulong( &argc, &argv, "--ele-max",  NULL, 1024UL   );
  ulong iter_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-cnt", NULL, 100000UL );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_LOG_NOTICE(( "Testing (--ele-max %lu --iter-cnt %lu)", ele_max, iter_cnt ));

  FD_LOG_NOTICE(( "Testing construction" ));

  FD_TEST( mypool_ele_max_max()>0UL );

  myele_t * shele = shmem_alloc( alignof(myele_t), sizeof(myele_t)*ele_max );

  ulong align = mypool_align();
  FD_TEST( fd_ulong_is_pow2( align ) );

  ulong footprint = mypool_footprint();
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  void * shpool = shmem_alloc( align, footprint );
  FD_TEST( !mypool_new( NULL        )    ); /* NULL       shmem */
  FD_TEST( !mypool_new( (void *)1UL )    ); /* misaligned shmem */
  FD_TEST(  mypool_new( shpool )==shpool );

  mypool_t pool[1];
  FD_TEST( !mypool_join( NULL,        shpool,      shele,       ele_max   ) ); // NULL       ljoin
  FD_TEST( !mypool_join( (void *)1UL, shpool,      shele,       ele_max   ) ); // misaligned ljoin
  FD_TEST( !mypool_join( pool,        NULL,        shele,       ele_max   ) ); // NULL       shpool
  FD_TEST( !mypool_join( pool,        (void *)1UL, shele,       ele_max   ) ); // misaligned shpool
  FD_TEST(  mypool_join( pool,        shpool,      NULL,        ele_max   )==(ele_max ? NULL : pool) ); // NULL shele
  FD_TEST( !mypool_join( pool,        shpool,      (void *)1UL, ele_max   ) ); // misaligned shele
  FD_TEST( !mypool_join( pool,        shpool,      shele,       ULONG_MAX ) ); // too large  ele_max
  FD_TEST(  mypool_join( pool, shpool, shele, ele_max )==pool );

  FD_LOG_NOTICE(( "Testing accessors" ));

  FD_TEST( mypool_shpool_const( pool )==shpool  );
  FD_TEST( mypool_shele_const ( pool )==shele   );
  FD_TEST( mypool_ele_max     ( pool )==ele_max );
  FD_TEST( mypool_shpool      ( pool )==shpool  );
  FD_TEST( mypool_shele       ( pool )==shele   );

  FD_LOG_NOTICE(( "Testing conversion" ));

  ulong null_idx = mypool_idx_null();
  FD_TEST( null_idx>=ele_max );

  FD_TEST( mypool_idx_is_null( null_idx )==1 );
  FD_TEST( mypool_idx      ( pool, NULL            )==null_idx );
  FD_TEST( mypool_ele      ( pool, null_idx        )==NULL     );
  FD_TEST( mypool_ele_const( pool, null_idx        )==NULL     );
  for( ulong ele_idx=0UL; ele_idx<ele_max; ele_idx++ ) {
    myele_t const * ele = shele + ele_idx;
    FD_TEST( mypool_idx_is_null( ele_idx )==0 );
    FD_TEST( mypool_idx      ( pool, ele     )==ele_idx );
    FD_TEST( mypool_ele      ( pool, ele_idx )==ele     );
    FD_TEST( mypool_ele_const( pool, ele_idx )==ele     );
  }
  FD_TEST( mypool_idx_is_null( ele_max )==0 );
  FD_TEST( mypool_idx      ( pool, shele + ele_max )==null_idx );
  FD_TEST( mypool_ele      ( pool, ele_max         )==NULL     );
  FD_TEST( mypool_ele_const( pool, ele_max         )==NULL     );

  FD_LOG_NOTICE(( "Testing initialization" ));

  FD_TEST( !mypool_lock( pool, 1 ) );
  FD_TEST(  mypool_lock( pool, 0 )==FD_POOL_ERR_AGAIN ); /* non-blocking on a locked pool */

  FD_TEST( !mypool_verify    ( pool ) );
  FD_TEST( !mypool_peek_const( pool ) );
  FD_TEST( !mypool_peek      ( pool ) );

  mypool_reset( pool ); /* all in pool in increasing order */
  FD_TEST(  mypool_peek_const( pool )==(ele_max ? shele : NULL) );
  FD_TEST(  mypool_peek      ( pool )==(ele_max ? shele : NULL) );

  FD_TEST( !mypool_verify  ( pool ) );

  mypool_unlock( pool );

  FD_LOG_NOTICE(( "Testing nolock acquire" ));
  test_acquire_nolock( pool, shele, ele_max );

  FD_LOG_NOTICE(( "Testing batch acquire" ));
  test_acquire_batch( pool, shele, ele_max, rng );

  FD_LOG_NOTICE(( "Testing batch acquire refill" ));
  test_acquire_batch_refill( pool, shele, ele_max, argc, argv );

  /* FIXME: use tpool here */

  tile_pool     = pool;
  tile_ele_max  = ele_max;
  tile_iter_cnt = iter_cnt;
  tile_owner    = shmem_alloc( alignof(ulong), ele_max*sizeof(ulong) );
  fd_memset( tile_owner, 0, ele_max*sizeof(ulong) );

  ulong tile_max = fd_tile_cnt();
  for( ulong pass=0UL; pass<2UL; pass++ ) {
    ulong batch_max = pass ? 16UL : 0UL;

    for( ulong tile_cnt=1UL; tile_cnt<=tile_max; tile_cnt++ ) {

      if( batch_max && ele_max<tile_cnt ) {
        FD_LOG_NOTICE(( "Skipping concurrent batch acquire / release on %lu tiles (ele_max %lu leaves no per tile quota)", tile_cnt, ele_max ));
        continue;
      }

      FD_LOG_NOTICE(( "Testing concurrent %sacquire / release on %lu tiles", batch_max ? "batch " : "", tile_cnt ));

      mypool_reset( pool ); /* refill the lazy region so both regions are hit under contention */
      tile_batch_max  = batch_max;
      tile_active_cnt = tile_cnt;

      FD_COMPILER_MFENCE();
      FD_VOLATILE( tile_go ) = 0;
      FD_COMPILER_MFENCE();

      for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) fd_tile_exec_new( tile_idx, tile_main, argc, argv );

      fd_log_sleep( (long)0.1e9 );

      FD_COMPILER_MFENCE();
      FD_VOLATILE( tile_go ) = 1;
      FD_COMPILER_MFENCE();

      tile_main( argc, argv );
      for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) fd_tile_exec_delete( fd_tile_exec( tile_idx ), NULL );

      FD_TEST( !mypool_verify( pool ) );
      for( ulong ele_idx=0UL; ele_idx<ele_max; ele_idx++ ) FD_TEST( !tile_owner[ ele_idx ] );

    }
  }

  FD_LOG_NOTICE(( "Testing destruction" ));

  FD_TEST( !mypool_leave( NULL )       );
  FD_TEST(  mypool_leave( pool )==pool );

  FD_TEST( !mypool_delete( NULL   )         ); /* NULL       shmem */
  FD_TEST( !mypool_delete( (void *)1UL )    ); /* misaligned shmem */
  FD_TEST(  mypool_delete( shpool )==shpool );

  FD_TEST( !mypool_delete( shpool )                     ); /* bad magic */
  FD_TEST( !mypool_join( pool, shpool, shele, ele_max ) ); /* bad magic */

  FD_LOG_NOTICE(( "bad error code      (%i-%s)", 1,                   mypool_strerror( 1                   ) ));
  FD_LOG_NOTICE(( "FD_POOL_SUCCESS     (%i-%s)", FD_POOL_SUCCESS,     mypool_strerror( FD_POOL_SUCCESS     ) ));
  FD_LOG_NOTICE(( "FD_POOL_ERR_AGAIN   (%i-%s)", FD_POOL_ERR_AGAIN,   mypool_strerror( FD_POOL_ERR_AGAIN   ) ));
  FD_LOG_NOTICE(( "FD_POOL_ERR_CORRUPT (%i-%s)", FD_POOL_ERR_CORRUPT, mypool_strerror( FD_POOL_ERR_CORRUPT ) ));

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
