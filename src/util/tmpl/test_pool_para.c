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
#include "fd_pool_para.c"

FD_STATIC_ASSERT( FD_POOL_SUCCESS    == 0, unit_test );
FD_STATIC_ASSERT( FD_POOL_ERR_INVAL  ==-1, unit_test );
FD_STATIC_ASSERT( FD_POOL_ERR_AGAIN  ==-2, unit_test );
FD_STATIC_ASSERT( FD_POOL_ERR_CORRUPT==-3, unit_test );
FD_STATIC_ASSERT( FD_POOL_ERR_EMPTY  ==-4, unit_test );

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

static mypool_t * tile_pool;
static ulong      tile_ele_max;
static ulong      tile_iter_cnt;
static ulong      tile_go;

static int
tile_main( int     argc,
           char ** argv ) {
  (void)argc; (void)argv;
  mypool_t * pool     = tile_pool;
  ulong      ele_max  = tile_ele_max;
  ulong      iter_cnt = tile_iter_cnt;
  ulong      tile_idx = fd_tile_idx();
  ulong      tile_cnt = fd_tile_cnt();

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)tile_idx, 0UL ) );

  ulong       save    = shmem_cnt;
  myele_t **  acq_ele = shmem_alloc( alignof(myele_t *), ele_max*sizeof(myele_t *) );
  ulong       acq_cnt = 0UL;

  myele_t sentinel[1];

  while( !FD_VOLATILE_CONST( tile_go ) ) FD_SPIN_PAUSE();

  ulong diag_rem = 0UL;
  for( ulong iter_idx=0UL; iter_idx<iter_cnt; iter_idx++ ) {
    if( FD_UNLIKELY( !diag_rem ) ) {
      if( !tile_idx ) FD_LOG_NOTICE(( "Iteration %lu of %lu (acq_cnt %lu)", iter_idx, iter_cnt, acq_cnt ));
      diag_rem = 10000UL;
    }
    diag_rem--;

    uint r = fd_rng_uint( rng );

    int op       = (int)(r & 1U); r>>=1;
    int blocking = (int)(r & 1U); r>>=1;

    int       err;
    myele_t * ele;

    switch( op ) {

    case 0: { /* acquire */
      ele = mypool_acquire( pool, sentinel, blocking, &err );
      if( ele!=sentinel ) {
        FD_TEST( !err );
        FD_TEST( mypool_idx( pool, ele )<ele_max );
        /* FIXME: Ideally would check unique cross thread */
        for( ulong acq_idx=0UL; acq_idx<acq_cnt; acq_idx++ ) FD_TEST( ele!=acq_ele[ acq_idx ] );
        acq_ele[ acq_cnt++ ] = ele;
      } else {
        FD_TEST( err==FD_POOL_ERR_EMPTY );
        if( tile_cnt==1UL ) FD_TEST( acq_cnt==ele_max );
      }
      break;
    }

    case 1: { /* release */
      if( !acq_cnt ) FD_TEST( mypool_release( pool, sentinel, blocking )==FD_POOL_ERR_INVAL );
      else {
        ulong acq_idx = fd_rng_ulong_roll( rng, acq_cnt );
        FD_TEST( !mypool_release( pool, acq_ele[ acq_idx ], blocking ) );
        acq_ele[ acq_idx ] = acq_ele[ --acq_cnt ];
      }
      break;
    }

    default: /* never get here */
      break;
    }
  }

  for( ulong acq_idx=0UL; acq_idx<acq_cnt; acq_idx++ ) FD_TEST( !mypool_release( pool, acq_ele[ acq_idx ], 1 ) );
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

  FD_TEST( !mypool_is_locked( pool ) );
  FD_TEST( !mypool_lock( pool, 1 ) );
  FD_TEST(  mypool_lock( pool, 0 )==FD_POOL_ERR_AGAIN ); /* non-blocking on a locked pool */
  FD_TEST(  mypool_is_locked( pool )==1 );

  FD_TEST( !mypool_verify    ( pool ) );
  FD_TEST( !mypool_peek_const( pool ) );
  FD_TEST( !mypool_peek      ( pool ) );

  mypool_reset( pool, ULONG_MAX ); /* empty pool */
  FD_TEST( !mypool_verify    ( pool ) );
  FD_TEST( !mypool_peek_const( pool ) );
  FD_TEST( !mypool_peek      ( pool ) );

  mypool_reset( pool, ele_max ); /* empty pool */
  FD_TEST( !mypool_verify    ( pool ) );
  FD_TEST( !mypool_peek_const( pool ) );
  FD_TEST( !mypool_peek      ( pool ) );

  mypool_reset( pool, 1UL ); /* all but first in pool in increasing order */
  FD_TEST( !mypool_verify    ( pool ) );
  FD_TEST(  mypool_peek_const( pool )==((ele_max>1UL) ? (shele+1) : NULL) );
  FD_TEST(  mypool_peek      ( pool )==((ele_max>1UL) ? (shele+1) : NULL) );

  mypool_reset( pool, 0UL ); /* all in pool in increasing order */
  FD_TEST(  mypool_peek_const( pool )==(ele_max ? shele : NULL) );
  FD_TEST(  mypool_peek      ( pool )==(ele_max ? shele : NULL) );

  mypool_unlock( pool );
  FD_TEST( !mypool_is_locked( pool ) );

  /* FIXME: use tpool here */

  tile_pool     = pool;
  tile_ele_max  = ele_max;
  tile_iter_cnt = iter_cnt;

  ulong tile_max = fd_tile_cnt();
  for( ulong tile_cnt=1UL; tile_cnt<=tile_max; tile_cnt++ ) {

    FD_LOG_NOTICE(( "Testing concurrent acquire / release on %lu tiles", tile_cnt ));

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
  FD_LOG_NOTICE(( "FD_POOL_ERR_INVAL   (%i-%s)", FD_POOL_ERR_INVAL,   mypool_strerror( FD_POOL_ERR_INVAL   ) ));
  FD_LOG_NOTICE(( "FD_POOL_ERR_AGAIN   (%i-%s)", FD_POOL_ERR_AGAIN,   mypool_strerror( FD_POOL_ERR_AGAIN   ) ));
  FD_LOG_NOTICE(( "FD_POOL_ERR_CORRUPT (%i-%s)", FD_POOL_ERR_CORRUPT, mypool_strerror( FD_POOL_ERR_CORRUPT ) ));
  FD_LOG_NOTICE(( "FD_POOL_ERR_EMPTY   (%i-%s)", FD_POOL_ERR_EMPTY,   mypool_strerror( FD_POOL_ERR_EMPTY   ) ));

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
