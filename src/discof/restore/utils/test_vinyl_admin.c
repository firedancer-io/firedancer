#include "fd_vinyl_admin.h"
#include "../../../util/fd_util.h"
#include <stdlib.h>

char * tile_argv[] = { NULL, NULL, NULL };

char * mem_argv[FD_VINYL_ADMIN_WR_SEQ_CNT_MAX] = { NULL };

#define MEM_CMD_SZ (1024)
char   mem_cmd[MEM_CMD_SZ];

#define SHMEM_MAX (131072UL)

static FD_TL uchar shmem[ SHMEM_MAX ];

static void *
shmem_join( ulong a,
            ulong s ) {
  uchar * m  = (uchar *)fd_ulong_align_up( (ulong)shmem, a );
  uchar * m_end = m + s;
  FD_TEST( ((ulong)(m_end)-(ulong)shmem) <= SHMEM_MAX );
  return (void *)m;
}

int
tile_main( int     argc,
           char ** argv ) {

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, (uint)fd_log_wallclock(), fd_tile_id() ) );

  FD_TEST( fd_tile_id()==fd_log_thread_id() );
  ulong wr_idx = fd_tile_idx();
  FD_TEST( wr_idx<FD_VINYL_ADMIN_WR_SEQ_CNT_MAX );

  FD_TEST( argc==1 );
  fd_vinyl_admin_t * admin = (fd_vinyl_admin_t *)argv[ 0 ];

  /* test_lockfree_init_sync */

  FD_TEST( admin->status==FD_VINYL_ADMIN_STATUS_INIT_PENDING );

  for(;;) {
    if( fd_vinyl_admin_ulong_query( &admin->status )==FD_VINYL_ADMIN_STATUS_INIT_DONE ) break;
    FD_SPIN_PAUSE();
  }

  fd_vinyl_admin_ulong_update( &admin->wr_seq[ wr_idx ], fd_vinyl_admin_ulong_query( &admin->bstream_seq.present ) );

  /* test_lockfree_wr_seq_regression */

  for(;;) {
    if( fd_vinyl_admin_ulong_query( &admin->status )==FD_VINYL_ADMIN_STATUS_SNAPSHOT_FULL ) break;
    FD_SPIN_PAUSE();
  }

  ulong wr_seqA = fd_vinyl_admin_ulong_query( &admin->bstream_seq.past    );
  ulong wr_seqB = fd_vinyl_admin_ulong_query( &admin->bstream_seq.present );

  for( ulong wr_seq=wr_seqA; wr_seq<=wr_seqB; wr_seq++ ) {
    fd_vinyl_admin_ulong_update( &admin->wr_seq[ wr_idx ], wr_seq );
    FD_SPIN_PAUSE();
  }

  for(;;) {
    if( fd_vinyl_admin_ulong_query( &admin->wr_seq[ wr_idx ] )==wr_seqA ) break;
    FD_SPIN_PAUSE();
  }

  fd_vinyl_admin_ulong_update( &admin->wr_seq[ wr_idx ], ULONG_MAX );

  /* test_rwlock_init_and_wr_seq */

  for(;;) {
    fd_rwlock_read( &admin->lock );
    int found = fd_vinyl_admin_ulong_query( &admin->status )==FD_VINYL_ADMIN_STATUS_SNAPSHOT_FULL;
    fd_rwlock_unread( &admin->lock );
    fd_log_sleep( (long)1e3 /*1us*/ );
    if( found ) break;
    FD_SPIN_PAUSE();
  }

  ulong wr_seqC = fd_vinyl_admin_ulong_query( &admin->bstream_seq.past    );
  ulong wr_seqD = fd_vinyl_admin_ulong_query( &admin->bstream_seq.present );

  for( ulong wr_seq=wr_seqC; wr_seq<=wr_seqD; wr_seq++ ) {
    fd_rwlock_write( &admin->lock );
    fd_vinyl_admin_ulong_update( &admin->wr_seq[ wr_idx ], wr_seq );
    fd_rwlock_unwrite( &admin->lock );
    FD_SPIN_PAUSE();
  }

  fd_log_flush();

  return 0;
}

void
test_lockfree_init_sync( fd_vinyl_admin_t * admin,
                         fd_rng_t *         rng,
                         ulong              tile_cnt ) {
  (void)rng;
  FD_LOG_NOTICE(( "testing lockfree init sync ..." ));

  /* Init - the other tiles are waiting. */
  FD_TEST( admin->status==FD_VINYL_ADMIN_STATUS_INIT_PENDING );
  ulong past    = 0UL;
  ulong present = ULONG_MAX-1UL;
  fd_vinyl_admin_ulong_update( &admin->bstream_seq.past,    past    );
  fd_vinyl_admin_ulong_update( &admin->bstream_seq.present, present );
  for( ulong idx=1UL; idx<tile_cnt; idx++ ) {
    FD_TEST( !fd_vinyl_admin_ulong_query( &admin->wr_seq[ idx ] ) );
  }
  fd_vinyl_admin_ulong_update( &admin->wr_cnt, tile_cnt );
  fd_vinyl_admin_ulong_update( &admin->status, FD_VINYL_ADMIN_STATUS_INIT_DONE );

  /* The other tiles will respond by updating wr_seq to "present". */
  for(;;) {
    ulong seq_min = ULONG_MAX;
    for( ulong idx=1UL; idx<tile_cnt; idx++ ) {
      ulong seq = fd_vinyl_admin_ulong_query( &admin->wr_seq[ idx ] );
      seq_min = fd_ulong_min( seq_min, seq );
    }
    if( seq_min==present ) break;
    FD_SPIN_PAUSE();
  }

  FD_LOG_NOTICE(( "... pass" ));
}

void
test_lockfree_wr_seq_regression( fd_vinyl_admin_t * admin,
                                 fd_rng_t *         rng,
                                 ulong              tile_cnt ) {
  FD_LOG_NOTICE(( "testing lockfree wr_seq regression ..." ));

  ulong past    = 1UL;
  ulong present = past + 100UL + (fd_rng_ulong( rng ) & ((1UL<<20)-1UL));
  FD_LOG_NOTICE(( "... past     %lu", past     ));
  FD_LOG_NOTICE(( "... present  %lu", present  ));

  /* Init - the other tiles are waiting. */
  fd_vinyl_admin_ulong_update( &admin->status, FD_VINYL_ADMIN_STATUS_UPDATING );
  fd_vinyl_admin_ulong_update( &admin->bstream_seq.past,    past    );
  fd_vinyl_admin_ulong_update( &admin->bstream_seq.present, present );
  for( ulong idx=1UL; idx<tile_cnt; idx++ ) fd_vinyl_admin_ulong_update( &admin->wr_seq[ idx ], past );
  fd_vinyl_admin_ulong_update( &admin->status, FD_VINYL_ADMIN_STATUS_SNAPSHOT_FULL );

  /* The other tiles will respond by incrementing wr_seq gradually, up
     until reaching "present". */
  for(;;) {
    ulong seq_min = ULONG_MAX;
    for( ulong idx=1UL; idx<tile_cnt; idx++ ) {
      ulong seq = fd_vinyl_admin_ulong_query( &admin->wr_seq[ idx ] );
      seq_min = fd_ulong_min( seq_min, seq );
    }
    if( seq_min==present ) break;
    FD_SPIN_PAUSE();
  }

  FD_LOG_NOTICE(( "... present has been reached" ));

  /* The other tiles are waiting for a regression to "past". */
  for( ulong idx=1UL; idx<tile_cnt; idx++ ) {
    fd_vinyl_admin_ulong_update( &admin->wr_seq[ idx ], past );
  }

  /* The other tiles will respond by setting wr_seq to ULONG_MAX. */
  for(;;) {
    ulong seq_min = ULONG_MAX;
    for( ulong idx=1UL; idx<tile_cnt; idx++ ) {
      ulong seq = fd_vinyl_admin_ulong_query( &admin->wr_seq[ idx ] );
      seq_min = fd_ulong_min( seq_min, seq );
    }
    if( seq_min==ULONG_MAX ) break;
    FD_SPIN_PAUSE();
  }

  FD_LOG_NOTICE(( "... pass" ));
}

void
test_rwlock_init_and_wr_seq( fd_vinyl_admin_t * admin,
                             fd_rng_t *         rng,
                             ulong              tile_cnt ) {
  FD_LOG_NOTICE(( "testing rwlock ..." ));

  ulong past     = 1UL;
  ulong present = past + 100UL + (fd_rng_ulong( rng ) & ((1UL<<20)-1UL));
  FD_LOG_NOTICE(( "... past     %lu", past     ));
  FD_LOG_NOTICE(( "... present  %lu", present  ));

  /* Init - the other tiles are waiting. */
  fd_rwlock_write( &admin->lock );
  fd_vinyl_admin_ulong_update( &admin->status, FD_VINYL_ADMIN_STATUS_UPDATING );
  fd_vinyl_admin_ulong_update( &admin->bstream_seq.past,    past    );
  fd_vinyl_admin_ulong_update( &admin->bstream_seq.present, present );
  for( ulong idx=1UL; idx<tile_cnt; idx++ ) fd_vinyl_admin_ulong_update( &admin->wr_seq[ idx ], past );
  fd_vinyl_admin_ulong_update( &admin->status, FD_VINYL_ADMIN_STATUS_SNAPSHOT_INCR );
  fd_rwlock_unwrite( &admin->lock );

  /* The other tiles will respond by updating wr_seq to "present". */
  for(;;) {
    ulong seq_min = ULONG_MAX;
    fd_rwlock_read( &admin->lock );
    for( ulong idx=1UL; idx<tile_cnt; idx++ ) {
      ulong seq = fd_vinyl_admin_ulong_query( &admin->wr_seq[ idx ] );
      seq_min = fd_ulong_min( seq_min, seq );
    }
    fd_rwlock_unread( &admin->lock );
    fd_log_sleep( (long)1e3 /*1us*/ );
    if( seq_min==present ) break;
    FD_SPIN_PAUSE();
  }

  FD_LOG_NOTICE(( "... present has been reached" ));

  FD_LOG_NOTICE(( "... pass" ));
}

int
main( int     argc,
      char ** argv ) {

  int     t_argc = argc;
  char ** t_argv = argv;

  /* The test needs a minimum number of tiles > 1, which is typically
     provided either as an environment variable (FD_TILE_CPUS) or via
     the command line (--tile-cpus).  If neither is given, the code
     below will set this to a default value before calling fd_boot. */
  int contains_tile_cpus = !!getenv( "FD_TILE_CPUS" );
  for( int i=0UL; i<argc; i++ ) {
    if( !strcmp( "--tile-cpus", t_argv[ i ] ) ) contains_tile_cpus = 1;
  }
  if( !contains_tile_cpus ) {
    /* Use mem_argv as a 1-D buffer. */
    t_argc = 0;
    t_argv = (char**)mem_argv;
    char * p = mem_cmd;
    for( int i=0; i<argc; i++ ) {
      p = fd_cstr_init( p );
      t_argv[ t_argc++ ] = p;
      p = fd_cstr_append_cstr( p, argv[ i ] );
      fd_cstr_fini( p );
      p += 1;
    }
    p = fd_cstr_init( p );
    t_argv[ t_argc++ ] = p;
    p = fd_cstr_append_cstr( p, "--tile-cpus" );
    fd_cstr_fini( p );
    p += 1;
    t_argv[ t_argc++ ] = p;
    ulong sz_used  = 0UL;
    ulong sz_avail = ((ulong)mem_cmd)+MEM_CMD_SZ-2UL-(ulong)p;
    fd_cstr_printf( p, sz_avail, &sz_used, "1-%lu", FD_VINYL_ADMIN_WR_SEQ_CNT_MAX );
    FD_TEST( sz_used );
    FD_TEST( sz_used <= sz_avail );
    t_argv[ t_argc ] = NULL;
    FD_LOG_WARNING(( "unspecified --tile-cpus, using default: %s %s", t_argv[ t_argc-2 ], t_argv[ t_argc-1 ] ));
  }

  /* Unit test boot. */
  fd_boot( &t_argc, &t_argv );

  FD_LOG_NOTICE(( "fd_vinyl_admin_align()     %lu", fd_vinyl_admin_align()     ));
  FD_LOG_NOTICE(( "fd_vinyl_admin_footprint() %lu", fd_vinyl_admin_footprint() ));

  ulong tile_cnt = fd_tile_cnt();
  if( tile_cnt > FD_VINYL_ADMIN_WR_SEQ_CNT_MAX ) FD_LOG_ERR(( "tile count cannot exceed FD_VINYL_ADMIN_WR_SEQ_CNT_MAX %lu", FD_VINYL_ADMIN_WR_SEQ_CNT_MAX ));
  if( tile_cnt <= 1UL )                          FD_LOG_ERR(( "tile count must be > 1" ));
  FD_TEST( fd_tile_id()==fd_log_thread_id() );

  FD_LOG_NOTICE(( "cnt %lu", tile_cnt      )); FD_TEST( tile_cnt>0UL ); FD_TEST( tile_cnt<=FD_TILE_MAX );
  FD_LOG_NOTICE(( "id0 %lu", fd_tile_id0() ));
  FD_LOG_NOTICE(( "id1 %lu", fd_tile_id1() )); FD_TEST( tile_cnt==(fd_tile_id1()-fd_tile_id0()) );
  FD_LOG_NOTICE(( "id  %lu", fd_tile_id () )); FD_TEST( fd_tile_id()==fd_tile_id0() );
  FD_LOG_NOTICE(( "idx %lu", fd_tile_idx() )); FD_TEST( fd_tile_idx()==0UL );
  fd_log_flush();

  /* Random number generator init. */
  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, (uint)fd_log_wallclock(), 0UL ) );

  /* Vinyl admin (shared memory). */
  void * vinyl_admin_shmem = shmem_join( fd_vinyl_admin_align(), fd_vinyl_admin_footprint() );
  tile_argv[ 0 ] = vinyl_admin_shmem;
  fd_vinyl_admin_t * admin = fd_vinyl_admin_join( fd_vinyl_admin_new( vinyl_admin_shmem ) );

  /* Other tiles's exec context. */
  fd_tile_exec_t * exec[FD_VINYL_ADMIN_WR_SEQ_CNT_MAX] = { NULL };

  /* Starting all the other tiles, running "tile_main". */
  FD_LOG_NOTICE(( "starting %lu tiles", tile_cnt ));

  for( ulong idx=1UL; idx<tile_cnt; idx++ ) {
    int     argc = 1;
    char ** argv = (char **)tile_argv;

    exec[ idx ] = fd_tile_exec_new( idx, tile_main, argc, argv );
    FD_TEST( !!exec[ idx ] );

    FD_TEST( fd_tile_exec( idx )==exec[ idx ] );

    FD_LOG_NOTICE(( "... tile idx %lu running", idx ));
  }

  fd_log_flush();

  /* Main tests: note that the other tiles are running, each waiting
     and ready to respond in accordance to each test (see tile_main). */
  test_lockfree_init_sync( admin, rng, tile_cnt );

  test_lockfree_wr_seq_regression( admin, rng, tile_cnt );

  test_rwlock_init_and_wr_seq( admin, rng, tile_cnt );

  /* Closing all other tiles. */
  for( ulong idx=1UL; idx<tile_cnt; idx++ ) {
    FD_LOG_NOTICE(( "closing tile %lu", idx ));

    int done = fd_tile_exec_done( exec[ idx ] );
    FD_TEST( 0<=done && done<=1 );

    int          ret;
    char const * fail = fd_tile_exec_delete( exec[ idx ], &ret );
    FD_TEST( !fail );
  }

  /* Final check: wr_seq[0] must have remained unchanged (==0). */
  FD_TEST( !fd_vinyl_admin_ulong_query( &admin->wr_seq[0] ) );

  FD_LOG_NOTICE(( "pass" ));

  fd_rng_delete( fd_rng_leave( rng ) );
  fd_vinyl_admin_delete( fd_vinyl_admin_leave( admin ) );
  fd_halt();
  return 0;
}
