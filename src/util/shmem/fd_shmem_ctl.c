#include "../fd_util.h"

#if FD_HAS_HOSTED

#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
 
FD_IMPORT_CSTR( fd_shmem_ctl_help, "src/util/shmem/fd_shmem_ctl_help" );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
# define SHIFT(n) argv+=(n),argc-=(n)

  if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "No arguments" ));
  char const * bin = argv[0];
  SHIFT(1);
  
  umask( (mode_t)0 ); /* So mode setting gets respected */

  int cnt = 0;
  while( argc ) {
    char const * cmd = argv[0];
    SHIFT(1);

    if( !strcmp( cmd, "help" ) ) {

      fputs( fd_shmem_ctl_help, stdout );

      FD_LOG_NOTICE(( "%i: %s: success", cnt, cmd ));

    } else if( !strcmp( cmd, "cpu-cnt" ) ) {

      printf( "%lu\n", fd_shmem_cpu_cnt() );

      FD_LOG_NOTICE(( "%i: %s: success", cnt, cmd ));

    } else if( !strcmp( cmd, "numa-cnt" ) ) {

      printf( "%lu\n", fd_shmem_numa_cnt() );

      FD_LOG_NOTICE(( "%i: %s: success", cnt, cmd ));

    } else if( !strcmp( cmd, "cpu-idx" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      ulong numa_idx = fd_cstr_to_ulong( argv[0] );

      ulong cpu_idx = fd_shmem_cpu_idx( numa_idx );

      if( FD_LIKELY( cpu_idx<ULONG_MAX ) ) printf( "%lu\n", cpu_idx );
      else                                 printf( "-\n" );

      FD_LOG_NOTICE(( "%i: %s %lu: success", cnt, cmd, numa_idx ));
      SHIFT(1);

    } else if( !strcmp( cmd, "numa-idx" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      ulong cpu_idx = fd_cstr_to_ulong( argv[0] );

      ulong numa_idx = fd_shmem_numa_idx( cpu_idx );

      if( FD_LIKELY( numa_idx<ULONG_MAX ) ) printf( "%lu\n", numa_idx );
      else                                  printf( "-\n" );

      FD_LOG_NOTICE(( "%i: %s %lu: success", cnt, cmd, cpu_idx ));
      SHIFT(1);

    } else if( !strcmp( cmd, "create" ) ) {

      if( FD_UNLIKELY( argc<5 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name     =                           argv[0];
      ulong        page_cnt = fd_cstr_to_ulong        ( argv[1] );
      ulong        page_sz  = fd_cstr_to_shmem_page_sz( argv[2] );
      char const * seq      =                           argv[3];
      ulong        mode     = fd_cstr_to_ulong_octal  ( argv[4] );

      ulong sub_page_cnt[ 512 ];
      ulong sub_cpu_idx [ 512 ];
      ulong sub_cnt = fd_cstr_to_ulong_seq( seq, sub_cpu_idx, 512UL );

      if( FD_UNLIKELY( !sub_cnt ) )
        FD_LOG_ERR(( "%i: %s %s %lu %s %s 0%03lo: empty or invalid cpu sequence\n\t"
                     "Do %s help for help", cnt, cmd, name, page_cnt, argv[2], seq, mode, bin ));

      if( FD_UNLIKELY( sub_cnt>512UL ) )
        FD_LOG_ERR(( "%i: %s %s %lu %s %s 0%03lo: sequence too long, increase limit in fd_shmem_ctl.c\n\t"
                     "Do %s help for help", cnt, cmd, name, page_cnt, argv[2], seq, mode, bin ));

      ulong sub_page_min = page_cnt / sub_cnt;
      ulong sub_page_rem = page_cnt % sub_cnt;
      for( ulong sub_idx=0UL; sub_idx<sub_cnt; sub_idx++ ) sub_page_cnt[ sub_idx ] = sub_page_min + (ulong)(sub_idx<sub_page_rem);

      if( FD_UNLIKELY( fd_shmem_create_multi( name, page_sz, sub_cnt, sub_page_cnt, sub_cpu_idx, mode ) ) )
        FD_LOG_ERR(( "%i: %s %s %lu %s %s 0%03lo: FAIL\n\t"
                     "Do %s help for help", cnt, cmd, name, page_cnt, argv[2], seq, mode, bin ));

      FD_LOG_NOTICE(( "%i: %s %s %lu %s %s 0%03lo: success", cnt, cmd, name, page_cnt, argv[2], seq, mode ));
      SHIFT(5);

    } else if( !strcmp( cmd, "unlink" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name     =                           argv[0];
      ulong        page_sz  = fd_cstr_to_shmem_page_sz( argv[1] );

      if( !page_sz ) {
        fd_shmem_info_t info[1];
        if( FD_UNLIKELY( fd_shmem_info( name, page_sz, info ) ) )
          FD_LOG_ERR(( "%i: %s %s %s: not found or bad permissions\n\tDo %s help for help", cnt, cmd, name, argv[1], bin ));
        page_sz = info->page_sz;
      }

      if( FD_UNLIKELY( fd_shmem_unlink( name, page_sz ) ) )
        FD_LOG_ERR(( "%i: %s %s %s: FAIL\n\tDo %s help for help", cnt, cmd, name, argv[1], bin ));

      FD_LOG_NOTICE(( "%i: %s %s %s: success", cnt, cmd, name, argv[1]));
      SHIFT(2);

    } else if( !strcmp( cmd, "query" ) ) {

      /* FIXME: MAKE THIS MORE LIKE POD QUERY WITH "WHAT" FIELDS */

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name     =                           argv[0];
      ulong        page_sz  = fd_cstr_to_shmem_page_sz( argv[1] );

      fd_shmem_info_t info[1];
      int err = fd_shmem_info( name, page_sz, info );
      if( FD_UNLIKELY( err ) ) printf( "%i 0 0\n",    err );
      else                     printf( "0 %lu %lu\n", info->page_cnt, info->page_sz );

      FD_LOG_NOTICE(( "%i: %s %s %s: success", cnt, cmd, name, argv[1]));
      SHIFT(2);

    } else {

      FD_LOG_ERR(( "%i: %s: unknown command\n\t"
                   "Do %s help for help", cnt, cmd, bin ));

    }
    cnt++;
  }

  FD_LOG_NOTICE(( "processed %i commands", cnt ));

# undef SHIFT
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "No arguments" ));
  if( FD_UNLIKELY( argc>1 ) ) FD_LOG_ERR(( "fd_shmem_ctl not supported on this platform" ));
  FD_LOG_NOTICE(( "processed 0 commands" ));
  fd_halt();
  return 0;
}

#endif
