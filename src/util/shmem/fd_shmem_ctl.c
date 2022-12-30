#include "../fd_util.h"

#if FD_HAS_HOSTED && FD_HAS_X86

#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

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

      FD_LOG_NOTICE(( "\n\t"
        "Usage: %s [cmd] [cmd args] [cmd] [cmd args] ...\n\t"
        "Commands are:\n\t"
        "\n\t"
        "\thelp\n\t"
        "\t- Prints this message\n\t"
        "\n\t"
        "\tcreate name page_cnt page_sz cpu_idx mode\n\t"
        "\t- Create a shared memory region named name from page_cnt page_sz\n\t"
        "\t  pages near logical cpu_idx.  The region will have the unix\n\t"
        "\t  permissions specified by mode (assumed octal).\n\t"
        "\n\t"
        "\tunlink name page_sz\n\t"
        "\t- Unlinks a page_sz page backed shared memory region named name.\n\t"
        "\t- If page_sz is zero, this will attempt to detected the page_sz\n\t"
        "\t  If there are multiple with the same name, one will be\n\t"
        "\t  deleted (typically the one backed by the largest page_sz)\n\t"
        "\n\t"
        "\tquery name page_sz\n\t"
        "\t- Pretty prints info to stdout about a shared memory region\n\t"
        "\t  named name.  The format is:\n\t"
        "\t    [err_code] [page_cnt] [page_sz]\n\t"
        "\t  err code is zero, the query was successful.  If not, the query\n\t"
        "\t  failed (details logged) and page_cnt and page_sz will be zero.\n\t"
        "\t- If page_sz is zero, this will attempt to detected the page_sz\n\t"
        "\t  If there are multiple with the same name, one will be\n\t"
        "\t  queried (typically the one backed by the largest page_sz)\n\t"
        "\n\t", bin ));
      FD_LOG_NOTICE(( "%i: %s: success", cnt, cmd ));

    } else if( !strcmp( cmd, "create" ) ) {

      if( FD_UNLIKELY( argc<5 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name     =                           argv[0];
      ulong        page_cnt = fd_cstr_to_ulong        ( argv[1] );
      ulong        page_sz  = fd_cstr_to_shmem_page_sz( argv[2] );
      ulong        cpu_idx  = fd_cstr_to_ulong        ( argv[3] );
      ulong        mode     = fd_cstr_to_ulong_octal  ( argv[4] );

      if( FD_UNLIKELY( fd_shmem_create( name, page_sz, page_cnt, cpu_idx, mode ) ) )
        FD_LOG_ERR(( "%i: %s %s %lu %s %lu 0%03lo: FAIL\n\t"
                     "Do %s help for help", cnt, cmd, name, page_cnt, argv[2], cpu_idx, mode, bin ));

      FD_LOG_NOTICE(( "%i: %s %s %lu %s %lu 0%03lo: success", cnt, cmd, name, page_cnt, argv[2], cpu_idx, mode ));
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
