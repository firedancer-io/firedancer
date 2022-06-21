#include "../fd_util.h"

#if FD_HAS_HOSTED
#include <sys/stat.h>
#endif

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
# define SHIFT(n) argv+=(n),argc-=(n)

  if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "No arguments" ));
  char const * bin = argv[0];
  SHIFT(1);
  
# if FD_HAS_HOSTED
  umask( (mode_t)0 ); /* So mode setting gets respected */
# endif

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
        "\t- Create a shared memory region named name from  page_cnt page_sz\n\t"
        "\t  pages near logical cpu_idx.  The region will have the unix\n\t"
        "\t  specified by mode.\n\t"
        "\n\t"
        "\tunlink name page_sz\n\t"
        "\t- Unlinks a page_sz page backed shared memory region named name.\n\t"
        "\t  If page_sz is zero, shared memory region backed by the largest\n\t"
        "\t  page size will be deleted."
        "\n\t", bin ));
      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, bin, cmd ));

    } else if( !strcmp( cmd, "create" ) ) {

      if( FD_UNLIKELY( argc<5 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name     =                           argv[0];
      ulong        page_cnt = fd_cstr_to_ulong        ( argv[1] );
      ulong        page_sz  = fd_cstr_to_shmem_page_sz( argv[2] );
      ulong        cpu_idx  = fd_cstr_to_ulong        ( argv[3] );
      uint         mode     = fd_cstr_to_uint         ( argv[4] );

      /* FIXME: CONSIDER SETTING THE UMASK HERE? */

      if( FD_UNLIKELY( fd_shmem_create( name, page_sz, page_cnt, cpu_idx, mode ) ) )
        FD_LOG_ERR(( "%i: %s %s %lu %s %lu 0%03o: FAIL\n\t"
                     "Do %s help for help", cnt, cmd, name, page_cnt, argv[2], cpu_idx, mode, bin ));

      FD_LOG_NOTICE(( "%i: %s %s %lu %s %lu 0%03o: success", cnt, cmd, name, page_cnt, argv[2], cpu_idx, mode ));
      SHIFT(5);

    } else if( !strcmp( cmd, "unlink" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name     =                           argv[0];
      ulong        page_sz  = fd_cstr_to_shmem_page_sz( argv[1] );

      if( !page_sz ) {
        FD_LOG_ERR(( "%i: %s %s %s: FIXME: IMPLEMENT THIS\n\tDo %s help for help", cnt, cmd, name, argv[1], bin ));
      }

      if( FD_UNLIKELY( fd_shmem_unlink( name, page_sz ) ) )
        FD_LOG_ERR(( "%i: %s %s %s: FAIL\n\tDo %s help for help", cnt, cmd, name, argv[1], bin ));

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

