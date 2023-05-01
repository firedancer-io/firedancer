#include "../fd_util.h"
#include "../wksp/fd_wksp_private.h"

#if FD_HAS_HOSTED

#include <stdio.h>

FD_IMPORT_CSTR( fd_alloc_ctl_help, "src/util/alloc/fd_alloc_ctl_help" );

int
fd_alloc_fprintf( fd_alloc_t * join,
                  FILE *       stream );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
# define SHIFT(n) argv+=(n),argc-=(n)

  if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "no arguments" ));
  char const * bin = argv[0];
  SHIFT(1);

  ulong tag = 1UL;

  int cnt = 0;
  while( argc ) {
    char const * cmd = argv[0];
    SHIFT(1);

    if( !strcmp( cmd, "help" ) ) {

      fputs( fd_alloc_ctl_help, stdout );

      FD_LOG_NOTICE(( "%i: %s: success", cnt, cmd ));

    } else if( !strcmp( cmd, "tag" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      tag = fd_cstr_to_ulong( argv[0] );

      FD_LOG_NOTICE(( "%i: %s %lu: success", cnt, cmd, tag ));
      SHIFT(1);

    } else if( !strcmp( cmd, "new" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name     =                   argv[0];
      ulong        wksp_tag = fd_cstr_to_ulong( argv[1] );

      ulong align     = fd_alloc_align();
      ulong footprint = fd_alloc_footprint();

      fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
      if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "%i: %s: fd_wksp_attach( \"%s\" ) failed", cnt, cmd, name ));

      ulong gaddr = fd_wksp_alloc( wksp, align, footprint, wksp_tag );
      if( FD_UNLIKELY( !gaddr ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_alloc(\"%s\",%lu,%lu,%lu) failed", cnt, cmd, name, align, footprint, wksp_tag ));

      void * shmem = fd_wksp_laddr_fast( wksp, gaddr );
      if( FD_UNLIKELY( !fd_alloc_new( shmem, wksp_tag ) ) ) /* logs details */
        FD_LOG_ERR(( "%i: %s: fd_alloc_new(\"%s\",%lu) failed", cnt, cmd, name, wksp_tag ));

      char cstr[ FD_WKSP_CSTR_MAX ];
      printf( "%s\n", fd_wksp_cstr( wksp, gaddr, cstr ) );

      fd_wksp_detach( wksp ); /* logs details */

      FD_LOG_NOTICE(( "%i: %s %s %lu: success", cnt, cmd, name, wksp_tag ));
      SHIFT(2);

    } else if( !strcmp( cmd, "delete" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * cstr            =                 argv[0];
      int          garbage_collect = fd_cstr_to_int( argv[1] );

      void * shalloc = fd_wksp_map( cstr );
      if( FD_UNLIKELY( !shalloc ) ) FD_LOG_ERR(( "%i: %s: fd_wksp_map(\"%s\") failed", cnt, cmd, cstr ));

      fd_alloc_t * alloc = fd_alloc_join( shalloc, 0UL /* d/c */ );
      if( FD_UNLIKELY( !alloc ) ) FD_LOG_ERR(( "%i: %s: fd_alloc_join(\"%s\",0UL) failed", cnt, cmd, cstr ));

      fd_wksp_t * wksp     = fd_alloc_wksp( shalloc );
      ulong       wksp_tag = fd_alloc_tag ( alloc   );

      fd_alloc_delete( fd_alloc_leave( alloc ) ); /* logs details */

      if( garbage_collect ) fd_wksp_tag_free( wksp, &wksp_tag, 1UL ); /* logs details */

      fd_wksp_unmap( shalloc ); /* logs details */

      FD_LOG_NOTICE(( "%i: %s %s %i: success", cnt, cmd, cstr, garbage_collect ));
      SHIFT(2);

    } else if( !strcmp( cmd, "malloc" ) ) {

      if( FD_UNLIKELY( argc<4 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * cstr       =                   argv[0];
      ulong        cgroup_idx = fd_cstr_to_ulong( argv[1] );
      ulong        align      = fd_cstr_to_ulong( argv[2] );
      ulong        sz         = fd_cstr_to_ulong( argv[3] );

      void * shalloc = fd_wksp_map( cstr );
      if( FD_UNLIKELY( !shalloc ) ) FD_LOG_ERR(( "%i: %s: fd_wksp_map(\"%s\") failed", cnt, cmd, cstr ));

      fd_alloc_t * alloc = fd_alloc_join( shalloc, cgroup_idx );
      if( FD_UNLIKELY( !alloc ) ) FD_LOG_ERR(( "%i: %s: fd_alloc_join(\"%s\",%lu) failed", cnt, cmd, cstr, cgroup_idx ));

      fd_wksp_t * wksp  = fd_alloc_wksp( alloc );
      void *      laddr = fd_alloc_malloc( alloc, align, sz );

      char buf[ FD_WKSP_CSTR_MAX ];
      if(      FD_LIKELY( laddr ) ) printf( "%s\n", fd_wksp_cstr( wksp, fd_wksp_gaddr_fast( wksp, laddr ), buf ) );
      else if( FD_LIKELY( !sz   ) ) printf( "%s\n", fd_wksp_cstr( wksp, 0UL,                               buf ) );
      else                          FD_LOG_ERR(( "%i: %s: fd_alloc_malloc(\"%s\":%lu,%lu,%lu) failed",
                                                 cnt, cmd, cstr, cgroup_idx, align, sz ));

      fd_wksp_unmap( fd_alloc_leave( alloc ) ); /* logs details */

      FD_LOG_NOTICE(( "%i: %s %s %lu %lu %lu: success", cnt, cmd, cstr, cgroup_idx, align, sz ));
      SHIFT(4);

    } else if( !strcmp( cmd, "free" ) ) {

      if( FD_UNLIKELY( argc<3 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * cstr       =                   argv[0];
      ulong        cgroup_idx = fd_cstr_to_ulong( argv[1] );
      char const * name_gaddr =                   argv[2];

      void * laddr = fd_wksp_map( name_gaddr ); /* logs details */
      if( FD_LIKELY( laddr ) ) {
        void * shalloc = fd_wksp_map( cstr ); /* logs details */
        if( FD_LIKELY( shalloc ) ) {
          fd_alloc_t * alloc = fd_alloc_join( shalloc, cgroup_idx ); /* logs details */
          if( FD_LIKELY( alloc ) ) {
            if( FD_LIKELY( fd_wksp_containing( laddr )==fd_alloc_wksp( alloc ) ) ) fd_alloc_free( alloc, laddr );
            else FD_LOG_WARNING(( "%i: %s: alloc %s was not used for %s", cnt, cmd, cstr, name_gaddr ));
            fd_alloc_leave( alloc ); /* logs details */
          }
          fd_wksp_unmap( shalloc ); /* logs details */
        }
        fd_wksp_unmap( laddr ); /* logs details */
      }

      FD_LOG_NOTICE(( "%i: %s %s %lu %s: success", cnt, cmd, cstr, cgroup_idx, name_gaddr ));
      SHIFT(3);

    } else if( !strcmp( cmd, "compact" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * cstr = argv[0];

      void * shalloc = fd_wksp_map( cstr );
      if( FD_UNLIKELY( !shalloc ) ) FD_LOG_ERR(( "%i: %s: fd_wksp_map(\"%s\") failed", cnt, cmd, cstr ));

      fd_alloc_t * alloc = fd_alloc_join( shalloc, 0 /*d/c*/ );
      if( FD_UNLIKELY( !alloc ) ) FD_LOG_ERR(( "%i: %s: fd_alloc_join(\"%s\",0) failed", cnt, cmd, cstr ));

      fd_alloc_compact( alloc ); /* logs details */

      fd_wksp_unmap( fd_alloc_leave( alloc ) ); /* logs details */

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, cstr ));
      SHIFT(1);

    } else if( !strcmp( cmd, "query" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * what = argv[0];
      char const * cstr = argv[1];

      void *       shmem = NULL;
      fd_alloc_t * alloc = NULL;
      int          err   = -1;

      shmem = fd_wksp_map( cstr );
      if( FD_LIKELY( shmem ) ) {
        alloc = fd_alloc_join( shmem, 0UL /* d/c */ );
        if( FD_LIKELY( alloc ) ) err = 0;
      }

      if(      !strcmp( what, "test" ) ) printf( "%i\n", err );
      else if( !strcmp( what, "tag"  ) ) printf( "%lu\n", FD_UNLIKELY( err ) ? 0UL : fd_alloc_tag( alloc ) );
      else if( !strcmp( what, "leak" ) ) printf( "%i\n",  FD_UNLIKELY( err ) ? -1  : !fd_alloc_is_empty( alloc ) );
      else if( !strcmp( what, "full" ) ) fd_alloc_fprintf( alloc, stdout );
      else                               FD_LOG_ERR(( "unknown query %s", what ));

      if( FD_LIKELY( alloc ) ) fd_alloc_leave( alloc );
      if( FD_LIKELY( shmem ) ) fd_wksp_unmap( shmem );

      FD_LOG_NOTICE(( "%i: %s %s %s: success", cnt, cmd, what, cstr ));
      SHIFT(2);

    } else {

      FD_LOG_ERR(( "%i: %s: unknown command\n\t"
                   "Do %s help for help", cnt, cmd, bin ));

    }
    cnt++;
  }

  if( FD_UNLIKELY( cnt<1 ) ) FD_LOG_NOTICE(( "processed %i commands\n\tDo %s help for help", cnt, bin ));
  else                       FD_LOG_NOTICE(( "processed %i commands", cnt ));

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
  if( FD_UNLIKELY( argc>1 ) ) FD_LOG_ERR(( "fd_alloc_ctl not supported on this platform" ));
  FD_LOG_NOTICE(( "processed 0 commands" ));
  fd_halt();
  return 0;
}

#endif

