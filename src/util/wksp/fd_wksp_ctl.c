#include "../fd_util.h"
#include "fd_wksp_private.h"

#if FD_HAS_HOSTED

/* TODO: add owner query */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

FD_IMPORT_CSTR( fd_wksp_ctl_help, "src/util/wksp/fd_wksp_ctl_help" );

/* fd_printf_wksp pretty prints the detailed workspace state to file.
   Includes detailed metadata integrity checking.  Return value
   semantics are the same as for fprintf. */

static int
fprintf_wksp( FILE *      file,
              fd_wksp_t * wksp ) {

  if( FD_UNLIKELY( !file ) ) {
    FD_LOG_WARNING(( "NULL file" ));
    return -1;
  }

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return -1;
  }

  int ret = 0;
# define TRAP(x) do { int _err = (x); if( _err<0 ) { fd_wksp_private_unlock( wksp ); return _err; } ret += _err; } while(0)

  ulong part_max = wksp->part_max;
  ulong gaddr_lo = wksp->gaddr_lo;
  ulong gaddr_hi = wksp->gaddr_hi;

  fd_wksp_private_pinfo_t * pinfo = fd_wksp_private_pinfo( wksp );

  TRAP( fprintf( file,
                 "wksp %s\n"
                 "\tmagic     0x%016lx\n"
                 "\tseed      %u\n"
                 "\tpart_max  %lu\n"
                 "\tdata_max  %lu\n"
                 "\tgaddr     [0x%016lx,0x%016lx)\n",
                 wksp->name, wksp->magic, wksp->seed, part_max, wksp->data_max, gaddr_lo, gaddr_hi ) );

  /* TODO: considering running verify and/or doing extra metadata
     integrity checks */

  ulong cnt = 0UL;

  if( FD_UNLIKELY( fd_wksp_private_lock( wksp ) ) ) { cnt++; TRAP( fprintf( file, "\tlock err\n" ) ); }
  else {
    ulong used_cnt = 0UL; ulong free_cnt = 0UL;
    ulong used_sz  = 0UL; ulong free_sz  = 0UL;
    ulong used_max = 0UL; ulong free_max = 0UL;

    ulong cycle_tag = wksp->cycle_tag++;

    ulong last_i  = FD_WKSP_PRIVATE_PINFO_IDX_NULL;
    ulong last_hi = gaddr_lo;
    ulong i       = fd_wksp_private_pinfo_idx( wksp->part_head_cidx );
    while( !fd_wksp_private_pinfo_idx_is_null( i ) ) {
      if( FD_UNLIKELY( i>=part_max                     ) ) { cnt++; TRAP( fprintf( file, "\tindex err\n" ) ); break; }
      if( FD_UNLIKELY( pinfo[ i ].cycle_tag==cycle_tag ) ) { cnt++; TRAP( fprintf( file, "\tcycle err\n" ) ); break; }
      pinfo[ i ].cycle_tag = cycle_tag;

      ulong lo  = pinfo[ i ].gaddr_lo;
      ulong hi  = pinfo[ i ].gaddr_hi;
      ulong tag = pinfo[ i ].tag;
      ulong sz  = hi - lo;
      ulong h   = fd_wksp_private_pinfo_idx( pinfo[ i ].prev_cidx );

      int used = !!tag;
      if( used ) {
        used_cnt++;
        used_sz += sz;
        if( sz>used_max ) used_max = sz;
      } else {
        free_cnt++;
        free_sz += sz;
        if( sz>free_max ) free_max = sz;
      }

      TRAP( fprintf( file, "\tpartition [0x%016lx,0x%016lx) sz %20lu tag %20lu idx %lu", lo, hi, sz, tag, i ) );
      if( FD_UNLIKELY( h !=last_i  ) ) { cnt++; TRAP( fprintf( file, ", link_err"     ) ); }
      if( FD_UNLIKELY( lo!=last_hi ) ) { cnt++; TRAP( fprintf( file, ", adjacent_err" ) ); }
      if( FD_UNLIKELY( lo>=hi      ) ) { cnt++; TRAP( fprintf( file, ", size_err"     ) ); }
      TRAP( fprintf( file, "\n" ) );

      last_i  = i;
      last_hi = hi;
      i       = fd_wksp_private_pinfo_idx( pinfo[ i ].next_cidx );
    }

    ulong j = fd_wksp_private_pinfo_idx( wksp->part_tail_cidx );
    if( FD_UNLIKELY(        j!=last_i  ) ) { cnt++; TRAP( fprintf( file, "\ttail err\n"       ) ); }
    if( FD_UNLIKELY( gaddr_hi!=last_hi ) ) { cnt++; TRAP( fprintf( file, "\tincomplete err\n" ) ); }

    TRAP( fprintf( file, "\t%20lu bytes used (%20lu blocks, largest %20lu bytes)\n", used_sz, used_cnt, used_max ) );
    TRAP( fprintf( file, "\t%20lu bytes free (%20lu blocks, largest %20lu bytes)\n", free_sz, free_cnt, free_max ) );

    fd_wksp_private_unlock( wksp );
  }

  TRAP( fprintf( file, "\t%20lu errors detected\n", cnt ) );
# undef TRAP

  return ret;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
# define SHIFT(n) argv+=(n),argc-=(n)

  if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "no arguments" ));
  char const * bin = argv[0];
  SHIFT(1);

  umask( (mode_t)0 ); /* So mode setting gets respected */

  ulong tag = 1UL;

  int cnt = 0;
  while( argc ) {
    char const * cmd = argv[0];
    SHIFT(1);

    if( !strcmp( cmd, "help" ) ) {

      fflush( stdout ); fflush( stderr );
      fputs( fd_wksp_ctl_help, stdout );
      fflush( stdout ); fflush( stderr );

      FD_LOG_NOTICE(( "%i: %s: success", cnt, cmd ));

    } else if( !strcmp( cmd, "tag" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      tag = fd_cstr_to_ulong( argv[0] );

      FD_LOG_NOTICE(( "%i: %s %lu: success", cnt, cmd, tag ));
      SHIFT(1);

    } else if( !strcmp( cmd, "supported-styles" ) ) {

      printf( "%s\n", FD_HAS_LZ4 ? "0 1 2 3" : "0 1 2" );

      FD_LOG_NOTICE(( "%i: %s: success", cnt, cmd ));

    } else if( !strcmp( cmd, "new" ) ) {

      if( FD_UNLIKELY( argc<5 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name     =                           argv[0];
      ulong        page_cnt = fd_cstr_to_ulong        ( argv[1] );
      ulong        page_sz  = fd_cstr_to_shmem_page_sz( argv[2] );
      char const * seq      =                           argv[3];
      ulong        mode     = fd_cstr_to_ulong_octal  ( argv[4] );

      /* Partition the pages over the seq */

      ulong sub_page_cnt[ 512 ];
      ulong sub_cpu_idx [ 512 ];
      ulong sub_cnt = fd_cstr_to_ulong_seq( seq, sub_cpu_idx, 512UL );

      if( FD_UNLIKELY( !sub_cnt ) )
        FD_LOG_ERR(( "%i: %s %s %lu %s %s 0%03lo: empty or invalid cpu sequence\n\t"
                     "Do %s help for help", cnt, cmd, name, page_cnt, argv[2], seq, mode, bin ));

      if( FD_UNLIKELY( sub_cnt>512UL ) )
        FD_LOG_ERR(( "%i: %s %s %lu %s %s 0%03lo: sequence too long, increase limit in fd_wksp_ctl.c\n\t"
                     "Do %s help for help", cnt, cmd, name, page_cnt, argv[2], seq, mode, bin ));

      ulong sub_page_min = page_cnt / sub_cnt;
      ulong sub_page_rem = page_cnt % sub_cnt;
      for( ulong sub_idx=0UL; sub_idx<sub_cnt; sub_idx++ ) sub_page_cnt[ sub_idx ] = sub_page_min + (ulong)(sub_idx<sub_page_rem);

      /* Create the workspace */

      /* TODO: allow user to specify seed and/or part_max */
      int err = fd_wksp_new_named( name, page_sz, sub_cnt, sub_page_cnt, sub_cpu_idx, mode, 0U, 0UL ); /* logs details */
      if( FD_UNLIKELY( err ) )
        FD_LOG_ERR(( "%i: %s %s %lu %s %s 0%03lo: fd_wksp_new_named failed (%i-%s)\n\t"
                     "Do %s help for help", cnt, cmd, name, page_cnt, argv[2], seq, mode, err, fd_wksp_strerror( err ), bin ));

      FD_LOG_NOTICE(( "%i: %s %s %lu %s %s 0%03lo: success", cnt, cmd, name, page_cnt, argv[2], seq, mode ));
      SHIFT(5);

    } else if( !strcmp( cmd, "delete" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name = argv[0];

      int err = fd_wksp_delete_named( name );
      if( FD_UNLIKELY( err ) )
        FD_LOG_ERR(( "%i: %s %s: fd_wksp_delete_named failed (%i-%s)\n\t"
                     "Do %s help for help", cnt, cmd, name, err, fd_wksp_strerror( err ), bin ));

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, name ));
      SHIFT(1);

    } else if( !strcmp( cmd, "alloc" ) ) {

      if( FD_UNLIKELY( argc<3 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name  =                   argv[0];
      ulong        align = fd_cstr_to_ulong( argv[1] );
      ulong        sz    = fd_cstr_to_ulong( argv[2] );

      char name_gaddr[ FD_WKSP_CSTR_MAX ];
      if( !fd_wksp_cstr_alloc( name, align, sz, tag, name_gaddr ) ) /* logs details */
        FD_LOG_ERR(( "%i: %s %s %lu %lu %lu: fd_wksp_cstr_alloc failed", cnt, cmd, name, align, sz, tag ));
      printf( "%s\n", name_gaddr );

      FD_LOG_NOTICE(( "%i: %s %s %lu %lu: success", cnt, cmd, name, align, sz ));
      SHIFT(3);

    } else if( !strcmp( cmd, "info" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name =                   argv[0];
      ulong        tag  = fd_cstr_to_ulong( argv[1] );

      fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
      if( FD_LIKELY( wksp ) ) {
        fd_wksp_tag_query_info_t info[1];
        ulong tag_cnt = tag ? fd_wksp_tag_query( wksp, &tag, 1UL, info, 1UL ) : 0UL; /* logs details */
        if( tag_cnt ) printf( "%s:%lu %lu\n", name, info->gaddr_lo, info->gaddr_hi - info->gaddr_lo );
        else          printf( "- 0\n" );
        fd_wksp_detach( wksp ); /* logs details */
      }

      FD_LOG_NOTICE(( "%i: %s %s %lu: success", cnt, cmd, name, tag ));
      SHIFT(2);

    } else if( !strcmp( cmd, "free" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name_gaddr = argv[0];

      fd_wksp_cstr_free( name_gaddr ); /* logs details */

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, name_gaddr )); /* FIXME: HMMM (print success on bad free?) */
      SHIFT(1);

    } else if( !strcmp( cmd, "tag-query" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name_gaddr = argv[0];

      printf( "%lu\n", fd_wksp_cstr_tag( name_gaddr ) ); /* logs details */

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, name_gaddr ));
      SHIFT(1);

    } else if( !strcmp( cmd, "tag-free" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name =                   argv[0];
      ulong        tag  = fd_cstr_to_ulong( argv[1] );

      fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
      if( FD_LIKELY( wksp ) ) {
        fd_wksp_tag_free( wksp, &tag, 1UL ); /* logs details */
        fd_wksp_detach( wksp );              /* logs details */
      }

      FD_LOG_NOTICE(( "%i: %s %s %lu: success", cnt, cmd, name, tag ));
      SHIFT(2);

    } else if( !strcmp( cmd, "memset" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name_gaddr =                 argv[0];
      int          c          = fd_cstr_to_int( argv[1] );

      fd_wksp_cstr_memset( name_gaddr, c ); /* logs details */

      FD_LOG_NOTICE(( "%i: %s %s %i: success", cnt, cmd, name_gaddr, c ));
      SHIFT(2);

    } else if( !strcmp( cmd, "check" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name = argv[0];

      fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
      if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "%i: %s %s: wksp_attach failed", cnt, cmd, name ));

      if( FD_UNLIKELY( fd_wksp_private_lock( wksp ) ) ) FD_LOG_ERR(( "%i: %s %s: failed", cnt, cmd, name )); /* logs details */
      fd_wksp_private_unlock( wksp );

      fd_wksp_detach( wksp ); /* logs details */

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, name ));
      SHIFT(1);

    } else if( !strcmp( cmd, "verify" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name = argv[0];

      fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
      if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "%i: %s %s: wksp_attach failed", cnt, cmd, name ));

      if( FD_UNLIKELY( fd_wksp_private_lock( wksp ) ) || /* logs details */
          FD_UNLIKELY( fd_wksp_verify( wksp )       ) )  /* logs details */
        FD_LOG_ERR(( "%i: %s %s: failed", cnt, cmd, name ));
      fd_wksp_private_unlock( wksp );

      fd_wksp_detach( wksp ); /* logs details */

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, name ));
      SHIFT(1);

    } else if( !strcmp( cmd, "rebuild" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name  = argv[0];
      char const * _seed = argv[1];

      fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
      if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "%i: %s %s %s: wksp_attach failed", cnt, cmd, name, _seed ));

      uint seed = strcmp( _seed, "-" ) ? fd_cstr_to_uint( _seed ) : fd_wksp_seed( wksp );

      if( FD_UNLIKELY( fd_wksp_private_lock( wksp )  ) || /* logs details */
          FD_UNLIKELY( fd_wksp_rebuild( wksp, seed ) ) )  /* logs details */
        FD_LOG_ERR(( "%i: %s %s %u: failed", cnt, cmd, name, seed ));
      fd_wksp_private_unlock( wksp );

      fd_wksp_detach( wksp ); /* logs details */

      FD_LOG_NOTICE(( "%i: %s %s %u: success", cnt, cmd, name, seed ));
      SHIFT(2);

    } else if( !strcmp( cmd, "reset" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name = argv[0];

      fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
      if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "%i: %s %s: wksp_attach failed", cnt, cmd, name ));
      fd_wksp_reset( wksp, fd_wksp_seed( wksp ) ); /* logs details */
      fd_wksp_detach( wksp ); /* logs details */

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, name ));
      SHIFT(1);

    } else if( !strcmp( cmd, "usage" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name =                   argv[0];
      ulong        tag  = fd_cstr_to_ulong( argv[1] );

      fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
      if( FD_UNLIKELY( !wksp ) ) fprintf( stdout, "-\n" );
      else {
        fd_wksp_usage_t usage[1];
        fd_wksp_usage( wksp, &tag, 1UL, usage );
        fprintf( stdout,
                 "wksp %s\n"
                 "\t%20lu bytes max        (%lu blocks, %lu blocks max)\n"
                 "\t%20lu bytes used       (%lu blocks)\n"
                 "\t%20lu bytes avail      (%lu blocks)\n"
                 "\t%20lu bytes w/tag %4lu (%lu blocks)\n",
                 wksp->name,
                 usage->total_sz,                  usage->total_cnt,                   usage->total_max,
                 usage->total_sz - usage->free_sz, usage->total_cnt - usage->free_cnt,
                 usage->free_sz,                   usage->free_cnt,
                 usage->used_sz, tag,              usage->used_cnt );
        fd_wksp_detach( wksp ); /* logs details */
      }

      FD_LOG_NOTICE(( "%i: %s %s %lu: success", cnt, cmd, name, tag ));
      SHIFT(2);

    } else if( !strcmp( cmd, "query" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name = argv[0];

      fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
      if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "%i: %s %s: wksp_attach failed", cnt, cmd, name ));
      fprintf_wksp( stdout, wksp ); /* logs details */
      fd_wksp_detach( wksp ); /* logs details */

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, name ));
      SHIFT(1);

    } else if( !strcmp( cmd, "checkpt" ) ) {

      if( FD_UNLIKELY( argc<5 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name  =                         argv[0];
      char const * path  =                         argv[1];
      ulong        mode  = fd_cstr_to_ulong_octal( argv[2] );
      int          style = fd_cstr_to_int        ( argv[3] );
      char const * info  =                         argv[4];

      fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
      if( FD_UNLIKELY( !wksp ) )
        FD_LOG_ERR(( "%i: %s %s %s 0%03lo %i ...: wksp_attach failed", cnt, cmd, name, path, mode, style ));

      int err = fd_wksp_checkpt( wksp, path, mode, style, info ); /* logs details */
      if( FD_UNLIKELY( err ) )
        FD_LOG_ERR(( "%i: %s %s %s 0%03lo %i ...: fd_wksp_checkpt failed", cnt, cmd, name, path, mode, style ));

      fd_wksp_detach( wksp ); /* logs details */

      FD_LOG_NOTICE(( "%i: %s %s %s 0%03lo %i ...: success", cnt, cmd, name, path, mode, style ));
      SHIFT(5);

    } else if( !strcmp( cmd, "checkpt-query" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * path    =                 argv[0];
      int          verbose = fd_cstr_to_int( argv[1] );

      fd_wksp_printf( fileno( stdout ), path, verbose );

      FD_LOG_NOTICE(( "%i: %s %s %i: success", cnt, cmd, path, verbose ));
      SHIFT(2);

    } else if( !strcmp( cmd, "restore" ) ) {

      if( FD_UNLIKELY( argc<3 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name  = argv[0];
      char const * path  = argv[1];
      char const * _seed = argv[2];

      fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
      if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "%i: %s %s %s %s: wksp_attach failed", cnt, cmd, name, path, _seed ));

      uint seed = strcmp( _seed, "-" ) ? fd_cstr_to_uint( _seed ) : fd_wksp_seed( wksp );

      int err = fd_wksp_restore( wksp, path, seed ); /* logs details */
      if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "%i: %s %s %s %u: fd_wksp_restore failed", cnt, cmd, name, path, seed ));

      fd_wksp_detach( wksp ); /* logs details */

      FD_LOG_NOTICE(( "%i: %s %s %s %u: success", cnt, cmd, name, path, seed ));
      SHIFT(3);

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
  if( FD_UNLIKELY( argc>1 ) ) FD_LOG_ERR(( "fd_wksp_ctl not supported on this platform" ));
  FD_LOG_NOTICE(( "processed 0 commands" ));
  fd_halt();
  return 0;
}

#endif
