#include "../fd_util.h"
#include "fd_wksp_private.h"

#if FD_HAS_HOSTED && FD_HAS_X86

#include <stdio.h>
#include <sys/stat.h>

FD_IMPORT_CSTR( fd_wksp_ctl_help, "src/util/wksp/fd_wksp_ctl_help" );

/* fd_printf_wksp pretty prints the detailed workspace state to file.
   Includes detailed metadata integrity checking.  Return value
   semantics are the same as for fprintf. */

static int
fprintf_wksp( FILE *      file,
              fd_wksp_t * wksp ) {
  ulong cnt = 0UL;
  int   ret = 0;

  if( FD_UNLIKELY( !file ) ) {
    FD_LOG_WARNING(( "NULL file" ));
    return -1;
  }

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return -1;
  }

  fd_wksp_private_lock( wksp );

  fd_wksp_private_part_t * part     = wksp->part;
  ulong                    part_cnt = wksp->part_cnt;
  ulong                    part_max = wksp->part_max;
  ulong                    gaddr_lo = wksp->gaddr_lo;
  ulong                    gaddr_hi = wksp->gaddr_hi;

  int err;
# define TRAP(x) do { err = (x); if( err<0 ) { fd_wksp_private_unlock( wksp ); return err; } ret += err; } while(0)

  TRAP( fprintf( file, "wksp %s", wksp->name ) );
  TRAP( fprintf( file, "\n\tpart_cnt %li part_max %li gaddr [0x%016lx,0x%016lx)", part_cnt, part_max, gaddr_lo, gaddr_hi ) );
  if( ! (1UL<=part_max)                                         ) { cnt++; TRAP( fprintf( file, " max_err"     ) ); }
  if( !((1UL<=part_cnt) & (part_cnt<=part_max))                 ) { cnt++; TRAP( fprintf( file, " cnt_err"     ) ); }
  if( !fd_ulong_is_aligned( gaddr_hi, FD_WKSP_ALLOC_ALIGN_MIN ) ) { cnt++; TRAP( fprintf( file, " alignhi_err" ) ); }
  TRAP( fprintf( file, "\n" ) );

  ulong active_cnt = 0UL; ulong inactive_cnt = 0UL;
  ulong active_sz  = 0UL; ulong inactive_sz  = 0UL;
  ulong active_max = 0UL; ulong inactive_max = 0UL;

  int last_active = 1;
  for( ulong i=0UL; i<part_cnt; i++ ) {
    ulong tag    = fd_wksp_private_part_tag  (  part[i    ] );
    ulong lo     = fd_wksp_private_part_gaddr(  part[i    ] );
    ulong hi     = fd_wksp_private_part_gaddr(  part[i+1UL] );

    ulong sz = hi-lo;

    int active = !!tag;
    if( active ) {
      active_cnt++;
      active_sz += sz;
      if( sz>active_max ) active_max = sz;
    } else {
      inactive_cnt++;
      inactive_sz += sz;
      if( sz>inactive_max ) inactive_max = sz;
    }

    TRAP( fprintf( file, "\tpartition %20li: [0x%016lx,0x%016lx) sz %20lu tag %4lu", i, lo, hi, sz, tag ) );

    if( lo>=hi                                                            ) { cnt++; TRAP( fprintf( file, " part_err"      ) ); }
    if( ((i==0UL)            & (lo!=gaddr_lo))                            ) { cnt++; TRAP( fprintf( file, " lo_err"        ) ); }
    if( ((i==(part_cnt-1UL)) & (hi!=gaddr_hi))                            ) { cnt++; TRAP( fprintf( file, " hi_err"        ) ); }
    if( i==(part_cnt-1UL) && fd_wksp_private_part_tag( part[i+1UL] )!=1UL ) { cnt++; TRAP( fprintf( file, " hi_active_err" ) ); }
    if( !fd_ulong_is_aligned( lo, FD_WKSP_ALLOC_ALIGN_MIN )               ) { cnt++; TRAP( fprintf( file, " align_err"     ) ); }
    if( ((!last_active) & (!active))                                      ) { cnt++; TRAP( fprintf( file, " merge_err"     ) ); }
    TRAP( fprintf( file, "\n" ) );

    last_active = active;
  }

  TRAP( fprintf( file, "\t%20lu bytes used  (%20lu alloc(s), largest %20lu bytes)\n",   active_sz,   active_cnt,   active_max ) );
  TRAP( fprintf( file, "\t%20lu bytes avail (%20lu block(s), largest %20lu bytes)\n", inactive_sz, inactive_cnt, inactive_max ) );
  TRAP( fprintf( file, "\t%20lu errors detected\n", cnt ) );

# undef TRAP
  fd_wksp_private_unlock( wksp );

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

      fputs( fd_wksp_ctl_help, stdout );

      FD_LOG_NOTICE(( "%i: %s: success", cnt, cmd ));

    } else if( !strcmp( cmd, "tag" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      tag = fd_cstr_to_ulong( argv[0] );

      FD_LOG_NOTICE(( "%i: %s %lu: success", cnt, cmd, tag ));
      SHIFT(1);

    } else if( !strcmp( cmd, "new" ) ) {

      if( FD_UNLIKELY( argc<5 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name     =                           argv[0];
      ulong        page_cnt = fd_cstr_to_ulong        ( argv[1] );
      ulong        page_sz  = fd_cstr_to_shmem_page_sz( argv[2] );
      char const * seq      =                           argv[3];
      ulong        mode     = fd_cstr_to_ulong_octal  ( argv[4] );

      /* Create the shared memory region for the workspace */

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

      if( FD_UNLIKELY( fd_shmem_create_multi( name, page_sz, sub_cnt, sub_page_cnt, sub_cpu_idx, mode ) ) ) /* logs details */
        FD_LOG_ERR(( "%i: %s %s %lu %s %s 0%03lo: fd_shmem_create_multi failed\n\t"
                     "Do %s help for help", cnt, cmd, name, page_cnt, argv[2], seq, mode, bin ));

      ulong sz = page_cnt*page_sz; /* Safe as create succeeded */
      if( FD_UNLIKELY( !((fd_wksp_align()<=page_sz) & (fd_wksp_footprint( sz )==sz)) ) ) { /* paranoid checks */
        fd_shmem_unlink( name, page_sz ); /* logs details */
        FD_LOG_ERR(( "%i: %s %s %lu %s %s 0%03lo: internal error\n\t"
                     "Do %s help for help", cnt, cmd, name, page_cnt, argv[2], seq, mode, bin ));
      }

      /* Join the region */

      fd_shmem_join_info_t info[1];
      void * shmem = fd_shmem_join( name, FD_SHMEM_JOIN_MODE_READ_WRITE, NULL, NULL, info );
      if( FD_UNLIKELY( !shmem ) ) {
        fd_shmem_unlink( name, page_sz ); /* logs details */
        FD_LOG_ERR(( "%i: %s %s %lu %s %s 0%03lo: fd_shmem_join failed\n\t"
                     "Do %s help for help", cnt, cmd, name, page_cnt, argv[2], seq, mode, bin ));
      }

      if( FD_UNLIKELY( ((info->page_sz!=page_sz) | (info->page_cnt!=page_cnt)) ) ) { /* paranoid checks */
        fd_shmem_unlink( name, page_sz ); /* logs details */
        fd_shmem_leave( shmem, NULL, NULL ); /* logs details */ /* after the unlink as per unix file semantics */
        FD_LOG_ERR(( "%i: %s %s %lu %s %s 0%03lo: multiple regions with same name but different sizes detected\n\t"
                     "Do %s help for help", cnt, cmd, name, page_cnt, argv[2], seq, mode, bin ));
      }

      /* Format the region as a workspace */

      if( FD_UNLIKELY( !fd_wksp_new( shmem, name, sz, 0UL ) ) ) {
        fd_shmem_unlink( name, page_sz ); /* logs details */
        fd_shmem_leave( shmem, NULL, NULL ); /* logs details */ /* after the unlink as per unix file semantics */
        FD_LOG_ERR(( "%i: %s %s %lu %s %s 0%03lo: fd_wksp_new failed\n\t"
                     "Do %s help for help", cnt, cmd, name, page_cnt, argv[2], seq, mode, bin ));
      }

      /* Leave the region */

      fd_shmem_leave( shmem, NULL, NULL ); /* logs details */
      FD_LOG_NOTICE(( "%i: %s %s %lu %s %s 0%03lo: success", cnt, cmd, name, page_cnt, argv[2], seq, mode ));
      SHIFT(5);

    } else if( !strcmp( cmd, "delete" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name = argv[0];

      /* Join the region and get the page size */

      fd_shmem_join_info_t info[1];
      void * shmem = fd_shmem_join( name, FD_SHMEM_JOIN_MODE_READ_WRITE, NULL, NULL, info ); /* logs details */
      if( FD_UNLIKELY( !shmem ) ) FD_LOG_ERR(( "%i: %s %s: fd_shmem_join failed\n\tDo %s help for help", cnt, cmd, name, bin ));
      ulong page_sz = info->page_sz;

      /* Unformat the region */

      if( FD_UNLIKELY( !fd_wksp_delete( shmem ) ) ) {
        fd_shmem_leave( shmem, NULL, NULL ); /* logs details */
        FD_LOG_ERR(( "%i: %s %s: fd_shmem_delete failed\n\t"
                     "Do %s help for help", cnt, cmd, name, bin ));
      }

      /* Unlink the region */

      if( FD_UNLIKELY( fd_shmem_unlink( name, page_sz ) ) ) { /* logs details */
        fd_shmem_leave( shmem, NULL, NULL ); /* logs details */
        FD_LOG_ERR(( "%i: %s %s: fd_shmem_unlink failed\n\t"
                     "Do %s help for help", cnt, cmd, name, bin ));
      }

      fd_shmem_leave( shmem, NULL, NULL ); /* logs details */ /* after the unlink as per unix file semantics */
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
      if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "%i: %s: wksp_attach failed", cnt, cmd ));
      fd_wksp_check( wksp ); /* logs details */
      fd_wksp_detach( wksp ); /* logs details */

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, name ));
      SHIFT(1);

    } else if( !strcmp( cmd, "reset" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * name = argv[0];

      fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
      if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "%i: %s: wksp_attach failed", cnt, cmd ));
      fd_wksp_reset( wksp ); /* logs details */
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
      if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "%i: %s: wksp_attach failed", cnt, cmd ));
      fprintf_wksp( stdout, wksp ); /* logs details */
      fd_wksp_detach( wksp ); /* logs details */

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, name ));
      SHIFT(1);

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

