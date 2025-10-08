/* For O_DIRECT and O_NOATIME */
#define _GNU_SOURCE

#include "fd_vinyl.h"
#include "../util/pod/fd_pod.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

FD_IMPORT_CSTR( fd_vinyl_ctl_help, "src/vinyl/fd_vinyl_ctl_help" );

static int
fd_vinyl_main( int     argc,
               char ** argv ) {

  ulong seed_default = fd_cstr_hash_append( (ulong)fd_log_wallclock(), fd_log_host() );

  char const * _pod      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--pod",      NULL, NULL            );
  char const * _cfg      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cfg",      NULL, NULL            );
  ulong        seed      = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed",     NULL, seed_default    );
  char const * type      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--type",     NULL, "mm"            );
  char const * path      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--path",     NULL, NULL            );
  int          dsync     = fd_env_strip_cmdline_int  ( &argc, &argv, "--dsync",    NULL, 0               );
  int          direct    = fd_env_strip_cmdline_int  ( &argc, &argv, "--direct",   NULL, 0               );
  int          noatime   = fd_env_strip_cmdline_int  ( &argc, &argv, "--noatime",  NULL, 0               );
  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"      );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL             );
  ulong        near_cpu  = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu", NULL, fd_log_cpu_id() );
  int          reset     = fd_env_strip_cmdline_int  ( &argc, &argv, "--reset",    NULL, 0               );
  char const * info      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--info",     NULL, NULL            );
  ulong        io_seed   = fd_env_strip_cmdline_ulong( &argc, &argv, "--io-seed",  NULL, 0UL             );

  int   open_flags = O_RDWR | (dsync ? O_DSYNC : 0 ) | (direct ? O_DIRECT : 0) | (noatime ? O_NOATIME : 0);
  ulong page_sz    = fd_cstr_to_shmem_page_sz( _page_sz );
  ulong info_sz    = info ? (strlen( info )+1UL) : 0UL;

  if( FD_UNLIKELY( !_pod    ) ) FD_LOG_ERR(( "--pod not specified" ));
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "bad --page-sz" ));

  FD_LOG_NOTICE(( "Attaching to --pod %s", _pod ));

  uchar const * pod = fd_wksp_pod_attach( _pod ); /* logs details, guaranteed to succeed */
  uchar const * cfg;
  if( FD_UNLIKELY( !_cfg ) ) {
    FD_LOG_NOTICE(( "--cfg not specified (using pod root for config)" ));
    cfg = pod;
  } else {
    FD_LOG_NOTICE(( "Finding config --cfg %s", _cfg ));
    cfg = fd_pod_query_subpod( pod, _cfg );
    if( FD_UNLIKELY( !cfg ) ) FD_LOG_ERR(( "config not found" ));
  }

  FD_LOG_NOTICE(( "Extracting pod configuration" ));

  /* See below for explanation of defaults */
  ulong spad_max    = fd_pod_query_ulong( cfg, "spad_max",    fd_vinyl_io_spad_est()         );
  ulong async_min   = fd_pod_query_ulong( cfg, "async_min",   2UL                            );
  ulong async_max   = fd_pod_query_ulong( cfg, "async_max",   2UL*async_min                  );
  ulong part_thresh = fd_pod_query_ulong( cfg, "part_thresh", 1UL<<30                        );
  ulong gc_thresh   = fd_pod_query_ulong( cfg, "gc_thresh",   8UL<<30                        );
  int   gc_eager    = fd_pod_query_int  ( cfg, "gc_eager",    2                              );
  int   style       = fd_pod_query_int  ( cfg, "style",       FD_VINYL_BSTREAM_CTL_STYLE_LZ4 );
  int   level       = fd_pod_query_int  ( cfg, "level",       1                              );

  FD_LOG_NOTICE(( "Processing command line configuration overrides" ));

  char const * _style = fd_env_strip_cmdline_cstr( &argc, &argv, "--style", NULL, NULL );
  if( _style ) style = fd_cstr_to_vinyl_bstream_ctl_style( _style );

  spad_max    = fd_env_strip_cmdline_ulong( &argc, &argv, "--spad-max",    NULL, spad_max    );
  async_min   = fd_env_strip_cmdline_ulong( &argc, &argv, "--async-min",   NULL, async_min   );
  async_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--async-max",   NULL, async_max   );
  part_thresh = fd_env_strip_cmdline_ulong( &argc, &argv, "--part-thresh", NULL, part_thresh );
  gc_thresh   = fd_env_strip_cmdline_ulong( &argc, &argv, "--gc-thresh",   NULL, gc_thresh   );
  gc_eager    = fd_env_strip_cmdline_int  ( &argc, &argv, "--gc-eager",    NULL, gc_eager    );
  level       = fd_env_strip_cmdline_int  ( &argc, &argv, "--level",       NULL, level       );

  FD_LOG_NOTICE(( "Mapping vinyl memory regions" ));

  void * _vinyl = fd_wksp_pod_map( cfg, "vinyl" ); ulong vinyl_footprint = fd_pod_query_ulong( cfg, "vinyl_footprint", 0UL );
  void * _cnc   = fd_wksp_pod_map( cfg, "cnc"   ); ulong cnc_footprint   = fd_pod_query_ulong( cfg, "cnc_footprint",   0UL );
  void * _meta  = fd_wksp_pod_map( cfg, "meta"  ); ulong meta_footprint  = fd_pod_query_ulong( cfg, "meta_footprint",  0UL );
  void * _line  = fd_wksp_pod_map( cfg, "line"  ); ulong line_footprint  = fd_pod_query_ulong( cfg, "line_footprint",  0UL );
  void * _io    = fd_wksp_pod_map( cfg, "io"    ); ulong io_footprint    = fd_pod_query_ulong( cfg, "io_footprint",    0UL );
  void * _ele   = fd_wksp_pod_map( cfg, "ele"   ); ulong ele_footprint   = fd_pod_query_ulong( cfg, "ele_footprint",   0UL );
  void * _obj   = fd_wksp_pod_map( cfg, "obj"   ); ulong obj_footprint   = fd_pod_query_ulong( cfg, "obj_footprint",   0UL );

# define TEST( c, msg ) do {                                              \
    if( FD_UNLIKELY( !(c) ) ) FD_LOG_ERR(( "FAIL: %s (%s)", #c, (msg) )); \
  } while(0)

  fd_wksp_t * wksp = fd_wksp_containing( _obj );
  TEST( wksp, "fd_wksp_containing failed" );

  TEST( fd_ulong_is_aligned( (ulong)_vinyl, fd_vinyl_io_mm_align() ), "bad alloc" );
  TEST( vinyl_footprint >= fd_vinyl_footprint(),                      "bad alloc" );

  int is_mmio = !strcmp( type, "mm" );

  FD_LOG_NOTICE(( "io config"
                  "\n\t--type      \"%s\""
                  "\n\t--spad-max  %lu bytes"
                  "\n\t--path      \"%s\""
                  "\n\t--dsync     %i"
                  "\n\t--direct    %i"
                  "\n\t--noatime   %i"
                  "\n\t--page-sz   \"%s\"%s"
                  "\n\t--page-cnt  %lu pages%s"
                  "\n\t--near-cpu  %lu%s"
                  "\n\t--reset     %i"
                  "\n\t--info      \"%s\" (info_sz %lu bytes%s)"
                  "\n\t--io-seed   0x%016lx%s",
                  type, spad_max, path ? path : "(null)", dsync, direct, noatime,
                  _page_sz, is_mmio && !path ? "" : " (ignored)",
                  page_cnt, is_mmio && !path ? "" : " (ignored)",
                  near_cpu, is_mmio && !path ? "" : " (ignored)",
                  reset, info ? info : "(null)", info_sz, reset ? "" : ", ignored", io_seed, reset ? "" : " (ignored)" ));

  FD_LOG_NOTICE(( "Joining bstream" ));

  int    bstream_type;
  int    fd = -1;
  void * mmio;
  ulong  mmio_sz;

  fd_vinyl_io_t * io;

  if( FD_LIKELY( is_mmio ) ) {

    if( FD_LIKELY( path ) ) {

      fd = open( path, open_flags, (mode_t)0 );

      if( FD_LIKELY( fd!=-1 ) ) { /* --path seems to be file (e.g. testing or basic I/O with weak persistence) */

        TEST( !direct, "--direct 1 not supported with --type mm and file --path" );
        /* FIXME: is dsync valid for mmio? (unclear) noatime? (probably) */

        FD_LOG_NOTICE(( "Using file at --path as a memory mapped bstream" ));

        bstream_type = 0;

        int err = fd_io_mmio_init( fd, FD_IO_MMIO_MODE_READ_WRITE, &mmio, &mmio_sz );
        if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_io_mmio_init failed (%i-%s)", err, fd_io_strerror( err ) ));

      } else { /* --path doesn't seem to be a file, use shmem (e.g. testing or ultra HPC with weak persistence) */

        FD_LOG_NOTICE(( "Using shmem region at --path as a memory mapped bstream (ignoring --dsync, --direct and --noatime)" ));

        bstream_type = 1;

        fd_shmem_join_info_t info[1];
        mmio = fd_shmem_join( path, FD_SHMEM_JOIN_MODE_READ_WRITE, NULL, NULL, info );
        TEST( mmio, "fd_shmem_join failed" );
        mmio_sz = info->page_sz * info->page_cnt;

      }

    } else { /* No --path, use an anonymous region (e.g. testing or ultra HPC with no persistence) */

      FD_LOG_NOTICE(( "Using an anonymous shmem region as a memory mapped bstream "
                      "(ignoring --dsync, --direct and --noatime, setting --reset to 1)" ));

      bstream_type = 2;
      reset        = 1;

      mmio = fd_shmem_acquire( page_sz, page_cnt, near_cpu );
      TEST( mmio, "fd_shmem_acquire failed" );
      mmio_sz = page_sz*page_cnt;

    }

    TEST( fd_ulong_is_aligned( (ulong)_io, fd_vinyl_io_mm_align() ), "bad alloc" );
    TEST( io_footprint >= fd_vinyl_io_mm_footprint( spad_max ),      "bad alloc" );

    io = fd_vinyl_io_mm_init( _io, spad_max, mmio, mmio_sz, reset, info, info_sz, io_seed );
    TEST( io, "fd_vinyl_io mm_init failed" );

  } else if( !strcmp( type, "bd" ) ) {

    TEST( path, "--path not specified for --type bd" );

    FD_LOG_NOTICE(( "Using --path as a block device bstream" ));

    bstream_type = 3;

    fd = open( path, open_flags, 0 );
    if( FD_UNLIKELY( fd==-1 ) ) FD_LOG_ERR(( "open failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    TEST( fd_ulong_is_aligned( (ulong)_io, fd_vinyl_io_bd_align() ), "bad wksp alloc" );
    TEST( io_footprint >= fd_vinyl_io_bd_footprint( spad_max ),      "bad wksp alloc" );

    io = fd_vinyl_io_bd_init( _io, spad_max, fd, reset, info, info_sz, io_seed );
    TEST( io, "fd_vinyl_io bd_init failed" );

  } else {

    FD_LOG_ERR(( "Unsupported io type" ));

  }

  FD_LOG_NOTICE(( "Creating vinyl" ));

  fd_tpool_t * tpool = NULL;

  ulong thread_cnt = fd_tile_cnt();

  if( thread_cnt>1UL ) {
    FD_LOG_NOTICE(( "Creating temporary tpool from all %lu tiles for thread parallel init", thread_cnt ));

    static uchar _tpool[ FD_TPOOL_FOOTPRINT( FD_TILE_MAX ) ] __attribute__((aligned(FD_TPOOL_ALIGN)));

    tpool = fd_tpool_init( _tpool, thread_cnt, 0UL ); /* logs details */
    if( FD_UNLIKELY( !tpool ) ) FD_LOG_ERR(( "fd_tpool_init failed" ));

    for( ulong thread_idx=1UL; thread_idx<thread_cnt; thread_idx++ )
      if( FD_UNLIKELY( !fd_tpool_worker_push( tpool, thread_idx ) ) ) FD_LOG_ERR(( "fd_tpool_worker_push failed" ));
  }

  fd_vinyl_t * vinyl = fd_vinyl_init( tpool, 0UL, thread_cnt, level,
                                      _vinyl,
                                      _cnc,  cnc_footprint,
                                      _meta, meta_footprint,
                                      _line, line_footprint,
                                      _ele,  ele_footprint,
                                      _obj,  obj_footprint,
                                      io, seed, wksp, async_min, async_max, part_thresh, gc_thresh, gc_eager, style );

  TEST( vinyl, "fd_vinyl_init failed" );

  if( tpool ) {
    FD_LOG_NOTICE(( "Destroying temporary tpool" ));
    fd_tpool_fini( tpool );
  }

# undef TEST

  FD_LOG_NOTICE(( "Running" ));

  fd_vinyl_exec( vinyl );

  FD_LOG_NOTICE(( "Cleaning up" ));

  fd_vinyl_fini( vinyl );
  fd_vinyl_io_fini( io );

  switch( bstream_type ) {
  case 0:  fd_io_mmio_fini ( mmio, mmio_sz           ); /* logs details */ break; /* mmio on a file */
  case 1:  fd_shmem_leave  ( mmio, NULL, 0UL         ); /* logs details */ break; /* mmio on a named shmem region */
  case 2:  fd_shmem_release( mmio, page_sz, page_cnt ); /* logs details */ break; /* mmio on a anon  shmem region */
  default: break;                                                                 /* block device or other */
  }

  if( FD_LIKELY( fd!=-1 ) && FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close failed (%i-%s); attempting to continue", errno, fd_io_strerror( errno ) ));

  fd_wksp_pod_unmap( _ele   );
  fd_wksp_pod_unmap( _obj   );
  fd_wksp_pod_unmap( _io    );
  fd_wksp_pod_unmap( _line  );
  fd_wksp_pod_unmap( _meta  );
  fd_wksp_pod_unmap( _cnc   );
  fd_wksp_pod_unmap( _vinyl );

  fd_wksp_pod_detach( pod );

  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define SHIFT(n) argv += (n), argc -= (n)

  if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "no arguments" ));

  char const * bin = argv[0];
  SHIFT(1);

  umask( (mode_t)0 ); /* So mode setting gets respected */

  /* We let advanced operators configure these.  The defaults are
     reasonable safe values.  E.g. a larger pod might be useful if an
     operator wants to stash their own config in the pod created by a
     vinyl instance (and then might want the specific vinyl config to be
     its own subpod of that pod).  Or might want to stash additional
     info in the vinyl tile cnc_app region.  Or might want a
     larger/smaller io append scratch pad to speed up performance/reduce
     memory footprint.  Or to set the meta cache seed manually.  Or use
     their own tagging conventions.  Or ...

     For obj_footprint_avg, if we assume most objects are minimum sized,
     they will take up 2 blocks in the object store (1 for the header
     and 1 for the raw encoded pair).  Such objects will be stored in a
     superblock with 64 other objects.  So there is an 8 byte overhead
     for the superblock header.  And the superblocks are recursively
     contained in a larger superblocks with a radix of ~12 which adds a
     little more to the overhead (less than 1 byte practically). */

  ulong        wksp_tag          = 0xfdc12113c597a600UL; /* FD VINYL WKSP TAG 00 */
  ulong        pod_max           = 4096UL;
  char const * cfg_path          = NULL;
  ulong        cnc_app_sz        = FD_VINYL_CNC_APP_SZ;
  ulong        spad_max          = fd_vinyl_io_spad_est();
  ulong        async_min         = 2UL;
  ulong        async_max         = 4UL;
  ulong        part_thresh       = 1UL << 30;                      /* insert parallel recovery partitions every ~1 GiB */
  ulong        gc_thresh         = 8UL << 30;                      /* don't compact unless >~ 8 GiB used */
  int          gc_eager          = 2;                              /* target <~25% garbage items */
  int          style             = FD_VINYL_BSTREAM_CTL_STYLE_LZ4; /* enable data compression */
  int          level             = 1;                              /* do a hard reset by default */
  ulong        obj_footprint_avg = 2UL*FD_VINYL_BSTREAM_BLOCK_SZ + 8UL + 1UL; /* see note above */

  int err = 0;
  int cnt = 0;

  while( argc ) {
    char const * cmd = argv[0];
    SHIFT(1);

    if( !strcmp( cmd, "help" ) ) {

      fflush( stdout ); fflush( stderr );
      fputs( fd_vinyl_ctl_help, stdout );
      fflush( stdout ); fflush( stderr );

      FD_LOG_NOTICE(( "%i: %s: success", cnt, cmd ));

    } else if( !strcmp( cmd, "set" ) ) {

      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * key = argv[0];
      char const * val = argv[1];

      /**/ if( !strcmp( key, "wksp_tag"          ) ) wksp_tag          = fd_cstr_to_ulong                  ( val );
      else if( !strcmp( key, "pod_max"           ) ) pod_max           = fd_cstr_to_ulong                  ( val );
      else if( !strcmp( key, "cfg_path"          ) ) cfg_path          =                                     val;
      else if( !strcmp( key, "cnc_app_sz"        ) ) cnc_app_sz        = fd_cstr_to_ulong                  ( val );
      else if( !strcmp( key, "spad_max"          ) ) spad_max          = fd_cstr_to_ulong                  ( val );
      else if( !strcmp( key, "async_min"         ) ) async_min         = fd_cstr_to_ulong                  ( val );
      else if( !strcmp( key, "async_max"         ) ) async_max         = fd_cstr_to_ulong                  ( val );
      else if( !strcmp( key, "part_thresh"       ) ) part_thresh       = fd_cstr_to_ulong                  ( val );
      else if( !strcmp( key, "gc_thresh"         ) ) gc_thresh         = fd_cstr_to_ulong                  ( val );
      else if( !strcmp( key, "gc_eager"          ) ) gc_eager          = fd_cstr_to_int                    ( val );
      else if( !strcmp( key, "style"             ) ) style             = fd_cstr_to_vinyl_bstream_ctl_style( val );
      else if( !strcmp( key, "level"             ) ) level             = fd_cstr_to_int                    ( val );
      else if( !strcmp( key, "obj_footprint_avg" ) ) obj_footprint_avg = fd_cstr_to_ulong                  ( val );
      else FD_LOG_ERR(( "%i: %s %s %s: unknown key", cnt, cmd, key, val));

      FD_LOG_NOTICE(( "%i: %s %s %s: success", cnt, cmd, key, val ));
      SHIFT(2);

    } else if( !strcmp( cmd, "alloc-memory" ) ) {

      if( FD_UNLIKELY( argc<5 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * mem      =                           argv[0];
      ulong        page_cnt = fd_cstr_to_ulong        ( argv[1] );
      ulong        page_sz  = fd_cstr_to_shmem_page_sz( argv[2] );
      char const * seq      =                           argv[3];
      ulong        mode     = fd_cstr_to_ulong_octal  ( argv[4] );

      if( FD_UNLIKELY( !page_cnt ) )
        FD_LOG_ERR(( "%i: %s %s %lu %s %s 0%03lo: bad page count\n\t"
                     "Do %s help for help", cnt, cmd, mem, page_cnt, argv[2], seq, mode, bin ));

      if( FD_UNLIKELY( !page_sz ) )
        FD_LOG_ERR(( "%i: %s %s %lu %s %s 0%03lo: bad page size\n\t"
                     "Do %s help for help", cnt, cmd, mem, page_cnt, argv[2], seq, mode, bin ));

      /* Partition the pages over the seq */

      ulong sub_page_cnt[ 512UL ];
      ulong sub_cpu_idx [ 512UL ];
      ulong sub_cnt = fd_cstr_to_ulong_seq( seq, sub_cpu_idx, 512UL );

      if( FD_UNLIKELY( !sub_cnt ) )
        FD_LOG_ERR(( "%i: %s %s %lu %s %s 0%03lo: empty or invalid cpu sequence\n\t"
                     "Do %s help for help", cnt, cmd, mem, page_cnt, argv[2], seq, mode, bin ));

      if( FD_UNLIKELY( sub_cnt>512UL ) )
        FD_LOG_ERR(( "%i: %s %s %lu %s %s 0%03lo: sequence too long, increase limit in fd_vinyl_ctl.c\n\t"
                     "Do %s help for help", cnt, cmd, mem, page_cnt, argv[2], seq, mode, bin ));

      /* TODO: consider striping instead of blocking */

      ulong sub_page_min = page_cnt / sub_cnt;
      ulong sub_page_rem = page_cnt % sub_cnt;
      for( ulong sub_idx=0UL; sub_idx<sub_cnt; sub_idx++ ) sub_page_cnt[ sub_idx ] = sub_page_min + (ulong)(sub_idx<sub_page_rem);

      /* Create the workspace */

      /* TODO: allow user to specify seed and/or part_max */
      int err = fd_wksp_new_named( mem, page_sz, sub_cnt, sub_page_cnt, sub_cpu_idx, mode, 0U, 0UL ); /* logs details */
      if( FD_UNLIKELY( err ) )
        FD_LOG_ERR(( "%i: %s %s %lu %s %s 0%03lo: fd_wksp_new_named failed (%i-%s)\n\t"
                     "Do %s help for help", cnt, cmd, mem, page_cnt, argv[2], seq, mode, err, fd_wksp_strerror( err ), bin ));

      FD_LOG_NOTICE(( "%i: %s %s %lu %s %s 0%03lo: success", cnt, cmd, mem, page_cnt, argv[2], seq, mode ));
      SHIFT(5);

   } else if( !strcmp( cmd, "free-memory" ) ) {

      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * mem = argv[0];

      int err = fd_wksp_delete_named( mem );
      if( FD_UNLIKELY( err ) )
        FD_LOG_ERR(( "%i: %s %s: fd_wksp_delete_named failed (%i-%s)\n\t"
                     "Do %s help for help", cnt, cmd, mem, err, fd_wksp_strerror( err ), bin ));

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, mem ));
      SHIFT(1);

    } else if( !strcmp( cmd, "alloc-storage" ) ) {

      if( FD_UNLIKELY( argc<3 ) )
        FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * path    =                         argv[0];
      ulong        GiB_cnt = fd_cstr_to_ulong      ( argv[1] );
      ulong        mode    = fd_cstr_to_ulong_octal( argv[2] );

      if( FD_UNLIKELY( (!GiB_cnt) | (GiB_cnt>(1UL<<32)) ) )
        FD_LOG_ERR(( "%i: %s %s %lu 0%03lo: bad number of gigabytes\n\t"
                     "Do %s help for help", cnt, cmd, path, GiB_cnt, mode, bin ));

      ulong sz = GiB_cnt << 30;

      int fd = open( path, O_RDWR | O_CREAT | O_EXCL, (mode_t)mode );
      if( FD_UNLIKELY( fd==-1 ) )
        FD_LOG_ERR(( "%i: %s %s %lu 0%03lo: open failed (%i-%s)\n\tDo %s help for help",
                     cnt, cmd, path, GiB_cnt, mode, errno, fd_io_strerror( errno ), bin ));

      int err = fd_io_truncate( fd, sz );
      if( FD_UNLIKELY( err ) )
        FD_LOG_ERR(( "%i: %s %s %lu 0%03lo: fd_io_truncate failed (%i-%s)\n\tDo %s help for help",
                     cnt, cmd, path, GiB_cnt, mode, err, fd_io_strerror( err ), bin ));

      if( FD_UNLIKELY( close( fd ) ) )
        FD_LOG_WARNING(( "%i: %s %s %lu 0%03lo: close failed (%i-%s); attempting to continue",
                         cnt, cmd, path, GiB_cnt, mode, errno, fd_io_strerror( errno ) ));

      FD_LOG_NOTICE(( "%i: %s %s %lu 0%03lo: success", cnt, cmd, path, GiB_cnt, mode ));
      SHIFT(3);

    } else if( !strcmp( cmd, "free-storage" ) ) {

      if( FD_UNLIKELY( argc<1 ) )
        FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * store = argv[0];

      if( FD_UNLIKELY( unlink( store ) ) )
        FD_LOG_ERR(( "%i: %s %s: unlink failed (%i-%s)\n\tDo %s help for help",
                     cnt, cmd, store, errno, fd_io_strerror( errno ), bin ));

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, store ));
      SHIFT(1);

    } else if( !strcmp( cmd, "new" ) ) {

      if( FD_UNLIKELY( argc<3 ) )
        FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * mem      =                   argv[0];
      ulong        pair_max = fd_cstr_to_ulong( argv[1] );
      ulong        GiB_max  = fd_cstr_to_ulong( argv[2] );

#     define TEST( c, msg ) do {                                                 \
        if( FD_UNLIKELY( !(c) ) )                                                \
          FD_LOG_ERR(( "%i: %s %s %lu %lu: FAIL %s (%s)\n\tDo %s help for help", \
                       cnt, cmd, mem, pair_max, GiB_max, #c, (msg), bin ));      \
      } while(0)

      ulong ele_max   = fd_ulong_pow2_up( pair_max + 1UL );
      ulong lock_cnt  = fd_vinyl_meta_lock_cnt_est( ele_max );
      ulong probe_max = ele_max;

      TEST( (0UL<pair_max) & (pair_max<ele_max) & (ele_max<=(ULONG_MAX/sizeof(fd_vinyl_meta_ele_t))), "bad pair_max" );

      ulong mem_max = GiB_max << 30;

      ulong pod_align       = fd_pod_align();
      ulong pod_footprint   = fd_pod_footprint( pod_max );
      ulong vinyl_align     = fd_vinyl_align();
      ulong vinyl_footprint = fd_vinyl_footprint();
      ulong cnc_align       = fd_cnc_align();
      ulong cnc_footprint   = fd_cnc_footprint( cnc_app_sz );
      ulong meta_align      = fd_vinyl_meta_align();
      ulong meta_footprint  = fd_vinyl_meta_footprint( ele_max, lock_cnt, probe_max );
      ulong io_align        = fd_ulong_max( fd_vinyl_io_bd_align(),               fd_vinyl_io_mm_align()               );
      ulong io_footprint    = fd_ulong_max( fd_vinyl_io_bd_footprint( spad_max ), fd_vinyl_io_mm_footprint( spad_max ) );
      ulong line_align      = alignof(fd_vinyl_line_t);
      /* line footprint computed below */
      ulong ele_align       = alignof(fd_vinyl_meta_ele_t);
      ulong ele_footprint   =  sizeof(fd_vinyl_meta_ele_t)*ele_max;
      ulong obj_align       = alignof(fd_vinyl_data_obj_t);
      /* obj_footprint compted below */

      /* See note re io_align / io_footprint */

      TEST( pod_footprint,  "bad pod_max"    );
      TEST( cnc_footprint,  "bad cnc_app_sz" );
      TEST( meta_footprint, "bad pair_max"   );
      TEST( io_footprint,   "bad spad_max"   );

      ulong mem_req =   pod_footprint +   pod_align - 1UL
                    + vinyl_footprint + vinyl_align - 1UL
                    +   cnc_footprint +   cnc_align - 1UL
                    +  meta_footprint +  meta_align - 1UL
                    +    io_footprint +    io_align - 1UL
                    +     /* below */    line_align - 1UL
                    +   ele_footprint +   ele_align - 1UL
                    +     /* below */     obj_align - 1UL; /* FIXME: USE SATURATING ADDS */

      TEST( mem_req<mem_max, "increase maximum GiB allowed and/or decrease pair_max / spad_max / pod_max / cnc_app_sz" );

      ulong line_max = (mem_max - mem_req) / (sizeof(fd_vinyl_line_t) + obj_footprint_avg);

      TEST( line_max>=3UL, "increase maximum GiB allowed and/or decrease pair_max / spad_max / pod_max / cnc_app_sz" );

      ulong line_footprint = sizeof(fd_vinyl_line_t)*line_max;

      mem_req += line_footprint;

      ulong obj_footprint = fd_ulong_align_dn( mem_max - mem_req, alignof(fd_vinyl_data_obj_t) );

      mem_req += obj_footprint;

      TEST( mem_req<=mem_max, "internal error" );

      /* Attach to the memory that will contain this vinyl instance */

      fd_wksp_t * wksp = fd_wksp_attach( mem );
      TEST( wksp, "fd_wksp_attach failed" );

      /* Allocate all the needed regions.  Note that, even though the
         vinyl io tile state is neither shared nor persistent, we
         allocate it here so the vinyl tile itself doesn't have to
         allocate it (it is dynamically sized and rather large).  Since
         we want the vinyl tile to be able to pick the type of io
         interface and bstream store at startup without creating a new
         vinyl instance, we allocated an upper bound for all supported
         io types above (they are all roughly the same size anyway).

         Alternatively, we could have the vinyl tile do this allocation
         at tile startup.  But this would create some additional
         complexity: the vinyl tile would need an allocator (and then
         one potentially has allocations left over from previous runs
         that did not terminate cleanly).

         Similar considerations apply for the data cache state, vinyl
         tile state, lines and data objects.

         Note also that, though meta is shared and persistent,
         persistence should only be used for post mortem debugging (the
         meta cache is recreated from scratch on vinyl tile startup). */

      void * _pod   = fd_wksp_alloc_laddr( wksp,   pod_align,   pod_footprint, wksp_tag );
      void * _vinyl = fd_wksp_alloc_laddr( wksp, vinyl_align, vinyl_footprint, wksp_tag );
      void * _cnc   = fd_wksp_alloc_laddr( wksp,   cnc_align,   cnc_footprint, wksp_tag );
      void * _meta  = fd_wksp_alloc_laddr( wksp,  meta_align,  meta_footprint, wksp_tag );
      void * _io    = fd_wksp_alloc_laddr( wksp,    io_align,    io_footprint, wksp_tag );
      void * _line  = fd_wksp_alloc_laddr( wksp,  line_align,  line_footprint, wksp_tag ); /* This is kinda big */
      void * _ele   = fd_wksp_alloc_laddr( wksp,   ele_align,   ele_footprint, wksp_tag ); /* This is really big */
      void * _obj   = fd_wksp_alloc_laddr( wksp,   obj_align,   obj_footprint, wksp_tag );

      /* Note: the bigger obj gets, the better the performance (until it
         is large enough pairs always fit in cache but that would dwarf
         ele).  In typical use cases, this is probably smaller to
         comparable to ele (resulting in much cheaper hardware at
         comparable speeds for typical usage patterns but less robust
         performance for extreme usage patterns). */

      TEST( (!!_pod) & (!!_vinyl) & (!!_cnc) & (!!_io) & (!!_line) & (!!_ele) & (!!_obj),
           "fd_wksp_alloc_laddr failed (free unneeded allocs or increase wksp size or partitions)" );

      /* Format and the join the pod and create the cfg subpod as
         necessary. */

      uchar * pod = fd_pod_join( fd_pod_new( _pod, pod_max ) );
      TEST( pod, "internal error" );

      uchar * cfg;
      if( !cfg_path ) cfg = pod;
      else {
        ulong off = fd_pod_alloc_subpod( pod, cfg_path, 1024UL );
        TEST( off, "use shorter cfg_path or increase pod_max?" );
        cfg = pod + off;
      }

      /* Populate the pod */

      char tmp[ FD_WKSP_CSTR_MAX ];

      TEST( fd_pod_insert_cstr( cfg, "vinyl", fd_wksp_cstr_laddr( _vinyl, tmp ) ), "increase pod_max?" );
      TEST( fd_pod_insert_cstr( cfg, "cnc",   fd_wksp_cstr_laddr( _cnc,   tmp ) ), "increase pod_max?" );
      TEST( fd_pod_insert_cstr( cfg, "meta",  fd_wksp_cstr_laddr( _meta,  tmp ) ), "increase pod_max?" );
      TEST( fd_pod_insert_cstr( cfg, "io",    fd_wksp_cstr_laddr( _io,    tmp ) ), "increase pod_max?" );
      TEST( fd_pod_insert_cstr( cfg, "line",  fd_wksp_cstr_laddr( _line,  tmp ) ), "increase pod_max?" );
      TEST( fd_pod_insert_cstr( cfg, "ele",   fd_wksp_cstr_laddr( _ele,   tmp ) ), "increase pod_max?" );
      TEST( fd_pod_insert_cstr( cfg, "obj",   fd_wksp_cstr_laddr( _obj,   tmp ) ), "increase pod_max?" );

      TEST( fd_pod_insert_ulong( cfg, "vinyl_footprint", vinyl_footprint ), "increase pod_max?" );
      TEST( fd_pod_insert_ulong( cfg,   "cnc_footprint",   cnc_footprint ), "increase pod_max?" );
      TEST( fd_pod_insert_ulong( cfg,  "meta_footprint",  meta_footprint ), "increase pod_max?" );
      TEST( fd_pod_insert_ulong( cfg,    "io_footprint",    io_footprint ), "increase pod_max?" );
      TEST( fd_pod_insert_ulong( cfg,  "line_footprint",  line_footprint ), "increase pod_max?" );
      TEST( fd_pod_insert_ulong( cfg,   "ele_footprint",   ele_footprint ), "increase pod_max?" );
      TEST( fd_pod_insert_ulong( cfg,   "obj_footprint",   obj_footprint ), "increase pod_max?" );

      TEST( fd_pod_insert_ulong( cfg, "spad_max",    spad_max    ), "increase pod_max?" );
      TEST( fd_pod_insert_ulong( cfg, "pair_max",    pair_max    ), "increase pod_max?" );
      TEST( fd_pod_insert_ulong( cfg, "line_max",    line_max    ), "increase pod_max?" );
      TEST( fd_pod_insert_ulong( cfg, "async_min",   async_min   ), "increase pod_max?" );
      TEST( fd_pod_insert_ulong( cfg, "async_max",   async_max   ), "increase pod_max?" );
      TEST( fd_pod_insert_ulong( cfg, "part_thresh", part_thresh ), "increase pod_max?" );
      TEST( fd_pod_insert_ulong( cfg, "gc_thresh",   gc_thresh   ), "increase pod_max?" );
      TEST( fd_pod_insert_int  ( cfg, "gc_eager",    gc_eager    ), "increase pod_max?" );
      TEST( fd_pod_insert_int  ( cfg, "style",       style       ), "increase pod_max?" );
      TEST( fd_pod_insert_int  ( cfg, "level",       level       ), "increase pod_max?" );

      /* Tell the operator where the pod is */
      /* FIXME: consider putting the config pod in a normal page named
         shmem region or a flat file instead?  Probably easier to pass
         between applications than a wksp gaddr. */

      printf( "%s\n", fd_wksp_cstr_laddr( _pod, tmp ) );

      /* Clean up */

      if( cfg!=pod ) TEST( fd_pod_compact( cfg, 1 ), "internal error" );

      TEST( fd_pod_leave( pod )==_pod, "internal error" );

      TEST( !fd_wksp_detach( wksp ), "internal error" );

#     undef TEST

      FD_LOG_NOTICE(( "%i: %s %s %lu %lu: success", cnt, cmd, mem, pair_max, GiB_max ));
      SHIFT(3);

    } else if( !strcmp( cmd, "delete" ) ) {

      if( FD_UNLIKELY( argc<1 ) )
        FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * cstr = argv[0];

#     define TEST( c, msg ) do {                                         \
        if( FD_UNLIKELY( !(c) ) )                                        \
          FD_LOG_ERR(( "%i: %s %s: FAIL %s (%s)\n\tDo %s help for help", \
                       cnt, cmd, cstr, #c, (msg), bin ));                \
      } while(0)

      uchar const * pod = fd_pod_join( fd_wksp_map( cstr ) ); /* logs details */
      TEST( pod, "unable to join pod" );

      uchar const * cfg;
      if( !cfg_path ) cfg = pod;
      else {
        cfg = fd_pod_query_subpod( pod, cfg_path );
        TEST( cfg, "cfg not found at cfg_path" );
      }

      fd_wksp_cstr_free( fd_pod_query_cstr( cfg, "obj",   NULL ) );
      fd_wksp_cstr_free( fd_pod_query_cstr( cfg, "ele",   NULL ) );
      fd_wksp_cstr_free( fd_pod_query_cstr( cfg, "line",  NULL ) );
      fd_wksp_cstr_free( fd_pod_query_cstr( cfg, "io",    NULL ) );
      fd_wksp_cstr_free( fd_pod_query_cstr( cfg, "meta",  NULL ) );
      fd_wksp_cstr_free( fd_pod_query_cstr( cfg, "cnc",   NULL ) );
      fd_wksp_cstr_free( fd_pod_query_cstr( cfg, "vinyl", NULL ) );

      fd_wksp_unmap( fd_pod_leave( pod ) );

      fd_wksp_cstr_free( cstr );

      FD_LOG_NOTICE(( "%i: %s %s: success", cnt, cmd, cstr ));
      SHIFT(1);

    } else if( !strcmp( cmd, "exec" ) ) {

      err = fd_vinyl_main( argc, argv );
      break;

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
  return err;
}
