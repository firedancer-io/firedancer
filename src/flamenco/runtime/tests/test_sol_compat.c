/* test_sol_compat.c runs solfuzz/sol_compat/protosol Protobuf fixtures.
   Supports parallel / tile-based execution. */

#define _DEFAULT_SOURCE
#include "fd_solfuzz.h"
#include <errno.h>
#include <dirent.h> /* opendir */
#include <fcntl.h>
#include <sched.h> /* sched_yield */
#include <stdio.h> /* fputs */
#include <sys/types.h>
#include <sys/stat.h> /* fstat */
#include <unistd.h> /* close */
#include "../../../ballet/nanopb/pb_firedancer.h"
#include "../../../tango/fd_tango.h"

#define MCACHE_DEPTH     (256UL)
#define MCACHE_FOOTPRINT FD_MCACHE_FOOTPRINT( MCACHE_DEPTH, 0UL )
#define DCACHE_DATA_SZ   FD_DCACHE_REQ_DATA_SZ( PATH_MAX, MCACHE_DEPTH, 1UL, 1 )
#define DCACHE_FOOTPRINT FD_DCACHE_FOOTPRINT( DCACHE_DATA_SZ, 0UL )

static int g_fail_fast;
static int g_error_occurred;

static uint shutdown_signal __attribute__((aligned(64)));

/* run_test runs a test.
   Return 1 on success, 0 on failure. */
static int
run_test1( fd_solfuzz_runner_t * runner,
           char const *          path ) {

  /* Read file content to memory */

  int file = open( path, O_RDONLY );
  if( FD_UNLIKELY( file<0 ) ) {
    FD_LOG_WARNING(( "open(%s) failed: (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return 0;
  }
  struct stat st;
  if( FD_UNLIKELY( 0!=fstat( file, &st ) ) ) {
    FD_LOG_WARNING(( "fstat(%s) failed: (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return 0;
  }
  ulong file_sz = (ulong)st.st_size;
  uchar * buf = fd_spad_alloc( runner->spad, 1, file_sz );
  FD_TEST( 0==fd_io_read( file, buf, file_sz, file_sz, &file_sz ) );
  FD_TEST( 0==close( file ) );

  /* Execute test */
  int ok = 0;

  FD_LOG_DEBUG(( "Running test %s", path ));

  if( strstr( path, "/instr/" ) != NULL ) {
    ok = fd_solfuzz_instr_fixture( runner, buf, file_sz );
  } else if( strstr( path, "/txn/" ) != NULL ) {
    ok = fd_solfuzz_txn_fixture( runner, buf, file_sz );
  } else if( strstr( path, "/elf_loader/" ) != NULL ) {
    ok = fd_solfuzz_elf_loader_fixture( runner, buf, file_sz );
  } else if( strstr( path, "/syscall/" ) != NULL ) {
    ok = fd_solfuzz_syscall_fixture( runner, buf, file_sz );
  } else if( strstr( path, "/vm_interp/" ) != NULL ){
    ok = fd_solfuzz_vm_interp_fixture( runner, buf, file_sz );
  } else if( strstr( path, "/block/" ) != NULL ){
    ok = fd_solfuzz_block_fixture( runner, buf, file_sz );
  } else {
    FD_LOG_WARNING(( "Unknown test type: %s", path ));
  }

  if( ok ) FD_LOG_INFO   (( "OK   %s", path ));
  else     FD_LOG_WARNING(( "FAIL %s", path ));

  return ok;
}

static int
run_test( fd_solfuzz_runner_t * runner,
          char const *          path ) {
  ulong frames_used_pre_test = runner->spad->frame_free;
  ulong mem_used_pre_test    = runner->spad->mem_used;

  fd_spad_push( runner->spad );
  int ok = !!run_test1( runner, path );
  fd_spad_pop( runner->spad );

  ulong frames_used_post_test = runner->spad->frame_free;
  ulong mem_used_post_test    = runner->spad->mem_used;

  FD_TEST( frames_used_pre_test == frames_used_post_test );
  FD_TEST( mem_used_pre_test    == mem_used_post_test    );
  return ok;
}

/* Recursive dir walk function, follows symlinks */

typedef int
(* visit_path)( void *       ctx,
                char const * path,
                ulong        path_len );

static int
recursive_walk1( DIR *      dir,
                 char       path[ PATH_MAX ],
                 ulong      path_len,
                 visit_path visit,
                 void *     visit_ctx ) {
  struct dirent * entry;
  errno = 0;
  int ok = 1;
  while(( entry = readdir( dir ) )) {
    path[ path_len ] = '\0';
    if( FD_LIKELY( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) ) continue;

    ulong child_len = strlen( entry->d_name );
    if( FD_UNLIKELY( path_len+1+child_len+1>PATH_MAX ) ) {
      FD_LOG_WARNING(( "Ignoring overlong path name: %s/%s", path, entry->d_name ));
      continue;
    }

    char * p = path+path_len;
    p = fd_cstr_append_char( p, '/' );
    p = fd_cstr_append_text( p, entry->d_name, child_len );
    fd_cstr_fini( p );
    ulong sub_path_len = (ulong)( p-path );

    DIR * subdir = NULL;
    char * suffix;
    if( entry->d_type==DT_DIR ) {
      subdir = opendir( path );
      if( FD_UNLIKELY( !subdir ) ) {
        FD_LOG_WARNING(( "opendir(%s) failed: (%i-%s)", path, errno, fd_io_strerror( errno ) ));
        continue;
      }
as_dir:
      ok = recursive_walk1( subdir, path, sub_path_len, visit, visit_ctx );
      closedir( subdir );
      if( !ok ) break;
    } else if( entry->d_type==DT_REG ) {
as_file:
      suffix = strstr( entry->d_name, ".fix" );
      if( !suffix || suffix[4]!='\0' ) continue;
      if( !visit( visit_ctx, path, sub_path_len ) ) { ok = 0; break; }
    } else if( entry->d_type==DT_LNK ) {
      subdir = opendir( path );
      if( subdir ) {
        goto as_dir;
      } else {
        if( FD_UNLIKELY( errno!=ENOTDIR ) ) {
          FD_LOG_WARNING(( "opendir(%s) failed: (%i-%s)", path, errno, fd_io_strerror( errno ) ));
          continue;
        }
        goto as_file;
      }
    }
  }
  return ok;
}

static int
recursive_walk( char const * path,
                visit_path   visit,
                void *       visit_ctx ) {
  char  path1[ PATH_MAX ];
  ulong path_len = strlen( path );
  if( FD_UNLIKELY( path_len>=PATH_MAX ) ) {
    FD_LOG_WARNING(( "Ignoring overlong path name: %s", path ));
    return 0;
  }
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( path1 ), path, path_len ) );
  DIR * root_dir = opendir( path1 );
  if( FD_UNLIKELY( !root_dir ) ) {
    if( errno==ENOTDIR ) {
      return visit( visit_ctx, path1, path_len );
    }
    FD_LOG_WARNING(( "opendir(%s) failed: (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return 0;
  }
  int ok = recursive_walk1( root_dir, path1, path_len, visit, visit_ctx );
  closedir( root_dir );
  return ok;
}

/* Single-threaded mode: execute synchronously while walking dir */

static int
visit_sync( void *       ctx,
            char const * path,
            ulong        path_len ) {
  (void)path_len;
  fd_solfuzz_runner_t * runner = ctx;
  int ok = run_test( runner, path );
  if( !ok ) {
    g_error_occurred = 1;
    if( g_fail_fast ) return 0;
  }
  return 1;
}

static void
run_single_threaded( fd_solfuzz_runner_t * runner,
                     int     argc,
                     char ** argv ) {
  for( int j=1; j<argc; j++ ) {
    int ok = recursive_walk( argv[ j ], visit_sync, runner );
    if( !ok ) {
      FD_LOG_WARNING(( "Stopping early" ));
    }
  }
}

/* Multi-threaded mode: fan out tasks to bank of tiles */

struct walkdir_state {
  fd_frag_meta_t * mcache;
  uchar *          dcache;

  ulong depth;
  ulong chunk0;
  ulong wmark;

  ulong seq;
  ulong chunk;
  ulong cr_avail;

  ulong    worker_cnt;
  ulong ** fseqs;
};
typedef struct walkdir_state walkdir_state_t;

static int
walkdir_backpressure( walkdir_state_t * state ) {
  ulong const worker_cnt = state->worker_cnt;
  ulong const seq_pub    = state->seq;
  ulong       cr_avail   = state->cr_avail;
  do {
    if( FD_VOLATILE_CONST( shutdown_signal ) ) return 0;
    sched_yield();
    cr_avail = ULONG_MAX;
    for( ulong i=0UL; i<worker_cnt; i++ ) {
      long lag = fd_seq_diff( seq_pub, fd_fseq_query( state->fseqs[ i ] ) );
      /**/ lag = fd_long_max( lag, 0L );
      cr_avail = fd_ulong_min( cr_avail, MCACHE_DEPTH-(ulong)lag );
    }
  } while( !cr_avail );
  state->cr_avail = cr_avail;
  return 1;
}

static int
walkdir_publish( void *       ctx,
                 char const * path,
                 ulong        path_len ) {
  walkdir_state_t * state = ctx;
  if( FD_UNLIKELY( !state->cr_avail ) ) {
    /* Blocked on flow-control credits ... spin until they're replenished */
    if( !walkdir_backpressure( state ) ) return 0;
    /* Guaranteed to have more flow-control credits */
  }

  /* Write data record */
  ulong  chunk = state->chunk;
  char * msg   = fd_chunk_to_laddr( state->dcache, chunk );
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( msg ), path, path_len ) );
  state->chunk = fd_dcache_compact_next( chunk, path_len+1UL, state->chunk0, state->wmark );

  /* Write frag descriptor */
  ulong seq = state->seq;
  fd_mcache_publish( state->mcache, state->depth, seq, 0UL, chunk, 0UL, 0UL, 0UL, 0UL );
  state->seq = fd_seq_inc( seq, 1UL );
  state->cr_avail--;
  return 1;
}

static void
walkdir_tile( fd_frag_meta_t * mcache,
              uchar *          dcache,
              ulong **         fseqs,
              ulong            worker_cnt,
              int              argc,
              char **          argv ) {
  walkdir_state_t state = {
    .mcache     = mcache,
    .dcache     = dcache,
    .depth      = fd_mcache_depth( mcache ),
    .chunk0     = fd_dcache_compact_chunk0( dcache, dcache ),
    .wmark      = fd_dcache_compact_wmark ( dcache, dcache, PATH_MAX ),
    .seq        = fd_mcache_seq0( mcache ),
    .worker_cnt = worker_cnt,
    .fseqs      = fseqs
  };
  state.chunk    = state.chunk0;
  state.cr_avail = state.depth;

  for( int j=1; j<argc; j++ ) {
    int ok = recursive_walk( argv[ j ], walkdir_publish, &state );
    if( !ok ) {
      FD_LOG_WARNING(( "Stopping early" ));
    }
  }

  fd_mcache_seq_update( fd_mcache_seq_laddr( state.mcache ), state.seq );
}

struct mt_state {
  fd_solfuzz_runner_t ** runners;
  ulong                  worker_cnt;
  fd_frag_meta_t *       mcache;
  uchar *                dcache;
  ulong **               fseqs;
};
typedef struct mt_state mt_state_t;

static int
exec_tile( fd_solfuzz_runner_t *  runner,
           fd_frag_meta_t const * mcache,
           uchar *                dcache,
           ulong *                fseq,
           ulong                  idx,
           ulong                  cnt ) {
  ulong const depth     = fd_mcache_depth( mcache );
  ulong       seq       = 0UL;
  int         ok        = 1;
  int const   fail_fast = g_fail_fast;
  for(;;) {
    fd_frag_meta_t const * mline = mcache + fd_mcache_line_idx( seq, depth );
    ulong seq_found = fd_frag_meta_seq_query( mline );
    if( FD_UNLIKELY( seq!=seq_found ) ) {
      if( FD_VOLATILE_CONST( shutdown_signal ) ) break;
      FD_SPIN_PAUSE();
      continue;
    }

    if( seq%cnt==idx ) {
      char const * path = fd_chunk_to_laddr_const( dcache, mline->chunk );
      ok &= !!run_test( runner, path );
      if( fail_fast && !ok ) {
        FD_VOLATILE( shutdown_signal ) = 1;
        break;
      }
    }

    seq = fd_seq_inc( seq, 1UL );
    FD_VOLATILE( fseq[0] ) = seq;
  }
  FD_VOLATILE( fseq[0] ) = seq;
  return ok;
}

static int
exec_task( int     argc,
           char ** argv ) {
  ulong              worker_idx = (ulong)argc;
  mt_state_t const * state      = fd_type_pun_const( argv );
  return exec_tile( state->runners[ worker_idx ], state->mcache, state->dcache, state->fseqs[ worker_idx ], worker_idx, state->worker_cnt );
}

FD_FN_UNUSED static int
run_multi_threaded( fd_solfuzz_runner_t ** runners,
                    ulong                  worker_cnt,
                    int                    argc,
                    char **                argv,
                    fd_frag_meta_t *       mcache,
                    uchar *                dcache,
                    ulong **               fseqs ) {
  mt_state_t state = {
    .runners    = runners,
    .worker_cnt = worker_cnt,
    .mcache     = mcache,
    .dcache     = dcache,
    .fseqs      = fseqs
  };

  for( ulong i=0UL; i<worker_cnt; i++ ) {
    fd_tile_exec_new( 1UL+i, exec_task, (int)i, fd_type_pun( &state ) );
  }

  walkdir_tile( mcache, dcache, fseqs, worker_cnt, argc, argv );
  FD_VOLATILE( shutdown_signal ) = 1;

  int ok = 1;
  for( ulong i=0UL; i<worker_cnt; i++ ) {
    int tile_ok = 0;
    fd_tile_exec_delete( fd_tile_exec_by_id( 1UL+i ), &tile_ok );
    ok &= !!tile_ok;
  }

  ulong cnt = fd_mcache_seq_query( fd_mcache_seq_laddr_const( mcache ) );
  if( ok ) FD_LOG_NOTICE(( "Processed %lu files", cnt ));
  else     FD_LOG_WARNING(( "Processed %lu files, but at least one error occurred", cnt ));
  return ok;
}

int
main( int     argc,
      char ** argv ) {
  if( FD_UNLIKELY( fd_env_strip_cmdline_contains( &argc, &argv, "--help" ) ) ) {
    fputs(
        "\nUsage: test_sol_compat [options] <file/directory...>\n"
        "\n"
        "Options:\n"
        "\n"
        "  --page-sz      {gigantic|huge|normal}    Page size\n"
        "  --page-cnt     {count}                   Page count\n"
        "  --wksp         [file path]               Reuse existing workspace\n"
        "  --wksp-tag     1                         Workspace allocation tag\n"
        "  --fail-fast    1                         Stop executing after first failure?\n"
        "\n",
        stderr );
    return 0;
  }

  fd_boot( &argc, &argv );

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL,   "normal" );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL,        0UL );
  char const * wksp_name = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL,       NULL );
  uint         wksp_seed = fd_env_strip_cmdline_uint ( &argc, &argv, "--wksp-seed", NULL,         0U );
  ulong        wksp_tag  = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL,        1UL );
  int const    fail_fast = fd_env_strip_cmdline_int  ( &argc, &argv, "--fail-fast", NULL,        1   );
  g_fail_fast = !!fail_fast;

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  /* Run strategy: If the application was launched with one tile
     (default), run everything on the current tile.  If more than one
     tile is detected, use the first tile (recommended floating) to walk
     the file system, use all other tiles to execute fuzz vectors. */
  ulong worker_cnt = fd_tile_cnt();
  if( worker_cnt>1UL ) worker_cnt--;

  fd_wksp_t * wksp;
  if( wksp_name ) {
    FD_LOG_INFO(( "Attaching to --wksp %s", wksp_name ));
    wksp = fd_wksp_attach( wksp_name );
  } else if( !page_cnt ) {
    ulong data_max = worker_cnt*(7UL<<30);
    ulong part_max = fd_wksp_part_max_est( data_max, 64UL<<10 );
    FD_LOG_INFO(( "--wksp not specified, using anonymous demand-paged memory --part-max %lu --data-max %lu", part_max, data_max ));
    wksp = fd_wksp_demand_paged_new( "solfuzz", wksp_seed, part_max, data_max );
  } else {
    FD_LOG_INFO(( "Creating anonymous workspace (--page-cnt %lu, --page-sz %s, --wksp-seed %u)", page_cnt, _page_sz, wksp_seed ));
    wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_log_cpu_id(), "solfuzz", wksp_seed );
  }
  if( FD_UNLIKELY( !wksp ) ) return 255;

  /* Allocate runners */
  int exit_code = 255;
  fd_solfuzz_runner_t ** runners    = fd_wksp_alloc_laddr( wksp, alignof(void *),   worker_cnt*sizeof(void *),    wksp_tag );
  void *                 mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), MCACHE_FOOTPRINT,             wksp_tag );
  void *                 dcache_mem = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), DCACHE_FOOTPRINT,             wksp_tag );
  uchar *                fseqs_mem  = fd_wksp_alloc_laddr( wksp, fd_fseq_align(),   worker_cnt*FD_FSEQ_FOOTPRINT, wksp_tag );
  ulong **               fseqs      = fd_wksp_alloc_laddr( wksp, alignof(void *),   worker_cnt*sizeof(void *),    wksp_tag );
  if( FD_UNLIKELY( !runners | !mcache_mem | !dcache_mem | !fseqs_mem | !fseqs ) ) {
    FD_LOG_WARNING(( "init failed" )); goto exit;
  }
  fd_memset( runners, 0, worker_cnt*sizeof(void *) );
  for( ulong i=0UL; i<worker_cnt; i++ ) {
    fd_solfuzz_runner_options_t options = {
      .enable_vm_tracing = 0
    };
    runners[i] = fd_solfuzz_runner_new( wksp, wksp_tag, &options );
    if( FD_UNLIKELY( !runners[i] ) ) { FD_LOG_WARNING(( "init failed (creating worker %lu)", i )); goto exit; }
  }

  /* Create objects */
  fd_frag_meta_t * mcache = fd_mcache_join( fd_mcache_new( mcache_mem, MCACHE_DEPTH, 0UL, 0UL ) ); FD_TEST( mcache );
  uchar *          dcache = fd_dcache_join( fd_dcache_new( dcache_mem, DCACHE_DATA_SZ, 0UL    ) ); FD_TEST( dcache );
  for( ulong i=0UL; i<worker_cnt; i++ ) {
    fseqs[i] = fd_fseq_join( fd_fseq_new( fseqs_mem + i*FD_FSEQ_FOOTPRINT, 0UL ) ); FD_TEST( fseqs[i] );
  }

  /* Run strategy */
  if( fd_tile_cnt()==1 ) {
    run_single_threaded( runners[0], argc, argv );
  } else {
    g_error_occurred = !run_multi_threaded( runners, worker_cnt, argc, argv, mcache, dcache, fseqs );
  }
  if( g_error_occurred ) {
    if( fail_fast ) exit_code = 255;
    else            exit_code = 1;
  } else {
    exit_code = 0;
  }

exit:
  /* Undo all wksp allocs */
  for( ulong i=0UL; runners && i<worker_cnt; i++ ) {
    if( runners[i] ) fd_solfuzz_runner_delete( runners[i] );
  }
  fd_wksp_free_laddr( runners    );
  fd_wksp_free_laddr( mcache_mem );
  fd_wksp_free_laddr( dcache_mem );
  fd_wksp_free_laddr( fseqs_mem  );
  fd_wksp_free_laddr( fseqs      );
  if( wksp_name      ) fd_wksp_detach( wksp );
  else if( !page_cnt ) fd_wksp_demand_paged_delete( wksp );
  else                 fd_wksp_delete_anonymous( wksp );

  fd_halt();
  return exit_code;
}
