#define _DEFAULT_SOURCE
#include "fd_solfuzz.h"
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../fd_runtime.h"
#include "../../../ballet/nanopb/pb_firedancer.h"

static int fail_fast;
static int error_occurred;

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

typedef int (* visit_path)( void * ctx, char const * path );

static int
recursive_walk1( DIR *      dir,
                 char       path[ PATH_MAX ],
                 ulong      path_len,
                 visit_path visit,
                 void *     visit_ctx ) {
  struct dirent * entry;
  errno = 0;
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
      recursive_walk1( subdir, path, sub_path_len, visit, visit_ctx );
      closedir( subdir );
    } else if( entry->d_type==DT_REG ) {
as_file:
      suffix = strstr( entry->d_name, ".fix" );
      if( !suffix || suffix[4]!='\0' ) continue;
      if( !visit( visit_ctx, path ) ) break;
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
  return 1;
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
            char const * path ) {
  fd_solfuzz_runner_t * runner = ctx;
  int ok = run_test( runner, path );
  if( !ok ) {
    error_occurred = 1;
    if( fail_fast ) return 0;
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

FD_FN_UNUSED static void
run_multi_threaded( fd_solfuzz_runner_t ** runners,
                    ulong                  worker_cnt,
                    int     argc,
                    char ** argv ) {
  (void)runners; (void)worker_cnt; (void)argc; (void)argv;
  FD_LOG_WARNING(( "Multi-threaded mode not implemented yet" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * wksp_name = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL,    NULL );
  uint         wksp_seed = fd_env_strip_cmdline_uint ( &argc, &argv, "--wksp-seed", NULL,      0U );
  ulong        wksp_tag  = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL,     1UL );
  ulong        data_max  = fd_env_strip_cmdline_ulong( &argc, &argv, "--data-max",  NULL, 6UL<<30 ); /* 6 GiB */
  ulong        part_max  = fd_env_strip_cmdline_ulong( &argc, &argv, "--part-max",  NULL, fd_wksp_part_max_est( data_max, 64UL<<10 ) );

  fd_wksp_t * wksp;
  if( wksp_name ) {
    FD_LOG_INFO(( "Attaching to --wksp %s", wksp_name ));
    wksp = fd_wksp_attach( wksp_name );
  } else {
    FD_LOG_INFO(( "--wksp not specified, using anonymous demand-paged memory --part-max %lu --data-max %lu", part_max, data_max ));
    wksp = fd_wksp_demand_paged_new( "solfuzz", wksp_seed, part_max, data_max );
  }
  if( FD_UNLIKELY( !wksp ) ) return 255;

  /* Run strategy: If the application was launched with one tile
     (default), run everything on the current tile.  If more than one
     tile is detected, use the first tile (recommended floating) to walk
     the file system, use all other tiles to execute fuzz vectors. */
  ulong worker_cnt = fd_tile_cnt();
  if( worker_cnt>1UL ) worker_cnt--;

  /* Allocate runners */
  int exit_code = 255;
  fd_solfuzz_runner_t ** runners = fd_wksp_alloc_laddr( wksp, alignof(void *), worker_cnt*sizeof(void *), 1UL );
  if( FD_UNLIKELY( !runners ) ) { FD_LOG_WARNING(( "init failed" )); goto exit; }
  fd_memset( runners, 0, worker_cnt*sizeof(void *) );
  for( ulong i=0UL; i<worker_cnt; i++ ) {
    runners[i] = fd_solfuzz_runner_new( wksp, wksp_tag );
    if( FD_UNLIKELY( !runners[i] ) ) { FD_LOG_WARNING(( "init failed (creating worker %lu)", i )); goto exit; }
  }

  /* Run strategy */
  //if( fd_tile_cnt()==1 ) {
    run_single_threaded( runners[0], argc, argv );
  //} else {
  //  run_multi_threaded( runners, worker_cnt, argc, argv );
  //}
  if( error_occurred ) {
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
  fd_wksp_free_laddr( runners );
  if( wksp_name ) fd_wksp_detach( wksp );
  else            fd_wksp_demand_paged_delete( wksp );

  fd_halt();
  return exit_code;
}
