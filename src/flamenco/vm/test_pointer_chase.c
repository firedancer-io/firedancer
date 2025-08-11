#include "../../util/fd_util.h"
#include <stdio.h>

/* RNG patterns */

typedef void
(* pattern_fn_t)( ulong *    ptr,
                  ulong      sz,
                  fd_rng_t * rng );

static void pattern_seq( ulong * ptr, ulong n, fd_rng_t * rng ) {
  (void)rng;
  for( ulong i=0UL; i<n; i++ ) {
    ptr[i] = (ulong)ptr + 8*i;
  }
}

static void pattern_random( ulong * ptr, ulong n, fd_rng_t * rng ) {
  /* Create a random permutation */
  for( ulong i=0UL; i<n; i++ ) {
    ptr[i] = (ulong)ptr + 8*i;
  }
  /* Fisher-Yates shuffle */
  for( ulong i=0UL; i<=n-2; i++ ) {
    ulong j = i+fd_rng_ulong_roll( rng, n-i );
    fd_swap( ptr[i], ptr[j] );
  }
}

static const struct {
  char const * name;
  char const * help;
  pattern_fn_t fn;
} patterns[] = {
  {
    .name = "seq",
    .help = "sequential scan",
    .fn   = pattern_seq
  },
  {
    .name = "random",
    .help = "random permutation",
    .fn   = pattern_random
  },
  {0}
};

/* Pointer chasing test */


static ulong
ptr_chase_block( ulong x ) {
  #define ITER_BLOCK 512
  #pragma GCC unroll 512
  for( ulong i=0UL; i<ITER_BLOCK; i++ ) {
    x = *(ulong *)x;
  }
  return x;
}

static ulong
ptr_chase( ulong * ptr, ulong iter ) {
  ulong x = (ulong)ptr;
  while( iter>=ITER_BLOCK ) {
    x = ptr_chase_block( x );
    iter -= ITER_BLOCK;
  }
  while( iter-- ) x = *(ulong *)x;
  return x;
}

/* Command-line handling */

int
main( int     argc,
      char ** argv ) {
  int const help_requested = fd_env_strip_cmdline_contains( &argc, &argv, "--help" );
  if( FD_UNLIKELY( help_requested ) ) {
    fputs(
      "\nUsage: test_pointer_chase [workspace] [--size 10e6] [--pattern PATTERN]\n"
      "\n"
      "  anonymous workspace:\n"
      "    --page-sz normal/huge/gigantic\n"
      "    --near-cpu 0\n"
      "\n"
      "  existing workspace:\n"
      "    --wksp NAME\n"
      "\n"
      "  Supported patterns:\n"
      "\n",
      stderr );
    for( ulong i=0UL; patterns[i].name; i++ ) {
      fprintf( stderr, "    %-10s %s\n", patterns[i].name, patterns[i].help );
    }
    fputs( "\n", stderr );
    return 0;
  }

  fd_boot( &argc, &argv );
  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL,            NULL );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL,        "normal" );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  float        size_f   = fd_env_strip_cmdline_float( &argc, &argv, "--size",      NULL,            10e6 );
  char const * pattern  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--pattern",   NULL,        "random" );
  float        iter_f   = fd_env_strip_cmdline_float( &argc, &argv, "--iter",      NULL,             1e7 );

  ulong size = (ulong)size_f;
  if( FD_UNLIKELY( !size || size > (1UL<<46) ) ) FD_LOG_ERR(( "Invalid --size" ));

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "Invalid --page-sz %s", _page_sz ));

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    ulong page_cnt = fd_ulong_align_up( size + 16384UL, page_sz ) / page_sz;
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 2UL );
    if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_new_anonymous failed" ));
  }

  ulong   line_cnt = fd_ulong_align_up( size, sizeof(ulong) )>>3;
  ulong * scratch = fd_wksp_alloc_laddr( wksp, alignof(ulong), line_cnt*sizeof(ulong), 1UL );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "Unable to allocate scratch" ));

  pattern_fn_t pat_fn = NULL;
  for( ulong i=0UL; patterns[i].name; i++ ) {
    if( 0==strcmp( patterns[i].name, pattern ) ) {
      pat_fn = patterns[i].fn;
      break;
    }
  }
  if( FD_UNLIKELY( !pat_fn ) ) FD_LOG_ERR(( "Unsupported --pattern %s", pattern ));

  long dt = -fd_log_wallclock();
  FD_LOG_NOTICE(( "Params: --pattern \"%s\" --size %g --iter %g", pattern, (double)line_cnt*8, (double)iter_f ));
  pat_fn( scratch, line_cnt, rng );
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "PATTERN elapsed=%.2es", (double)dt/1e9 ));

  dt = -fd_log_wallclock();
  ulong res = ptr_chase( scratch, (ulong)iter_f );
  FD_COMPILER_UNPREDICTABLE( res );
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "BENCH   elapsed=%.2es iter=%.1e period=%.2fns", (double)dt/1e9, (double)iter_f, (double)dt/(double)iter_f ));

  if( name ) fd_wksp_detach( wksp );
  else       fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );
  fd_halt();
  return 0;
}
