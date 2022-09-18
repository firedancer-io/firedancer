#include "../fd_disco.h"

#if FD_HAS_HOSTED && FD_HAS_X86

FD_STATIC_ASSERT( FD_DEDUP_TILE_SCRATCH_ALIGN<=FD_SHMEM_HUGE_PAGE_SZ, alignment );

static char const * in_mcache[ FD_DEDUP_TILE_IN_MAX  ];
static char const * in_fseq  [ FD_DEDUP_TILE_IN_MAX  ];
static char const * out_fseq [ FD_DEDUP_TILE_OUT_MAX ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * cnc        = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cnc",        NULL, NULL );
  char const * in_mcaches = fd_env_strip_cmdline_cstr ( &argc, &argv, "--in-mcaches", NULL, ""   );
  char const * in_fseqs   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--in-fseqs",   NULL, ""   );
  char const * tcache     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--tcache",     NULL, NULL );
  char const * mcache     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--mcache",     NULL, NULL );
  char const * out_fseqs  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--out-fseqs",  NULL, ""   );
  ulong        cr_max     = fd_env_strip_cmdline_ulong( &argc, &argv, "--cr-max",     NULL, 0UL  ); /*   0 <> use default */
  long         lazy       = fd_env_strip_cmdline_long ( &argc, &argv, "--lazy",       NULL, 0L   ); /* <=0 <> use default */
  uint         seed       = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",       NULL, (uint)(ulong)fd_tickcount() );

  if( FD_UNLIKELY( !cnc    ) ) FD_LOG_ERR(( "--cnc not specified"    ));
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "--mcache not specified" ));
  if( FD_UNLIKELY( !tcache ) ) FD_LOG_ERR(( "--tcache not specified" ));

  ulong in_cnt = fd_cstr_tokenize( (char **)in_mcache, FD_DEDUP_TILE_IN_MAX, (char *)in_mcaches, ',' ); /* argv is non-const */
  if( FD_UNLIKELY( in_cnt>FD_DEDUP_TILE_IN_MAX ) ) FD_LOG_ERR(( "too many --in-mcaches specified"   ));

  ulong tmp = fd_cstr_tokenize( (char **)in_fseq, FD_DEDUP_TILE_IN_MAX, (char *)in_fseqs, ',' ); /* argv is non-const */
  if( FD_UNLIKELY( tmp!=in_cnt ) ) FD_LOG_ERR(( "--in-mcaches and --in-fseqs mismatch" ));

  ulong out_cnt = fd_cstr_tokenize( (char **)out_fseq, FD_DEDUP_TILE_OUT_MAX, (char *)out_fseqs, ',' ); /* argv is non-const */
  if( FD_UNLIKELY( out_cnt>FD_DEDUP_TILE_OUT_MAX ) ) FD_LOG_ERR(( "too many --out-fseqs specified" ));

  ulong footprint = fd_dedup_tile_scratch_footprint( in_cnt, out_cnt );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "fd_dedup_tile_scratch_footprint failed" ));

  ulong  page_sz  = FD_SHMEM_HUGE_PAGE_SZ;
  ulong  page_cnt = fd_ulong_align_up( footprint, page_sz ) / page_sz;
  ulong  cpu_idx  = fd_tile_cpu_id( fd_tile_idx() );
  void * scratch  = fd_shmem_acquire( page_sz, page_cnt, cpu_idx );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "fd_shmem_acquire failed (need at least %lu free huge pages on numa node %lu)",
                                             page_cnt, fd_shmem_numa_idx( cpu_idx ) ));

  int err = fd_dedup_tile( cnc, in_cnt, in_mcache, in_fseq, tcache, mcache, out_cnt, out_fseq, cr_max, lazy, seed, scratch );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_dedup_tile failed (%i)", err ));

  fd_shmem_release( scratch, page_sz, page_cnt );
  fd_halt();
  return err;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "implement support for this build target" ));
  fd_halt();
  return 1;
}

#endif

