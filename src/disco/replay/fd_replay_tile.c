#include "../fd_disco.h"

#if FD_HAS_HOSTED && FD_HAS_X86

FD_STATIC_ASSERT( FD_REPLAY_TILE_SCRATCH_ALIGN<=FD_SHMEM_HUGE_PAGE_SZ, alignment );

static char const * out_fseq[ FD_REPLAY_TILE_OUT_MAX ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * cnc       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cnc",       NULL, NULL   );
  char const * pcap      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--pcap",      NULL, NULL   );
  ulong        pkt_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--pkt-max",   NULL, 1522UL );
  ulong        orig      = fd_env_strip_cmdline_ulong( &argc, &argv, "--orig",      NULL, 0UL    );
  char const * mcache    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--mcache",    NULL, NULL   );
  char const * dcache    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--dcache",    NULL, NULL   );
  char const * out_fseqs = fd_env_strip_cmdline_cstr ( &argc, &argv, "--out-fseqs", NULL, ""     );
  ulong        cr_max    = fd_env_strip_cmdline_ulong( &argc, &argv, "--cr-max",    NULL, 0UL    ); /*   0 <> use default */
  long         lazy      = fd_env_strip_cmdline_long ( &argc, &argv, "--lazy",      NULL, 0L     ); /* <=0 <> use default */
  uint         seed      = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",      NULL, (uint)(ulong)fd_tickcount() );

  if( FD_UNLIKELY( !cnc    ) ) FD_LOG_ERR(( "--cnc not specified"    ));
  if( FD_UNLIKELY( !pcap   ) ) FD_LOG_ERR(( "--pcap not specified"   ));
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "--mcache not specified" ));
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "--dcache not specified" ));

  ulong out_cnt = fd_cstr_tokenize( (char **)out_fseq, FD_REPLAY_TILE_OUT_MAX, (char *)out_fseqs, ',' ); /* argv is non-const */
  if( FD_UNLIKELY( out_cnt>FD_REPLAY_TILE_OUT_MAX ) ) FD_LOG_ERR(( "too many --out-fseqs specified" ));

  ulong footprint = fd_replay_tile_scratch_footprint( out_cnt );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "fd_replay_tile_scratch_footprint failed" ));

  ulong  page_sz  = FD_SHMEM_HUGE_PAGE_SZ;
  ulong  page_cnt = fd_ulong_align_up( footprint, page_sz ) / page_sz;
  ulong  cpu_idx  = fd_tile_cpu_id( fd_tile_idx() );
  void * scratch  = fd_shmem_acquire( page_sz, page_cnt, cpu_idx );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "fd_shmem_acquire failed (need at least %lu free huge pages on numa node %lu)",
                                             page_cnt, fd_shmem_numa_idx( cpu_idx ) ));

  int err = fd_replay_tile( cnc, pcap, pkt_max, orig, mcache, dcache, out_cnt, out_fseq, cr_max, lazy, seed, scratch );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_replay_tile failed (%i)", err ));

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

