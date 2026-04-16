#define _GNU_SOURCE
#include "fd_vinyl_io_ur_private.h"
#include "../../../util/io_uring/fd_io_uring_setup.h"
#include "../../../util/io_uring/fd_io_uring_register.h"
#include "../../../util/hist/fd_histf.h"

#include <stdlib.h> /* mkstemp */
#include <errno.h>
#include <unistd.h> /* ftruncate */
#include <fcntl.h>  /* open */
#include <linux/io_uring.h> /* io_uring_params */
#include <sys/mman.h> /* mmap */

#include "../test_vinyl_io_common.c"

static void
bench_append( fd_vinyl_io_t * io,
              ulong           pair_sz ) {
  fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io; /* Note: io must be non-NULL to have even been called */
  double ns_per_tick = 1.0 / fd_tempo_tick_per_ns( NULL );

  long start = fd_log_wallclock();
  fd_histf_t hist_[1];
  fd_histf_t * hist = fd_histf_join( fd_histf_new( hist_, 0UL, (ulong)10e6 ) );

  ulong const dev_sz    = ur->dev_sz;
  ulong const tot_sz    = (ulong)1e9;
  ulong const block_cnt = tot_sz / pair_sz;
  for( ulong rem=block_cnt; rem; rem-- ) {
    if( fd_vinyl_seq_gt( io->seq_future+pair_sz, io->seq_ancient+dev_sz ) ) {
      fd_vinyl_io_forget( io, fd_ulong_align_up( io->seq_future - (dev_sz/4UL), FD_VINYL_BSTREAM_BLOCK_SZ ) );
      fd_vinyl_io_sync( io, 0 );
    }
    long dt = -fd_tickcount();
    void * smem = fd_vinyl_io_alloc( io, pair_sz, FD_VINYL_IO_FLAG_BLOCKING );
    FD_TEST( smem );
    fd_vinyl_io_append( io, smem, pair_sz );
    dt += fd_tickcount();
    double dt_ns = (double)dt * ns_per_tick;
    if( dt_ns<0.0 ) dt_ns = 0.0;
    fd_histf_sample( hist, (ulong)dt_ns );
    FD_TEST( fd_vinyl_io_commit( io, 0UL )==FD_VINYL_SUCCESS ); /* commits are free */
  }
  fd_vinyl_io_sync( io, FD_VINYL_IO_FLAG_BLOCKING );
  long dt = fd_log_wallclock() - start;
  FD_TEST( 0==fsync( ur->dev_fd ) );
  long dt_sync = fd_log_wallclock() - start;

  FD_TEST( ur->sqe_prep_cnt == ur->sqe_sent_cnt  );
  FD_TEST( ur->cqe_cnt      == ur->sqe_sent_cnt  );
  FD_TEST( ur->base->file_write_tot_sz >= block_cnt*pair_sz );
  FD_TEST( ur->cqe_write_pending == 0 );
  FD_TEST( ur->cqe_pending       == 0 );
  FD_LOG_NOTICE((
      "\n  block size %lu bytes:\n"
      "    elapsed: %.2f seconds (%.1f GB in %lu blocks)\n"
      "    throughput:        %.2f MB/s\n"
      "    throughput (sync): %.2f MB/s\n"
      "    p50: %e ms"
      "    p90: %e ms"
      "    p95: %e ms",
      pair_sz,
      (double)dt/1e9, (double)tot_sz/1e9, block_cnt,
      (double)tot_sz / ((double)dt     *1e-3),
      (double)tot_sz / ((double)dt_sync*1e-3),
      (double)fd_histf_percentile( hist, 50, 0UL ) * 1e-6,
      (double)fd_histf_percentile( hist, 90, 0UL ) * 1e-6,
      (double)fd_histf_percentile( hist, 95, 0UL ) * 1e-6
  ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong        spad_max = fd_env_strip_cmdline_ulong   ( &argc, &argv, "--spad-max", NULL, 131072UL );
  char const * path     = fd_env_strip_cmdline_cstr    ( &argc, &argv, "--path",     NULL, NULL     );
  ulong        seed     = fd_env_strip_cmdline_ulong   ( &argc, &argv, "--seed",     NULL, 1234UL   );
  uint         depth    = fd_env_strip_cmdline_uint    ( &argc, &argv, "--depth",    NULL, 256U     );
  _Bool        umem     = fd_env_strip_cmdline_contains( &argc, &argv, "--umem"     );
  _Bool        defer_io = fd_env_strip_cmdline_contains( &argc, &argv, "--defer-io" );

  FD_LOG_NOTICE(( "Testing with --spad-max %lu --seed %lu", spad_max, seed ));

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  ulong store_sz = (off_t)(FD_VINYL_BSTREAM_BLOCK_SZ + BCACHE_SZ);

  char _path[]  = "/tmp/test_vinyl_io_ur.XXXXXX";

  int fd;
  if( FD_UNLIKELY( path ) ) {
    FD_LOG_NOTICE(( "Using --path %s for the test storage", path ));
    fd = open( path, O_RDWR | O_CREAT | O_EXCL, (mode_t)0644 );
    if( FD_UNLIKELY( fd==-1 ) ) FD_LOG_ERR(( "open failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  } else {
    FD_LOG_NOTICE(( "--path not specified, using a temp file for test storage" ));
    fd = mkstemp( _path );
    if( FD_UNLIKELY( fd==-1 ) ) FD_LOG_ERR(( "mkstemp failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    path = _path;
    FD_LOG_NOTICE(( "temp file at %s", path ));
  }

  if( FD_UNLIKELY( ftruncate( fd, (off_t)store_sz ) ) )
    FD_LOG_ERR(( "ftruncate failed (%i-%s)", errno, fd_io_strerror( errno ) ));

# define MEM_MAX (1048576UL)
  static uchar mem[ MEM_MAX ] __attribute__((aligned(512)));

  FD_LOG_NOTICE(( "Testing construction" ));

  /* Create a bstream using io_bd */
  {
    char const * info    = "info";
    ulong        info_sz = strlen( info ) + 1UL;

    ulong align = fd_vinyl_io_bd_align();
    ulong footprint = fd_vinyl_io_bd_footprint( spad_max );
    if( FD_UNLIKELY( (footprint>MEM_MAX) | (align>512UL) ) ) FD_LOG_ERR(( "update mem for this test" ));
    fd_vinyl_io_t * io_bd = fd_vinyl_io_bd_init( mem, spad_max, fd, 1, info, info_sz, seed );
    FD_TEST( io_bd );
    FD_TEST( fd_vinyl_io_fini( io_bd )==mem );
  }

  void * ring_umem = NULL;
  if( umem ) {
    ulong ring_sz = fd_io_uring_shmem_footprint( depth, depth );
    ring_umem = mmap( NULL, ring_sz, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0 );
    if( FD_UNLIKELY( ring_umem==MAP_FAILED ) ) {
      FD_LOG_ERR(( "mmap ring_umem failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }

  /* Join the bstream using io_ur */
  fd_io_uring_t ring[1];
  fd_vinyl_io_t * io = NULL;
  {
    fd_io_uring_params_t params[1];
    fd_io_uring_params_init( params, depth );
    if( defer_io ) {
      params->flags    |= IORING_SETUP_COOP_TASKRUN;
      params->features |= IORING_SETUP_DEFER_TASKRUN;
    }

    int map_ok;
    if( umem ) map_ok = !!fd_io_uring_init_shmem( ring, params, ring_umem, depth, depth );
    else       map_ok = !!fd_io_uring_init_mmap ( ring, params );
    if( FD_UNLIKELY( !map_ok ) ) {
      if( FD_UNLIKELY( errno==-EPERM ) ) {
        FD_LOG_WARNING(( "skip: unit test is missing privileges to setup io_uring" ));
        if( FD_UNLIKELY( unlink( path ) ) ) FD_LOG_WARNING(( "unlink failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        fd_rng_delete( fd_rng_leave( rng ) );
        return 0;
      } else {
        FD_LOG_ERR(( "fd_io_uring_init failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      }
    }

    FD_TEST( 0==fd_io_uring_register_files( ring->ioring_fd, &fd, 1 ) );

    FD_TEST( 0==fd_io_uring_enable_rings( ring->ioring_fd ) );

    ulong align = fd_vinyl_io_ur_align();
    FD_TEST( fd_ulong_is_pow2( align ) );
    ulong footprint = fd_vinyl_io_ur_footprint( spad_max );
    FD_TEST( fd_ulong_is_aligned( footprint, align ) );
    if( FD_UNLIKELY( (footprint>MEM_MAX) | (align>512UL) ) ) FD_LOG_ERR(( "update mem for this test" ));
    io = fd_vinyl_io_ur_init( mem, spad_max, fd, ring );
    FD_TEST( io );
  }

  FD_LOG_NOTICE(( "Testing accessors" ));

  FD_TEST( fd_vinyl_io_type        ( io )==FD_VINYL_IO_TYPE_UR );
  FD_TEST( fd_vinyl_io_seed        ( io )==seed                );
  FD_TEST( fd_vinyl_io_seq_ancient ( io )==seq_ancient         );
  FD_TEST( fd_vinyl_io_seq_past    ( io )==seq_past            );
  FD_TEST( fd_vinyl_io_seq_present ( io )==seq_present         );
  FD_TEST( fd_vinyl_io_seq_future  ( io )==seq_future          );

  FD_LOG_NOTICE(( "Testing operations" ));

  test( io, rng );

  FD_LOG_NOTICE(( "Aborting and resuming" ));

  FD_TEST( fd_vinyl_io_fini( io )==mem );

  io = fd_vinyl_io_ur_init( mem, spad_max, fd, ring );
  FD_TEST( io );

  FD_LOG_NOTICE(( "Testing operations (after resume)" ));

  test( io, rng );

  FD_TEST( fd_vinyl_io_type        ( io )==FD_VINYL_IO_TYPE_UR );
  FD_TEST( fd_vinyl_io_seed        ( io )==seed                );
  FD_TEST( fd_vinyl_io_seq_ancient ( io )==seq_ancient         );
  FD_TEST( fd_vinyl_io_seq_past    ( io )==seq_past            );
  FD_TEST( fd_vinyl_io_seq_present ( io )==seq_present         );
  FD_TEST( fd_vinyl_io_seq_future  ( io )==seq_future          );

  /* FIXME: TEST BSTREAM WRITE HELPERS */

  FD_LOG_NOTICE(( "Testing wraparound async read" ));

  {
    fd_vinyl_io_ur_t * ur = (fd_vinyl_io_ur_t *)io;
    ulong dev_sz = ur->dev_sz;

    /* Fill up the device until seq_future % dev_sz is near the end,
       leaving just one block of headroom before the wraparound point. */

    ulong block_sz = FD_VINYL_BSTREAM_BLOCK_SZ;
    while( (io->seq_future % dev_sz) < (dev_sz - 2*block_sz) ) {
      ulong dev_free = dev_sz - (io->seq_future - io->seq_ancient);
      if( dev_free < block_sz ) {
        /* Need to free space */
        fd_vinyl_io_forget( io, io->seq_present );
        fd_vinyl_io_sync( io, FD_VINYL_IO_FLAG_BLOCKING );
      }

      fd_vinyl_bstream_block_t blk[1];
      memset( blk, (int)((io->seq_future / block_sz) & 0xFFU), block_sz );
      bcache_append( blk, block_sz );
      fd_vinyl_io_append( io, blk, block_sz );
      bcache_commit();
      FD_TEST( !fd_vinyl_io_commit( io, FD_VINYL_IO_FLAG_BLOCKING ) );
    }

    /* Now seq_future % dev_sz is within 2 blocks of the device end.
       Append 2 more blocks so the read will span the boundary. */

    ulong dev_free = dev_sz - (io->seq_future - io->seq_ancient);
    if( dev_free < 4*block_sz ) {
      fd_vinyl_io_forget( io, io->seq_present );
      fd_vinyl_io_sync( io, FD_VINYL_IO_FLAG_BLOCKING );
    }

    ulong read_seq = io->seq_future;
    for( ulong i=0; i<4; i++ ) {
      fd_vinyl_bstream_block_t blk[1];
      memset( blk, (int)((0xA0UL+i) & 0xFFU), block_sz );
      bcache_append( blk, block_sz );
      fd_vinyl_io_append( io, blk, block_sz );
    }
    bcache_commit();
    FD_TEST( !fd_vinyl_io_commit( io, FD_VINYL_IO_FLAG_BLOCKING ) );
    bcache_sync();
    FD_TEST( !fd_vinyl_io_sync( io, FD_VINYL_IO_FLAG_BLOCKING ) );

    ulong read_sz = 4*block_sz;

    /* Verify the read wraps around */
    FD_TEST( (read_seq % dev_sz) + read_sz > dev_sz );

    /* Re-init the io backend so that seq_cache resets to seq_present,
       forcing all reads through io_uring instead of the write-back
       cache.  Without this, wb_read serves the data from cache and the
       io_uring wraparound code path is never exercised. */

    FD_TEST( fd_vinyl_io_fini( io )==mem );
    io = fd_vinyl_io_ur_init( mem, spad_max, fd, ring );
    FD_TEST( io );

    /* Do an async read across the wraparound boundary */
    uchar ref[ 4*FD_VINYL_BSTREAM_BLOCK_SZ ] __attribute__((aligned(FD_VINYL_BSTREAM_BLOCK_SZ)));
    uchar tst[ 4*FD_VINYL_BSTREAM_BLOCK_SZ ] __attribute__((aligned(FD_VINYL_BSTREAM_BLOCK_SZ)));

    bcache_read( read_seq, ref, read_sz );
    memset( tst, 0, read_sz );

    fd_vinyl_io_rd_t rd[1];
    rd->ctx = 0xDEADBEEFUL;
    rd->seq = read_seq;
    rd->dst = tst;
    rd->sz  = read_sz;

    fd_vinyl_io_read( io, rd );

    fd_vinyl_io_rd_t * completed;
    FD_TEST( !fd_vinyl_io_poll( io, &completed, FD_VINYL_IO_FLAG_BLOCKING ) );
    FD_TEST( completed==rd );
    FD_TEST( rd->ctx==0xDEADBEEFUL );
    FD_TEST( !memcmp( ref, tst, read_sz ) );
  }

  FD_LOG_NOTICE(( "Testing destruction" ));

  fd_vinyl_bstream_block_t block[1];
  memset( block, 0, FD_VINYL_BSTREAM_BLOCK_SZ );
  fd_vinyl_io_append( io, block, FD_VINYL_BSTREAM_BLOCK_SZ );

  FD_TEST( !fd_vinyl_io_fini( NULL ) );
  FD_TEST( fd_vinyl_io_fini( io )==mem ); /* fini with uncommitted bytes */

  FD_LOG_NOTICE(( "Benchmarking writes" ));

  ulong dev_sz = fd_ulong_align_dn( (ulong)1e9, FD_VINYL_BSTREAM_BLOCK_SZ );
  store_sz = FD_VINYL_BSTREAM_BLOCK_SZ + dev_sz;
  if( FD_UNLIKELY( ftruncate( fd, (off_t)store_sz ) ) )
    FD_LOG_ERR(( "ftruncate failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  io = fd_vinyl_io_ur_init( mem, spad_max, fd, ring );
  FD_TEST( io );

  bench_append( io,   512UL );
  bench_append( io,  1024UL );
  bench_append( io,  2048UL );
  bench_append( io,  4096UL );
  bench_append( io,  8192UL );
  bench_append( io, 16384UL );
  bench_append( io, 32768UL );
  bench_append( io, 65536UL );

  FD_TEST( fd_vinyl_io_fini( io ) );

  FD_LOG_NOTICE(( "Cleaning up" ));

  if( ring_umem ) {
    if( FD_UNLIKELY( munmap( ring_umem, fd_io_uring_shmem_footprint( depth, depth ) ) ) ) {
      FD_LOG_WARNING(( "munmap ring_umem failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }
  (void)fd_io_uring_fini( ring );

  if( FD_UNLIKELY( unlink( path ) ) ) FD_LOG_WARNING(( "unlink failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
