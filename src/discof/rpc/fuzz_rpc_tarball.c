#define _GNU_SOURCE

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#if !FD_HAS_BZIP2
#error "This target requires FD_HAS_BZIP2"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

#include "../../util/fd_util.h"
#include "../../disco/topo/fd_topob.h"
#include "../../util/sanitize/fd_fuzz.h"

#define FD_TILE_TEST
#include "fd_rpc_tile.c"

#define FUZZ_RPC_GENESIS_MAX_MESSAGE_SIZE (64UL)
#define FUZZ_RPC_TAR_SZ (FUZZ_RPC_GENESIS_MAX_MESSAGE_SIZE + 4UL*512UL)
#define FUZZ_RPC_TAR_BZ_SZ (FUZZ_RPC_TAR_SZ + ((FUZZ_RPC_TAR_SZ + 100UL - 1UL) / 100UL) + 600UL)

static fd_rpc_tile_t * ctx;
static fd_topo_t * topo;

static fd_wksp_t *
fd_wksp_new_lazy( ulong footprint ) {
  footprint = fd_ulong_align_up( footprint, FD_SHMEM_NORMAL_PAGE_SZ );
  void * mem = mmap( NULL, footprint, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) {
    FD_LOG_ERR(( "mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS) failed (%i-%s)",
                 footprint>>10, errno, fd_io_strerror( errno ) ));
  }

  ulong part_max = fd_wksp_part_max_est( footprint, 64UL<<10 );
  FD_TEST( part_max );
  ulong data_max = fd_wksp_data_max_est( footprint, part_max );
  FD_TEST( data_max );
  fd_wksp_t * wksp = fd_wksp_join( fd_wksp_new( mem, "wksp", 1U, part_max, data_max ) );
  FD_TEST( wksp );

  FD_TEST( 0==fd_shmem_join_anonymous( "wksp", FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, mem, FD_SHMEM_NORMAL_PAGE_SZ, footprint>>FD_SHMEM_NORMAL_LG_PAGE_SZ ) );
  return wksp;
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  (void)privileged_init;
  (void)unprivileged_init;
  (void)populate_allowed_seccomp;
  (void)populate_allowed_fds;
  (void)rlimit_file_cnt;

  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  putenv( "FD_LOG_PATH=" );
  fd_boot( argc, argv );
  fd_log_level_core_set(0); /* crash on debug log */

  ctx  = aligned_alloc( alignof(fd_rpc_tile_t), sizeof(fd_rpc_tile_t) );
  FD_TEST( ctx );
  memset( ctx, 0, sizeof(fd_rpc_tile_t) );

  topo = aligned_alloc( alignof(fd_topo_t), sizeof(fd_topo_t) );
  FD_TEST( topo );

  fd_wksp_t * wksp = fd_wksp_new_lazy( 4UL << 30UL );
  fd_topob_new( topo, "topo" );
  fd_topo_wksp_t * topo_wksp = fd_topob_wksp( topo, "wksp" );
  topo_wksp->wksp = wksp;

  void * shalloc = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 1UL );
  ctx->bz2_alloc = fd_alloc_join( fd_alloc_new( shalloc, 1UL ), 1UL );
  FD_TEST( ctx->bz2_alloc );

  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  ulong __i = 0UL;
#define FETCH_REF(__sz) (__extension__({ \
  __i += (__sz); \
  if( FD_UNLIKELY( __i>=size ) ) return 0; \
  (void const *)(data+__i-(__sz)); }))

#define FETCH_TYPE(__type) (FD_LOAD(__type, FETCH_REF(sizeof(__type))))

  char filename[ 128UL ] = { 0 };
  ulong filename_len = FETCH_TYPE( uchar ) % 128UL;
  if( !filename_len ) return 0;
  fd_memcpy( filename, FETCH_REF( filename_len ), filename_len );

  uchar tar_scratch[ FUZZ_RPC_TAR_SZ ];
  uchar tar_bz_out [ FUZZ_RPC_TAR_BZ_SZ ];
  ulong file_bin_sz = FETCH_TYPE( uint ) % (FUZZ_RPC_GENESIS_MAX_MESSAGE_SIZE + 1UL);
  uchar const * file_bin = FETCH_REF( file_bin_sz );

  fd_rpc_file_as_tarball(
    ctx,
    filename,
    file_bin,
    file_bin_sz,
    tar_scratch,
    FUZZ_RPC_TAR_SZ,
    tar_bz_out,
    FUZZ_RPC_TAR_BZ_SZ
  );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;

#undef FETCH_TYPE
#undef FETCH_REF
}
