#define FD_SCRATCH_USE_HANDHOLDING 1
#include "../fd_flamenco.h"
#include "../../ballet/base58/fd_base58.h"
#include "../types/fd_types.h"
#include "../leaders/fd_leaders.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "fd_stakes.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

static int
usage( void ) {
  fprintf( stderr,
    "usage: fd_stakes_from_snapshot {nodes/leaders} {FILE}\n"
    "\n"
    "Derive epoch stake information from snapshot.\n"
    "\n"
    "Mode:\n"
    "  epochs     Print available epochs\n"
    "  nodes      Dump active stake per node identity\n"
    "             CSV format: {pubkey},{stake}\n"
    "  leaders    Dump leader schedule\n"
    "             CSV format: {slot},{pubkey}\n"
    "\n"
    "FILE is the file path to a .tar.zst snapshot or a raw\n"
    "  bincode snapshot manifest\n"
    "\n"
    "Options:\n"
    "\n"
    "  --page-sz      {gigantic|huge|normal}    Page size\n"
    "  --page-cnt     2                         Page count\n"
    "  --scratch-mb   1024                      Scratch mem MiB\n"
    "  --epoch        <ulong>                   Epoch number\n" );
  return 0;
}

#define ACTION_NODES   (0)
#define ACTION_LEADERS (1)
#define ACTION_EPOCHS  (2)

/* _find_epoch looks for epoch stakes for the requested epoch.
   On failure, logs error and aborts application. */

static fd_epoch_stakes_t const *
_find_epoch( fd_solana_manifest_t const * manifest,
             ulong                        epoch ) {


  if( FD_UNLIKELY( epoch==ULONG_MAX ) ) {
    fprintf( stderr, "error: missing --epoch\n" );
    usage();
    exit(1);
  }

  fd_epoch_stakes_t const * stakes = NULL;
  fd_epoch_epoch_stakes_pair_t const * epochs = manifest->bank.epoch_stakes;
  for( ulong i=0; i < manifest->bank.epoch_stakes_len; i++ ) {
    if( epochs[ i ].key==epoch ) {
      stakes = &epochs[i].value;
      break;
    }
  }
  if( FD_UNLIKELY( !stakes ) )
    FD_LOG_ERR(( "Snapshot missing EpochStakes for epoch %lu", epoch ));

  return stakes;
}

static fd_stake_weight_t *
_get_stake_weights( fd_solana_manifest_t const * manifest,
                    ulong                        epoch,
                    ulong *                      out_cnt ) {

  fd_epoch_stakes_t  const * stakes = _find_epoch( manifest, epoch );
  fd_vote_accounts_t const * vaccs = &stakes->stakes.vote_accounts;

  ulong vote_acc_cnt = fd_vote_accounts_pair_t_map_size( vaccs->vote_accounts_pool, vaccs->vote_accounts_root );
  FD_LOG_NOTICE(( "vote_acc_cnt=%lu", vote_acc_cnt ));
  fd_stake_weight_t * weights = fd_scratch_alloc( alignof(fd_stake_weight_t), vote_acc_cnt * sizeof(fd_stake_weight_t) );
  if( FD_UNLIKELY( !weights ) ) FD_LOG_ERR(( "fd_scratch_alloc() failed" ));

  ulong weight_cnt = fd_stake_weights_by_node( vaccs, weights );
  if( FD_UNLIKELY( weight_cnt==ULONG_MAX ) ) FD_LOG_ERR(( "fd_stake_weights_by_node() failed" ));

  *out_cnt = weight_cnt;
  return weights;
}

static int
action_epochs( fd_solana_manifest_t const * manifest ) {
  fd_epoch_epoch_stakes_pair_t const * epochs = manifest->bank.epoch_stakes;
  for( ulong i=0; i < manifest->bank.epoch_stakes_len; i++ )
    printf( "%lu\n", epochs[ i ].key );
  return 0;
}

static int
action_nodes( fd_solana_manifest_t const * manifest,
              ulong                        epoch ) {

  ulong               weight_cnt;
  fd_stake_weight_t * weights = _get_stake_weights( manifest, epoch, &weight_cnt );

  for( ulong i=0UL; i<weight_cnt; i++ ) {
    fd_stake_weight_t const * w = weights + i;
    char keyB58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( w->key.key, NULL,  keyB58 );
    printf( "%s,%lu\n", keyB58, w->stake );
  }

  return 0;
}

static int
action_leaders( fd_solana_manifest_t const * manifest,
                ulong                        epoch ) {

  ulong               weight_cnt;
  fd_stake_weight_t * weights = _get_stake_weights( manifest, epoch, &weight_cnt );

  fd_epoch_schedule_t const * sched = &manifest->bank.epoch_schedule;
  ulong slot0     = fd_epoch_slot0   ( sched, epoch );
  ulong slot_cnt  = fd_epoch_slot_cnt( sched, epoch );
  ulong sched_cnt = slot_cnt/FD_EPOCH_SLOTS_PER_ROTATION;

  void * leaders_mem = fd_scratch_alloc( fd_epoch_leaders_align(), fd_epoch_leaders_footprint( weight_cnt, sched_cnt ) );
         leaders_mem = fd_epoch_leaders_new( leaders_mem, epoch, slot0, slot_cnt, weight_cnt, weights );
  fd_epoch_leaders_t * leaders = fd_epoch_leaders_join( leaders_mem );
  FD_TEST( leaders );

  fd_epoch_leaders_derive( leaders, weights, epoch );

  ulong slot = slot0;
  for( ulong i=0; i<sched_cnt; i++ ) {
    fd_pubkey_t const * leader = fd_epoch_leaders_get( leaders, i );
    char keyB58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( leader->key, NULL, keyB58 );
    for( ulong j=0; j<FD_EPOCH_SLOTS_PER_ROTATION; j++ ) {
      printf( "%lu,%s\n", slot, keyB58 );
      slot++;
    }
  }

  return 0;
}

/* _is_zstd returns 1 if given file handle points to the beginning of a
    zstd stream, otherwise zero. */

static int
_is_zstd( FILE * file ) {
  uint magic;
  ulong n = fread( &magic, 1UL, 4UL, file );
  if( FD_UNLIKELY( feof( file ) ) ) {
    clearerr( file );
    fseek( file, -(long)n, SEEK_CUR );
    return 0;
  }
  int err = ferror( file );
  if( FD_UNLIKELY( err ) )
    FD_LOG_ERR(( "fread() failed (%d-%s)", err, strerror( err ) ));
  fseek( file, -4L, SEEK_CUR );
  return ( magic==0xFD2FB528UL );
}

/* TODO older Solana snapshots are gzip, add support */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  for( int i=1; i<argc; i++ )
    if( 0==strcmp( argv[i], "--help" ) ) return usage();

  char const * _page_sz   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",    NULL, "gigantic" );
  ulong        page_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",   NULL, 2UL        );
  ulong        scratch_mb = fd_env_strip_cmdline_ulong( &argc, &argv, "--scratch-mb", NULL, 1024UL     );
  ulong        epoch      = fd_env_strip_cmdline_ulong( &argc, &argv, "--epoch",      NULL, ULONG_MAX  );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  if( FD_UNLIKELY( argc!=3 ) ) {
    fprintf( stderr, "error: missing arguments\n" );
    return usage();
  }

  char const * mode     = argv[1];
  char const * filepath = argv[2];

  int action;
  /**/ if( 0==strcmp( mode, "epochs"  ) ) action = ACTION_EPOCHS;
  else if( 0==strcmp( mode, "nodes"   ) ) action = ACTION_NODES;
  else if( 0==strcmp( mode, "leaders" ) ) action = ACTION_LEADERS;
  else {
    fprintf( stderr, "error: invalid mode \"%s\"\n", mode );
    return usage();
  }

  /* Create workspace and scratch allocator */

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_log_cpu_id(), "wksp", 0UL );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_new_anonymous() failed" ));

  ulong  smax = scratch_mb << 20;
  void * smem = fd_wksp_alloc_laddr( wksp, fd_scratch_smem_align(), smax, 1UL );
  if( FD_UNLIKELY( !smem ) ) FD_LOG_ERR(( "Failed to alloc scratch mem" ));
  ulong  scratch_depth = 4UL;
  void * fmem = fd_wksp_alloc_laddr( wksp, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( scratch_depth ), 2UL );
  if( FD_UNLIKELY( !fmem ) ) FD_LOG_ERR(( "Failed to alloc scratch frames" ));

  fd_scratch_attach( smem, fmem, smax, scratch_depth );
  fd_scratch_push();
  fd_valloc_t scratch_valloc = fd_scratch_virtual();

  /* Open file */

  FD_LOG_INFO(( "Reading snapshot %s", filepath ));
  FILE * file = fopen( filepath, "rb" );
  if( FD_UNLIKELY( !file ) ) FD_LOG_ERR(( "fopen(%s) failed (%d-%s)", filepath, errno, strerror( errno ) ));

  /* Read manifest bytes */

  void * manifest_bin;
  ulong  manifest_binsz;
  if( _is_zstd( file ) ) {
    FD_LOG_NOTICE(( "Detected .tar.zst stream" ));
    FD_LOG_ERR(( "TODO" ));
  } else {
    FD_LOG_NOTICE(( "Assuming raw bincode file" ));

    /* Allocate buffer suitable for storing file */

    struct stat stat;
    int err = fstat( fileno( file ), &stat );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fstat() failed (%d-%s)", errno, strerror( errno ) ));
    manifest_binsz = (ulong)stat.st_size;

    manifest_bin = fd_wksp_alloc_laddr( wksp, 1UL, manifest_binsz, 3UL );
    if( FD_UNLIKELY( !manifest_bin ) ) FD_LOG_ERR(( "failed to allocate metadata buffer" ));

    /* Read file into buffer */

    ulong n = fread( manifest_bin, manifest_binsz, 1UL, file );
    if( FD_UNLIKELY( n!=1UL ) ) FD_LOG_ERR(( "fread() failed (eof=%d)", feof( file ) ));
    FD_LOG_NOTICE(( "Read manifest (%.3f MiB)", (double)manifest_binsz/(1UL<<20) ));
  }

  /* Deserialize manifest */

  long dt = -fd_log_wallclock();
  fd_solana_manifest_t manifest;

  fd_bincode_decode_ctx_t decode = {
    .valloc  = scratch_valloc,
    .data    = manifest_bin,
    .dataend = (void *)( (ulong)manifest_bin + manifest_binsz ),
  };
  if( FD_UNLIKELY( FD_BINCODE_SUCCESS!=
                   fd_solana_manifest_decode( &manifest, &decode ) ) )
    FD_LOG_ERR(( "Failed to deserialize manifest" ));

  fd_wksp_free_laddr( manifest_bin ); manifest_bin = NULL;
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "Deserialized manifest (took %.3fs)", (double)dt/1e9 ));

  /* Action */

  int res;
  fd_scratch_push();
  switch( action ) {
  case ACTION_LEADERS:
    res = action_leaders( &manifest, epoch );
    break;
  case ACTION_NODES:
    res = action_nodes( &manifest, epoch );
    break;
  case ACTION_EPOCHS:
    res = action_epochs( &manifest );
    break;
  default:
    __builtin_unreachable();
  }
  fd_scratch_pop();

  /* Cleanup */

  fd_scratch_pop();
  FD_TEST( fd_scratch_frame_used()==0UL );
  fd_wksp_free_laddr( fd_scratch_detach( NULL ) );
  fd_wksp_free_laddr( fmem                      );
  fclose( file );
  fd_wksp_detach( wksp );
  fd_flamenco_halt();
  fd_halt();
  return res;
}
