/* snapshot-minimize writes a snapshot at the start slot that holds
   only the accounts the slots after it load.  It trims the shredcap,
   copies genesis and runs the backtest with the snapshot writer tiles.
   The loader boots from <ledger>/.snapmin-<name>, which holds hard
   links to the ledger's archives up to the start slot, and the writer
   writes into the output directory. */
#define _GNU_SOURCE
#include "backtest.h"
#include "../../platform/fd_file_util.h"
#include "../../../discof/backtest/fd_shredcap_trim.h"
#include "../../../discof/restore/utils/fd_ssarchive.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>

#define NAME "snapshot-minimize"

#define USAGE NAME " --ledger <dir> --start-slot <S> --end-slot <E> --out <dir> [--max-accounts <n>] [--no-watch]"

static void
snapshot_minimize_args( int *    pargc,
                        char *** pargv,
                        args_t * args ) {
  char const * ledger = fd_env_strip_cmdline_cstr( pargc, pargv, "--ledger", NULL, NULL );
  char const * out    = fd_env_strip_cmdline_cstr( pargc, pargv, "--out",    NULL, NULL );
  args->snapshot_minimize.start_slot   = fd_env_strip_cmdline_ulong   ( pargc, pargv, "--start-slot",   NULL, 0UL       );
  args->snapshot_minimize.end_slot     = fd_env_strip_cmdline_ulong   ( pargc, pargv, "--end-slot",     NULL, 0UL       );
  args->snapshot_minimize.max_accounts = fd_env_strip_cmdline_ulong   ( pargc, pargv, "--max-accounts", NULL, 4194304UL );
  args->snapshot_minimize.no_watch     = fd_env_strip_cmdline_contains( pargc, pargv, "--no-watch" );
  if( FD_UNLIKELY( !ledger || !out ||
                   !args->snapshot_minimize.start_slot ||
                   !args->snapshot_minimize.end_slot ) ) {
    FD_LOG_ERR(( "usage: " USAGE ));
  }
  if( FD_UNLIKELY( args->snapshot_minimize.end_slot<=args->snapshot_minimize.start_slot ) ) {
    FD_LOG_ERR(( "--end-slot must be after --start-slot" ));
  }
  fd_cstr_ncpy( args->snapshot_minimize.ledger, ledger, sizeof(args->snapshot_minimize.ledger) );
  fd_cstr_ncpy( args->snapshot_minimize.out,    out,    sizeof(args->snapshot_minimize.out)    );
}

/* Copy a file, possibly to another file system */

static void
copy_file( char const * src,
           char const * dst ) {
  int src_fd = open( src, O_RDONLY );
  if( FD_UNLIKELY( src_fd<0 ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s)", src, errno, fd_io_strerror( errno ) ));
  struct stat st;
  if( FD_UNLIKELY( fstat( src_fd, &st ) ) ) FD_LOG_ERR(( "fstat(%s) failed (%i-%s)", src, errno, fd_io_strerror( errno ) ));
  int dst_fd = open( dst, O_WRONLY|O_CREAT|O_EXCL, 0644 );
  if( FD_UNLIKELY( dst_fd<0 ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s)", dst, errno, fd_io_strerror( errno ) ));
  for( ulong sz=(ulong)st.st_size; sz; ) {
    long n = sendfile( dst_fd, src_fd, NULL, sz );
    if( FD_UNLIKELY( n<=0L ) ) FD_LOG_ERR(( "sendfile(%s,%s) failed (%i-%s)", src, dst, errno, fd_io_strerror( errno ) ));
    sz -= (ulong)n;
  }
  if( FD_UNLIKELY( close( dst_fd ) ) ) FD_LOG_ERR(( "close(%s) failed (%i-%s)", dst, errno, fd_io_strerror( errno ) ));
  close( src_fd );
}

/* Hard link every snapshot archive at or before start_slot into the
   work dir.  Returns the slot the loader will boot from, asking the
   loader's own picker. */

static ulong
link_archives( char const * ledger,
               char const * work,
               ulong        start_slot,
               int          incremental_snapshots ) {
  DIR * dir = opendir( ledger );
  if( FD_UNLIKELY( !dir ) ) FD_LOG_ERR(( "opendir(%s) failed (%i-%s)", ledger, errno, fd_io_strerror( errno ) ));
  struct dirent * entry;
  while( (entry = readdir( dir )) ) {
    ulong full;
    ulong incr;
    uchar hash[ FD_HASH_FOOTPRINT ];
    int   is_zstd;
    if( fd_ssarchive_parse_filename( entry->d_name, &full, &incr, hash, &is_zstd ) ) continue;
    if( fd_ulong_if( incr!=ULONG_MAX, incr, full )>start_slot ) continue;
    char src[ PATH_MAX ];
    char dst[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( src, sizeof(src), NULL, "%s/%s", ledger, entry->d_name ) );
    FD_TEST( fd_cstr_printf_check( dst, sizeof(dst), NULL, "%s/%s", work,   entry->d_name ) );
    if( FD_UNLIKELY( link( src, dst ) ) ) FD_LOG_ERR(( "link(%s,%s) failed (%i-%s)", src, dst, errno, fd_io_strerror( errno ) ));
  }
  closedir( dir );

  ulong full_slot;
  ulong incr_slot;
  char  full_path[ PATH_MAX ];
  char  incr_path[ PATH_MAX ];
  int   full_is_zstd;
  int   incr_is_zstd;
  uchar full_hash[ FD_HASH_FOOTPRINT ];
  uchar incr_hash[ FD_HASH_FOOTPRINT ];
  if( FD_UNLIKELY( fd_ssarchive_latest_best( work, incremental_snapshots, 0UL, &full_slot, &incr_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_hash, incr_hash ) ) ) {
    FD_LOG_ERR(( "%s has no full snapshot at or before slot %lu", ledger, start_slot ));
  }
  return fd_ulong_if( incr_slot!=ULONG_MAX, incr_slot, full_slot );
}

static void
snapshot_minimize_cmd_fn( args_t *   args,
                          config_t * config ) {
  char const * ledger     = args->snapshot_minimize.ledger;
  char const * out        = args->snapshot_minimize.out;
  ulong        start_slot = args->snapshot_minimize.start_slot;
  ulong        end_slot   = args->snapshot_minimize.end_slot;

  if( FD_UNLIKELY( !config->gossip.entrypoints_cnt ) ) {
    FD_LOG_ERR(( "[gossip] entrypoints must not be empty, set [\"0.0.0.0:1\"] so the snapshot loader runs" ));
  }
  ulong need = end_slot-start_slot+config->firedancer.development.backtest.root_distance+2UL;
  if( FD_UNLIKELY( config->firedancer.runtime.max_live_slots<need ) ) {
    FD_LOG_ERR(( "[runtime] max_live_slots must be at least %lu for this span", need ));
  }

  char shreds[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( shreds, sizeof(shreds), NULL, "%s/shreds.pcapng.zst", ledger ) );
  if( FD_UNLIKELY( access( shreds, R_OK ) ) ) {
    char rocksdb[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( rocksdb, sizeof(rocksdb), NULL, "%s/rocksdb", ledger ) );
    if( !access( rocksdb, F_OK ) ) {
      FD_LOG_ERR(( "%s is missing, create it with: contrib/blockstore/blockstore2shredcap --rocksdb %s --out %s --zstd", shreds, rocksdb, shreds ));
    }
    FD_LOG_ERR(( "%s is missing", shreds ));
  }

  char work[ PATH_MAX ];
  char genesis[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( work,    sizeof(work),    NULL, "%s/.snapmin-%s", ledger, config->name ) );
  FD_TEST( fd_cstr_printf_check( genesis, sizeof(genesis), NULL, "%s/genesis.bin",  ledger ) );
  if( FD_UNLIKELY( access( genesis, R_OK ) ) ) FD_LOG_ERR(( "%s is missing", genesis ));

  /* The loader boots from the work dir, nothing is downloaded, and
     the writer, which keeps one snapshot, writes into the output
     directory. */
  fd_cstr_ncpy( config->paths.snapshots, out,     sizeof(config->paths.snapshots) );
  fd_cstr_ncpy( config->paths.genesis,   genesis, sizeof(config->paths.genesis)   );
  fd_cstr_ncpy( config->firedancer.development.ledger_input.path,                   shreds, sizeof(config->firedancer.development.ledger_input.path)                   );
  fd_cstr_ncpy( config->firedancer.development.backtest.snapshot_minimize.boot_dir, work,   sizeof(config->firedancer.development.backtest.snapshot_minimize.boot_dir) );
  config->firedancer.development.ledger_input.end_slot                   = end_slot;
  config->firedancer.development.backtest.snapshot_minimize.slot         = start_slot;
  config->firedancer.development.backtest.snapshot_minimize.max_accounts = args->snapshot_minimize.max_accounts;
  config->firedancer.snapshots.max_full_snapshots_to_keep                = 1U;
  config->firedancer.snapshots.max_incremental_snapshots_to_keep         = 0U;
  config->firedancer.snapshots.sources.gossip.allow_any                  = 0;
  config->firedancer.snapshots.sources.gossip.allow_list_cnt             = 0UL;
  config->firedancer.snapshots.sources.servers_cnt                       = 0UL;

  /* Build the topology once so its checks fail before anything is
     written. */
  backtest_cmd_topo( config );

  if( FD_UNLIKELY( fd_file_util_rmtree( work, 1 ) ) ) FD_LOG_ERR(( "rm -rf %s failed (%i-%s)", work, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fd_file_util_mkdir_all( work, config->uid, config->gid, 1 ) ) ) FD_LOG_ERR(( "mkdir(%s) failed (%i-%s)", work, errno, fd_io_strerror( errno ) ));
  ulong boot_slot = link_archives( ledger, work, start_slot, config->firedancer.snapshots.incremental_snapshots );
  if( FD_UNLIKELY( mkdir( out, 0700 ) ) ) FD_LOG_ERR(( "mkdir(%s) failed (%i-%s)", out, errno, fd_io_strerror( errno ) ));

  /* The snapshot writer needs direct IO, which tmpfs does not have */
  char probe[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( probe, sizeof(probe), NULL, "%s/.odirect-probe", out ) );
  int probe_fd = open( probe, O_WRONLY|O_CREAT|O_DIRECT, 0600 );
  if( FD_UNLIKELY( probe_fd<0 ) ) {
    int err = errno;
    unlink( probe );
    rmdir( out );
    if( err==EINVAL ) FD_LOG_ERR(( "%s does not support O_DIRECT (is it tmpfs?), the snapshot writer needs it", out ));
    FD_LOG_ERR(( "open(%s) failed (%i-%s)", probe, err, fd_io_strerror( err ) ));
  }
  close( probe_fd );
  unlink( probe );

  char trimmed[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( trimmed, sizeof(trimmed), NULL, "%s/shreds.pcapng.zst", out ) );
  fd_shredcap_trim_stats_t stats;
  if( FD_UNLIKELY( fd_shredcap_trim( shreds, trimmed, start_slot, end_slot, &stats ) ) ) {
    rmdir( out );
    FD_LOG_ERR(( "failed to trim %s to slots %lu..%lu", shreds, start_slot, end_slot ));
  }
  /* The backtest refuses a ledger that starts after the slot it boots
     from.  Check that here, before the snapshot load. */
  if( FD_UNLIKELY( stats.first_slot>boot_slot ) ) {
    unlink( trimmed );
    rmdir( out );
    FD_LOG_ERR(( "%s starts at slot %lu but must include the boot snapshot slot %lu", shreds, stats.first_slot, boot_slot ));
  }
  if( FD_UNLIKELY( chown( trimmed, config->uid, config->gid ) ) ) FD_LOG_ERR(( "chown(%s) failed (%i-%s)", trimmed, errno, fd_io_strerror( errno ) ));
  FD_LOG_NOTICE(( "wrote %s with %lu shreds and %lu bank hashes for slots %lu..%lu", trimmed, stats.shred_cnt, stats.bank_hash_cnt, start_slot, stats.last_slot ));
  if( FD_UNLIKELY( stats.last_slot<end_slot ) ) FD_LOG_WARNING(( "%s has no shreds for the end slot %lu, so the copied shreds end at slot %lu", shreds, end_slot, stats.last_slot ));
  char genesis_out[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( genesis_out, sizeof(genesis_out), NULL, "%s/genesis.bin", out ) );
  copy_file( genesis, genesis_out );
  if( FD_UNLIKELY( chown( genesis_out, config->uid, config->gid ) ) ) FD_LOG_ERR(( "chown(%s) failed (%i-%s)", genesis_out, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( chown( out, config->uid, config->gid ) ) ) FD_LOG_ERR(( "chown(%s) failed (%i-%s)", out, errno, fd_io_strerror( errno ) ));
  FD_LOG_NOTICE(( "%s holds links to the ledger's archives and is left behind", work ));

  args_t run_args = { .backtest.no_watch = args->snapshot_minimize.no_watch };
  backtest_cmd_fn( &run_args, config );
}

static void
snapshot_minimize_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--ledger",       "<dir>", "Ledger directory holding the snapshot archives, genesis.bin and shreds.pcapng.zst" );
  fd_action_help_arg( help, "--start-slot",   "<S>",   "Slot of the minimized snapshot" );
  fd_action_help_arg( help, "--end-slot",     "<E>",   "Last slot the minimized snapshot must replay" );
  fd_action_help_arg( help, "--out",          "<dir>", "Output directory, must not exist" );
  fd_action_help_arg( help, "--max-accounts", "<n>",   "Upper bound on the accounts kept (default 4194304)" );
  fd_action_help_arg( help, "--no-watch",     NULL,    "Do not print periodic progress updates" );
}

action_t fd_action_snapshot_minimize = {
  .name        = NAME,
  .args        = snapshot_minimize_args,
  .fn          = snapshot_minimize_cmd_fn,
  .perm        = backtest_cmd_perm,
  .topo        = backtest_cmd_topo,
  .description = "Write a minimized snapshot at S for replaying slots S+1..E from a ledger directory",
  .detail      = "Replays the ledger from its snapshot to E with the root held at S,\n"
                 "records the accounts the slots after S load, and writes a snapshot\n"
                 "at S holding only those accounts.  genesis.bin and the shreds of\n"
                 "slots S..E are copied next to it, so the output directory replays\n"
                 "on its own with `firedancer-dev backtest`.",
  .usage       = USAGE,
  .args_help   = snapshot_minimize_args_help,
};
