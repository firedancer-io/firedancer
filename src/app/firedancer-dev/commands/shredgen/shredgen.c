/* firedancer-dev shredgen runs a synthetic turbine source (the shrgen
   tile) against a validator's shred tile.  It is a standalone topology
   like `load`: the validator runs separately, typically as
   `firedancer-dev dev`, and this command sends it shreds over UDP. */

#define _GNU_SOURCE
#include "../../../shared/fd_config.h"
#include "../../../shared/commands/run/run.h"
#include "../../../../discof/genesis/genesis_hash.h"
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../disco/topo/fd_cpu_topo.h"
#include "../../../../util/net/fd_ip4.h"

#include <errno.h>
#include <unistd.h>   /* pause */
#include <sys/stat.h> /* stat */

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
shredgen_cmd_args( int *    pargc,
                   char *** pargv,
                   args_t * args ) {
  char const * dest_ip    = fd_env_strip_cmdline_cstr( pargc, pargv, "--dest-ip",    NULL, NULL );
  char const * metrics_ip = fd_env_strip_cmdline_cstr( pargc, pargv, "--metrics-ip", NULL, NULL );
  char const * key        = fd_env_strip_cmdline_cstr( pargc, pargv, "--key",        NULL, ""   );
  char const * affinity   = fd_env_strip_cmdline_cstr( pargc, pargv, "--affinity",   NULL, "auto" );

  args->shredgen.dest_port         = fd_env_strip_cmdline_ushort( pargc, pargv, "--dest-port",     NULL, 0      );
  args->shredgen.shred_version     = fd_env_strip_cmdline_ushort( pargc, pargv, "--shred-version", NULL, 0      );
  args->shredgen.start_slot        = fd_env_strip_cmdline_ulong ( pargc, pargv, "--slot",          NULL, 0UL    );
  args->shredgen.slot_cnt          = fd_env_strip_cmdline_ulong ( pargc, pargv, "--slots",         NULL, 0UL    );
  /* 157 FEC sets * 64 shreds = 10048 shreds per slot. */
  args->shredgen.fec_sets_per_slot = fd_env_strip_cmdline_ulong ( pargc, pargv, "--fec-sets",      NULL, 157UL  );
  args->shredgen.slot_ms           = fd_env_strip_cmdline_ulong ( pargc, pargv, "--slot-ms",       NULL, 400UL  );
  args->shredgen.metrics_port      = fd_env_strip_cmdline_ushort( pargc, pargv, "--metrics-port",  NULL, 0      );
  args->shredgen.slot_ahead        = fd_env_strip_cmdline_ulong ( pargc, pargv, "--slot-ahead",    NULL, 100UL  );

  args->shredgen.dest_ip = 0U;
  if( FD_LIKELY( dest_ip ) ) {
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( dest_ip, &args->shredgen.dest_ip ) ) ) FD_LOG_ERR(( "invalid --dest-ip `%s`", dest_ip ));
  }
  args->shredgen.metrics_ip = 0U;
  if( FD_LIKELY( metrics_ip ) ) {
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( metrics_ip, &args->shredgen.metrics_ip ) ) ) FD_LOG_ERR(( "invalid --metrics-ip `%s`", metrics_ip ));
  }
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( args->shredgen.key_path ), key,      sizeof(args->shredgen.key_path)-1UL ) );
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( args->shredgen.affinity ), affinity, sizeof(args->shredgen.affinity)-1UL ) );
}

static void
shredgen_topo( fd_topo_t *  topo,
               args_t *     args,
               char const * max_page_size ) {
  /* Default affinity "auto" leaves the tile unpinned: it runs on the
     invoking shell's inherited CPU mask and never claims a core a
     neighbouring validator has pinned.  An explicit --affinity pins it
     to the named CPU. */
  int is_auto_affinity = !strcmp( args->shredgen.affinity, "auto" );

  ulong tile_cpu = ULONG_MAX;

  if( FD_UNLIKELY( !is_auto_affinity ) ) {
    fd_topo_cpus_t cpus[1];
    fd_topo_cpus_init( cpus );

    ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
    for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;
    ulong affinity_tile_cnt = fd_topob_parse_affinity_cstr( args->shredgen.affinity, parsed_tile_to_cpu, 0, 1 );
    if( FD_UNLIKELY( affinity_tile_cnt!=1UL ) ) FD_LOG_ERR(( "--affinity must name exactly one CPU, got %lu", affinity_tile_cnt ));

    ushort cpu_idx = (ushort)( parsed_tile_to_cpu[ 0 ] & ~FD_TOPOB_CPU_SHARED );
    if( FD_UNLIKELY( parsed_tile_to_cpu[ 0 ]!=USHORT_MAX && cpu_idx>=cpus->cpu_cnt ) )
      FD_LOG_ERR(( "--affinity specifies CPU %hu but the system only has %lu CPUs", cpu_idx, cpus->cpu_cnt ));
    tile_cpu = fd_ulong_if( parsed_tile_to_cpu[ 0 ]==USHORT_MAX, ULONG_MAX, (ulong)parsed_tile_to_cpu[ 0 ] );
  }

  topo->max_page_size = fd_cstr_to_shmem_page_sz( max_page_size );

  fd_topob_wksp( topo, "metric_in" );
  fd_topob_wksp( topo, "shrgen"    );

  fd_topo_tile_t * tile = fd_topob_tile( topo, "shrgen", "shrgen", "metric_in", tile_cpu, 0, 0, 0, 0 );
  tile->shrgen.dest_ip_addr      = args->shredgen.dest_ip;
  tile->shrgen.dest_port         = args->shredgen.dest_port;
  tile->shrgen.shred_version     = args->shredgen.shred_version;
  tile->shrgen.start_slot        = args->shredgen.start_slot;
  tile->shrgen.slot_cnt          = args->shredgen.slot_cnt;
  tile->shrgen.fec_sets_per_slot = args->shredgen.fec_sets_per_slot;
  tile->shrgen.slot_duration_ns  = args->shredgen.slot_ms*1000UL*1000UL;
  tile->shrgen.metrics_ip        = args->shredgen.metrics_ip;
  tile->shrgen.metrics_port      = args->shredgen.metrics_port;
  tile->shrgen.slot_ahead        = args->shredgen.slot_ahead;
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( tile->shrgen.key_path ), args->shredgen.key_path, sizeof(tile->shrgen.key_path)-1UL ) );

  fd_topob_finish( topo, CALLBACKS );
}

static void
shredgen_cmd_fn( args_t *   args,
                 config_t * config ) {
  if( FD_UNLIKELY( !config->is_firedancer ) ) FD_LOG_ERR(( "shredgen requires a Firedancer configuration" ));

  /* The shred tile looks up the leader for shred->slot and drops the
     shred (BadSlot, before sigverify) if it has no leader schedule for
     that slot, and the FEC resolver ignores any slot below its root.
     With no --slot, auto-track: the tile scrapes replay_root_slot from
     the validator's Prometheus endpoint and targets root+--slot-ahead.
     NOTE: on a catching-up node root can lag the live tip by many
     slots, putting root+N inside the in-progress (root,tip] window,
     which has been observed to crash the shred tile.  The metrics
     endpoint defaults to the local validator's configured Prometheus
     address/port. */
  if( FD_UNLIKELY( !args->shredgen.start_slot ) ) {
    if( FD_UNLIKELY( !args->shredgen.metrics_ip ) ) {
      if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.metric.prometheus_listen_address, &args->shredgen.metrics_ip ) ) )
        FD_LOG_ERR(( "could not parse [tiles.metric.prometheus_listen_address] `%s`; pass --metrics-ip", config->tiles.metric.prometheus_listen_address ));
      /* 0.0.0.0 is a bind wildcard, not a connect target. */
      if( FD_UNLIKELY( !args->shredgen.metrics_ip ) ) FD_TEST( fd_cstr_to_ip4_addr( "127.0.0.1", &args->shredgen.metrics_ip ) );
    }
    if( FD_UNLIKELY( !args->shredgen.metrics_port ) ) args->shredgen.metrics_port = config->tiles.metric.prometheus_listen_port;
  }

  if( FD_UNLIKELY( !args->shredgen.dest_ip   ) ) args->shredgen.dest_ip   = config->net.ip_addr;
  if( FD_UNLIKELY( !args->shredgen.dest_port ) ) args->shredgen.dest_port = config->tiles.shred.shred_listen_port;
  if( FD_UNLIKELY( !strcmp( args->shredgen.key_path, "" ) ) )
    fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( args->shredgen.key_path ), config->paths.identity_key, sizeof(args->shredgen.key_path)-1UL ) );

  /* Same derivation as `dev`: the configured shred version if set,
     otherwise computed from the genesis file. */
  if( FD_UNLIKELY( !args->shredgen.shred_version ) ) args->shredgen.shred_version = config->consensus.expected_shred_version;
  if( FD_UNLIKELY( !args->shredgen.shred_version ) ) {
    ushort shred_version = 0;
    int result = read_genesis_bin( config->paths.genesis, &shred_version, NULL );
    if( FD_UNLIKELY( -1==result ) )
      FD_LOG_ERR(( "could not compute shred version from genesis file `%s` (%i-%s), pass --shred-version", config->paths.genesis, errno, fd_io_strerror( errno ) ));
    args->shredgen.shred_version = shred_version;
  }
  if( FD_UNLIKELY( !args->shredgen.shred_version ) ) FD_LOG_ERR(( "shred version is zero, pass --shred-version" ));

  /* Isolate from any validator sharing this box: a distinct topology
     name gives distinct workspace file names (<name>_<wksp>.wksp under
     the hugetlbfs mount) and a distinct (absent) cpuset cgroup, so
     shredgen never reuses or evicts a running validator's shared
     memory or joins its core partition. */
  FD_TEST( fd_cstr_printf_check( config->name, sizeof(config->name), NULL, "shredgen" ) );

  fd_topo_t * topo = fd_topob_new( &config->topo, config->name );
  /* 2 MB pages: the topology is a few hundred kB, so there is no reason
     to consume the scarce 1 GB pages a validator reserves. */
  shredgen_topo( topo, args, "huge" );

  /* Deliberately do NOT run the hugetlbfs configure stage.  Its INIT
     unmounts and remounts the hugetlbfs with a min_size sized for this
     tiny topology, which would tear the memory out from under a
     validator sharing the mount.  We rely on the mount already
     existing (created by the validator, or by a prior
     `firedancer-dev configure init hugetlbfs`). */
  {
    struct stat st;
    if( FD_UNLIKELY( -1==stat( config->hugetlbfs.huge_page_mount_path, &st ) ) )
      FD_LOG_ERR(( "hugetlbfs mount `%s` does not exist (%i-%s).  Start the target validator first, or run "
                   "`firedancer-dev configure init hugetlbfs` before shredgen.",
                   config->hugetlbfs.huge_page_mount_path, errno, fd_io_strerror( errno ) ));
  }

  initialize_workspaces( config );
  initialize_stacks( config );

  FD_LOG_NOTICE(( "Running" ));
  FD_LOG_NOTICE(( "  --dest-ip " FD_IP4_ADDR_FMT, FD_IP4_ADDR_FMT_ARGS( args->shredgen.dest_ip ) ));
  FD_LOG_NOTICE(( "  --dest-port %hu",           args->shredgen.dest_port         ));
  FD_LOG_NOTICE(( "  --key %s",                  args->shredgen.key_path          ));
  FD_LOG_NOTICE(( "  --shred-version %hu",       args->shredgen.shred_version     ));
  FD_LOG_NOTICE(( "  --fec-sets %lu",            args->shredgen.fec_sets_per_slot ));
  FD_LOG_NOTICE(( "  --slot-ms %lu",             args->shredgen.slot_ms           ));
  FD_LOG_NOTICE(( "  --affinity %s",             args->shredgen.affinity          ));
  if( FD_LIKELY( !args->shredgen.start_slot ) ) {
    FD_LOG_NOTICE(( "  slot mode auto-track: target = replay_root_slot + %lu", args->shredgen.slot_ahead ));
    FD_LOG_NOTICE(( "  --metrics " FD_IP4_ADDR_FMT ":%hu", FD_IP4_ADDR_FMT_ARGS( args->shredgen.metrics_ip ), args->shredgen.metrics_port ));
  } else {
    FD_LOG_NOTICE(( "  slot mode fixed: --slot %lu --slots %lu", args->shredgen.start_slot, args->shredgen.slot_cnt ));
  }

  /* FIXME allow running sandboxed/multiprocess */
  fd_topo_run_single_process( &config->topo, 0, config->uid, config->gid, fdctl_tile_run );

  /* The tile exits the process when --slots is reached; otherwise
     Ctrl+C terminates. */
  for(;;) pause();
}

action_t fd_action_shredgen = {
  .name        = "shredgen",
  .args        = shredgen_cmd_args,
  .fn          = shredgen_cmd_fn,
  .description = "Send synthetic turbine shreds to a validator's shred tile"
};
