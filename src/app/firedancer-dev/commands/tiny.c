/* tiny: gossip-only participant that runs no configure stages.

   sock -> gossvf -> gossip -> sock, plus ipecho, sign, metric, waker.
   All workspaces and stacks are private anonymous mappings, no
   configure stages run, tiles are unpinned and run as threads of one
   process. */

#define _GNU_SOURCE
#include "../../shared/commands/watch/watch.h"
#include "../../shared/fd_config.h"
#include "../../platform/fd_file_util.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../disco/net/fd_net_tile.h"
#include "../../../discof/gossip/fd_gossip_tile.h"
#include "../../../util/pod/fd_pod.h"
#include "../../../util/tile/fd_tile_private.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define TINY_MAX_ENTRIES  (65536UL)
#define TINY_TCACHE_DEPTH (1UL<<16)
#define TINY_NET_RX_DEPTH (4096UL)
#define TINY_NET_TX_DEPTH (4096UL)
#define TINY_LINK_DEPTH   (4096UL)
#define TINY_BURST_DEPTH  (131072UL) /* reliable gossip outs must hold the gossip tile STEM_BURST (65570) */
#define TINY_MEM_MAX      (2UL<<30)

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

void
generate_keypair( char const * keyfile,
                  uint         uid,
                  uint         gid,
                  int          use_grnd_random );

static void
tiny_cmd_topo( config_t * config ) {
  fd_cstr_ncpy( config->net.provider, "socket", sizeof(config->net.provider) );
  config->development.sandbox  = 0;
  config->development.no_clone = 1;

  fd_topo_t * topo = &config->topo;
  fd_topob_new( topo, config->name );
  topo->max_page_size = FD_SHMEM_HUGE_PAGE_SZ;

  ulong const cpu = ULONG_MAX; /* unpinned */

  fd_topob_wksp( topo, "metric"    );
  fd_topob_wksp( topo, "metric_in" );
  fd_topo_tile_t * metric_tile = fd_topob_tile( topo, "metric", "metric", "metric_in", cpu, 0, 0, 1 );
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.metric.prometheus_listen_address, &metric_tile->metric.prometheus_listen_addr ) ) )
    FD_LOG_ERR(( "failed to parse prometheus listen address `%s`", config->tiles.metric.prometheus_listen_address ));
  metric_tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;

  fd_pod_insert_cstr( topo->props, "net.provider", "socket" );
  fd_topob_wksp( topo, "net_umem" );
  fd_topob_wksp( topo, "sock"     );
  fd_topo_tile_t * sock_tile = fd_topob_tile( topo, "sock", "sock", "metric_in", cpu, 0, 0, 0 );
  sock_tile->sock.net.bind_address   = config->net.bind_address_parsed;
  sock_tile->sock.so_rcvbuf          = (int)config->net.socket.receive_buffer_size;
  sock_tile->sock.so_sndbuf          = (int)config->net.socket.send_buffer_size;
  sock_tile->net.gossip_listen_port  = config->gossip.port;

  fd_topob_wksp( topo, "sign" );
  fd_topo_tile_t * sign_tile = fd_topob_tile( topo, "sign", "sign", "metric_in", cpu, 1, 0, 0 );
  fd_cstr_ncpy( sign_tile->sign.identity_key_path, config->paths.identity_key, sizeof(sign_tile->sign.identity_key_path) );

  fd_topob_wksp( topo, "gossip" );
  fd_topo_tile_t * gossip_tile = fd_topob_tile( topo, "gossip", "gossip", "metric_in", cpu, 1, 0, 0 );
  fd_cstr_ncpy( gossip_tile->gossip.identity_key_path, config->paths.identity_key, sizeof(gossip_tile->gossip.identity_key_path) );
  gossip_tile->gossip.entrypoints_cnt = config->gossip.entrypoints_cnt;
  for( ulong i=0UL; i<config->gossip.entrypoints_cnt; i++ )
    fd_cstr_ncpy( gossip_tile->gossip.entrypoints[ i ], config->gossip.entrypoints[ i ], sizeof(gossip_tile->gossip.entrypoints[ i ]) );
  fd_cstr_ncpy( gossip_tile->gossip.gossip_host, config->firedancer.gossip.host, sizeof(gossip_tile->gossip.gossip_host) );
  gossip_tile->gossip.net_ip_addr            = config->net.ip_addr;
  gossip_tile->gossip.ip_addr                = config->net.ip_addr;
  gossip_tile->gossip.expected_shred_version = config->consensus.expected_shred_version;
  gossip_tile->gossip.max_entries            = TINY_MAX_ENTRIES;
  gossip_tile->gossip.ports.gossip           = config->gossip.port;
  gossip_tile->gossip.boot_timestamp_nanos   = config->boot_timestamp_nanos;
  gossip_tile->gossip.wait_for_supermajority_at_slot      = 0UL;
  gossip_tile->gossip.wait_for_supermajority_hash_is_zero = 1;

  fd_topob_wksp( topo, "gossvf" );
  fd_topo_tile_t * gossvf_tile = fd_topob_tile( topo, "gossvf", "gossvf", "metric_in", cpu, 1, 0, 0 );
  fd_cstr_ncpy( gossvf_tile->gossvf.identity_key_path, config->paths.identity_key, sizeof(gossvf_tile->gossvf.identity_key_path) );
  gossvf_tile->gossvf.tcache_depth          = TINY_TCACHE_DEPTH;
  gossvf_tile->gossvf.shred_version         = config->consensus.expected_shred_version;
  gossvf_tile->gossvf.allow_private_address = config->development.gossip.allow_private_address;
  gossvf_tile->gossvf.entrypoints_cnt       = config->gossip.entrypoints_cnt;
  gossvf_tile->gossvf.boot_timestamp_nanos  = config->boot_timestamp_nanos;
  fd_cstr_ncpy( gossvf_tile->gossvf.gossip_host, config->firedancer.gossip.host, sizeof(gossvf_tile->gossvf.gossip_host) );
  gossvf_tile->gossvf.gossip_addr.addr = config->net.ip_addr;
  gossvf_tile->gossvf.gossip_addr.port = fd_ushort_bswap( config->gossip.port );
  gossvf_tile->gossvf.src_addr.addr    = config->net.ip_addr;
  gossvf_tile->gossvf.src_addr.port    = fd_ushort_bswap( config->gossip.port );
  for( ulong i=0UL; i<config->gossip.entrypoints_cnt; i++ )
    fd_cstr_ncpy( gossvf_tile->gossvf.entrypoints[ i ], config->gossip.entrypoints[ i ], sizeof(gossvf_tile->gossvf.entrypoints[ i ]) );

  fd_topob_wksp( topo, "ipecho" );
  fd_topo_tile_t * ipecho_tile = fd_topob_tile( topo, "ipecho", "ipecho", "metric_in", cpu, 0, 0, 1 );
  ipecho_tile->ipecho.expected_shred_version = config->consensus.expected_shred_version;
  ipecho_tile->ipecho.bind_address           = config->net.ip_addr;
  ipecho_tile->ipecho.bind_port              = config->gossip.port;
  ipecho_tile->ipecho.entrypoints_cnt        = config->gossip.entrypoints_cnt;
  for( ulong i=0UL; i<config->gossip.entrypoints_cnt; i++ )
    fd_cstr_ncpy( ipecho_tile->ipecho.entrypoints[ i ], config->gossip.entrypoints[ i ], sizeof(ipecho_tile->ipecho.entrypoints[ i ]) );

  fd_topob_wksp( topo, "gossip_net"    );
  fd_topob_wksp( topo, "ipecho_out"    );
  fd_topob_wksp( topo, "gossvf_gossip" );
  fd_topob_wksp( topo, "gossip_gossvf" );
  fd_topob_wksp( topo, "gossip_ciaddr" );
  fd_topob_wksp( topo, "gossip_misc"   );
  fd_topob_wksp( topo, "gossip_sign"   );
  fd_topob_wksp( topo, "sign_gossip"   );

  fd_topob_link( topo, "net_gossvf",    "net_umem",      TINY_NET_RX_DEPTH, FD_NET_MTU,                         64UL );
  fd_topob_link( topo, "gossip_net",    "gossip_net",    TINY_NET_TX_DEPTH, FD_NET_MTU,                         1UL  );
  fd_topob_link( topo, "ipecho_out",    "ipecho_out",    4UL,               0UL,                                1UL  );
  fd_topob_link( topo, "gossip_gossvf", "gossip_gossvf", TINY_BURST_DEPTH,  sizeof(fd_gossip_ping_update_t),    1UL  );
  fd_topob_link( topo, "gossip_ciaddr", "gossip_ciaddr", TINY_BURST_DEPTH,  sizeof(fd_gossip_update_message_t), 1UL  );
  fd_topob_link( topo, "gossip_misc",   "gossip_misc",   TINY_LINK_DEPTH,   sizeof(fd_gossip_update_message_t), 1UL  )->permit_no_consumers = 1;
  fd_topob_link( topo, "gossvf_gossip", "gossvf_gossip", TINY_LINK_DEPTH,   FD_GOSSIP_GOSSVF_MTU,               1UL  );
  fd_topob_link( topo, "gossip_sign",   "gossip_sign",   128UL,             2048UL,                             1UL  );
  fd_topob_link( topo, "sign_gossip",   "sign_gossip",   128UL,             64UL,                               1UL  );

  fd_topob_tile_out( topo, "sock",   0UL, "net_gossvf",    0UL );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_net",    0UL );
  fd_topob_tile_out( topo, "ipecho", 0UL, "ipecho_out",    0UL );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_gossvf", 0UL );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_ciaddr", 0UL );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_misc",   0UL );
  fd_topob_tile_out( topo, "gossvf", 0UL, "gossvf_gossip", 0UL );
  fd_topob_tile_out( topo, "gossip", 0UL, "gossip_sign",   0UL );
  fd_topob_tile_out( topo, "sign",   0UL, "sign_gossip",   0UL );

  fd_topob_tile_in( topo, "gossvf", 0UL, "metric_in", "net_gossvf",    0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  fd_topob_tile_in( topo, "sock",   0UL, "metric_in", "gossip_net",    0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  fd_topob_tile_in( topo, "gossvf", 0UL, "metric_in", "ipecho_out",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  fd_topob_tile_in( topo, "gossip", 0UL, "metric_in", "ipecho_out",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  fd_topob_tile_in( topo, "gossip", 0UL, "metric_in", "gossvf_gossip", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  fd_topob_tile_in( topo, "gossvf", 0UL, "metric_in", "gossip_gossvf", 0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  fd_topob_tile_in( topo, "gossvf", 0UL, "metric_in", "gossip_ciaddr", 0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED   );
  fd_topob_tile_in( topo, "sign",   0UL, "metric_in", "gossip_sign",   0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );
  fd_topob_tile_in( topo, "gossip", 0UL, "metric_in", "sign_gossip",   0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );

  fd_topob_waker( topo );
  fd_topob_finish( topo, CALLBACKS );
}

/* tiny_anon maps page_cnt huge page sized, huge page aligned private
   anonymous memory and registers it as the shmem region name, so the
   usual fd_shmem_join( name ) code paths find it. */

static void *
tiny_anon( char const * name,
           ulong        page_cnt ) {
  ulong   sz  = page_cnt*FD_SHMEM_HUGE_PAGE_SZ;
  uchar * mem = mmap( NULL, sz+FD_SHMEM_HUGE_PAGE_SZ, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0 );
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) FD_LOG_ERR(( "mmap(%lu MiB) failed (%i-%s)", sz>>20, errno, fd_io_strerror( errno ) ));
  uchar * lo = (uchar *)fd_ulong_align_up( (ulong)mem, FD_SHMEM_HUGE_PAGE_SZ );
  if( lo>mem ) munmap( mem, (ulong)(lo-mem) );
  munmap( lo+sz, (ulong)(mem+FD_SHMEM_HUGE_PAGE_SZ-lo) );
  if( FD_UNLIKELY( fd_shmem_join_anonymous( name, FD_SHMEM_JOIN_MODE_READ_WRITE, lo, lo, FD_SHMEM_HUGE_PAGE_SZ, page_cnt ) ) )
    FD_LOG_ERR(( "fd_shmem_join_anonymous(%s) failed", name ));
  return lo;
}

static void
tiny_cmd_fn( args_t *   args,
             config_t * config ) {
  fd_topo_t * topo = &config->topo;

  struct stat st;
  if( FD_UNLIKELY( stat( config->paths.identity_key, &st ) ) ) {
    if( FD_UNLIKELY( errno!=ENOENT ) ) FD_LOG_ERR(( "stat(%s) failed (%i-%s)", config->paths.identity_key, errno, fd_io_strerror( errno ) ));
    char dir[ PATH_MAX ];
    fd_cstr_ncpy( dir, config->paths.identity_key, sizeof(dir) );
    char * slash = strrchr( dir, '/' );
    if( FD_LIKELY( slash && slash!=dir ) ) {
      *slash = '\0';
      if( FD_UNLIKELY( -1==fd_file_util_mkdir_all( dir, config->uid, config->gid, 1 ) ) )
        FD_LOG_ERR(( "mkdir(%s) failed (%i-%s)", dir, errno, fd_io_strerror( errno ) ));
    }
    generate_keypair( config->paths.identity_key, config->uid, config->gid, 0 );
  }

  ulong total = 0UL;
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) total += topo->workspaces[ i ].page_cnt*topo->workspaces[ i ].page_sz;
  total += topo->tile_cnt*FD_TILE_PRIVATE_STACK_SZ;
  FD_LOG_NOTICE(( "tiny: %lu tiles, %lu workspaces, %lu MiB", topo->tile_cnt, topo->wksp_cnt, total>>20 ));
  if( FD_UNLIKELY( total>TINY_MEM_MAX ) ) FD_LOG_ERR(( "topology needs %lu MiB, limit is %lu MiB", total>>20, TINY_MEM_MAX>>20 ));

  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_t * wksp = &topo->workspaces[ i ];
    FD_TEST( wksp->page_sz==FD_SHMEM_HUGE_PAGE_SZ );

    char name[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL, "%s_%s.wksp", topo->app_name, wksp->name ) );
    void * mem = tiny_anon( name, wksp->page_cnt );

    fd_wksp_t * join = fd_wksp_join( fd_wksp_new( mem, name, 0U, wksp->part_max, wksp->total_footprint ) );
    FD_TEST( join );
    if( FD_LIKELY( wksp->known_footprint ) ) FD_TEST( fd_wksp_alloc( join, fd_topo_workspace_align(), wksp->known_footprint, 1UL ) );
    fd_wksp_leave( join );

    fd_topo_join_workspace( topo, wksp, FD_SHMEM_JOIN_MODE_READ_WRITE, 0 );
    fd_topo_wksp_new( topo, wksp, CALLBACKS );
  }

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    char name[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL, "%s_stack_%s%lu", topo->app_name, tile->name, tile->kind_id ) );
    tiny_anon( name, (FD_TILE_PRIVATE_STACK_SZ/FD_SHMEM_HUGE_PAGE_SZ)+2UL );
  }

  fd_topo_fill( topo );

  /* Route log output through the watch dashboard */
  int pipefd[ 2 ];
  if( FD_UNLIKELY( pipe2( pipefd, O_NONBLOCK ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==dup2( pipefd[ 1 ], STDERR_FILENO ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( pipefd[ 1 ] ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_topo_run_single_process( topo, config->uid, config->gid, fdctl_tile_run );

  args->watch.drain_output_fd = pipefd[ 0 ];
  args->watch.full            = 0;
  watch_cmd_fn( args, config );
}

action_t fd_action_tiny = {
  .name        = "tiny",
  .fn          = tiny_cmd_fn,
  .topo        = tiny_cmd_topo,
  .description = "Run a gossip-only participant in under 2 GiB of memory, without configure stages",
  .usage       = "tiny",
};
