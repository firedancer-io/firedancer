#define _GNU_SOURCE
#include <linux/unistd.h>
#include <sys/mman.h> /* For mmap, etc. */
#include <string.h> /* for explicit_bzero */

#include "tiles.h"
#include "../../fdctl.h"
#include "../run.h"

#include "../../../../disco/fd_disco.h"
#include "../../../../disco/shred/fd_shred_tile.h"
#include "../../../../tango/ip/fd_ip.h"


#define FD_SHRED_TAG (0x5117ed711eUL) /* SHRED TILE */



static void
init( fd_tile_args_t * args ) {
  void * _ip = fd_wksp_alloc_laddr( fd_wksp_containing( args->wksp_pod[ 0 ] ), fd_ip_align(), fd_ip_footprint( 256UL, 256UL ), FD_SHRED_TAG );
  fd_ip_t * ip = (void *)fd_ip_join( fd_ip_new( _ip, 256UL, 256UL ) );
  if( FD_UNLIKELY( !ip ) ) FD_LOG_ERR(( "fd_ip_join failed" ));
  args->lo_xsk = (void *)ip; /* FIXME: Hack */

  /* calling fd_tempo_tick_per_ns requires nanosleep, it is cached with
     a FD_ONCE */
  fd_tempo_tick_per_ns( NULL );

  const char * identity_key_path = fd_pod_query_cstr( args->wksp_pod[ 0 ], "identity_key_path", NULL );
  if( FD_UNLIKELY( !identity_key_path ) ) FD_LOG_ERR(( "identity_key_path not found in tpod" ));

  uchar const * key_page = load_key_into_protected_memory( identity_key_path );

  args->xsk = (void *)key_page; /* FIXME: Fix this after topology merge */
}

static void
run( fd_tile_args_t * tile_args ) {
  uchar const * tile_pod        = tile_args->wksp_pod[ 0 ];
  uchar const * bank_shred_pod  = tile_args->wksp_pod[ 1 ];
  uchar const * shred_store_pod = tile_args->wksp_pod[ 2 ];
  uchar const * net_shred_pod   = tile_args->wksp_pod[ 3 ];

  fd_shred_tile_args_t args = {0};
  args.fec_resolver_depth = fd_pod_query_ulong( tile_pod, "fec_resolver_depth", 0UL );
  if( FD_UNLIKELY( !args.fec_resolver_depth ) ) FD_LOG_ERR(( "fec_resolver_depth missing from pod or 0" ));

  args.fec_resolver_done_depth = fd_pod_query_ulong( tile_pod, "fec_resolver_done_depth", args.fec_resolver_depth*128UL );

  ulong bank_cnt = fd_pod_query_ulong( bank_shred_pod, "cnt", 0UL );
  if( FD_UNLIKELY( !bank_cnt ) ) FD_LOG_ERR(( "0 bank tiles" ));
  if( FD_UNLIKELY( bank_cnt>MAX_BANK_CNT ) ) FD_LOG_ERR(( "Too many banks" ));
  args.bank_cnt = bank_cnt;


  args.src_mac  = fd_pod_query_buf( tile_pod, "src_mac_addr", NULL );
  if( FD_UNLIKELY( !args.src_mac ) ) FD_LOG_ERR(( "src_mac_addr missing from pod" ));
  args.src_ip = fd_pod_query_uint( tile_pod, "ip_addr", 0 );
  if( FD_UNLIKELY( !args.src_ip  ) ) FD_LOG_ERR(( "ip_addr missing from pod"      ));

  ulong * _shred_version = fd_wksp_pod_map( tile_pod, "shred_version" );
  if( FD_UNLIKELY( !_shred_version ) ) FD_LOG_ERR(( "shred_version missing from pod" ));
  ulong shred_version = FD_VOLATILE_CONST( *_shred_version );
  if( shred_version == 0UL ) {
    FD_LOG_INFO(( "Waiting for shred version to be determined via gossip." ));
    while( !shred_version ) {
      shred_version = FD_VOLATILE_CONST( *_shred_version );
    }
  }
  if( FD_UNLIKELY( shred_version > USHORT_MAX ) ) FD_LOG_ERR(( "invalid shred version %lu", shred_version ));
  FD_LOG_INFO(( "Using shred version %hu", (ushort)shred_version ));
  args.shred_version = (ushort)shred_version;

  args.shred_listen_port = fd_pod_query_ushort( tile_pod, "shred_listen_port", 0 );
  if( FD_UNLIKELY( !args.shred_listen_port ) ) FD_LOG_ERR(( "shred_listen_port missing or 0" ));

  args.cnc = fd_cnc_join( fd_wksp_pod_map( tile_pod, "cnc" ) );
  args.pid = (ulong)tile_args->pid;

  fd_rng_t _rng[1];
  args.rng = fd_rng_join( fd_rng_new( _rng, 0UL, 0UL ) );
  args.lazy   = fd_pod_query_long ( tile_pod, "lazy",    0L );
  args.cr_max = fd_pod_query_ulong( tile_pod, "cr_max", 0UL );

  args.ip = (fd_ip_t *)tile_args->lo_xsk;

  args.cluster_nodes_mvcc = fd_mvcc_join( fd_wksp_pod_map( tile_pod, "cluster_nodes" ) );

  args.shred_signing_key = (uchar const *)tile_args->xsk;

  fd_wksp_t * bank_shred_wksp = fd_wksp_containing( bank_shred_pod );
  if( FD_UNLIKELY( !bank_shred_wksp ) ) FD_LOG_ERR(( "fd_wksp_containing( bank_shred_pod ) failed" ));

  for( ulong i=0UL; i<bank_cnt; i++) {
    args.bank_shred_mcache[ i ] = fd_mcache_join( fd_wksp_pod_map1( bank_shred_pod, "mcache%lu", i ) );
    args.bank_shred_fseq  [ i ] = fd_fseq_join  ( fd_wksp_pod_map1( bank_shred_pod, "fseq%lu",   i ) );

    uchar * bank_shred_dcache_i = fd_dcache_join( fd_wksp_pod_map1( bank_shred_pod, "dcache%lu", i ) );
    if( FD_UNLIKELY( !bank_shred_dcache_i ) ) FD_LOG_ERR(( "fd_dcache_join failed %lu", i ));

    args.bank_shred_chunk0[ i ] = fd_dcache_compact_chunk0( bank_shred_wksp, bank_shred_dcache_i );
    args.bank_shred_wmark [ i ] = fd_dcache_compact_wmark ( bank_shred_wksp, bank_shred_dcache_i, FD_BANK_SHRED_MTU );

    fd_dcache_leave( bank_shred_dcache_i );
  }

  args.from_net_mcache = fd_mcache_join( fd_wksp_pod_map( net_shred_pod, "mcache"           ) );
  args.from_net_fseq   = fd_fseq_join  ( fd_wksp_pod_map( net_shred_pod, "shred-in-fseq"    ) );

  /* The from_net mcache contains frags from several dcaches. */
  fd_wksp_t * net_shred_wksp = fd_wksp_containing( net_shred_pod );
  if( FD_UNLIKELY( !net_shred_wksp ) ) FD_LOG_ERR(( "fd_wksp_containing( net_shred_pod ) failed." ));
  args.from_net_chunk0 = fd_disco_compact_chunk0( net_shred_wksp );
  args.from_net_wmark  = fd_disco_compact_chunk0( net_shred_wksp );

  args.bank_shred_wksp = bank_shred_wksp;

  args.to_net_mcache   = fd_mcache_join( fd_wksp_pod_map( net_shred_pod, "shred-out-mcache" ) );
  args.to_net_dcache   = fd_dcache_join( fd_wksp_pod_map( net_shred_pod, "shred-out-dcache" ) );
  args.to_net_fseq     = fd_fseq_join  ( fd_wksp_pod_map( net_shred_pod, "shred-out-fseq"   ) );


  args.shred_store_mcache   = fd_mcache_join( fd_wksp_pod_map( shred_store_pod, "mcache" ) );
  args.shred_store_dcache   = fd_dcache_join( fd_wksp_pod_map( shred_store_pod, "dcache" ) );
  args.shred_store_fseq     = fd_fseq_join  ( fd_wksp_pod_map( shred_store_pod, "fseq"   ) );

  if( FD_UNLIKELY( !args.shred_store_mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed on shred_store_mcache" ));
  ulong shred_store_mcache_depth = fd_mcache_depth( args.shred_store_mcache );

  ulong scratch_footprint = fd_shred_tile_scratch_footprint( bank_cnt, shred_store_mcache_depth, args.fec_resolver_depth, args.fec_resolver_done_depth );
  void * shred_tile_mem = fd_wksp_alloc_laddr( fd_wksp_containing( tile_pod ), fd_shred_tile_scratch_align(), scratch_footprint, FD_SHRED_TAG );
  if( FD_UNLIKELY( !shred_tile_mem ) ) FD_LOG_ERR(( "fd_wksp_alloc_laddr failed" ));

  fd_shred_tile( &args, shred_tile_mem );
}

static long allow_syscalls[] = {
  __NR_write,     /* logging */
  __NR_fsync,     /* logging, WARNING and above fsync immediately */
  __NR_sendto,    /* fd_io requires send and recv for ARP */
  __NR_recvfrom,  /* fd_io requires send and recv for ARP */
};

static workspace_kind_t allow_workspaces[] = {
  wksp_shred,        /* the tile itself */
  wksp_bank_shred,   /* receive from bank */
  wksp_shred_store,  /* send to blockstore */
  wksp_netmux_inout, /* send/recv from network */
};

static ulong
allow_fds( fd_tile_args_t * args,
           ulong            out_fds_sz,
           int *            out_fds ) {
  (void)args;
  if( FD_UNLIKELY( out_fds_sz < 3 ) ) FD_LOG_ERR(( "out_fds_sz %lu", out_fds_sz ));
  out_fds[ 0 ] = 2; /* stderr */
  out_fds[ 1 ] = 3; /* logfile */
  out_fds[ 2 ] = fd_ip_netlink_get( (fd_ip_t*)args->lo_xsk )->fd;
  return 3;
}

fd_tile_config_t shred = {
  .name                 = "shred",
  .allow_workspaces_cnt = sizeof(allow_workspaces)/sizeof(allow_workspaces[ 0 ]),
  .allow_workspaces     = allow_workspaces,
  .allow_syscalls_cnt   = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls       = allow_syscalls,
  .allow_fds            = allow_fds,
  .init                 = init,
  .run                  = run,
};
