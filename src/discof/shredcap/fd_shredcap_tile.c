#define _GNU_SOURCE  /* Enable GNU and POSIX extensions */
#include "../../disco/tiles.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../disco/fd_disco.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include <linux/if_xdp.h>
#include "generated/fd_shredcap_tile_seccomp.h"


/* This tile spies on the net_shred, repair_net, and shred_repair links
   and currently outputs to a csv that can analyze repair performance
   in post. */

#define FD_SHREDCAP_DEFAULT_WRITER_BUF_SZ  (4096UL)  /* local filesystem block size */
#define FD_SHREDCAP_ALLOC_TAG              (4UL)
#define MAX_BUFFER_SIZE  ( 20000UL * sizeof(fd_shred_dest_wire_t))

#define NET_SHRED  (0UL)
#define REPAIR_NET (1UL)
#define SHRED_REPAIR (2UL)
#define GOSSIP_SHRED (3UL)
#define GOSSIP_REPAIR (4UL)

typedef union {
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
  };
  fd_net_rx_bounds_t net_rx;
} fd_capture_in_ctx_t;

struct fd_capture_tile_ctx {
  uchar               in_kind[ 32 ];
  fd_capture_in_ctx_t in_links[ 32 ];

  int skip_frag;
  ushort repair_intake_listen_port;

  ulong shred_buffer_sz;
  uchar shred_buffer[ FD_NET_MTU ];

  ulong repair_buffer_sz;
  uchar repair_buffer[ FD_NET_MTU ];


  fd_ip4_udp_hdrs_t intake_hdr[1];

  ulong now;
  ulong  last_packet_ns;
  double tick_per_ns;

  fd_io_buffered_ostream_t shred_ostream;
  fd_io_buffered_ostream_t repair_ostream;
  fd_io_buffered_ostream_t fecs_ostream;
  fd_io_buffered_ostream_t peers_ostream;

  int  shreds_fd;
  int  requests_fd;
  int  fecs_fd;
  int  peers_fd;

  ulong write_buf_sz;

  uchar * shreds_buf;
  uchar * requests_buf;
  uchar * fecs_buf;
  uchar * peers_buf;

  fd_alloc_t * alloc;
  uchar contact_info_buffer[ MAX_BUFFER_SIZE ];
};
typedef struct fd_capture_tile_ctx fd_capture_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 1UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_shredcap_tile( out_cnt,
                                             out,
                                             (uint)fd_log_private_logfile_fd(),
                                             (uint)tile->shredcap.shreds_fd,
                                             (uint)tile->shredcap.requests_fd,
                                             (uint)tile->shredcap.fecs_fd,
                                             (uint)tile->shredcap.peers_fd );
  return sock_filter_policy_fd_shredcap_tile_instr_cnt;
}


FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_capture_tile_ctx_t), sizeof(fd_capture_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline int
before_frag( fd_capture_tile_ctx_t * ctx,
             ulong            in_idx,
             ulong            seq FD_PARAM_UNUSED,
             ulong            sig ) {
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==NET_SHRED ) ) {
    return (fd_disco_netmux_sig_proto( sig )!=DST_PROTO_SHRED) & (fd_disco_netmux_sig_proto( sig )!=DST_PROTO_REPAIR);
  }
  return 0;
}

static inline void
handle_new_turbine_contact_info( fd_capture_tile_ctx_t * ctx,
                                 uchar const *          buf ) {
  ulong const * header = (ulong const *)fd_type_pun_const( buf );
  ulong dest_cnt = header[ 0 ];

  fd_shred_dest_wire_t const * in_dests = fd_type_pun_const( header+1UL );

  for( ulong i=0UL; i<dest_cnt; i++ ) {
    // need to bswap the port
    //ushort port = fd_ushort_bswap( in_dests[i].udp_port );
    char peers_buf[1024];
    snprintf( peers_buf, sizeof(peers_buf),
              "%u,%u,%s,%d\n",
              in_dests[i].ip4_addr, in_dests[i].udp_port, FD_BASE58_ENC_32_ALLOCA(in_dests[i].pubkey), 1);
    int err = fd_io_buffered_ostream_write( &ctx->peers_ostream, peers_buf, strlen(peers_buf) );
    FD_TEST( err==0 );
  }
}


static int
is_fec_completes_msg( ulong sz ) {
  return sz == FD_SHRED_DATA_HEADER_SZ + FD_SHRED_MERKLE_ROOT_SZ;
}

static inline void
during_frag( fd_capture_tile_ctx_t * ctx,
             ulong                   in_idx,
             ulong                   seq     FD_PARAM_UNUSED,
             ulong                   sig,
             ulong                   chunk,
             ulong                   sz,
             ulong                   ctl ) {
  ctx->skip_frag = 0;
  if( ctx->in_kind[ in_idx ]==SHRED_REPAIR ) {
    if( !is_fec_completes_msg( sz ) ) {
      ctx->skip_frag = 1;
      return;
    }
    fd_memcpy( ctx->shred_buffer, fd_chunk_to_laddr_const( ctx->in_links[ in_idx ].mem, chunk ), sz );
    ctx->shred_buffer_sz = sz;
  } else if( ctx->in_kind[ in_idx ] == NET_SHRED ) {
    uchar const * dcache_entry = fd_net_rx_translate_frag( &ctx->in_links[ in_idx ].net_rx, chunk, ctl, sz );
    ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( sig );
    FD_TEST( hdr_sz <= sz ); /* Should be ensured by the net tile */
    fd_shred_t const * shred = fd_shred_parse( dcache_entry+hdr_sz, sz-hdr_sz );
    if( FD_UNLIKELY( !shred ) ) {
      ctx->skip_frag = 1;
      return;
    };
    fd_memcpy( ctx->shred_buffer, dcache_entry, sz );
    ctx->shred_buffer_sz = sz-hdr_sz;
  } else if( ctx->in_kind[ in_idx ] == REPAIR_NET ) {
    /* Repair will have outgoing pings, outgoing repair requests, and
       outgoing served shreds we want to filter everything but the
       repair requests.
       1. We can index into the ip4 udp packet hdr and check if the src
          port is the intake listen port or serve port
       2. Then we can filter on the discriminant which luckily does not
          require decoding! */

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in_links[ in_idx ].mem, chunk );
    fd_ip4_udp_hdrs_t const * hdr = (fd_ip4_udp_hdrs_t const *)dcache_entry;
    if( hdr->udp->net_sport != fd_ushort_bswap( ctx->repair_intake_listen_port ) ) {
      ctx->skip_frag = 1;
      return;
    }
    const uchar * encoded_protocol = dcache_entry + sizeof(fd_ip4_udp_hdrs_t);
    uint discriminant = FD_LOAD(uint, encoded_protocol);

    if( FD_UNLIKELY( discriminant <= fd_repair_protocol_enum_pong ) ) {
      ctx->skip_frag = 1;
      return;
    }
    fd_memcpy( ctx->repair_buffer, dcache_entry, sz );
    ctx->repair_buffer_sz = sz;
  } else {
    // contact infos can be copied into a buffer
    if( FD_UNLIKELY( chunk<ctx->in_links[ in_idx ].chunk0 || chunk>ctx->in_links[ in_idx ].wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
                   ctx->in_links[ in_idx ].chunk0, ctx->in_links[ in_idx ].wmark ));
    }
    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in_links[ in_idx ].mem, chunk );
    fd_memcpy( ctx->contact_info_buffer, dcache_entry, sz );
  }
}

static inline void
after_frag( fd_capture_tile_ctx_t * ctx,
            ulong                   in_idx,
            ulong                   seq    FD_PARAM_UNUSED,
            ulong                   sig,
            ulong                   sz,
            ulong                   tsorig FD_PARAM_UNUSED,
            ulong                   tspub  FD_PARAM_UNUSED,
            fd_stem_context_t *     stem   FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( ctx->skip_frag ) ) return;

  if( ctx->in_kind[ in_idx ] == SHRED_REPAIR ) {
    /* This is a fec completes message! we can use it to check how long
       it takes to complete a fec */

    fd_shred_t const * shred = (fd_shred_t *)fd_type_pun( ctx->shred_buffer );
    uint data_cnt = fd_disco_shred_repair_fec_sig_data_cnt( sig );
    uint ref_tick = shred->data.flags & FD_SHRED_DATA_REF_TICK_MASK;
    char fec_complete[1024];
    snprintf( fec_complete, sizeof(fec_complete),
             "%ld,%lu,%u,%u,%u\n",
              fd_log_wallclock(), shred->slot, ref_tick, shred->fec_set_idx, data_cnt );

    // Last shred is guaranteed to be a data shred


    int err = fd_io_buffered_ostream_write( &ctx->fecs_ostream, fec_complete, strlen(fec_complete) );
    FD_TEST( err==0 );
  } else if( ctx->in_kind[ in_idx ] == NET_SHRED ) {
    /* TODO: leader schedule early exits in shred tile right around
       startup, which discards some turbine shreds, but there is a
       chance we capture this shred here. Currently handled in post, but
       in the future will want to get the leader schedule here so we can
       also benchmark whether the excepcted sender in the turbine tree
       matches the actual sender. */

    ulong hdr_sz     = fd_disco_netmux_sig_hdr_sz( sig );
    fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)ctx->shred_buffer;
    uint src_ip4_addr = hdr->ip4->saddr;
    ushort src_port   = hdr->udp->net_sport;

    fd_shred_t const * shred = fd_shred_parse( ctx->shred_buffer + hdr_sz, sz - hdr_sz );
    int   is_turbine = fd_disco_netmux_sig_proto( sig ) == DST_PROTO_SHRED;
    uint  nonce      = is_turbine ? 0 : FD_LOAD(uint, ctx->shred_buffer + hdr_sz + fd_shred_sz( shred ) );
    int   is_data    = fd_shred_is_data( fd_shred_type( shred->variant ) );
    ulong slot       = shred->slot;
    uint  idx        = shred->idx;
    uint  fec_idx    = shred->fec_set_idx;
    uint  ref_tick   = 65;
    if( FD_UNLIKELY( is_turbine && is_data ) ) {
      /* We can then index into the flag and get a REFTICK */
      ref_tick = shred->data.flags & FD_SHRED_DATA_REF_TICK_MASK;
    }

    char repair_data_buf[1024];
    snprintf( repair_data_buf, sizeof(repair_data_buf),
             "%u,%u,%ld,%lu,%u,%u,%u,%d,%d,%u\n",
              src_ip4_addr, src_port, fd_log_wallclock(), slot, ref_tick, fec_idx, idx, is_turbine, is_data, nonce );

    int err = fd_io_buffered_ostream_write( &ctx->shred_ostream, repair_data_buf, strlen(repair_data_buf) );
    FD_TEST( err==0 );
  } else if( ctx->in_kind[ in_idx ] == REPAIR_NET ) {
    /* We have a valid repair request that we can finally decode.
       Unfortunately we actually have to decode because we cant cast
       directly to the protocol */
    fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)ctx->repair_buffer;
    fd_repair_protocol_t protocol;
    fd_bincode_decode_ctx_t bctx = { .data = ctx->repair_buffer + sizeof(fd_ip4_udp_hdrs_t), .dataend = ctx->repair_buffer + ctx->repair_buffer_sz };
    fd_repair_protocol_t * decoded = fd_repair_protocol_decode( &protocol, &bctx );

    FD_TEST( decoded == &protocol );
    FD_TEST( decoded != NULL );

    uint   peer_ip4_addr = hdr->ip4->daddr;
    ushort peer_port     = hdr->udp->net_dport;
    ulong  slot          = 0UL;
    ulong  shred_index   = UINT_MAX;
    uint   nonce         = 0U;

    switch( protocol.discriminant ) {
      case fd_repair_protocol_enum_window_index: {
        slot        = protocol.inner.window_index.slot;
        shred_index = protocol.inner.window_index.shred_index;
        nonce       = protocol.inner.window_index.header.nonce;
        break;
      }
      case fd_repair_protocol_enum_highest_window_index: {
        slot        = protocol.inner.highest_window_index.slot;
        shred_index = protocol.inner.highest_window_index.shred_index;
        nonce       = protocol.inner.highest_window_index.header.nonce;
        break;
      }
      case fd_repair_protocol_enum_orphan: {
        slot  = protocol.inner.orphan.slot;
        nonce = protocol.inner.orphan.header.nonce;
        break;
      }
      default:
        break;
    }

    char repair_data_buf[1024];
    snprintf( repair_data_buf, sizeof(repair_data_buf),
              "%u,%u,%ld,%u,%lu,%lu\n",
              peer_ip4_addr, peer_port, fd_log_wallclock(), nonce, slot, shred_index );
    int err = fd_io_buffered_ostream_write( &ctx->repair_ostream, repair_data_buf, strlen(repair_data_buf) );
    FD_TEST( err==0 );
  } else if( ctx->in_kind[ in_idx ] == GOSSIP_REPAIR ) {
    fd_shred_dest_wire_t const * in_dests = (fd_shred_dest_wire_t const *)fd_type_pun_const( ctx->contact_info_buffer );
    ulong dest_cnt = sz;
    for( ulong i=0UL; i<dest_cnt; i++ ) {
      char peers_buf[1024];
      snprintf( peers_buf, sizeof(peers_buf),
                "%u,%u,%s,%d\n",
                 in_dests[i].ip4_addr, in_dests[i].udp_port, FD_BASE58_ENC_32_ALLOCA(in_dests[i].pubkey), 0);
      int err = fd_io_buffered_ostream_write( &ctx->peers_ostream, peers_buf, strlen(peers_buf) );
      FD_TEST( err==0 );
    }
  } else { // crds_shred contact infos
    handle_new_turbine_contact_info( ctx, ctx->contact_info_buffer );
  }
}

static ulong
populate_allowed_fds( fd_topo_t const      * topo        FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt FD_PARAM_UNUSED,
                      int *                  out_fds ) {
  ulong out_cnt = 0UL;

  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_LIKELY( -1!=tile->shredcap.shreds_fd ) )
    out_fds[ out_cnt++ ] = tile->shredcap.shreds_fd; /* shred file */
  if( FD_LIKELY( -1!=tile->shredcap.requests_fd ) )
    out_fds[ out_cnt++ ] = tile->shredcap.requests_fd; /* request file */
  if( FD_LIKELY( -1!=tile->shredcap.fecs_fd ) )
    out_fds[ out_cnt++ ] = tile->shredcap.fecs_fd; /* fec complete file */
  if( FD_LIKELY( -1!=tile->shredcap.peers_fd ) )
    out_fds[ out_cnt++ ] = tile->shredcap.peers_fd; /* peers file */

  return out_cnt;
}

static void
privileged_init( fd_topo_t *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile ) {
  char file_path[PATH_MAX];
  strcpy( file_path, tile->shredcap.folder_path );
  strcat( file_path, "/shred_data.csv" );
  tile->shredcap.shreds_fd = open( file_path, O_WRONLY|O_CREAT|O_APPEND /*| O_DIRECT*/, 0644 );
  if ( FD_UNLIKELY( tile->shredcap.shreds_fd == -1 ) ) {
    FD_LOG_ERR(( "failed to open or create shred csv dump file %s %d %s", file_path, errno, strerror(errno) ));
  }

  strcpy( file_path, tile->shredcap.folder_path );
  strcat( file_path, "/request_data.csv" );
  tile->shredcap.requests_fd = open( file_path, O_WRONLY|O_CREAT|O_APPEND /*| O_DIRECT*/, 0644 );
  if ( FD_UNLIKELY( tile->shredcap.requests_fd == -1 ) ) {
    FD_LOG_ERR(( "failed to open or create request csv dump file %s %d %s", file_path, errno, strerror(errno) ));
  }

  strcpy( file_path, tile->shredcap.folder_path );
  strcat( file_path, "/fec_complete.csv" );
  tile->shredcap.fecs_fd = open( file_path, O_WRONLY|O_CREAT|O_APPEND /*| O_DIRECT*/, 0644 );
  if ( FD_UNLIKELY( tile->shredcap.fecs_fd == -1 ) ) {
    FD_LOG_ERR(( "failed to open or create fec complete csv dump file %s %d %s", file_path, errno, strerror(errno) ));
  }
  FD_LOG_NOTICE(( "Opening shred csv dump file at %s", file_path ));

  strcpy( file_path, tile->shredcap.folder_path );
  strcat( file_path, "/peers.csv" );
  tile->shredcap.peers_fd = open( file_path, O_WRONLY|O_CREAT|O_APPEND /*| O_DIRECT*/, 0644 );
  if ( FD_UNLIKELY( tile->shredcap.peers_fd == -1 ) ) {
    FD_LOG_ERR(( "failed to open or create peers csv dump file %s %d %s", file_path, errno, strerror(errno) ));
  }
}

static void
init_file_handlers( fd_capture_tile_ctx_t    * ctx,
                    int                      * ctx_file,
                    int                        tile_file,
                    uchar                   ** ctx_buf,
                    fd_io_buffered_ostream_t * ctx_ostream ) {
  *ctx_file =  tile_file ;

  int err = ftruncate( *ctx_file, 0UL );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "failed to truncate file (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  long seek = lseek( *ctx_file, 0UL, SEEK_SET );
  if( FD_UNLIKELY( seek!=0L ) ) {
    FD_LOG_ERR(( "failed to seek to the beginning of file" ));
  }

  *ctx_buf = fd_alloc_malloc( ctx->alloc, 4096, ctx->write_buf_sz );
  if( FD_UNLIKELY( *ctx_buf == NULL ) ) {
    FD_LOG_ERR(( "failed to allocate ostream buffer" ));
  }

  if( FD_UNLIKELY( !fd_io_buffered_ostream_init(
    ctx_ostream,
    *ctx_file,
    *ctx_buf,
    ctx->write_buf_sz ) ) ) {
    FD_LOG_ERR(( "failed to initialize ostream" ));
  }
}


static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_capture_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_capture_tile_ctx_t), sizeof(fd_capture_tile_ctx_t) );
  void * alloc_mem            = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  /* Input links */
  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];
    if( 0==strcmp( link->name, "net_shred" ) ) {
      ctx->in_kind[ i ] = NET_SHRED;
      fd_net_rx_bounds_init( &ctx->in_links[ i ].net_rx, link->dcache );
      continue;
    } else if( 0==strcmp( link->name, "repair_net" ) ) {
      ctx->in_kind[ i ] = REPAIR_NET;
    } else if( 0==strcmp( link->name, "shred_repair" ) ) {
      ctx->in_kind[ i ] = SHRED_REPAIR;
    } else if( 0==strcmp( link->name, "crds_shred" ) ) {
      ctx->in_kind[ i ] = GOSSIP_SHRED;
    } else if( 0==strcmp( link->name, "gossip_repai" ) ) {
      ctx->in_kind[ i ] = GOSSIP_REPAIR;
    } else {
      FD_LOG_ERR(( "repair tile has unexpected input link %s", link->name ));
    }

    ctx->in_links[ i ].mem    = link_wksp->wksp;
    ctx->in_links[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in_links[ i ].mem, link->dcache );
    ctx->in_links[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in_links[ i ].mem, link->dcache, link->mtu );
  }

  ctx->repair_intake_listen_port = tile->shredcap.repair_intake_listen_port;
  ctx->write_buf_sz = tile->shredcap.write_buffer_size ? tile->shredcap.write_buffer_size : FD_SHREDCAP_DEFAULT_WRITER_BUF_SZ;

  /* Allocate the write buffers */
  ctx->alloc = fd_alloc_join( fd_alloc_new( alloc_mem, FD_SHREDCAP_ALLOC_TAG ), fd_tile_idx() );
  if( FD_UNLIKELY( !ctx->alloc ) ) {
    FD_LOG_ERR( ( "fd_alloc_join failed" ) );
  }

  /* Setup the csv files to be in the expected state */

  init_file_handlers( ctx, &ctx->shreds_fd,   tile->shredcap.shreds_fd,   &ctx->shreds_buf,   &ctx->shred_ostream );
  init_file_handlers( ctx, &ctx->requests_fd, tile->shredcap.requests_fd, &ctx->requests_buf, &ctx->repair_ostream );
  init_file_handlers( ctx, &ctx->fecs_fd,     tile->shredcap.fecs_fd,     &ctx->fecs_buf,     &ctx->fecs_ostream );
  init_file_handlers( ctx, &ctx->peers_fd,    tile->shredcap.peers_fd,    &ctx->peers_buf,    &ctx->peers_ostream );

  int err = fd_io_buffered_ostream_write( &ctx->shred_ostream,  "src_ip,src_port,timestamp,slot,ref_tick,fec_set_idx,idx,is_turbine,is_data,nonce\n", 81UL );
  err    |= fd_io_buffered_ostream_write( &ctx->repair_ostream, "dst_ip,dst_port,timestamp,nonce,slot,idx\n", 41UL );
  err    |= fd_io_buffered_ostream_write( &ctx->fecs_ostream,   "timestamp,slot,ref_tick,fec_set_idx,data_cnt\n", 45UL );
  err    |= fd_io_buffered_ostream_write( &ctx->peers_ostream,  "peer_ip4_addr,peer_port,pubkey,turbine\n", 48UL );

  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "failed to write header to any of the 4 files (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (50UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_capture_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_capture_tile_ctx_t)

#define STEM_CALLBACK_DURING_FRAG          during_frag
#define STEM_CALLBACK_AFTER_FRAG           after_frag
#define STEM_CALLBACK_BEFORE_FRAG          before_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_shredcap = {
  .name                     = "shrdcp",
  .loose_footprint          = loose_footprint,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
