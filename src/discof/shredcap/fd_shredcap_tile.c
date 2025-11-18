#define _GNU_SOURCE  /* Enable GNU and POSIX extensions */
#include "../../disco/topo/fd_topo.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../flamenco/gossip/fd_gossip_types.h"
#include "../../disco/fd_disco.h"
#include "../../discof/fd_discof.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../discof/replay/fd_exec.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../discof/restore/utils/fd_ssmanifest_parser.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../disco/fd_disco.h"
#include "../../util/pod/fd_pod_format.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include "generated/fd_shredcap_tile_seccomp.h"


/* This tile currently has two functionalities.

   The first is spying on the net_shred, repair_net, and shred_out
   links and currently outputs to a csv that can analyze repair
   performance in post.

   The second is to capture the bank hashes from the replay tile and
   slices of shreds from the repair tile.  These are outputted to binary
   files that can be used to reproduce a live replay execution. */

#define FD_SHREDCAP_DEFAULT_WRITER_BUF_SZ  (4096UL)  /* local filesystem block size */
#define FD_SHREDCAP_ALLOC_TAG              (4UL)
#define MAX_BUFFER_SIZE                    (20000UL * sizeof(fd_shred_dest_wire_t))
#define MANIFEST_MAX_TOTAL_BANKS           (2UL) /* the minimum is 2 */
#define MANIFEST_MAX_FORK_WIDTH            (1UL) /* banks are only needed during publish_stake_weights() */

#define NET_SHRED        (0UL)
#define REPAIR_NET       (1UL)
#define SHRED_OUT        (2UL)
#define GOSSIP_OUT       (3UL)
#define REPAIR_SHREDCAP  (4UL)
#define REPLAY_OUT       (5UL)

typedef union {
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
  };
  fd_net_rx_bounds_t net_rx;
} fd_capture_in_ctx_t;

struct out_link {
  ulong       idx;
  fd_frag_meta_t * mcache;
  ulong *          sync;
  ulong            depth;
  ulong            seq;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};
typedef struct out_link out_link_t;

struct fd_capture_tile_ctx {
  uchar               in_kind[ 32 ];
  fd_capture_in_ctx_t in_links[ 32 ];

  int skip_frag;
  ushort repair_intake_listen_port;

  ulong shred_buffer_sz;
  uchar shred_buffer[ FD_NET_MTU ];

  ulong repair_buffer_sz;
  uchar repair_buffer[ FD_NET_MTU ];

  out_link_t           stake_out[1];
  out_link_t           snap_out[1];
  int                  enable_publish_stake_weights;
  ulong *              manifest_wmark;
  uchar *              manifest_bank_mem;
  fd_banks_t *         banks;
  fd_bank_t *          bank;
  char                 manifest_path[ PATH_MAX ];
  int                  manifest_load_done;
  uchar *              manifest_spad_mem;
  fd_spad_t *          manifest_spad;
  uchar *              shared_spad_mem;
  fd_spad_t *          shared_spad;

  fd_ip4_udp_hdrs_t intake_hdr[1];

  ulong now;
  ulong  last_packet_ns;
  double tick_per_ns;

  fd_io_buffered_ostream_t shred_ostream;
  fd_io_buffered_ostream_t repair_ostream;
  fd_io_buffered_ostream_t fecs_ostream;
  fd_io_buffered_ostream_t peers_ostream;
  fd_io_buffered_ostream_t slices_ostream;
  fd_io_buffered_ostream_t bank_hashes_ostream;

  int shreds_fd; /* shreds snooped from net_shred */
  int requests_fd;
  int fecs_fd;
  int peers_fd;
  int slices_fd; /* all shreds in slices from repair tile */
  int bank_hashes_fd; /* bank hashes from replay tile */

  ulong write_buf_sz;

  uchar * shreds_buf;
  uchar * requests_buf;
  uchar * fecs_buf;
  uchar * peers_buf;
  uchar * slices_buf;
  uchar * bank_hashes_buf;

  fd_alloc_t * alloc;
  uchar contact_info_buffer[ MAX_BUFFER_SIZE ];
};
typedef struct fd_capture_tile_ctx fd_capture_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_CONST static inline ulong
manifest_bank_align( void ) {
  return fd_banks_align();
}

FD_FN_CONST static inline ulong
manifest_bank_footprint( void ) {
  return fd_banks_footprint( MANIFEST_MAX_TOTAL_BANKS, MANIFEST_MAX_FORK_WIDTH );
}

FD_FN_CONST static inline ulong
manifest_load_align( void ) {
  return 128UL;
}

FD_FN_CONST static inline ulong
manifest_load_footprint( void ) {
  /* A manifest typically requires 1GB, but closer to 2GB
     have been observed in mainnet.  The footprint is then
     set to 2GB.  TODO a future adjustment may be needed. */
  return 2UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_CONST static inline ulong
manifest_spad_max_alloc_align( void ) {
  return FD_SPAD_ALIGN;
}

FD_FN_CONST static inline ulong
manifest_spad_max_alloc_footprint( void ) {
  /* The amount of memory required in the manifest load
     scratchpad to process it tends to be slightly larger
     than the manifest load footprint. */
  return manifest_load_footprint() + 128UL * FD_SHMEM_HUGE_PAGE_SZ;
}

FD_FN_CONST static inline ulong
shared_spad_max_alloc_align( void ) {
  return FD_SPAD_ALIGN;
}

FD_FN_CONST static inline ulong
shared_spad_max_alloc_footprint( void ) {
  /* The shared scratchpad is used by the manifest banks
     and by the manifest load (but not at the same time).
     The footprint for the banks needs to be equal to
     banks footprint (at least for the current setup with
     MANIFEST_MAX_TOTAL_BANKS==2). */
  return fd_ulong_max( manifest_bank_footprint(), manifest_load_footprint() );
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong footprint = sizeof(fd_capture_tile_ctx_t)
                    + manifest_bank_footprint()
                    + fd_spad_footprint( manifest_spad_max_alloc_footprint() )
                    + fd_spad_footprint( shared_spad_max_alloc_footprint() )
                    + fd_alloc_footprint();
  return fd_ulong_align_up( footprint, FD_SHMEM_GIGANTIC_PAGE_SZ );
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
  l = FD_LAYOUT_APPEND( l, alignof(fd_capture_tile_ctx_t),  sizeof(fd_capture_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, manifest_bank_align(),           manifest_bank_footprint() );
  l = FD_LAYOUT_APPEND( l, manifest_spad_max_alloc_align(), fd_spad_footprint( manifest_spad_max_alloc_footprint() ) );
  l = FD_LAYOUT_APPEND( l, shared_spad_max_alloc_align(),   fd_spad_footprint( shared_spad_max_alloc_footprint() ) );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(),                fd_alloc_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline ulong
generate_stake_weight_msg_manifest( ulong                                       epoch,
                                    fd_epoch_schedule_t const *                 epoch_schedule,
                                    fd_snapshot_manifest_epoch_stakes_t const * epoch_stakes,
                                    ulong *                                     stake_weight_msg_out ) {
  fd_stake_weight_msg_t *  stake_weight_msg = (fd_stake_weight_msg_t *)fd_type_pun( stake_weight_msg_out );
  fd_vote_stake_weight_t * stake_weights    = stake_weight_msg->weights;

  stake_weight_msg->epoch             = epoch;
  stake_weight_msg->staked_cnt        = epoch_stakes->vote_stakes_len;
  stake_weight_msg->start_slot        = fd_epoch_slot0( epoch_schedule, epoch );
  stake_weight_msg->slot_cnt          = epoch_schedule->slots_per_epoch;
  stake_weight_msg->excluded_stake    = 0UL;
  stake_weight_msg->vote_keyed_lsched = 1UL;

  /* FIXME: SIMD-0180 - hack to (de)activate in testnet vs mainnet.
     This code can be removed once the feature is active. */
  {
    if(    ( 1==epoch_schedule->warmup && epoch<FD_SIMD0180_ACTIVE_EPOCH_TESTNET )
        || ( 0==epoch_schedule->warmup && epoch<FD_SIMD0180_ACTIVE_EPOCH_MAINNET ) ) {
      stake_weight_msg->vote_keyed_lsched = 0UL;
    }
  }

  /* epoch_stakes from manifest are already filtered (stake>0), but not sorted */
  for( ulong i=0UL; i<epoch_stakes->vote_stakes_len; i++ ) {
    stake_weights[ i ].stake = epoch_stakes->vote_stakes[ i ].stake;
    memcpy( stake_weights[ i ].id_key.uc, epoch_stakes->vote_stakes[ i ].identity, sizeof(fd_pubkey_t) );
    memcpy( stake_weights[ i ].vote_key.uc, epoch_stakes->vote_stakes[ i ].vote, sizeof(fd_pubkey_t) );
  }
  sort_vote_weights_by_stake_vote_inplace( stake_weights, epoch_stakes->vote_stakes_len);

  return fd_stake_weight_msg_sz( epoch_stakes->vote_stakes_len );
}

static void
publish_stake_weights_manifest( fd_capture_tile_ctx_t * ctx,
                                fd_stem_context_t *    stem,
                                fd_snapshot_manifest_t const * manifest ) {
  fd_epoch_schedule_t const * schedule = fd_type_pun_const( &manifest->epoch_schedule_params );
  ulong epoch = fd_slot_to_epoch( schedule, manifest->slot, NULL );

  /* current epoch */
  ulong * stake_weights_msg = fd_chunk_to_laddr( ctx->stake_out->mem, ctx->stake_out->chunk );
  ulong stake_weights_sz = generate_stake_weight_msg_manifest( epoch, schedule, &manifest->epoch_stakes[0], stake_weights_msg );
  ulong stake_weights_sig = 4UL;
  fd_stem_publish( stem, 0UL, stake_weights_sig, ctx->stake_out->chunk, stake_weights_sz, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->stake_out->chunk = fd_dcache_compact_next( ctx->stake_out->chunk, stake_weights_sz, ctx->stake_out->chunk0, ctx->stake_out->wmark );
  FD_LOG_NOTICE(("sending current epoch stake weights - epoch: %lu, stake_weight_cnt: %lu, start_slot: %lu, slot_cnt: %lu", stake_weights_msg[0], stake_weights_msg[1], stake_weights_msg[2], stake_weights_msg[3]));

  /* next current epoch */
  stake_weights_msg = fd_chunk_to_laddr( ctx->stake_out->mem, ctx->stake_out->chunk );
  stake_weights_sz = generate_stake_weight_msg_manifest( epoch + 1, schedule, &manifest->epoch_stakes[1], stake_weights_msg );
  stake_weights_sig = 4UL;
  fd_stem_publish( stem, 0UL, stake_weights_sig, ctx->stake_out->chunk, stake_weights_sz, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->stake_out->chunk = fd_dcache_compact_next( ctx->stake_out->chunk, stake_weights_sz, ctx->stake_out->chunk0, ctx->stake_out->wmark );
  FD_LOG_NOTICE(("sending next epoch stake weights - epoch: %lu, stake_weight_cnt: %lu, start_slot: %lu, slot_cnt: %lu", stake_weights_msg[0], stake_weights_msg[1], stake_weights_msg[2], stake_weights_msg[3]));
}

static inline int
before_frag( fd_capture_tile_ctx_t * ctx,
             ulong            in_idx,
             ulong            seq FD_PARAM_UNUSED,
             ulong            sig ) {
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==NET_SHRED ) ) {
    return (int)(fd_disco_netmux_sig_proto( sig )!=DST_PROTO_SHRED) & (int)(fd_disco_netmux_sig_proto( sig )!=DST_PROTO_REPAIR);
  } else if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==GOSSIP_OUT)) {
    return sig!=FD_GOSSIP_UPDATE_TAG_CONTACT_INFO;
  }
  return 0;
}

static inline void
handle_new_contact_info( fd_capture_tile_ctx_t * ctx,
                         uchar const *           buf ) {
  fd_gossip_update_message_t const * msg = (fd_gossip_update_message_t const *)fd_type_pun_const( buf );
  char tvu_buf[1024];
  char repair_buf[1024];
  fd_ip4_port_t tvu    = msg->contact_info.contact_info->sockets[ FD_CONTACT_INFO_SOCKET_TVU ];
  fd_ip4_port_t repair = msg->contact_info.contact_info->sockets[ FD_CONTACT_INFO_SOCKET_SERVE_REPAIR ];

  if( FD_UNLIKELY( tvu.l!=0UL ) ){
    snprintf( tvu_buf, sizeof(tvu_buf),
              "%u,%u(tvu),%s,%d\n",
              tvu.addr, tvu.port, FD_BASE58_ENC_32_ALLOCA(msg->contact_info.contact_info->pubkey.uc), 1);
    int err = fd_io_buffered_ostream_write( &ctx->peers_ostream, tvu_buf, strlen(tvu_buf) );
    FD_TEST( err==0 );
  }
  if( FD_UNLIKELY( repair.l!=0UL ) ){
    snprintf( repair_buf, sizeof(repair_buf),
              "%u,%u(repair),%s,%d\n",
              repair.addr, repair.port, FD_BASE58_ENC_32_ALLOCA(msg->contact_info.contact_info->pubkey.uc), 1);
    int err = fd_io_buffered_ostream_write( &ctx->peers_ostream, repair_buf, strlen(repair_buf) );
    FD_TEST( err==0 );
  }
}

static int
is_fec_completes_msg( ulong sz ) {
  return sz == FD_SHRED_DATA_HEADER_SZ + 2 * FD_SHRED_MERKLE_ROOT_SZ;
}

static inline void
during_frag( fd_capture_tile_ctx_t * ctx,
             ulong                   in_idx,
             ulong                   seq FD_PARAM_UNUSED,
             ulong                   sig,
             ulong                   chunk,
             ulong                   sz,
             ulong                   ctl ) {
  ctx->skip_frag = 0;
  if( ctx->in_kind[ in_idx ]==SHRED_OUT ) {
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
  } else if( ctx->in_kind[ in_idx ] == REPAIR_SHREDCAP ) {

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in_links[ in_idx ].mem, chunk );

    /* FIXME this should all be happening in after_frag */

    /* We expect to get all of the data shreds in a batch at once.  When
       we do we will write the header, the shreds, and a trailer. */
    ulong payload_sz = sig;
    fd_shredcap_slice_header_msg_t header = {
      .magic      = FD_SHREDCAP_SLICE_HEADER_MAGIC,
      .version    = FD_SHREDCAP_SLICE_HEADER_V1,
      .payload_sz = payload_sz,
    };
    int err;
    err = fd_io_buffered_ostream_write( &ctx->slices_ostream, &header, FD_SHREDCAP_SLICE_HEADER_FOOTPRINT );
    if( FD_UNLIKELY( err != 0 ) ) {
      FD_LOG_CRIT(( "failed to write slice header %d", err ));
    }
    err = fd_io_buffered_ostream_write( &ctx->slices_ostream, dcache_entry, payload_sz );
    if( FD_UNLIKELY( err != 0 ) ) {
      FD_LOG_CRIT(( "failed to write slice data %d", err ));
    }
    fd_shredcap_slice_trailer_msg_t trailer = {
      .magic   = FD_SHREDCAP_SLICE_TRAILER_MAGIC,
      .version = FD_SHREDCAP_SLICE_TRAILER_V1,
    };
    err = fd_io_buffered_ostream_write( &ctx->slices_ostream, &trailer, FD_SHREDCAP_SLICE_TRAILER_FOOTPRINT );
    if( FD_UNLIKELY( err != 0 ) ) {
      FD_LOG_CRIT(( "failed to write slice trailer %d", err ));
    }

  } else if( ctx->in_kind[ in_idx ] == REPLAY_OUT ) {
    if( FD_UNLIKELY( sig!=REPLAY_SIG_SLOT_COMPLETED ) ) return;

    /* FIXME this should all be happening in after_frag */

   fd_replay_slot_completed_t const * msg = fd_chunk_to_laddr_const( ctx->in_links[ in_idx ].mem, chunk );
   fd_shredcap_bank_hash_msg_t bank_hash_msg = {
     .magic   = FD_SHREDCAP_BANK_HASH_MAGIC,
     .version = FD_SHREDCAP_BANK_HASH_V1
   };
   fd_memcpy( &bank_hash_msg.bank_hash, msg->bank_hash.uc, sizeof(fd_hash_t) );
   bank_hash_msg.slot = msg->slot;

   fd_io_buffered_ostream_write( &ctx->bank_hashes_ostream, &bank_hash_msg, FD_SHREDCAP_BANK_HASH_FOOTPRINT );

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

static void
after_credit( fd_capture_tile_ctx_t * ctx,
              fd_stem_context_t *     stem,
              int *                   opt_poll_in FD_PARAM_UNUSED,
              int *                   charge_busy FD_PARAM_UNUSED ) {

  if( FD_UNLIKELY( !ctx->manifest_load_done ) ) {
    if( FD_LIKELY( !!strcmp( ctx->manifest_path, "") ) ) {
      /* ctx->manifest_spad will hold the processed manifest. */
      fd_spad_reset( ctx->manifest_spad );
      /* do not pop from ctx->manifest_spad, the manifest needs
         to remain available until a new manifest is processed. */

      int fd = open( ctx->manifest_path, O_RDONLY );
      if( FD_UNLIKELY( fd < 0 ) ) {
        FD_LOG_WARNING(( "open(%s) failed (%d-%s)", ctx->manifest_path, errno, fd_io_strerror( errno ) ));
        return;
      }
      FD_LOG_NOTICE(( "manifest %s.", ctx->manifest_path ));

      fd_snapshot_manifest_t * manifest = NULL;
      FD_SPAD_FRAME_BEGIN( ctx->manifest_spad ) {
        manifest = fd_spad_alloc( ctx->manifest_spad, alignof(fd_snapshot_manifest_t), sizeof(fd_snapshot_manifest_t) );
      } FD_SPAD_FRAME_END;
      FD_TEST( manifest );

      FD_SPAD_FRAME_BEGIN( ctx->shared_spad ) {
        uchar * buf    = fd_spad_alloc( ctx->shared_spad, manifest_load_align(), manifest_load_footprint() );
        ulong   buf_sz = 0;
        FD_TEST( !fd_io_read( fd, buf/*dst*/, 0/*dst_min*/, manifest_load_footprint()-1UL /*dst_max*/, &buf_sz ) );

        fd_ssmanifest_parser_t * parser = fd_ssmanifest_parser_join( fd_ssmanifest_parser_new( aligned_alloc(
                fd_ssmanifest_parser_align(), fd_ssmanifest_parser_footprint() ) ) );
        FD_TEST( parser );
        fd_ssmanifest_parser_init( parser, manifest );
        int parser_err = fd_ssmanifest_parser_consume( parser, buf, buf_sz, NULL, NULL );
        FD_TEST( parser_err==1 );
        // if( FD_UNLIKELY( parser_err ) ) FD_LOG_ERR(( "fd_ssmanifest_parser_consume failed (%d)", parser_err ));
      } FD_SPAD_FRAME_END;
      FD_LOG_NOTICE(( "manifest bank slot %lu", manifest->slot ));

      fd_fseq_update( ctx->manifest_wmark, manifest->slot );

      uchar * chunk = fd_chunk_to_laddr( ctx->snap_out->mem, ctx->snap_out->chunk );
      ulong   sz    = sizeof(fd_snapshot_manifest_t);
      ulong   sig   = fd_ssmsg_sig( FD_SSMSG_MANIFEST_INCREMENTAL );
      memcpy( chunk, manifest, sz );
      fd_stem_publish( stem, ctx->snap_out->idx, sig, ctx->snap_out->chunk, sz, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
      ctx->snap_out->chunk = fd_dcache_compact_next( ctx->snap_out->chunk, sz, ctx->snap_out->chunk0, ctx->snap_out->wmark );

      fd_stem_publish( stem, ctx->snap_out->idx, fd_ssmsg_sig( FD_SSMSG_DONE ), 0UL, 0UL, 0UL, 0UL, 0UL );

      publish_stake_weights_manifest( ctx, stem, manifest );
      //*charge_busy = 0;
    }
    /* No need to strcmp every time after_credit is called. */
    ctx->manifest_load_done = 1;
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

  if( ctx->in_kind[ in_idx ] == SHRED_OUT ) {
    /* This is a fec completes message! we can use it to check how long
       it takes to complete a fec */

    fd_shred_t const * shred = (fd_shred_t *)fd_type_pun( ctx->shred_buffer );
    uint data_cnt = fd_disco_shred_out_fec_sig_data_cnt( sig );
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
  } else if( ctx->in_kind[ in_idx ] == GOSSIP_OUT ) {
    handle_new_contact_info( ctx, ctx->contact_info_buffer );
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
  if( FD_LIKELY( -1!=tile->shredcap.slices_fd ) )
    out_fds[ out_cnt++ ] = tile->shredcap.slices_fd; /* slices file */
  if( FD_LIKELY( -1!=tile->shredcap.bank_hashes_fd ) )
    out_fds[ out_cnt++ ] = tile->shredcap.bank_hashes_fd; /* bank hashes file */

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

  strcpy( file_path, tile->shredcap.folder_path );
  strcat( file_path, "/slices.bin" );
  tile->shredcap.slices_fd = open( file_path, O_WRONLY|O_CREAT|O_APPEND /*| O_DIRECT*/, 0644 );
  if ( FD_UNLIKELY( tile->shredcap.slices_fd == -1 ) ) {
    FD_LOG_ERR(( "failed to open or create slices csv dump file %s %d %s", file_path, errno, strerror(errno) ));
  }
  FD_LOG_NOTICE(( "Opening val_shreds binary dump file at %s", file_path ));

  strcpy( file_path, tile->shredcap.folder_path );
  strcat( file_path, "/bank_hashes.bin" );
  tile->shredcap.bank_hashes_fd = open( file_path, O_WRONLY|O_CREAT|O_APPEND /*| O_DIRECT*/, 0644 );
  if ( FD_UNLIKELY( tile->shredcap.bank_hashes_fd == -1 ) ) {
    FD_LOG_ERR(( "failed to open or create bank_hashes csv dump file %s %d %s", file_path, errno, strerror(errno) ));
  }
  FD_LOG_NOTICE(( "Opening bank_hashes binary dump file at %s", file_path ));
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
  fd_capture_tile_ctx_t * ctx       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_capture_tile_ctx_t),  sizeof(fd_capture_tile_ctx_t) );
  void * manifest_bank_mem          = FD_SCRATCH_ALLOC_APPEND( l, manifest_bank_align(),           manifest_bank_footprint() );
  void * manifest_spad_mem          = FD_SCRATCH_ALLOC_APPEND( l, manifest_spad_max_alloc_align(), fd_spad_footprint( manifest_spad_max_alloc_footprint() ) );
  void * shared_spad_mem            = FD_SCRATCH_ALLOC_APPEND( l, shared_spad_max_alloc_align(),   fd_spad_footprint( shared_spad_max_alloc_footprint() ) );
  void * alloc_mem                  = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(),                fd_alloc_footprint() );
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
    } else if( 0==strcmp( link->name, "shred_out" ) ) {
      ctx->in_kind[ i ] = SHRED_OUT;
    } else if( 0==strcmp( link->name, "gossip_out" ) ) {
      ctx->in_kind[ i ] = GOSSIP_OUT;
    } else if( 0==strcmp( link->name, "repair_scap" ) ) {
      ctx->in_kind[ i ] = REPAIR_SHREDCAP;
    } else if( 0==strcmp( link->name, "replay_out" ) ) {
      ctx->in_kind[ i ] = REPLAY_OUT;
    } else {
      FD_LOG_ERR(( "scap tile has unexpected input link %s", link->name ));
    }

    ctx->in_links[ i ].mem    = link_wksp->wksp;
    ctx->in_links[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in_links[ i ].mem, link->dcache );
    ctx->in_links[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in_links[ i ].mem, link->dcache, link->mtu );
  }

  ctx->repair_intake_listen_port = tile->shredcap.repair_intake_listen_port;
  ctx->write_buf_sz = tile->shredcap.write_buffer_size ? tile->shredcap.write_buffer_size : FD_SHREDCAP_DEFAULT_WRITER_BUF_SZ;

  /* Set up stake weights tile output */
  ctx->stake_out->idx       = fd_topo_find_tile_out_link( topo, tile, "replay_stake", 0 );
  if( FD_LIKELY( ctx->stake_out->idx!=ULONG_MAX ) ) {
    fd_topo_link_t * stake_weights_out = &topo->links[ tile->out_link_id[ ctx->stake_out->idx] ];
    ctx->stake_out->mcache  = stake_weights_out->mcache;
    ctx->stake_out->mem     = topo->workspaces[ topo->objs[ stake_weights_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->stake_out->sync    = fd_mcache_seq_laddr     ( ctx->stake_out->mcache );
    ctx->stake_out->depth   = fd_mcache_depth         ( ctx->stake_out->mcache );
    ctx->stake_out->seq     = fd_mcache_seq_query     ( ctx->stake_out->sync );
    ctx->stake_out->chunk0  = fd_dcache_compact_chunk0( ctx->stake_out->mem, stake_weights_out->dcache );
    ctx->stake_out->wmark   = fd_dcache_compact_wmark ( ctx->stake_out->mem, stake_weights_out->dcache, stake_weights_out->mtu );
    ctx->stake_out->chunk   = ctx->stake_out->chunk0;
  } else {
    FD_LOG_WARNING(( "no connection to stake_out link" ));
    memset( ctx->stake_out, 0, sizeof(out_link_t) );
  }

  ctx->snap_out->idx          = fd_topo_find_tile_out_link( topo, tile, "snapin_manif", 0 );
  if( FD_LIKELY( ctx->snap_out->idx!=ULONG_MAX ) ) {
    fd_topo_link_t * snap_out = &topo->links[tile->out_link_id[ctx->snap_out->idx]];
    ctx->snap_out->mem        = topo->workspaces[topo->objs[snap_out->dcache_obj_id].wksp_id].wksp;
    ctx->snap_out->chunk0     = fd_dcache_compact_chunk0( ctx->snap_out->mem, snap_out->dcache );
    ctx->snap_out->wmark      = fd_dcache_compact_wmark( ctx->snap_out->mem, snap_out->dcache, snap_out->mtu );
    ctx->snap_out->chunk      = ctx->snap_out->chunk0;
  } else {
    FD_LOG_WARNING(( "no connection to snap_out link" ));
    memset( ctx->snap_out, 0, sizeof(out_link_t) );
  }

  /* If the manifest is enabled (for processing), the stake_out link
     must be connected to the tile.  TODO in principle, it should be
     possible to gate the remaining of the manifest-related config. */
  ctx->enable_publish_stake_weights = tile->shredcap.enable_publish_stake_weights;
  FD_LOG_NOTICE(( "enable_publish_stake_weights ? %d", ctx->enable_publish_stake_weights ));

  /* manifest_wmark (root slot) */
  ulong root_slot_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "root_slot" );
  if( FD_LIKELY( root_slot_obj_id!=ULONG_MAX ) ) { /* for profiler */
    ctx->manifest_wmark = fd_fseq_join( fd_topo_obj_laddr( topo, root_slot_obj_id ) );
    if( FD_UNLIKELY( !ctx->manifest_wmark ) ) FD_LOG_ERR(( "no root_slot fseq" ));
    FD_TEST( ULONG_MAX==fd_fseq_query( ctx->manifest_wmark ) );
  }

  ctx->manifest_bank_mem    = manifest_bank_mem;

  // TODO: ???? Why is this calling fd_banks_new ... does not seem right
  ctx->banks = fd_banks_join( fd_banks_new( ctx->manifest_bank_mem, MANIFEST_MAX_TOTAL_BANKS, MANIFEST_MAX_FORK_WIDTH, 0 /* TODO? */, 8888UL /* TODO? */ ) );
  FD_TEST( ctx->banks );
  ctx->bank  = fd_banks_init_bank( ctx->banks );
  fd_bank_slot_set( ctx->bank, 0UL );
  FD_TEST( ctx->bank );

  strncpy( ctx->manifest_path, tile->shredcap.manifest_path, PATH_MAX );
  ctx->manifest_load_done = 0;
  ctx->manifest_spad_mem  = manifest_spad_mem;
  ctx->manifest_spad      = fd_spad_join( fd_spad_new( ctx->manifest_spad_mem, manifest_spad_max_alloc_footprint() ) );
  ctx->shared_spad_mem    = shared_spad_mem;
  ctx->shared_spad        = fd_spad_join( fd_spad_new( ctx->shared_spad_mem, shared_spad_max_alloc_footprint() ) );

  /* Allocate the write buffers */
  ctx->alloc = fd_alloc_join( fd_alloc_new( alloc_mem, FD_SHREDCAP_ALLOC_TAG ), fd_tile_idx() );
  if( FD_UNLIKELY( !ctx->alloc ) ) {
    FD_LOG_ERR( ( "fd_alloc_join failed" ) );
  }

  /* Setup the csv files to be in the expected state */

  init_file_handlers( ctx, &ctx->shreds_fd,      tile->shredcap.shreds_fd,      &ctx->shreds_buf,      &ctx->shred_ostream );
  init_file_handlers( ctx, &ctx->requests_fd,    tile->shredcap.requests_fd,    &ctx->requests_buf,    &ctx->repair_ostream );
  init_file_handlers( ctx, &ctx->fecs_fd,        tile->shredcap.fecs_fd,        &ctx->fecs_buf,        &ctx->fecs_ostream );
  init_file_handlers( ctx, &ctx->peers_fd,       tile->shredcap.peers_fd,       &ctx->peers_buf,       &ctx->peers_ostream );

  int err = fd_io_buffered_ostream_write( &ctx->shred_ostream,  "src_ip,src_port,timestamp,slot,ref_tick,fec_set_idx,idx,is_turbine,is_data,nonce\n", 81UL );
  err    |= fd_io_buffered_ostream_write( &ctx->repair_ostream, "dst_ip,dst_port,timestamp,nonce,slot,idx\n", 41UL );
  err    |= fd_io_buffered_ostream_write( &ctx->fecs_ostream,   "timestamp,slot,ref_tick,fec_set_idx,data_cnt\n", 45UL );
  err    |= fd_io_buffered_ostream_write( &ctx->peers_ostream,  "peer_ip4_addr,peer_port,pubkey,turbine\n", 48UL );

  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "failed to write header to any of the 4 csv files (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* Setup the binary files to be in the expected state. These files are
     not csv, so we don't need headers. */
  init_file_handlers( ctx, &ctx->slices_fd,      tile->shredcap.slices_fd,      &ctx->slices_buf,      &ctx->slices_ostream );
  init_file_handlers( ctx, &ctx->bank_hashes_fd, tile->shredcap.bank_hashes_fd, &ctx->bank_hashes_buf, &ctx->bank_hashes_ostream );
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (50UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_capture_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_capture_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT after_credit
#define STEM_CALLBACK_DURING_FRAG during_frag
#define STEM_CALLBACK_AFTER_FRAG  after_frag
#define STEM_CALLBACK_BEFORE_FRAG before_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_shredcap = {
  .name                     = "scap",
  .loose_footprint          = loose_footprint,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
