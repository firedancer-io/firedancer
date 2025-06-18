#include <linux/limits.h>
#define _GNU_SOURCE

#include "../../disco/topo/fd_topo.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include <linux/if_xdp.h>

#include "../../disco/tiles.h"

#include "../../groove/fd_groove.h"
#include "../../flamenco/runtime/fd_txn_account.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../flamenco/runtime/fd_system_ids.h"

#include "../../flamenco/snapshot/fd_snapshot.h"

#include "../../util/pod/fd_pod_format.h"

#include "fd_groove_messages.h"

#include "generated/fd_groove_tile_seccomp.h"

/* FIXME: adjust these constants */
#define FD_GROOVE_SPAD_ELE_MAX     (100 * 33554432UL) // ZSTD_WINDOW_SZ
#define FD_GROOVE_META_MAP_ELE_MAX (2 << 26)
#define FD_GROOVE_META_MAP_SEED    (0xDEADBEEF)
#define FD_GROOVE_VOLUME_MAX       (6000UL) /* FIXME: adjust this */

/* Funk eviction constants */
#define FD_GROOVE_FUNK_EVICT_BATCH_SZ       (500UL)
#define FD_GROOVE_FUNK_EVICT_HIGH_THRESHOLD (75)

struct fd_groove_tile_ctx {
  /* Replay in link */
  fd_wksp_t * in_mem;
  ulong       in_chunk0;
  ulong       in_wmark;

  /* Replay prefetch sequence number, for blocking prefetches */
  ulong replay_prefetch_fseq;

  /* Local join of Fseq.  R/W. */
  ulong * groove_replay_fseq;

  /* Local join of Funk.  R/W. */
  fd_funk_t           funk[1];
  fd_funk_txn_map_t * txn_map;

  /* Local join of Groove.  R/W. */
  fd_groove_t * groove;

  char   cold_store_dir[ PATH_MAX ];
  ulong  volume_count;

  uchar * volume_0_mmap_addr;

  /* Snapshot load inputs */
  int    snapshot_src_type;
  char   snapshot_path[ PATH_MAX ];
  char   snapshot_dir[ PATH_MAX ];
  char   snapshot_http_header[ PATH_MAX ];

  /* Prefetch inputs */
  fd_pubkey_t       cur_pubkey;
  ulong             cur_req_id;

  /* Spad memory for snapshot load */
  fd_spad_t * spad;
};
typedef struct fd_groove_tile_ctx fd_groove_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_groove_align();
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_groove_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_groove_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) {
    FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  }

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_groove_tile_ctx_t), sizeof(fd_groove_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_groove_align(), fd_groove_footprint( FD_GROOVE_META_MAP_ELE_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_spad_align(), fd_spad_footprint( FD_GROOVE_SPAD_ELE_MAX ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
privileged_init( fd_topo_t *     topo FD_PARAM_UNUSED,
                fd_topo_tile_t * tile FD_PARAM_UNUSED ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_groove_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_groove_tile_ctx_t), sizeof(fd_groove_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  strncpy( ctx->cold_store_dir, tile->groove.cold_store_dir, PATH_MAX );
}

static void
fd_groove_map_new_volume( fd_groove_tile_ctx_t * ctx ) {
  /* Open the file for the new volume */
  char volume_path[ PATH_MAX ];
  snprintf( volume_path, PATH_MAX, "%s/volume_%lu", ctx->cold_store_dir, ctx->volume_count );
  int volume_fd = open( volume_path, O_RDWR | O_CREAT, 0666 );
  if( FD_UNLIKELY( volume_fd == -1 ) ) {
    FD_LOG_ERR(("Failed to open cold store volume at path %s: %s (errno = %d)", volume_path, strerror(errno), errno));
  }

  /* Truncate the volume to the correct size */
  if ( FD_UNLIKELY( ftruncate(volume_fd, FD_GROOVE_VOLUME_FOOTPRINT) == -1 ) ) {
    FD_LOG_ERR(("Failed to truncate cold store volume at path %s: %s (errno = %d)", volume_path, strerror(errno), errno));
  }

  /* Memory-map the new volume */
  uchar * new_volume_addr = (uchar *)ctx->volume_0_mmap_addr + ctx->volume_count * FD_GROOVE_VOLUME_FOOTPRINT;

  /* Unmap the previous page */
  if ( FD_UNLIKELY( munmap( (void *)new_volume_addr, FD_GROOVE_VOLUME_FOOTPRINT ) == -1 ) ) {
    FD_LOG_ERR(("Failed to unmap previous page at address %p: %s (errno = %d)", (void *)new_volume_addr, strerror(errno), errno));
  }

  uchar * new_volume = mmap(
    new_volume_addr,
    FD_GROOVE_VOLUME_FOOTPRINT,
    PROT_READ | PROT_WRITE,
    MAP_SHARED | MAP_FIXED_NOREPLACE,
    volume_fd,
    0 );
  if( FD_UNLIKELY( new_volume == MAP_FAILED ) ) {
    FD_LOG_ERR(("Failed to memory map volume %lu at path %s: %s (errno = %d)",
      ctx->volume_count, volume_path, strerror(errno), errno));
  }
  FD_LOG_WARNING(( "mapped volume %lu at path %s at address %p", ctx->volume_count, volume_path, (void *)new_volume_addr ));

  /* Close the file descriptor */
  if( FD_UNLIKELY( close( volume_fd ) == -1 ) ) {
    FD_LOG_ERR(("Failed to close volume %lu fd at path %s: %s (errno = %d)",
      ctx->volume_count, volume_path, strerror(errno), errno));
  }

  /* Add the new volume to Groove */
  if( FD_UNLIKELY( fd_groove_data_volume_add(
    ctx->groove->data,
    new_volume,
    FD_GROOVE_VOLUME_FOOTPRINT,
    NULL,
    0UL ) ) ) {
    FD_LOG_ERR(("Failed to add volume %lu to Groove", ctx->volume_count));
  }

  /* Increment the volume count */
  ctx->volume_count++;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_groove_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_groove_tile_ctx_t), sizeof(fd_groove_tile_ctx_t) );
  uchar * groove_shmem       = FD_SCRATCH_ALLOC_APPEND( l, fd_groove_align(), fd_groove_footprint( FD_GROOVE_META_MAP_ELE_MAX ) );
  uchar * spad_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_spad_align(), fd_spad_footprint( FD_GROOVE_SPAD_ELE_MAX ) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  /* Set up the spad */
  ctx->spad = fd_spad_join( fd_spad_new( spad_mem, FD_GROOVE_SPAD_ELE_MAX ) );
  if( FD_UNLIKELY( !ctx->spad ) ) {
    FD_LOG_ERR(( "Failed to create spad" ));
  }

  /* Set up the in-link */
  fd_topo_link_t * in_link = &topo->links[tile->in_link_id[0]];
  if( FD_UNLIKELY( !in_link) ) {
    FD_LOG_ERR(( "Invalid in-link" ));
  }
  ctx->in_mem = topo->workspaces[topo->objs[in_link->dcache_obj_id].wksp_id].wksp;
  ctx->in_chunk0 = fd_dcache_compact_chunk0( ctx->in_mem, in_link->dcache );
  ctx->in_wmark = fd_dcache_compact_wmark( ctx->in_mem,
                                           in_link->dcache,
                                           in_link->mtu );

  /* Join Funk */
  if( FD_UNLIKELY( !fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->groove.funk_obj_id ) ) ) ) {
    FD_LOG_ERR(( "Failed to join database cache" ));
  }

  /* Reserve the memory region for the Groove volumes */
  void * initial_mmap_addr = mmap( NULL,
    /* +1 for alignment, we will not use the first unaligned bytes */
    FD_GROOVE_VOLUME_FOOTPRINT * (FD_GROOVE_VOLUME_MAX + 1),
    PROT_NONE,
    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
    -1,
    0 );
  if( FD_UNLIKELY( initial_mmap_addr == MAP_FAILED ) ) {
    FD_LOG_ERR(("Failed to reserve memory region for volumes: %s (errno = %d)", strerror(errno), errno));
  }

  /* Compute the aligned address for volume0 */
  ctx->volume_0_mmap_addr = (uchar *)fd_ulong_align_up( (ulong)initial_mmap_addr, FD_GROOVE_VOLUME_FOOTPRINT );

  /* Initialize Groove */
  void * initialized_groove = fd_groove_new(
      groove_shmem, FD_GROOVE_META_MAP_ELE_MAX, FD_GROOVE_META_MAP_SEED );
  if( FD_UNLIKELY( !initialized_groove ) ) {
    FD_LOG_ERR(("Failed to initialize groove"));
  }

  /* Join Groove */
  ctx->groove = fd_groove_join(
      groove_shmem,
      FD_GROOVE_META_MAP_ELE_MAX,
      ctx->volume_0_mmap_addr,
      FD_GROOVE_VOLUME_MAX,
      0UL );
  ctx->volume_count = 0UL;

  /* Add the first volume to Groove */
  fd_groove_map_new_volume( ctx );

  /* Initialize the current pubkey */
  fd_memset( &ctx->cur_pubkey, 0, sizeof(fd_pubkey_t) );

  /* Initialize the FSeq */
  ulong groove_replay_fseq_id = fd_pod_query_ulong( topo->props, "groove_fseq", ULONG_MAX );
  ctx->groove_replay_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, groove_replay_fseq_id ) );
  if( FD_UNLIKELY( !ctx->groove_replay_fseq ) ) {
    FD_LOG_CRIT(( "groove tile %lu fseq setup failed", tile->kind_id ));
  }
  fd_fseq_update( ctx->groove_replay_fseq, 0UL );

  /* Initialize the replay prefetch sequence number */
  ctx->replay_prefetch_fseq = 0UL;
}

/* Determines if a Funk record is evictable */
int
is_evictable_funk_record( fd_pubkey_t const * pubkey,
                          fd_pubkey_t const * owner ) {
  /* Don't evict the record if it is a vote account */
  if( FD_UNLIKELY( memcmp( owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }

  /* Don't evict the record if it is a sysvar account */
  if( FD_UNLIKELY( memcmp( owner, fd_sysvar_owner_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }

  /* Don't evict the record if it is a feature account */
  if( FD_UNLIKELY( memcmp( owner, fd_solana_feature_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }

  /* Don't evict the record if it is a system account */
  if( FD_UNLIKELY( memcmp( pubkey, fd_sysvar_owner_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }

  /* Don't evict the record if it is a native loader account */
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_native_loader_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }

  /* Don't evict the record if it is a feature program account */
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_feature_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_config_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_stake_program_config_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_system_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_bpf_loader_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_ed25519_sig_verify_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_keccak_secp_256k_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_secp256r1_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_compute_budget_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_spl_native_mint_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_spl_token_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_zk_elgamal_proof_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( pubkey, fd_solana_zk_token_proof_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }

  return 1;
}

struct fd_snapshot_new_account_groove_cb_ctx {
  fd_groove_tile_ctx_t * tile_ctx;
};
typedef struct fd_snapshot_new_account_groove_cb_ctx fd_snapshot_new_account_groove_cb_ctx_t;

static void
evict_accounts_from_funk_root( fd_groove_tile_ctx_t * ctx, ulong batch_sz ) {
  fd_funk_t * funk = ctx->funk;
  uchar *     lock = &funk->shmem->lock;

  while( FD_ATOMIC_CAS( lock, 0, 1 ) ) FD_SPIN_PAUSE();

  ulong next_rec_idx = funk->shmem->rec_head_idx;
  ulong evicted      = 0UL;

  /* Iterate over the Funk root transaction, evicting batch_sz number of records */
  while( ( evicted < batch_sz ) && ( next_rec_idx != FD_FUNK_REC_IDX_NULL ) ) {
    fd_funk_rec_t * rec = &funk->rec_pool->ele[ next_rec_idx ];
    next_rec_idx = rec->next_idx;

    /* Evict tombstone records without inserting them into Groove */
    if( FD_UNLIKELY( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) {
      fd_funk_rec_hard_remove( ctx->funk, NULL, rec->pair.key );
      evicted++;
      continue;
    }

    /* Check to see if the record is evictable */
    if( FD_LIKELY( fd_funk_key_is_acc( rec->pair.key ) ) ) {
        fd_account_meta_t const * meta = fd_funk_val_const( rec, fd_funk_wksp(ctx->funk ) );
      if( FD_UNLIKELY( meta == NULL || meta->magic != FD_ACCOUNT_META_MAGIC ) ) {
        continue;
      }
      fd_pubkey_t const * pubkey = (fd_pubkey_t const *)rec->pair.key->uc;
      fd_pubkey_t const * owner  = (fd_pubkey_t const *)meta->info.owner;

      /* If we find an evictable account, evict it */
      if( FD_LIKELY( is_evictable_funk_record( pubkey, owner ) ) ) {
        /* Upsert the account into Groove */
        fd_groove_upsert_account(
          ctx->groove,
          (fd_pubkey_t *)fd_type_pun_const( rec->pair.key ),
          fd_funk_val( rec, fd_funk_wksp( ctx->funk ) ),
          rec->val_sz );

        /* Erase the account from the Funk root transaction */
        fd_funk_rec_hard_remove( ctx->funk, NULL, rec->pair.key );
        evicted++;
      }
    }
  }

  FD_VOLATILE( *lock ) = 0;
}

static void
during_housekeeping( fd_groove_tile_ctx_t * ctx ) {
  /* Check to see if the Funk record count is greater than the eviction high threshold */
  ulong funk_rec_max            = fd_funk_rec_max( ctx->funk );
  ulong eviction_high_threshold = ( funk_rec_max * FD_GROOVE_FUNK_EVICT_HIGH_THRESHOLD ) / 100;
  ulong funk_root_rec_cnt        = fd_funk_root_rec_cnt( ctx->funk );

  // FD_LOG_WARNING(( "funk_rec_max: %lu, eviction_high_threshold: %lu, funk_root_rec_cnt: %lu", funk_rec_max, eviction_high_threshold, funk_root_rec_cnt ));

  /* If so, evict a batch of accounts from the root Funk txn */
  if( FD_LIKELY( funk_root_rec_cnt > eviction_high_threshold ) ) {
    evict_accounts_from_funk_root( ctx, FD_GROOVE_FUNK_EVICT_BATCH_SZ );
  }
}

uchar *
fd_snapshot_new_account_groove_cb( void *   _ctx,
                                   ulong    accv_slot,
                                   fd_solana_account_hdr_t const * hdr ) {
  fd_snapshot_new_account_groove_cb_ctx_t * ctx = fd_type_pun( _ctx );
  fd_groove_t * groove                          = ctx->tile_ctx->groove;
  fd_pubkey_t const * pubkey                    = fd_type_pun_const( hdr->meta.pubkey );

  /* Insert the account into Groove */
  int err = 0;
  uchar * groove_region = fd_groove_upsert_account_from_snapshot( groove,
                                                                  pubkey,
                                                                  accv_slot,
                                                                  hdr,
                                                                  &err );

  /* If we ran out of space, add a new volume to Groove and try again */
  if( FD_UNLIKELY( err && err == FD_GROOVE_ERR_FULL ) ) {
    fd_groove_map_new_volume( ctx->tile_ctx );
    int err = 0;
    groove_region = fd_groove_upsert_account_from_snapshot( groove,
                                                            pubkey,
                                                            accv_slot,
                                                            hdr,
                                                            &err );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "fd_groove_upsert_account_from_snapshot failed: %d", err ));
    }
  }
  if( FD_LIKELY( groove_region ) ) {
    groove_region += sizeof(fd_account_meta_t);
  }

  return groove_region;
}

struct fd_snapshot_acc_finish_read_groove_cb_ctx {
  fd_groove_tile_ctx_t * tile_ctx;
};
typedef struct fd_snapshot_acc_finish_read_groove_cb_ctx fd_snapshot_acc_finish_read_groove_cb_ctx_t;

void
fd_snapshot_acc_finish_read_groove_cb( void *              _ctx,
                                       fd_pubkey_t const * pubkey,
                                       ulong               accv_slot,
                                       uchar *             acc_data ) {
  fd_snapshot_acc_finish_read_groove_cb_ctx_t * ctx = fd_type_pun( _ctx );

  fd_account_meta_t * meta = fd_type_pun( acc_data - sizeof(fd_account_meta_t) );
  if( FD_UNLIKELY( meta->magic != FD_ACCOUNT_META_MAGIC ) ) {
    FD_LOG_ERR(( "invalid account meta magic: %u", meta->magic ));
    return;
  };

  /* If the account is evictable, we do not need to also insert it into Funk */
  if( FD_LIKELY( is_evictable_funk_record( pubkey, fd_type_pun_const( meta->info.owner ) ) == 1 ) ) {
    return;
  }

  /* Insert the account into Funk */
  fd_funk_t * funk = ctx->tile_ctx->funk;

  fd_account_meta_t const * rec_meta = fd_funk_get_acc_meta_readonly(
      funk, NULL, pubkey, NULL, NULL, NULL );
  if( FD_UNLIKELY( rec_meta && rec_meta->slot > accv_slot ) ) {
    return;
  }

  /* Do nothing if we have seen a newer version of this account */
  if( FD_UNLIKELY( rec_meta && rec_meta->slot > accv_slot ) ) {
    return;
  }

  /* Write account metadata */
  FD_TXN_ACCOUNT_DECL( acct );
  int write_result = fd_txn_account_init_from_funk_mutable(
    acct, pubkey, funk, NULL, /* do_create */ 1, meta->dlen );
  if( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_ERR(( "fd_txn_account_init_from_funk_mutable failed (%d)", write_result ));
  }
  acct->vt->set_data_len( acct, meta->dlen );
  acct->vt->set_slot( acct, accv_slot );
  acct->vt->set_hash( acct, fd_type_pun( meta->hash ) );
  acct->vt->set_info( acct, &meta->info );
  fd_memcpy( acct->vt->get_data_mut( acct ), acc_data, meta->dlen );

  fd_txn_account_mutable_fini( acct, funk, NULL );
}

static ulong
load_full_snapshot( fd_groove_tile_ctx_t * ctx,
                    char const *           snapshot_path,
                    char const *           snapshot_dir,
                    int                    snapshot_src_type,
                    char const *           snapshot_http_header ) {
  FD_LOG_WARNING(( "loading full snapshot into Groove" ));

  FD_LOG_WARNING(( "snapshot_http_header: %s", snapshot_http_header ));

  uchar mem[fd_snapshot_load_ctx_footprint()];
  fd_snapshot_load_ctx_t * snapshot_load_ctx = fd_snapshot_load_new( mem,
                                                                     snapshot_path,
                                                                     snapshot_src_type,
                                                                     snapshot_dir,
                                                                     0,
                                                                     0,
                                                                     FD_SNAPSHOT_TYPE_FULL,
                                                                     snapshot_http_header );

  fd_snapshot_load_init( snapshot_load_ctx );

  fd_snapshot_new_account_groove_cb_ctx_t new_account_groove_cb_ctx = {
    .tile_ctx = ctx
  };
  fd_snapshot_acc_finish_read_groove_cb_ctx_t acc_finish_read_groove_cb_ctx = {
    .tile_ctx = ctx
  };

  FD_LOG_WARNING(( "loading manifest and status cache into Groove" ));

  fd_snapshot_load_manifest_and_status_cache(
    snapshot_load_ctx,
    ctx->spad,
    NULL,
    0UL,
    FD_SNAPSHOT_RESTORE_NONE,
    NULL,
    &new_account_groove_cb_ctx,
    fd_snapshot_new_account_groove_cb,
    &acc_finish_read_groove_cb_ctx,
    fd_snapshot_acc_finish_read_groove_cb );

  FD_LOG_WARNING(( "loading full snapshot accounts into Groove" ));

  fd_snapshot_load_accounts( snapshot_load_ctx );

  FD_LOG_WARNING(( "loaded full snapshot accounts into Groove" ));

  return fd_snapshot_get_slot( snapshot_load_ctx );
}

/* Writes the account to the cold store. Assumes that the account is in the root Funk transaction.  */
static void
write_account_to_cold_store( fd_groove_tile_ctx_t *    ctx,
                             fd_pubkey_t const *       pubkey ) {
  fd_funk_t * funk = ctx->funk;
  fd_groove_t * groove = ctx->groove;

  /* Create the groove key */
  fd_groove_key_t groove_key[1];
  groove_key_init( pubkey, groove_key );

  /* Get the Funk transaction for the root transaction */
  fd_funk_txn_start_read( funk );
  fd_funk_txn_t * funk_txn = fd_funk_txn_query( fd_funk_root( funk ), ctx->txn_map );
  fd_funk_txn_end_read( funk );

  /* Look up the record in Funk */
  int err                      = FD_ACC_MGR_SUCCESS;
  fd_funk_rec_t * rec          = NULL;
  fd_funk_get_acc_meta_mutable(
      funk,
      funk_txn,
      pubkey,
      /* do_create */ 0,
      0,
      &rec,
      NULL,
      &err );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_ERR(( "unable to get account metadata in Funk" ));
    return;
  }

  /* Write the account to the cold store */
  fd_groove_upsert_account(
    groove,
    pubkey,
    fd_funk_val( rec, fd_funk_wksp( funk ) ),
    rec->val_sz );
}

/* Pulls the account from the cold store, inserting into the root Funk transaction. Assumes that the account is not in Funk. */
static void
pull_account_from_cold_store( fd_groove_tile_ctx_t *    ctx,
                              fd_pubkey_t const *       pubkey ) {

  FD_LOG_WARNING(( "pulling account from cold store %s", FD_BASE58_ENC_32_ALLOCA( pubkey->key ) ));

  fd_funk_t *   funk   = ctx->funk;
  fd_groove_t * groove = ctx->groove;

  /* Create the groove key */
  fd_groove_key_t groove_key[1];
  groove_key_init( pubkey, groove_key );

  /* Look up the account in the cold store index */
  fd_groove_meta_map_query_t query[1];
  int             err           = fd_groove_meta_map_query_try( groove->meta_map, groove_key, NULL, query, FD_MAP_FLAG_BLOCKING );
  fd_groove_meta_t const * meta = fd_groove_meta_map_query_ele_const( query );
  if( FD_UNLIKELY( err==FD_MAP_ERR_KEY ) ) {
    FD_LOG_ERR(( "unable to find account in cold store index: %s", FD_BASE58_ENC_32_ALLOCA( pubkey->key ) ));
    return;
  }
  ulong val_size = fd_groove_meta_bits_val_sz( meta->bits );
  uchar * data   = (uchar *)fd_type_pun( fd_groove_data_volume0( groove->data ) ) + meta->val_off;
  fd_groove_meta_map_cancel( query );

  /* Create a Funk record for the account, if one does not already exist */
  fd_funk_txn_start_read( funk );
  fd_funk_txn_t * funk_txn = fd_funk_txn_query( fd_funk_root( funk ), ctx->txn_map );
  fd_funk_txn_end_read( funk );
  FD_TXN_ACCOUNT_DECL( acc );
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_mutable(
      acc,
      pubkey,
      funk,
      funk_txn,
      /* do_create */ 1,
      val_size ) ) ) {
    FD_LOG_ERR(( "unable to create account in Funk" ));
    return;
  }

  /* Copy the account data into the Funk record */
  acc->vt->set_data( acc, data, val_size );

  /* Publish the Funk record */
  fd_txn_account_mutable_fini( acc, funk, funk_txn );
}

static void
during_frag( fd_groove_tile_ctx_t * ctx,
             ulong                  in_idx FD_PARAM_UNUSED,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig FD_PARAM_UNUSED,
             ulong                  chunk,
             ulong                  sz,
             ulong                  ctl FD_PARAM_UNUSED ) {

  FD_LOG_WARNING(( "during_frag" ));

  if( FD_UNLIKELY( chunk < ctx->in_chunk0 || chunk > ctx->in_wmark ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]",
                chunk,
                sz,
                ctx->in_chunk0,
                ctx->in_wmark ));
  }

  /* Load snapshot message */
  if( FD_UNLIKELY( sig==FD_GROOVE_TILE_LOAD_SNAPSHOT_SIGNATURE ) ) {
    if( FD_UNLIKELY( sz != sizeof(fd_msg_groove_replay_load_snapshot_req_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_chunk0, ctx->in_wmark ));
    }

    fd_msg_groove_replay_load_snapshot_req_t * msg = ((fd_msg_groove_replay_load_snapshot_req_t *)fd_chunk_to_laddr( ctx->in_mem, chunk ));

    ctx->snapshot_src_type = msg->snapshot_src_type;
    fd_memcpy( &ctx->snapshot_path, &msg->snapshot_path, PATH_MAX );
    fd_memcpy( &ctx->snapshot_dir, &msg->snapshot_dir, PATH_MAX );
    fd_memcpy( &ctx->snapshot_http_header, &msg->snapshot_http_header, PATH_MAX );
    ctx->cur_req_id = msg->req_id;

    return;
  }

  /* Prefetch account message */
  if( FD_LIKELY( sig==FD_GROOVE_TILE_PREFETCH_SIGNATURE ) ) {
    if( FD_UNLIKELY( sz != sizeof(fd_msg_groove_prefetch_account_req_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_chunk0, ctx->in_wmark ));
    }

    fd_msg_groove_prefetch_account_req_t * msg = ((fd_msg_groove_prefetch_account_req_t *)fd_chunk_to_laddr( ctx->in_mem, chunk ));
    fd_memcpy( &ctx->cur_pubkey, &msg->pubkey, sizeof(fd_pubkey_t) );
    ctx->cur_req_id = msg->req_id;
    FD_LOG_WARNING(("Prefetch req %lu", ctx->cur_req_id));

    return;
  }

  /* Write account message */
  if( FD_LIKELY( sig==FD_GROOVE_TILE_WRITE_ACCOUNT_SIGNATURE ) ) {
    if( FD_UNLIKELY( sz != sizeof(fd_msg_groove_write_account_req_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_chunk0, ctx->in_wmark ));
    }

    fd_msg_groove_write_account_req_t * msg = ((fd_msg_groove_write_account_req_t *)fd_chunk_to_laddr( ctx->in_mem, chunk ));
    fd_memcpy( &ctx->cur_pubkey, &msg->pubkey, sizeof(fd_pubkey_t) );
    ctx->cur_req_id = msg->req_id;

    return;
  }

  FD_LOG_ERR(( "unknown signature: %lu", sig ));
}

static void
after_frag( fd_groove_tile_ctx_t * ctx,
            ulong                  in_idx FD_PARAM_UNUSED,
            ulong                  seq    FD_PARAM_UNUSED,
            ulong                  sig,
            ulong                  sz     FD_PARAM_UNUSED,
            ulong                  tsorig FD_PARAM_UNUSED,
            ulong                  tspub  FD_PARAM_UNUSED,
            fd_stem_context_t *    stem   FD_PARAM_UNUSED ) {

  /* Pull out the pubkey from the message */
  if( FD_LIKELY( sig==FD_GROOVE_TILE_PREFETCH_SIGNATURE ) ) {
    pull_account_from_cold_store( ctx, &ctx->cur_pubkey );
    fd_fseq_update( ctx->groove_replay_fseq, ctx->cur_req_id );
  } else if( FD_LIKELY( sig==FD_GROOVE_TILE_WRITE_ACCOUNT_SIGNATURE ) ) {
    write_account_to_cold_store( ctx, &ctx->cur_pubkey );
    fd_fseq_update( ctx->groove_replay_fseq, ctx->cur_req_id );
  } else if( FD_UNLIKELY( sig==FD_GROOVE_TILE_LOAD_SNAPSHOT_SIGNATURE ) ) {
    ulong base_slot = load_full_snapshot( ctx,
                                         ctx->snapshot_path,
                                         ctx->snapshot_dir,
                                         ctx->snapshot_src_type,
                                         ctx->snapshot_http_header );
    fd_fseq_update( ctx->groove_replay_fseq, base_slot );
  } else {
    FD_LOG_ERR(( "unknown signature: %lu", sig ));
  }
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_groove_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_groove_tile_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_groove = {
  .name                     = "groove",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .privileged_init          = privileged_init,
  .run                      = stem_run,
};
