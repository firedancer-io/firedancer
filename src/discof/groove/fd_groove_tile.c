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

#include "../../funk/fd_funk_filemap.h"
#include "../../groove/fd_groove.h"
#include "../../flamenco/runtime/fd_txn_account.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../flamenco/runtime/fd_system_ids.h"

#include "../../flamenco/snapshot/fd_snapshot.h"

#include "../../disco/topo/fd_pod_format.h"

#include "fd_groove_messages.h"

#include "generated/fd_groove_tile_seccomp.h"

/* FIXME: adjust these constants */
#define FD_GROOVE_META_MAP_ELE_MAX (1UL << 10)
#define FD_GROOVE_META_MAP_SEED    (0xDEADBEEF)
#define FD_GROOVE_VOLUME_MAX       (6000UL)

struct fd_groove_tile_ctx {
  /* Replay in link */
  fd_wksp_t * in_mem;
  ulong       in_chunk0;
  ulong       in_wmark;

  /* Local join of Fseq.  R/W. */
  ulong * groove_replay_fseq;

  /* Local join of Funk.  R/W. */
  fd_funk_t *         funk;
  fd_funk_txn_map_t * txn_map;

  /* Local join of Groove.  R/W. */
  fd_groove_t * groove;

  char   cold_store_dir[ PATH_MAX ];

  int    volume_0_fd;
  void * volume_0_shmem;

  /* Snapshot load inputs */
  int    snapshot_src_type;
  char   snapshot_path[ PATH_MAX ];
  char   snapshot_dir[ PATH_MAX ];

  /* Prefetch inputs */
  fd_pubkey_t       cur_pubkey;
  fd_funk_txn_xid_t cur_funk_txn_xid;
};
typedef struct fd_groove_tile_ctx fd_groove_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
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

  /* Open the first volume */
  char volume_0_path[ PATH_MAX ];
  snprintf( volume_0_path, PATH_MAX, "%s/volume_0", ctx->cold_store_dir );
  ctx->volume_0_fd = open( volume_0_path, O_RDWR | O_CREAT, 0666 );
  if( FD_UNLIKELY( ctx->volume_0_fd == -1 ) ) {
    FD_LOG_ERR(("Failed to open cold_store_volume_0_fd at path %s: %s (errno = %d)", volume_0_path, strerror(errno), errno));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  FD_LOG_WARNING(( "groove unprivileged_init funk_file=%s, cold_store_dir=%s", tile->groove.funk_file, tile->groove.cold_store_dir ));

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_groove_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_groove_tile_ctx_t), sizeof(fd_groove_tile_ctx_t) );
  uchar * groove_shmem       = FD_SCRATCH_ALLOC_APPEND( l, fd_groove_align(), fd_groove_footprint( FD_GROOVE_META_MAP_ELE_MAX ) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

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

  /* Memory map the first volume */
  ctx->volume_0_shmem = mmap( NULL, 1UL * FD_SHMEM_GIGANTIC_PAGE_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, ctx->volume_0_fd, 0 );
  if( FD_UNLIKELY( ctx->volume_0_shmem == MAP_FAILED ) ) {
    FD_LOG_ERR(("Failed to memory map volume_0_fd: %s (errno = %d)", strerror(errno), errno));
  }

  /* Initialize Groove */
  void * initialized_groove = fd_groove_new(
      groove_shmem, FD_GROOVE_META_MAP_ELE_MAX, FD_GROOVE_META_MAP_SEED );
  if( FD_UNLIKELY( !initialized_groove ) ) {
    FD_LOG_ERR(("Failed to initialize groove"));
  }

  /* Join Funk */
  fd_funk_txn_start_write( NULL );
  ctx->funk = fd_funk_open_file( ctx->funk,
                                 tile->groove.funk_file,
                                 1UL,
                                 0UL,
                                 0UL,
                                 0UL,
                                 0UL,
                                 FD_FUNK_READ_WRITE,
                                 NULL );
  fd_funk_txn_end_write( NULL );
  ctx->txn_map = fd_funk_txn_map( ctx->funk );

  /* Join Groove */
  ctx->groove = fd_groove_join(
      groove_shmem,
      FD_GROOVE_META_MAP_ELE_MAX,
      ctx->volume_0_shmem,
      FD_GROOVE_VOLUME_MAX,
      0UL );

  /* Initialize the current pubkey and funk txn xid */
  fd_memset( &ctx->cur_pubkey, 0, sizeof(fd_pubkey_t) );
  fd_memset( &ctx->cur_funk_txn_xid, 0, sizeof(fd_funk_txn_xid_t) );

  /* Initialize the FSeq */
  ulong groove_replay_fseq_id = fd_pod_query_ulong( topo->props, "groove_fseq", ULONG_MAX );
  ctx->groove_replay_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, groove_replay_fseq_id ) );
  if( FD_UNLIKELY( !ctx->groove_replay_fseq ) ) {
    FD_LOG_CRIT(( "groove tile %lu fseq setup failed", tile->kind_id ));
  }
  fd_fseq_update( ctx->groove_replay_fseq, FD_MSG_GROOVE_REPLAY_FSEQ_INIT );
}

struct fd_snapshot_new_account_groove_cb_ctx {
  fd_groove_t * groove;
};
typedef struct fd_snapshot_new_account_groove_cb_ctx fd_snapshot_new_account_groove_cb_ctx_t;

uchar *
fd_snapshot_new_account_groove_cb( void *   _ctx,
                                   ulong    accv_slot,
                                   fd_solana_account_hdr_t const * hdr ) {
  fd_snapshot_new_account_groove_cb_ctx_t * ctx = fd_type_pun( _ctx );
  fd_groove_t * groove                          = ctx->groove;
  fd_pubkey_t const * pubkey                    = fd_type_pun_const( hdr->meta.pubkey );

  /* Insert the account into Groove */
  uchar * groove_region = fd_groove_upsert_account_from_snapshot( groove,
                                                                  pubkey,
                                                                  accv_slot,
                                                                  hdr );
  return groove_region + sizeof(fd_account_meta_t);
}

static void
load_full_snapshot( fd_groove_tile_ctx_t * ctx,
                    char const *           snapshot_path,
                    char const *           snapshot_dir,
                    int                    snapshot_src_type ) {
  uchar mem[fd_snapshot_load_ctx_footprint()];
  fd_snapshot_load_ctx_t * snapshot_load_ctx = fd_snapshot_load_new( mem,
                                                                     snapshot_path,
                                                                     snapshot_src_type,
                                                                     snapshot_dir,
                                                                     0,
                                                                     0,
                                                                     FD_SNAPSHOT_TYPE_FULL );

  fd_snapshot_load_init( snapshot_load_ctx );

  fd_spad_t * spad = fd_spad_new( NULL, 45 ); /* FIXME */
  ulong base_slot   = 0UL; /* FIXME */

  fd_snapshot_load_manifest_and_status_cache(
    snapshot_load_ctx,
    spad,
    NULL,
    base_slot,
    FD_SNAPSHOT_RESTORE_NONE );

  fd_snapshot_load_accounts( snapshot_load_ctx );

  /* Update the FSeq */
  fd_fseq_update( ctx->groove_replay_fseq, FD_MSG_GROOVE_REPLAY_FSEQ_LOAD_SNAPSHOT_DONE );
}

/* Determines if a Funk record is evictable */
int
is_evictable_funk_record( fd_funk_rec_t const * rec, fd_groove_tile_ctx_t * ctx ) {
  /* Don't evict the record if it is not an account */
  if( FD_UNLIKELY( !fd_funk_key_is_acc( rec->pair.key ) ) ) {
    return 0;
  }

  fd_account_meta_t const * meta = fd_funk_val_const( rec, fd_funk_wksp(ctx->funk ) );
  if( FD_UNLIKELY( meta == NULL || meta->magic != FD_ACCOUNT_META_MAGIC ) ) {
    return 0;
  }

  /* Don't evict the record if it is a vote account */
  if( FD_UNLIKELY( memcmp( meta->info.owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }

  /* Don't evict the record if it is a sysvar account */
  if( FD_UNLIKELY( memcmp( meta->info.owner, fd_sysvar_owner_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }

  /* Don't evict the record if it is a feature account */
  if( FD_UNLIKELY( memcmp( meta->info.owner, fd_solana_feature_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }

  /* Don't evict the record if it is a system account */
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_sysvar_owner_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_native_loader_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_feature_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_config_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_stake_program_config_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_system_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_bpf_loader_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_ed25519_sig_verify_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_keccak_secp_256k_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_secp256r1_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_compute_budget_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_spl_native_mint_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_spl_token_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_zk_elgamal_proof_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( memcmp( rec->pair.key->uc, fd_solana_zk_token_proof_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
    return 0;
  }

  return 1;
}

/* Evicts the least recently used account from Funk into Groove */
static void
evict_least_recently_used_account( fd_groove_tile_ctx_t * ctx ) {
  /* Find the LRU account in Funk */
  fd_funk_rec_t * rec = NULL;
  for ( ; ; ) {
    rec = fd_funk_rec_lru_pop_head( ctx->funk );
    if( FD_UNLIKELY( !rec ) ) {
      return;
    }

    /* Erase tombstone records without inserting them into Groove */
    if( FD_UNLIKELY( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) {
      fd_funk_rec_hard_remove( ctx->funk, NULL, rec->pair.key );
      continue;
    }

    if( is_evictable_funk_record( rec, ctx ) ) {
      break;
    }
  }

  if( FD_LIKELY( rec ) ) {
    /* Insert the account into Groove */
    uchar * val = fd_funk_val( rec, fd_funk_wksp( ctx->funk ) );
    fd_groove_upsert_account( ctx->groove, (fd_pubkey_t *)fd_type_pun_const( rec->pair.key ), val, rec->val_sz );

    /* Erase the account from the root Funk transaction */
    fd_funk_rec_hard_remove( ctx->funk, NULL, rec->pair.key );
  }
}

/* Pulls the account from the cold store index. Assumes that the account is not in Funk. */
static void
pull_account_from_cold_store( fd_pubkey_t const *       pubkey,
                              fd_funk_txn_xid_t const * funk_txn_xid,
                              fd_groove_tile_ctx_t *    ctx ) {
  fd_funk_t *   funk   = ctx->funk;
  fd_groove_t * groove = ctx->groove;

  /* Evict the least recently used account from Funk into Groove

     FIXME: do not call this function if the account has not been modified. */
  evict_least_recently_used_account( ctx );

  /* Create the groove key */
  fd_groove_key_t groove_key[1];
  groove_key_init( pubkey, groove_key );

  /* Look up the account in the cold store index */
  fd_groove_meta_map_query_t query[1];
  int             err           = fd_groove_meta_map_query_try( groove->meta_map, groove_key, NULL, query, FD_MAP_FLAG_BLOCKING );
  fd_groove_meta_t const * meta = fd_groove_meta_map_query_ele_const( query );
  if( FD_UNLIKELY( err==FD_MAP_ERR_KEY ) ) {
    FD_LOG_ERR(( "unable to find account in cold store index" ));
    return;
  }
  ulong val_size = fd_groove_meta_bits_val_sz( meta->bits );
  uchar * data   = (uchar *)fd_type_pun( fd_groove_data_volume0( groove->data ) ) + meta->val_off;
  fd_groove_meta_map_cancel( query );

  /* Create a Funk record for the account, if one does not already exist */
  fd_funk_txn_start_read( funk );
  fd_funk_txn_t * funk_txn = fd_funk_txn_query( funk_txn_xid, ctx->txn_map );
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

/* Two different types of messages:
   - Non-blocking prefetch, signature 0, contents: [pubkey,funk_txn]
   - Blocking prefetch,     signature 1, contents: [pubkey,funk_txn]
*/
static void
during_frag( fd_groove_tile_ctx_t * ctx,
             ulong                  in_idx FD_PARAM_UNUSED,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig FD_PARAM_UNUSED,
             ulong                  chunk,
             ulong                  sz,
             ulong                  ctl FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( in_idx != 0UL ) ) {
    FD_LOG_ERR(( "invalid in_idx: %lu", in_idx ));
  }

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

    fd_msg_groove_replay_load_snapshot_req_t * msg = ((fd_msg_groove_replay_load_snapshot_req_t *)fd_chunk_to_laddr( ctx->in_mem, ctx->in_chunk0 ));

    ctx->snapshot_src_type = msg->snapshot_src_type;
    fd_memcpy( &ctx->snapshot_path, &msg->snapshot_path, PATH_MAX );

    return;
  }

  /* Prefetch account message */
  if( FD_LIKELY( sig==FD_GROOVE_TILE_PREFETCH_SIGNATURE ) ) {
    if( FD_UNLIKELY( sz != sizeof(fd_msg_groove_prefetch_account_req_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_chunk0, ctx->in_wmark ));
    }

    fd_msg_groove_prefetch_account_req_t * msg = ((fd_msg_groove_prefetch_account_req_t *)fd_chunk_to_laddr( ctx->in_mem, ctx->in_chunk0 ));
    fd_memcpy( &ctx->cur_pubkey, &msg->pubkey, sizeof(fd_pubkey_t) );
    fd_memcpy( &ctx->cur_funk_txn_xid, &msg->funk_txn_xid, sizeof(fd_funk_txn_xid_t) );

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
    /* Pull out the pubkey from the message */
    pull_account_from_cold_store( &ctx->cur_pubkey, &ctx->cur_funk_txn_xid, ctx );
  } else if( FD_LIKELY( sig==FD_GROOVE_TILE_BLOCKING_PREFETCH_SIGNATURE ) ) {
    FD_LOG_WARNING(( "TODO: implement blocking prefetch" ));
  } else if( FD_UNLIKELY( sig==FD_GROOVE_TILE_LOAD_SNAPSHOT_SIGNATURE ) ) {
    load_full_snapshot( ctx,
    ctx->snapshot_path,
    ctx->snapshot_dir,
    ctx->snapshot_src_type );
  } else {
    FD_LOG_ERR(( "unknown signature: %lu", sig ));
  }

}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_groove_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_groove_tile_ctx_t)

#define STEM_CALLBACK_DURING_FRAG during_frag
#define STEM_CALLBACK_AFTER_FRAG  after_frag

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
