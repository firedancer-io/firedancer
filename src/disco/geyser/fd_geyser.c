#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "fd_geyser.h"
#include "../../funk/fd_funk_filemap.h"
#include "../../tango/mcache/fd_mcache.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../util/wksp/fd_wksp_private.h"
#include "../topo/fd_topo.h"

#define SHAM_LINK_CONTEXT fd_geyser_t
#define SHAM_LINK_STATE   fd_replay_notif_msg_t
#define SHAM_LINK_NAME    replay_sham_link
#include "sham_link.h"

#define SHAM_LINK_CONTEXT fd_geyser_t
#define SHAM_LINK_STATE   fd_stake_ci_t
#define SHAM_LINK_NAME    stake_sham_link
#include "sham_link.h"

struct fd_geyser {
  fd_funk_t *          funk;
  fd_blockstore_t *    blockstore;
  fd_stake_ci_t *      stake_ci;
  replay_sham_link_t * rep_notify;
  stake_sham_link_t *  stake_notify;

  void * fun_arg;
  fd_geyser_execute_fun execute_fun; /* Slot numbers, bank hash */
  fd_geyser_block_fun   block_fun;   /* Raw block data, additional metadata */
  fd_geyser_entry_fun   entry_fun;   /* Every entry/microblock */
  fd_geyser_txn_fun     txn_fun;     /* executed individual transaction */
  fd_geyser_block_done_fun block_done_fun;   /* Called after block specific updates are done */

  fd_geyser_acct_fun    acct_fun;    /* Account written */
};

ulong
fd_geyser_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_geyser_t), sizeof(fd_geyser_t) );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );
  l = FD_LAYOUT_APPEND( l, replay_sham_link_align(), replay_sham_link_footprint() );
  l = FD_LAYOUT_APPEND( l, stake_sham_link_align(), stake_sham_link_footprint() );
  return FD_LAYOUT_FINI( l, 1UL );
}

ulong
fd_geyser_align( void ) {
  return alignof(fd_geyser_t);
}

void *
fd_geyser_new( void * mem, fd_geyser_args_t * args ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_geyser_t * self = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_geyser_t), sizeof(fd_geyser_t) );
  void * stake_ci_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(), fd_stake_ci_footprint() );
  void * rep_notify_mem = FD_SCRATCH_ALLOC_APPEND( l, replay_sham_link_align(), replay_sham_link_footprint() );
  void * stake_notify_mem = FD_SCRATCH_ALLOC_APPEND( l, stake_sham_link_align(), stake_sham_link_footprint() );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  FD_TEST( scratch_top <= (ulong)mem + fd_geyser_footprint() );

  self->funk = fd_funk_open_file( args->funk_file, 1, 0, 0, 0, 0, FD_FUNK_READONLY, NULL );
  if( self->funk == NULL ) {
    FD_LOG_ERR(( "failed to join a funky" ));
  }

  fd_wksp_t * wksp = fd_wksp_attach( args->blockstore_wksp );
  if( FD_UNLIKELY( !wksp ) )
    FD_LOG_ERR(( "unable to attach to \"%s\"\n\tprobably does not exist or bad permissions", args->blockstore_wksp ));
  fd_wksp_tag_query_info_t info;
  ulong tag = 1;
  if( fd_wksp_tag_query( wksp, &tag, 1, &info, 1 ) <= 0 ) {
    FD_LOG_ERR(( "workspace \"%s\" does not contain a blockstore", args->blockstore_wksp ));
  }
  void * shmem = fd_wksp_laddr_fast( wksp, info.gaddr_lo );
  self->blockstore = fd_blockstore_join( shmem );
  if( self->blockstore == NULL ) {
    FD_LOG_ERR(( "failed to join a blockstore" ));
  }
  FD_LOG_NOTICE(( "blockstore has slot root=%lu", self->blockstore->smr ));
  fd_wksp_mprotect( wksp, 1 );

  fd_pubkey_t identity_key[1]; /* Just the public key */
  memset( identity_key, 0xa5, sizeof(fd_pubkey_t) );
  self->stake_ci = fd_stake_ci_join( fd_stake_ci_new( stake_ci_mem, identity_key ) );

  self->rep_notify = replay_sham_link_new( rep_notify_mem, "fd1_replay_notif.wksp" );
  self->stake_notify = stake_sham_link_new( stake_notify_mem, "fd1_stake_out.wksp" );

  replay_sham_link_start( self->rep_notify );
  stake_sham_link_start( self->stake_notify );

  self->execute_fun = args->execute_fun;
  self->block_fun = args->block_fun;
  self->block_done_fun = args->block_done_fun;
  self->entry_fun = args->entry_fun;
  self->txn_fun = args->txn_fun;
  self->acct_fun = args->acct_fun;
  self->fun_arg = args->fun_arg;

  return mem;
}

fd_geyser_t *
fd_geyser_join( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  return FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_geyser_t), sizeof(fd_geyser_t) );
}

void *
fd_geyser_leave( fd_geyser_t * self ) {
  return self;
}

void *
fd_geyser_delete( void * mem ) {
  return mem;
}

static void
fd_geyser_scan_txns( fd_geyser_t * ctx, ulong slotn, uchar * data, ulong sz ) {
  ulong blockoff = 0;
  while( blockoff < sz ) {
    if( blockoff + sizeof( ulong ) > sz ) FD_LOG_ERR(( "premature end of block" ));
    ulong mcount = FD_LOAD( ulong, (const uchar *)data + blockoff );
    blockoff += sizeof( ulong );

    /* Loop across microblocks */
    for( ulong mblk = 0; mblk < mcount; ++mblk ) {
      if( blockoff + sizeof( fd_microblock_hdr_t ) > sz ) {
        FD_LOG_WARNING(( "premature end of block" ));
        return;
      }
      fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)( (const uchar *)data + blockoff );
      blockoff += sizeof( fd_microblock_hdr_t );

      if( ctx->entry_fun != NULL ) {
        (*ctx->entry_fun)( slotn, hdr, ctx->fun_arg );
      }

      /* Loop across transactions */
      for( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
        uchar         txn_out[FD_TXN_MAX_SZ];
        uchar const * raw    = (uchar const *)data + blockoff;
        ulong         pay_sz = 0;
        ulong         txn_sz = fd_txn_parse_core( (uchar const *)raw,
                                                  fd_ulong_min( sz - blockoff, FD_TXN_MTU ),
                                                  txn_out,
                                                  NULL,
                                                  &pay_sz );
        if( txn_sz == 0 || txn_sz > FD_TXN_MTU ) {
          FD_LOG_WARNING(( "failed to parse transaction %lu in microblock %lu in slot %lu. txn size: %lu",
                           txn_idx,
                           mblk,
                           slotn,
                           txn_sz ));
          return;
        }
        fd_txn_t const * txn = (fd_txn_t const *)txn_out;

        if( ctx->txn_fun != NULL ) {
          (*ctx->txn_fun)( slotn, txn, raw, txn_sz, ctx->fun_arg );
        }

        blockoff += pay_sz;
      }
    }
  }
}

void
fd_geyser_replay_block( fd_geyser_t * ctx, ulong slotn ) {
  if( ctx->block_fun != NULL || ctx->entry_fun != NULL || ctx->txn_fun != NULL ) {
    FD_SCRATCH_SCOPE_BEGIN {
      fd_block_map_t meta[1];
      fd_block_rewards_t rewards[1];
      fd_hash_t parent_hash;
      uchar * blk_data;
      ulong blk_sz;
      if( fd_blockstore_block_data_query_volatile( ctx->blockstore, slotn, meta, rewards, &parent_hash, fd_scratch_virtual(), &blk_data, &blk_sz ) ) {
        FD_LOG_WARNING(( "failed to retrieve block for slot %lu", slotn ));
        return;
      }
      if( ctx->block_fun != NULL ) {
        (*ctx->block_fun)( slotn, meta, &parent_hash, blk_data, blk_sz, ctx->fun_arg );
      }
      if( ctx->entry_fun != NULL || ctx->txn_fun != NULL ) {
        fd_geyser_scan_txns( ctx, slotn, blk_data, blk_sz );
      }
    } FD_SCRATCH_SCOPE_END;
  }
  if( ctx->block_done_fun != NULL ) {
    ( *ctx->block_done_fun ) ( slotn, ctx->fun_arg );
  }
}

static void
replay_sham_link_during_frag( fd_geyser_t * ctx, fd_replay_notif_msg_t * state, void const * msg, int sz ) {
  (void)ctx;
  FD_TEST( sz == (int)sizeof(fd_replay_notif_msg_t) );
  fd_memcpy(state, msg, sizeof(fd_replay_notif_msg_t));
}

static void
replay_sham_link_after_frag(fd_geyser_t * ctx, fd_replay_notif_msg_t * msg) {
  (void)ctx;
  if( msg->type == FD_REPLAY_SLOT_TYPE ) {
    ulong slotn = msg->slot_exec.slot;
    if( ctx->execute_fun != NULL ) {
      ( *ctx->execute_fun ) ( msg, ctx->fun_arg );
    }
    fd_geyser_replay_block( ctx, slotn );

  } else if( msg->type == FD_REPLAY_ACCTS_TYPE ) {
    if( ctx->acct_fun != NULL ) {
      for( uint i = 0; i < msg->accts.accts_cnt; ++i ) {
        FD_SCRATCH_SCOPE_BEGIN {
          fd_pubkey_t addr;
          fd_memcpy(&addr, msg->accts.accts[i].id, 32U );
          fd_funk_rec_key_t key = fd_acc_funk_key( &addr );
          ulong datalen;
          void * data = fd_funk_rec_query_xid_safe( ctx->funk, &key, &msg->accts.funk_xid, fd_scratch_virtual(), &datalen );
          if( data ) {
            fd_account_meta_t const * meta = fd_type_pun_const( data );
            (*ctx->acct_fun)( msg->accts.funk_xid.ul[0], msg->accts.sig, &addr, meta, (uchar*)data + meta->hlen, meta->dlen, ctx->fun_arg );
          }
        } FD_SCRATCH_SCOPE_END;
      }
    }
  }
}

static void
stake_sham_link_during_frag( fd_geyser_t * ctx, fd_stake_ci_t * state, void const * msg, int sz ) {
  (void)ctx; (void)sz;
  fd_stake_ci_stake_msg_init( state, msg );
}

static void
stake_sham_link_after_frag(fd_geyser_t * ctx, fd_stake_ci_t * state) {
  (void)ctx;
  fd_stake_ci_stake_msg_fini( state );
}

void
fd_geyser_poll( fd_geyser_t * self ) {
  fd_replay_notif_msg_t msg;
  replay_sham_link_poll( self->rep_notify, self, &msg );

  stake_sham_link_poll( self->stake_notify, self, self->stake_ci );
}
