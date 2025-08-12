#include "fd_rpc_history.h"
#include <unistd.h>
#include <fcntl.h>

#include "../../ballet/block/fd_microblock.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../flamenco/runtime/fd_system_ids.h"

struct fd_rpc_block {
  ulong slot;
  ulong next;
  fd_replay_notif_msg_t info;
  ulong file_offset;
  ulong file_size;
};

typedef struct fd_rpc_block fd_rpc_block_t;

#define MAP_NAME              fd_rpc_block_map
#define MAP_T                 fd_rpc_block_t
#define MAP_KEY_T             ulong
#define MAP_KEY               slot
#define MAP_KEY_EQ(k0,k1)     ((*k0)==(*k1))
#define MAP_KEY_HASH(key,seed) fd_ulong_hash(*key ^ seed)
#include "../../util/tmpl/fd_map_giant.c"

struct fd_rpc_txn {
  fd_rpc_txn_key_t sig;
  ulong next;
  ulong slot;
  ulong file_offset;
  ulong file_size;
};
typedef struct fd_rpc_txn fd_rpc_txn_t;

FD_FN_PURE int
fd_rpc_txn_key_equal( fd_rpc_txn_key_t const * k0, fd_rpc_txn_key_t const * k1 ) {
  for( ulong i = 0; i < FD_ED25519_SIG_SZ / sizeof( ulong ); ++i )
    if( k0->v[i] != k1->v[i] ) return 0;
  return 1;
}

FD_FN_PURE ulong
fd_rpc_txn_key_hash( fd_rpc_txn_key_t const * k, ulong seed ) {
  ulong h = seed;
  for( ulong i = 0; i < FD_ED25519_SIG_SZ / sizeof( ulong ); ++i )
    h ^= k->v[i];
  return h;
}

#define MAP_NAME              fd_rpc_txn_map
#define MAP_T                 fd_rpc_txn_t
#define MAP_KEY               sig
#define MAP_KEY_T             fd_rpc_txn_key_t
#define MAP_KEY_EQ(k0,k1)     fd_rpc_txn_key_equal(k0,k1)
#define MAP_KEY_HASH(key,seed) fd_rpc_txn_key_hash(key,seed)
#include "../../util/tmpl/fd_map_giant.c"

struct fd_rpc_acct_map_elem {
  fd_pubkey_t key;
  ulong next;
  ulong slot;
  ulong age;
  fd_rpc_txn_key_t sig; /* Transaction signature */
};
typedef struct fd_rpc_acct_map_elem fd_rpc_acct_map_elem_t;
#define MAP_NAME fd_rpc_acct_map
#define MAP_KEY_T fd_pubkey_t
#define MAP_ELE_T fd_rpc_acct_map_elem_t
#define MAP_KEY_HASH(key,seed) fd_hash( seed, key, sizeof(fd_pubkey_t) )
#define MAP_KEY_EQ(k0,k1)      fd_pubkey_eq( k0, k1 )
#define MAP_MULTI 1
#include "../../util/tmpl/fd_map_chain.c"
#define POOL_NAME fd_rpc_acct_map_pool
#define POOL_T    fd_rpc_acct_map_elem_t
#include "../../util/tmpl/fd_pool.c"

struct fd_rpc_history {
  fd_spad_t * spad;
  fd_rpc_block_t * block_map;
  ulong block_cnt;
  fd_rpc_txn_t * txn_map;
  fd_rpc_acct_map_t * acct_map;
  fd_rpc_acct_map_elem_t * acct_pool;
  ulong first_slot;
  ulong latest_slot;
  int file_fd;
  ulong file_totsz;
};

fd_rpc_history_t *
fd_rpc_history_create(fd_rpcserver_args_t * args) {
  fd_spad_t * spad = args->spad;
  fd_rpc_history_t * hist = (fd_rpc_history_t *)fd_spad_alloc( spad, alignof(fd_rpc_history_t), sizeof(fd_rpc_history_t) );
  memset(hist, 0, sizeof(fd_rpc_history_t));
  hist->spad = spad;

  hist->first_slot = ULONG_MAX;
  hist->latest_slot = 0;

  hist->block_map = fd_rpc_block_map_join( fd_rpc_block_map_new( fd_spad_alloc( spad, fd_rpc_block_map_align(), fd_rpc_block_map_footprint(args->block_index_max) ), args->block_index_max, 0 ) );

  hist->txn_map = fd_rpc_txn_map_join( fd_rpc_txn_map_new( fd_spad_alloc( spad, fd_rpc_txn_map_align(), fd_rpc_txn_map_footprint(args->txn_index_max) ), args->txn_index_max, 0 ) );

  void * mem = fd_spad_alloc( spad, fd_rpc_acct_map_align(), fd_rpc_acct_map_footprint( args->acct_index_max/2 ) );
  hist->acct_map = fd_rpc_acct_map_join( fd_rpc_acct_map_new( mem, args->acct_index_max/2, 0 ) );
  mem = fd_spad_alloc( spad, fd_rpc_acct_map_pool_align(), fd_rpc_acct_map_pool_footprint( args->acct_index_max ) );
  hist->acct_pool = fd_rpc_acct_map_pool_join( fd_rpc_acct_map_pool_new( mem, args->acct_index_max ) );

  hist->file_fd = open( args->history_file, O_CREAT | O_RDWR | O_TRUNC, 0644 );
  if( hist->file_fd == -1 ) FD_LOG_ERR(( "unable to open rpc history file: %s", args->history_file ));
  hist->file_totsz = 0;

  return hist;
}

void
fd_rpc_history_save(fd_rpc_history_t * hist, fd_replay_notif_msg_t * info) {
  FD_SPAD_FRAME_BEGIN( hist->spad ) {
    if( fd_rpc_block_map_is_full( hist->block_map ) ) return; /* Out of space */

    ulong blk_max = info->slot_exec.shred_cnt * FD_SHRED_MAX_SZ;
    uchar * blk_data = fd_spad_alloc( hist->spad, 1, blk_max );
    ulong blk_sz = 0;
    // if( fd_blockstore_slice_query( blockstore, info->slot_exec.slot, 0, (uint)(info->slot_exec.shred_cnt-1), blk_max, blk_data, &blk_sz) ) {
    //   FD_LOG_WARNING(( "unable to read slot %lu block", info->slot_exec.slot ));
    //   return;
    // }

    FD_LOG_NOTICE(( "saving slot %lu block", info->slot_exec.slot ));

    if( hist->first_slot == ULONG_MAX ) hist->first_slot = info->slot_exec.slot;
    hist->latest_slot = info->slot_exec.slot;

    fd_rpc_block_t * blk = fd_rpc_block_map_insert( hist->block_map, &info->slot_exec.slot );
    if( blk == NULL ) {
      FD_LOG_ERR(( "unable to save slot %lu block", info->slot_exec.slot ));
      return;
    }
    blk->info = *info;

    if( pwrite( hist->file_fd, blk_data, blk_sz, (long)hist->file_totsz ) != (ssize_t)blk_sz ) {
      FD_LOG_ERR(( "unable to write to rpc history file" ));
    }
    ulong base_offset = blk->file_offset = hist->file_totsz;
    blk->file_size = blk_sz;
    hist->file_totsz += blk_sz;
    hist->block_cnt ++;

    ulong blockoff = 0;
    while (blockoff < blk_sz) {
      if ( blockoff + sizeof(ulong) > blk_sz )
        return;
      ulong mcount = *(const ulong *)(blk_data + blockoff);
      blockoff += sizeof(ulong);

      /* Loop across microblocks */
      for (ulong mblk = 0; mblk < mcount; ++mblk) {
        if ( blockoff + sizeof(fd_microblock_hdr_t) > blk_sz )
          FD_LOG_ERR(("premature end of block"));
        fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)((const uchar *)blk_data + blockoff);
        blockoff += sizeof(fd_microblock_hdr_t);

        /* Loop across transactions */
        for ( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
          uchar txn_out[FD_TXN_MAX_SZ];
          ulong pay_sz = 0;
          const uchar* raw = (const uchar *)blk_data + blockoff;
          ulong txn_sz = fd_txn_parse_core(raw, fd_ulong_min(blk_sz - blockoff, FD_TXN_MTU), txn_out, NULL, &pay_sz);
          if ( txn_sz == 0 || txn_sz > FD_TXN_MAX_SZ ) {
            FD_LOG_ERR( ( "failed to parse transaction %lu in microblock %lu", txn_idx, mblk ) );
          }
          fd_txn_t * txn = (fd_txn_t *)txn_out;

          /* Loop across signatures */
          fd_ed25519_sig_t const * sigs = (fd_ed25519_sig_t const *)(raw + txn->signature_off);
          for ( uchar j = 0; j < txn->signature_cnt; j++ ) {
            if( fd_rpc_txn_map_is_full( hist->txn_map ) ) break; /* Out of space */
            fd_rpc_txn_key_t key;
            memcpy(&key, (const uchar*)&sigs[j], sizeof(key));
            fd_rpc_txn_t * ent = fd_rpc_txn_map_insert( hist->txn_map, &key );
            ent->file_offset = base_offset + blockoff;
            ent->file_size = pay_sz;
            ent->slot = info->slot_exec.slot;
          }

          /* Loop across accoounts */
          fd_rpc_txn_key_t sig0;
          memcpy(&sig0, (const uchar*)sigs, sizeof(sig0));
          fd_pubkey_t * accs = (fd_pubkey_t *)((uchar *)raw + txn->acct_addr_off);
          for( ulong i = 0UL; i < txn->acct_addr_cnt; i++ ) {
            if( !memcmp(&accs[i], fd_solana_vote_program_id.key, sizeof(fd_pubkey_t)) ) continue; /* Ignore votes */
            if( !fd_rpc_acct_map_pool_free( hist->acct_pool ) ) break;
            fd_rpc_acct_map_elem_t * ele = fd_rpc_acct_map_pool_ele_acquire( hist->acct_pool );
            ele->key = accs[i];
            ele->slot = info->slot_exec.slot;
            ele->sig = sig0;
            fd_rpc_acct_map_ele_insert( hist->acct_map, ele, hist->acct_pool );
          }

          blockoff += pay_sz;
        }
      }
    }
    if ( blockoff != blk_sz )
      FD_LOG_ERR(("garbage at end of block"));

  } FD_SPAD_FRAME_END;
}

ulong
fd_rpc_history_first_slot(fd_rpc_history_t * hist) {
  return hist->first_slot;
}

ulong
fd_rpc_history_latest_slot(fd_rpc_history_t * hist) {
  return hist->latest_slot;
}

fd_replay_notif_msg_t *
fd_rpc_history_get_block_info(fd_rpc_history_t * hist, ulong slot) {
  fd_rpc_block_t * blk = fd_rpc_block_map_query( hist->block_map, &slot, NULL );
  if( !blk ) {
    return NULL;
  }
  return &blk->info;
}

fd_replay_notif_msg_t *
fd_rpc_history_get_block_info_by_hash(fd_rpc_history_t * hist, fd_hash_t * h) {
  for( fd_rpc_block_map_iter_t i = fd_rpc_block_map_iter_init( hist->block_map );
       !fd_rpc_block_map_iter_done( hist->block_map, i );
       i = fd_rpc_block_map_iter_next( hist->block_map, i ) ) {
    fd_rpc_block_t * ele = fd_rpc_block_map_iter_ele( hist->block_map, i );
    if( fd_hash_eq( &ele->info.slot_exec.block_hash, h ) ) return &ele->info;
  }
  return NULL;
}

uchar *
fd_rpc_history_get_block(fd_rpc_history_t * hist, ulong slot, ulong * blk_sz) {
  fd_rpc_block_t * blk = fd_rpc_block_map_query( hist->block_map, &slot, NULL );
  if( !blk ) {
    *blk_sz = ULONG_MAX;
    return NULL;
  }
  uchar * blk_data = fd_spad_alloc( hist->spad, 1, blk->file_size );
  if( pread( hist->file_fd, blk_data, blk->file_size, (long)blk->file_offset ) != (ssize_t)blk->file_size ) {
    FD_LOG_ERR(( "unable to read rpc history file" ));
    *blk_sz = ULONG_MAX;
    return NULL;
  }
  *blk_sz = blk->file_size;
  return blk_data;
}

uchar *
fd_rpc_history_get_txn(fd_rpc_history_t * hist, fd_rpc_txn_key_t * sig, ulong * txn_sz, ulong * slot) {
  fd_rpc_txn_t * txn = fd_rpc_txn_map_query( hist->txn_map, sig, NULL );
  if( !txn ) {
    *txn_sz = ULONG_MAX;
    return NULL;
  }
  uchar * txn_data = fd_spad_alloc( hist->spad, 1, txn->file_size );
  if( pread( hist->file_fd, txn_data, txn->file_size, (long)txn->file_offset ) != (ssize_t)txn->file_size ) {
    FD_LOG_ERR(( "unable to read rpc history file" ));
    *txn_sz = ULONG_MAX;
    return NULL;
  }
  *txn_sz = txn->file_size;
  *slot = txn->slot;
  return txn_data;
}

const void *
fd_rpc_history_first_txn_for_acct(fd_rpc_history_t * hist, fd_pubkey_t * acct, fd_rpc_txn_key_t * sig, ulong * slot) {
  fd_rpc_acct_map_elem_t const * ele = fd_rpc_acct_map_ele_query_const( hist->acct_map, acct, NULL, hist->acct_pool );
  if( ele == NULL ) return NULL;
  *sig = ele->sig;
  *slot = ele->slot;
  return ele;
}

const void *
fd_rpc_history_next_txn_for_acct(fd_rpc_history_t * hist, fd_rpc_txn_key_t * sig, ulong * slot, const void * iter) {
  fd_rpc_acct_map_elem_t const * ele = (fd_rpc_acct_map_elem_t const *)iter;
  ele = fd_rpc_acct_map_ele_next_const( ele, NULL, hist->acct_pool );
  if( ele == NULL ) return NULL;
  *sig = ele->sig;
  *slot = ele->slot;
  return ele;
}
