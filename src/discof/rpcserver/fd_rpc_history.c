#include "fd_rpc_history.h"
#include <unistd.h>
#include <fcntl.h>

#include "../../ballet/block/fd_microblock.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../flamenco/runtime/fd_system_ids.h"

#include <string.h>

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

#define FD_REASM_MAP_COL_CNT (1UL<<10)
#define FD_REASM_MAP_COL_HEIGHT (128UL)
struct fd_rpc_reasm_map {
  struct fd_rpc_reasm_map_column {
    ulong ele_cnt;  /* The number of shreds received in this column */    uchar end_found; /* Whether the last slice of the slot has been found */
    fd_reasm_fec_t ele[FD_REASM_MAP_COL_HEIGHT];
  } cols[FD_REASM_MAP_COL_CNT];
  ulong head; /* Next open column */
  ulong tail; /* Oldest column */
};
typedef struct fd_rpc_reasm_map fd_rpc_reasm_map_t;

struct fd_rpc_history {
  fd_spad_t * spad;
  fd_rpc_block_t * block_map;
  ulong block_cnt;
  fd_rpc_txn_t * txn_map;
  fd_rpc_acct_map_t * acct_map;
  fd_rpc_acct_map_elem_t * acct_pool;
  fd_rpc_reasm_map_t * reasm_map;
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

  mem = fd_spad_alloc( spad, alignof(fd_rpc_reasm_map_t), sizeof(fd_rpc_reasm_map_t) );
  memset(mem, 0, sizeof(fd_rpc_reasm_map_t));
  hist->reasm_map = (fd_rpc_reasm_map_t *)mem;

  hist->file_fd = open( args->history_file, O_CREAT | O_RDWR | O_TRUNC, 0644 );
  if( hist->file_fd == -1 ) FD_LOG_ERR(( "unable to open rpc history file: %s", args->history_file ));
  hist->file_totsz = 0;

  return hist;
}

static fd_rpc_block_t *
fd_rpc_history_alloc_block(fd_rpc_history_t * hist, ulong slot) {
  fd_rpc_block_t * blk = fd_rpc_block_map_query(hist->block_map, &slot, NULL);
  if( blk ) return blk;
  if( fd_rpc_block_map_is_full( hist->block_map ) ) return NULL; /* Out of space */
  blk = fd_rpc_block_map_insert( hist->block_map, &slot );
  if( blk == NULL ) {
    FD_LOG_ERR(( "unable to save slot %lu block", slot ));
    return NULL;
  }
  blk->slot = slot;
  blk->file_offset = 0UL;
  blk->file_size = 0UL;
  memset( &blk->info, 0, sizeof(fd_replay_notif_msg_t) );
  blk->info.slot_exec.slot = slot;
  if( hist->first_slot == ULONG_MAX ) {
    hist->first_slot = hist->latest_slot = slot;
  } else {
    if( slot < hist->first_slot ) hist->first_slot = slot;
    else if( slot > hist->latest_slot ) hist->latest_slot = slot;
  }
  hist->block_cnt++;
  return blk;
}

void
fd_rpc_history_debug(fd_rpc_history_t * hist) {
  fd_rpc_reasm_map_t * reasm_map = hist->reasm_map;
  ulong tot_cnt = 0;
  for( ulong slot = reasm_map->tail; slot < reasm_map->head; slot++ ) {
    ulong col_idx = slot & (FD_REASM_MAP_COL_CNT - 1);
    struct fd_rpc_reasm_map_column * col = &reasm_map->cols[col_idx];
    FD_LOG_NOTICE(( "slot %lu: %lu fecs", slot, col->ele_cnt ));
    tot_cnt += col->ele_cnt;
  }
  FD_LOG_NOTICE(( "%lu head, %lu tail, %lu total fecs, %lu total blocks",
                  reasm_map->head, reasm_map->tail, tot_cnt, reasm_map->head - reasm_map->tail ));
}

void
fd_rpc_history_save_info(fd_rpc_history_t * hist, fd_replay_notif_msg_t * info) {
  fd_rpc_block_t * blk = fd_rpc_history_alloc_block( hist, info->slot_exec.slot );
  if( blk == NULL ) return;
  blk->info = *info;
}

static void
fd_rpc_history_scan_block(fd_rpc_history_t * hist, ulong slot, ulong file_offset, uchar * blk_data, ulong blk_sz) {
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
          FD_LOG_WARNING( ( "failed to parse transaction %lu in microblock %lu at offset %lu", txn_idx, mblk, blockoff ) );
          return;
        }
        fd_txn_t * txn = (fd_txn_t *)txn_out;

        /* Loop across signatures */
        fd_ed25519_sig_t const * sigs = (fd_ed25519_sig_t const *)(raw + txn->signature_off);
        for ( uchar j = 0; j < txn->signature_cnt; j++ ) {
          if( fd_rpc_txn_map_is_full( hist->txn_map ) ) break; /* Out of space */
          fd_rpc_txn_key_t key;
          memcpy(&key, (const uchar*)&sigs[j], sizeof(key));
          fd_rpc_txn_t * ent = fd_rpc_txn_map_insert( hist->txn_map, &key );
          ent->file_offset = file_offset + blockoff;
          ent->file_size = pay_sz;
          ent->slot = slot;
        }

        /* Loop across accounts */
        fd_rpc_txn_key_t sig0;
        memcpy(&sig0, (const uchar*)sigs, sizeof(sig0));
        fd_pubkey_t * accs = (fd_pubkey_t *)((uchar *)raw + txn->acct_addr_off);
        for( ulong i = 0UL; i < txn->acct_addr_cnt; i++ ) {
          if( !memcmp(&accs[i], fd_solana_vote_program_id.key, sizeof(fd_pubkey_t)) ) continue; /* Ignore votes */
          if( !fd_rpc_acct_map_pool_free( hist->acct_pool ) ) break;
          fd_rpc_acct_map_elem_t * ele = fd_rpc_acct_map_pool_ele_acquire( hist->acct_pool );
          ele->key = accs[i];
          ele->slot = slot;
          ele->sig = sig0;
          fd_rpc_acct_map_ele_insert( hist->acct_map, ele, hist->acct_pool );
        }

        blockoff += pay_sz;
      }
    }
  }
  if ( blockoff != blk_sz )
    FD_LOG_ERR(("garbage at end of block"));
}

void
fd_rpc_history_process_column(fd_rpc_history_t * hist, struct fd_rpc_reasm_map_column * col, fd_store_t * store, fd_reasm_fec_t * fec) {
  FD_SPAD_FRAME_BEGIN( hist->spad ) {

    FD_LOG_NOTICE(( "assembling slot %lu block", fec->slot ));

    /* Assemble the block */
    fd_store_fec_t * list[FD_REASM_MAP_COL_HEIGHT];
    ulong slot = fec->slot;
    ulong blk_sz = 0;
    for( ulong i = 0; i < col->ele_cnt; i++ ) {
      fd_reasm_fec_t * ele = &col->ele[i];
      fd_store_fec_t * fec_p = list[i] = fd_store_query( store, &ele->key );
      if( !fec_p ) {
        FD_LOG_WARNING(( "missing fec" ));
        return;
      }
      blk_sz += fec_p->data_sz;
    }
    uchar * blk_data = fd_spad_alloc( hist->spad, alignof(ulong), blk_sz );
    ulong blk_off = 0;
    for( ulong i = 0; i < col->ele_cnt; i++ ) {
      fd_store_fec_t * fec_p = list[i];
      fd_memcpy( blk_data + blk_off, fec_p->data, fec_p->data_sz );
      blk_off += fec_p->data_sz;
    }
    FD_TEST( blk_off == blk_sz );

    /* Get a block from the map */
    fd_rpc_block_t * blk = fd_rpc_history_alloc_block( hist, slot );
    if( blk == NULL ) return;

    /* Write the block to the file */
    if( pwrite( hist->file_fd, blk_data, blk_sz, (long)hist->file_totsz ) != (ssize_t)blk_sz ) {
      FD_LOG_ERR(( "unable to write to rpc history file" ));
    }
    ulong file_offset = blk->file_offset = hist->file_totsz;
    blk->file_size = blk_sz;
    hist->file_totsz += blk_sz;

    /* Scan the block */
    fd_rpc_history_scan_block( hist, slot, file_offset, blk_data, blk_sz );

  } FD_SPAD_FRAME_END;
}

static void
fd_rpc_history_discard_column(fd_rpc_reasm_map_t * reasm_map, ulong slot) {
  ulong col_idx = slot & (FD_REASM_MAP_COL_CNT - 1);
  struct fd_rpc_reasm_map_column * col = &reasm_map->cols[col_idx];
  col->ele_cnt = 0;
}

void
fd_rpc_history_save_fec(fd_rpc_history_t * hist, fd_store_t * store, fd_reasm_fec_t * fec_msg ) {
  fd_store_fec_t * fec_p = fd_store_query( store, &fec_msg->key );
  if( !fec_p ) return;

  fd_rpc_reasm_map_t * reasm_map = hist->reasm_map;

  if( reasm_map->head == 0UL ) {
    reasm_map->head = fec_msg->slot+1;
    reasm_map->tail = fec_msg->slot;
  }
  if( fec_msg->slot < reasm_map->tail ) return; /* Do not go backwards */
  while( fec_msg->slot >= reasm_map->tail + FD_REASM_MAP_COL_CNT ) {
    FD_TEST( reasm_map->tail < reasm_map->head );
    fd_rpc_history_discard_column( reasm_map, reasm_map->tail++ );
  }
  while( fec_msg->slot >= reasm_map->head ) {
    ulong col_idx = (reasm_map->head++) & (FD_REASM_MAP_COL_CNT - 1);
    struct fd_rpc_reasm_map_column * col = &reasm_map->cols[col_idx];
    col->ele_cnt = 0;
  }
  FD_TEST( fec_msg->slot >= reasm_map->tail && fec_msg->slot < reasm_map->head && reasm_map->head - reasm_map->tail <= FD_REASM_MAP_COL_CNT );

  ulong col_idx = fec_msg->slot & (FD_REASM_MAP_COL_CNT - 1);
  struct fd_rpc_reasm_map_column * col = &reasm_map->cols[col_idx];

  if( col->ele_cnt == 0 ) {
    FD_TEST( fec_msg->fec_set_idx == 0 );
  } else {
    FD_TEST( fec_msg->fec_set_idx > col->ele[col->ele_cnt-1].fec_set_idx );
  }

  FD_TEST( col->ele_cnt < FD_REASM_MAP_COL_HEIGHT );

  col->ele[col->ele_cnt++] = *fec_msg;

  if( fec_msg->slot_complete ) {
    /* We've received all the shreds for this slot. Process it. */
    fd_rpc_history_process_column( hist, col, store, fec_msg );
    fd_rpc_history_discard_column( reasm_map, fec_msg->slot );
  }
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
