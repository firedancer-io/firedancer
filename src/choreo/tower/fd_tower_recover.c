#include "fd_tower_recover.h"

int
fd_tower_recover_init( fd_tower_recover_t *          out,
                       fd_tower_file_t const *       saved,
                       ulong                         snapshot_slot,
                       fd_hash_t const *             snapshot_bank_hash,
                       fd_hash_t const *             snapshot_block_id,
                       fd_slot_history_view_t const * history,
                       fd_slot_hashes_t const *       hashes ) {
  FD_TEST( saved->votes_cnt && saved->votes_cnt<=FD_TOWER_VOTE_MAX );
  if( FD_UNLIKELY( snapshot_slot==ULONG_MAX || !history ||
                   history->next_slot!=snapshot_slot+1UL ||
                   history->bits_len!=FD_SLOT_HISTORY_MAX_ENTRIES ||
                   history->blocks_len!=FD_SLOT_HISTORY_MAX_ENTRIES/64UL ||
                   !history->bits ) ) return FD_TOWER_RECOVER_ERR_HISTORY;

  if( saved->root!=ULONG_MAX && saved->root<=snapshot_slot &&
      fd_sysvar_slot_history_find_slot( history, saved->root )!=FD_SLOT_HISTORY_SLOT_FOUND )
    return FD_TOWER_RECOVER_ERR_HISTORY;

  ulong rooted_cnt = 0UL;
  while( rooted_cnt<saved->votes_cnt && saved->votes[ rooted_cnt ].slot<=snapshot_slot ) {
    if( fd_sysvar_slot_history_find_slot( history, saved->votes[ rooted_cnt ].slot )!=FD_SLOT_HISTORY_SLOT_FOUND )
      return FD_TOWER_RECOVER_ERR_HISTORY;
    rooted_cnt++;
  }

  if( rooted_cnt==saved->votes_cnt ) {
    ulong tip = saved->votes[ saved->votes_cnt-1UL ].slot;
    fd_hash_t const * bank_hash = NULL;
    if( tip==snapshot_slot ) {
      if( FD_UNLIKELY( memcmp( &saved->block_id, snapshot_block_id, sizeof(fd_hash_t) ) ) )
        return FD_TOWER_RECOVER_ERR_HASH;
      bank_hash = snapshot_bank_hash;
    } else if( hashes ) {
      for( ulong i=0UL; i<hashes->cnt; i++ ) {
        if( hashes->elems[ i ].slot==tip ) {
          bank_hash = &hashes->elems[ i ].hash;
          break;
        }
      }
    }
    if( FD_UNLIKELY( !bank_hash || memcmp( &saved->bank_hash, bank_hash, sizeof(fd_hash_t) ) ) )
      return FD_TOWER_RECOVER_ERR_HASH;
  }

  out->saved         = *saved;
  out->snapshot_slot = snapshot_slot;
  out->rooted_cnt    = rooted_cnt;
  return rooted_cnt==saved->votes_cnt ? FD_TOWER_RECOVER_READY : FD_TOWER_RECOVER_WAIT;
}

int
fd_tower_recover_check_onchain( fd_tower_recover_t const * recovery,
                                fd_tower_vote_t const *    onchain_votes,
                                ulong                      onchain_root ) {
  ulong tip = recovery->saved.votes[ recovery->saved.votes_cnt-1UL ].slot;
  if( FD_UNLIKELY( ( onchain_root!=ULONG_MAX &&
                     ( recovery->saved.root==ULONG_MAX || onchain_root>recovery->saved.root ) ) ||
                   ( !fd_tower_vote_empty( onchain_votes ) && fd_tower_vote_peek_tail_const( onchain_votes )->slot>tip ) ) )
    return FD_TOWER_RECOVER_ERR_STALE;
  return FD_TOWER_RECOVER_READY;
}

int
fd_tower_recover_try( fd_tower_recover_t const * recovery,
                      fd_tower_t *                tower,
                      fd_ghost_t *                ghost,
                      ulong *                     root_slot,
                      fd_hash_t *                 root_block_id ) {
  fd_tower_file_t const * saved = &recovery->saved;
  fd_ghost_blk_t const * snapshot = fd_ghost_root( ghost );
  FD_TEST( fd_tower_vote_empty( tower->votes ) );
  FD_TEST( tower->root==recovery->snapshot_slot );
  FD_TEST( snapshot && snapshot->slot==recovery->snapshot_slot );

  ulong new_root_slot = recovery->snapshot_slot;
  fd_hash_t new_root_id = snapshot->id;
  if( recovery->rooted_cnt==saved->votes_cnt ) {
    *root_slot     = new_root_slot;
    *root_block_id = new_root_id;
    return FD_TOWER_RECOVER_READY;
  }

  fd_ghost_blk_t * tip = fd_ghost_query( ghost, &saved->block_id );
  if( !tip ) return FD_TOWER_RECOVER_WAIT;
  if( FD_UNLIKELY( tip->slot!=saved->votes[ saved->votes_cnt-1UL ].slot ) ) return FD_TOWER_RECOVER_ERR_FORK;
  fd_tower_blk_t * tip_meta = fd_tower_blocks_query( tower, tip->slot );
  if( !tip_meta || !tip_meta->replayed || memcmp( &tip_meta->replayed_block_id, &tip->id, sizeof(fd_hash_t) ) )
    return FD_TOWER_RECOVER_WAIT;
  if( FD_UNLIKELY( memcmp( &tip_meta->bank_hash, &saved->bank_hash, sizeof(fd_hash_t) ) ) )
    return FD_TOWER_RECOVER_ERR_HASH;

  for( fd_ghost_blk_t * blk=tip; blk!=snapshot; ) {
    fd_tower_blk_t * blk_meta = fd_tower_blocks_query( tower, blk->slot );
    if( !blk_meta || !blk_meta->replayed || memcmp( &blk_meta->replayed_block_id, &blk->id, sizeof(fd_hash_t) ) )
      return FD_TOWER_RECOVER_WAIT;
    fd_ghost_blk_t * parent = fd_ghost_parent( ghost, blk );
    if( FD_UNLIKELY( !parent || blk_meta->parent_slot!=parent->slot ) ) return FD_TOWER_RECOVER_ERR_FORK;
    blk = parent;
  }

  /* Validate every retained vote before changing the live tower.  The
     library's slot-indexed metadata must refer to this exact ancestry,
     not an equivocating sibling replayed at the same slot. */
  fd_tower_blk_t * meta[ FD_TOWER_VOTE_MAX ];
  fd_hash_t       ids [ FD_TOWER_VOTE_MAX ];
  fd_ghost_blk_t * ancestor = tip;
  for( ulong i=saved->votes_cnt; i>recovery->rooted_cnt; ) {
    i--;
    ulong slot = saved->votes[ i ].slot;
    while( ancestor && ancestor->slot>slot ) ancestor = fd_ghost_parent( ghost, ancestor );
    if( FD_UNLIKELY( !ancestor || ancestor->slot!=slot ) ) return FD_TOWER_RECOVER_ERR_FORK;
    meta[ i ] = fd_tower_blocks_query( tower, slot );
    if( !meta[ i ] || !meta[ i ]->replayed || memcmp( &meta[ i ]->replayed_block_id, &ancestor->id, sizeof(fd_hash_t) ) )
      return FD_TOWER_RECOVER_WAIT;
    ids[ i ] = ancestor->id;
  }

  if( saved->root!=ULONG_MAX && saved->root>recovery->snapshot_slot ) {
    while( ancestor && ancestor->slot>saved->root ) ancestor = fd_ghost_parent( ghost, ancestor );
    if( FD_UNLIKELY( !ancestor || ancestor->slot!=saved->root ) ) return FD_TOWER_RECOVER_ERR_FORK;
    fd_tower_blk_t * root_meta = fd_tower_blocks_query( tower, saved->root );
    if( !root_meta || !root_meta->replayed || memcmp( &root_meta->replayed_block_id, &ancestor->id, sizeof(fd_hash_t) ) )
      return FD_TOWER_RECOVER_WAIT;
    new_root_slot = saved->root;
    new_root_id   = ancestor->id;
  }

  for( ulong i=recovery->rooted_cnt; i<saved->votes_cnt; i++ ) {
    fd_tower_vote_push_tail( tower->votes, saved->votes[ i ] );
    meta[ i ]->voted          = 1;
    meta[ i ]->voted_block_id = ids[ i ];
  }
  *root_slot     = new_root_slot;
  *root_block_id = new_root_id;
  return FD_TOWER_RECOVER_READY;
}
