#include "fd_tower_recover.h"

#include <string.h>

int
fd_tower_recover_init( fd_tower_recover_t *           out,
                       fd_tower_file_t const *        saved,
                       ulong                          snapshot_slot,
                       fd_slot_history_view_t const * history ) {
  FD_TEST( saved->votes_cnt && saved->votes_cnt<=FD_TOWER_VOTE_MAX );
  if( FD_UNLIKELY( snapshot_slot==ULONG_MAX || !history ||
                   history->next_slot!=snapshot_slot+1UL ||
                   history->bits_len!=FD_SLOT_HISTORY_MAX_ENTRIES ||
                   history->blocks_len!=FD_SLOT_HISTORY_MAX_ENTRIES/64UL ||
                   !history->bits ) ) return FD_TOWER_RECOVER_ERR_HISTORY;

  /* Newest to oldest.  Everything above the anchor, the newest saved
     slot the cluster rooted, is kept as a lockout. */
  int   anchored = 0;
  ulong retained = 0UL;
  for( ulong i=saved->votes_cnt; i>0UL; ) {
    i--;
    int check = fd_sysvar_slot_history_find_slot( history, saved->votes[ i ].slot );
    if( !anchored ) {
      if     ( check==FD_SLOT_HISTORY_SLOT_FOUND   ) anchored = 1;
      else if( check==FD_SLOT_HISTORY_SLOT_TOO_OLD ) return FD_TOWER_RECOVER_ERR_HISTORY;
      else                                           retained++;
    } else if( check==FD_SLOT_HISTORY_SLOT_NOT_FOUND ) {
      return FD_TOWER_RECOVER_ERR_FORK;
    }
  }
  if( saved->root!=ULONG_MAX ) {
    int check = fd_sysvar_slot_history_find_slot( history, saved->root );
    if( anchored ) {
      if( check==FD_SLOT_HISTORY_SLOT_NOT_FOUND ) return FD_TOWER_RECOVER_ERR_FORK;
    } else if( check==FD_SLOT_HISTORY_SLOT_FOUND ) {
      anchored = 1;
    } else if( check!=FD_SLOT_HISTORY_SLOT_FUTURE ) {
      return FD_TOWER_RECOVER_ERR_HISTORY;
    }
  }
  /* No slot in common with the rooted history is only fine when the
     whole tower is newer than the snapshot. */
  if( !anchored && saved->votes[ 0 ].slot<=snapshot_slot ) return FD_TOWER_RECOVER_ERR_HISTORY;

  out->saved         = *saved;
  out->snapshot_slot = snapshot_slot;
  out->retained_cnt  = retained;
  return FD_TOWER_RECOVER_READY;
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

void
fd_tower_recover_install( fd_tower_recover_t const * recovery,
                          fd_tower_t *               tower ) {
  FD_TEST( fd_tower_vote_empty( tower->votes ) );
  FD_TEST( tower->root==recovery->snapshot_slot );
  fd_tower_file_t const * saved = &recovery->saved;
  for( ulong i=saved->votes_cnt-recovery->retained_cnt; i<saved->votes_cnt; i++ )
    fd_tower_vote_push_tail( tower->votes, saved->votes[ i ] );
  /* The tower checks that assume a vote sits on a block we replayed
     take another path for the restored votes, see fd_tower_vote_is_restored. */
  if( recovery->retained_cnt ) tower->restored_tip = saved->votes[ saved->votes_cnt-1UL ].slot;
  /* A root above the snapshot stays the root we put in votes and use as
     the switch floor, as Agave keeps its tower root. */
  if( saved->root!=ULONG_MAX && saved->root>tower->root ) tower->saved_root = saved->root;
}

int
fd_tower_recover_replayed( fd_tower_recover_t const * recovery,
                           fd_tower_t *               tower,
                           ulong                      slot,
                           fd_hash_t const *          block_id ) {
  fd_tower_file_t const * saved = &recovery->saved;
  for( ulong i=saved->votes_cnt-recovery->retained_cnt; i<saved->votes_cnt; i++ ) {
    if( saved->votes[ i ].slot!=slot ) continue;
    fd_tower_blk_t * blk = fd_tower_blocks_query( tower, slot );
    if( FD_UNLIKELY( !blk || blk->voted ) ) return 1;
    /* The vote follows the slot, like Agave's slot keyed ancestors.  A
       different block at the tip slot is noted, the lockout binds to whatever
       the cluster built there. */
    if( FD_UNLIKELY( i+1UL==saved->votes_cnt ) ) {
      if( !fd_memeq( &saved->block_id, block_id, sizeof(fd_hash_t) ) )
        FD_LOG_NOTICE(( "saved tower tip slot %lu was replayed as a different block, the restored vote follows the slot", slot ));
      else if( !fd_memeq( &saved->bank_hash, &blk->bank_hash, sizeof(fd_hash_t) ) )
        FD_LOG_WARNING(( "saved tower tip slot %lu replayed with a different bank hash than the one voted on", slot ));
    }
    blk->voted          = 1;
    blk->voted_block_id = *block_id;
    return 1;
  }
  return 0;
}
