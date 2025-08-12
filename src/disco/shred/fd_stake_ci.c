#include "fd_stake_ci.h"
#include "fd_shred_dest.h"
#include "../../util/net/fd_ip4.h" /* Just for debug */

#define SORT_NAME sort_pubkey
#define SORT_KEY_T fd_shred_dest_weighted_t
#define SORT_BEFORE(a,b) (memcmp( (a).pubkey.uc, (b).pubkey.uc, 32UL )<0)
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME sort_weights_by_stake_id
#define SORT_KEY_T fd_stake_weight_t
#define SORT_BEFORE(a,b) ((a).stake > (b).stake ? 1 : ((a).stake < (b).stake ? 0 : memcmp( (a).key.uc, (b).key.uc, 32UL )>0))
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME sort_weights_by_id
#define SORT_KEY_T fd_stake_weight_t
#define SORT_BEFORE(a,b) (memcmp( (a).key.uc, (b).key.uc, 32UL )>0)
#include "../../util/tmpl/fd_sort.c"

/* We don't have or need real contact info for the local validator, but
   we want to be able to distinguish it from staked nodes with no
   contact info. */
#define SELF_DUMMY_IP 1U

void *
fd_stake_ci_new( void             * mem,
                fd_pubkey_t const * identity_key ) {
  fd_stake_ci_t * info = (fd_stake_ci_t *)mem;

  fd_vote_stake_weight_t dummy_stakes[ 1 ] = {{ .vote_key = {{0}}, .id_key = {{0}}, .stake = 1UL }};
  fd_shred_dest_weighted_t dummy_dests[ 1 ] = {{ .pubkey = *identity_key, .ip4 = SELF_DUMMY_IP }};

  /* Initialize first 2 to satisfy invariants */
  info->vote_stake_weight[ 0 ] = dummy_stakes[ 0 ];
  info->shred_dest  [ 0 ] = dummy_dests [ 0 ];
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_per_epoch_info_t * ei = info->epoch_info + i;
    ei->epoch          = i;
    ei->start_slot     = 0UL;
    ei->slot_cnt       = 0UL;
    ei->excluded_stake = 0UL;
    ei->vote_keyed_lsched = 0UL;

    ei->lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( ei->_lsched, 0UL, 0UL, 1UL, 1UL,    info->vote_stake_weight,  0UL, ei->vote_keyed_lsched ) );
    ei->sdest  = fd_shred_dest_join   ( fd_shred_dest_new   ( ei->_sdest,  info->shred_dest, 1UL, ei->lsched, identity_key, 0UL ) );
  }
  info->identity_key[ 0 ] = *identity_key;

  return (void *)info;
}

fd_stake_ci_t * fd_stake_ci_join( void * mem ) { return (fd_stake_ci_t *)mem; }

void * fd_stake_ci_leave ( fd_stake_ci_t * info ) { return (void *)info; }
void * fd_stake_ci_delete( void          * mem  ) { return mem;          }


void
fd_stake_ci_stake_msg_init( fd_stake_ci_t               * info,
                            fd_stake_weight_msg_t const * msg ) {
  if( FD_UNLIKELY( msg->staked_cnt > MAX_SHRED_DESTS ) )
    FD_LOG_ERR(( "The stakes -> Firedancer splice sent a malformed update with %lu stakes in it,"
                 " but the maximum allowed is %lu", msg->staked_cnt, MAX_SHRED_DESTS ));

  info->scratch->epoch          = msg->epoch;
  info->scratch->start_slot     = msg->start_slot;
  info->scratch->slot_cnt       = msg->slot_cnt;
  info->scratch->staked_cnt     = msg->staked_cnt;
  info->scratch->excluded_stake = msg->excluded_stake;
  info->scratch->vote_keyed_lsched = msg->vote_keyed_lsched;

  fd_memcpy( info->vote_stake_weight, msg->weights, msg->staked_cnt*sizeof(fd_vote_stake_weight_t) );
}

static inline void
log_summary( char const * msg, fd_stake_ci_t * info ) {
#if 0
  fd_per_epoch_info_t const * ei = info->epoch_info;
  FD_LOG_NOTICE(( "Dumping stake contact information because %s", msg ));
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_LOG_NOTICE(( "  Dumping shred destination details for epoch %lu, slots [%lu, %lu)", ei[i].epoch, ei[i].start_slot, ei[i].start_slot+ei[i].slot_cnt ));
    fd_shred_dest_t * sdest = ei[i].sdest;
    for( fd_shred_dest_idx_t j=0; j<(fd_shred_dest_idx_t)fd_shred_dest_cnt_all( sdest ); j++ ) {
      fd_shred_dest_weighted_t * dest = fd_shred_dest_idx_to_dest( sdest, j );
      FD_LOG_NOTICE(( "    %16lx  %20lu " FD_IP4_ADDR_FMT " %hu ", *(ulong *)dest->pubkey.uc, dest->stake_lamports, FD_IP4_ADDR_FMT_ARGS( dest->ip4 ), dest->port ));
    }
  }
#else
  (void)msg;
  (void)info;
#endif
}

ulong
compute_id_weights_from_vote_weights( fd_stake_weight_t *            stake_weight,
                                      fd_vote_stake_weight_t const * vote_stake_weight,
                                      ulong                          staked_cnt ) {
  /* Copy from input message [(vote, id, stake)] into old format [(id, stake)]. */
  for( ulong i=0UL; i<staked_cnt; i++ ) {
    memcpy( stake_weight[ i ].key.uc, vote_stake_weight[ i ].id_key.uc, sizeof(fd_pubkey_t) );
    stake_weight[ i ].stake = vote_stake_weight[ i ].stake;
  }

  /* Sort [(id, stake)] by id, so we can dedup */
  sort_weights_by_id_inplace( stake_weight, staked_cnt );

  /* Dedup entries, aggregating stake */
  ulong j=0UL;
  for( ulong i=1UL; i<staked_cnt; i++ ) {
    fd_pubkey_t * pre = &stake_weight[ j ].key;
    fd_pubkey_t * cur = &stake_weight[ i ].key;
    if( 0==memcmp( pre, cur, sizeof(fd_pubkey_t) ) ) {
      stake_weight[ j ].stake += stake_weight[ i ].stake;
    } else {
      ++j;
      stake_weight[ j ].stake = stake_weight[ i ].stake;
      memcpy( stake_weight[ j ].key.uc, stake_weight[ i ].key.uc, sizeof(fd_pubkey_t) );
    }
  }
  ulong staked_cnt_by_id = fd_ulong_min( staked_cnt, j+1 );

  /* Sort [(id, stake)] by stake then id, as expected */
  sort_weights_by_stake_id_inplace( stake_weight, staked_cnt_by_id );

  return staked_cnt_by_id;
}

#define SET_NAME unhit_set
#define SET_MAX  MAX_SHRED_DESTS
#include "../../util/tmpl/fd_set.c"

void
fd_stake_ci_stake_msg_fini( fd_stake_ci_t * info ) {
  /* The grossness here is a sign our abstractions are wrong and need to
     be fixed instead of just patched.  We need to generate weighted
     shred destinations using a combination of the new stake information
     and whatever contact info we previously knew. */
  ulong epoch                  = info->scratch->epoch;
  ulong staked_cnt             = info->scratch->staked_cnt;
  ulong unchanged_staked_cnt   = info->scratch->staked_cnt;
  ulong vote_keyed_lsched      = info->scratch->vote_keyed_lsched;

  /* Just take the first one arbitrarily because they both have the same
     contact info, other than possibly some staked nodes with no contact
     info. */
  fd_shred_dest_t * existing_sdest    = info->epoch_info->sdest;
  ulong             existing_dest_cnt = fd_shred_dest_cnt_all( existing_sdest );

  /* Keep track of the destinations in existing_sdest that are not
     staked in this new epoch, i.e. the ones we don't hit in the loop
     below. */
  unhit_set_t _unhit[ unhit_set_word_cnt ];
  /* This memsets to 0, right before we memset to 1, and is probably
     unnecessary, but using it without joining seems like a hack. */
  unhit_set_t * unhit = unhit_set_join( unhit_set_new( _unhit ) );
  unhit_set_full( unhit );

  staked_cnt = compute_id_weights_from_vote_weights( info->stake_weight, info->vote_stake_weight, staked_cnt );

  for( ulong i=0UL; i<staked_cnt; i++ ) {
    fd_shred_dest_idx_t old_idx = fd_shred_dest_pubkey_to_idx( existing_sdest, &(info->stake_weight[ i ].key) );
    fd_shred_dest_weighted_t * in_prev = fd_shred_dest_idx_to_dest( existing_sdest, old_idx );
    info->shred_dest[ i ] = *in_prev;
    if( FD_UNLIKELY( old_idx==FD_SHRED_DEST_NO_DEST ) ) {
      /* We got the generic empty entry, so fixup the pubkey */
      info->shred_dest[ i ].pubkey = info->stake_weight[ i ].key;
    } else {
      unhit_set_remove( unhit, old_idx );
    }
    info->shred_dest[ i ].stake_lamports = info->stake_weight[ i ].stake;
  }

  int any_destaked = 0;
  ulong j = staked_cnt;
  for( ulong idx=unhit_set_iter_init( unhit ); (idx<existing_dest_cnt) & (!unhit_set_iter_done( idx )) & (j<MAX_SHRED_DESTS);
             idx=unhit_set_iter_next( unhit, idx ) ) {
    fd_shred_dest_weighted_t * in_prev = fd_shred_dest_idx_to_dest( existing_sdest, (fd_shred_dest_idx_t)idx );
    if( FD_LIKELY( in_prev->ip4 ) ) {
      info->shred_dest[ j ] = *in_prev;
      any_destaked |= (in_prev->stake_lamports > 0UL);
      info->shred_dest[ j ].stake_lamports = 0UL;
      j++;
    }
  }

  unhit_set_delete( unhit_set_leave( unhit ) );

  if( FD_UNLIKELY( any_destaked ) ) {
    /* The unstaked list might be a little out of order because the
       destinations that were previously staked will be at the start of
       the unstaked list, sorted by their previous stake, instead of
       where they should be.  If there weren't any destaked, then the
       only unstaked nodes come from the previous list, which we know
       was in order, perhaps skipping some, which doesn't ruin the
       order. */
    sort_pubkey_inplace( info->shred_dest + staked_cnt, j - staked_cnt );
  }

  /* Now we have a plausible shred_dest list. */

  /* Clear the existing info */
  fd_per_epoch_info_t * new_ei = info->epoch_info + (epoch % 2UL);
  fd_shred_dest_delete   ( fd_shred_dest_leave   ( new_ei->sdest  ) );
  fd_epoch_leaders_delete( fd_epoch_leaders_leave( new_ei->lsched ) );

  /* And create the new one */
  ulong excluded_stake = info->scratch->excluded_stake;

  new_ei->epoch          = epoch;
  new_ei->start_slot     = info->scratch->start_slot;
  new_ei->slot_cnt       = info->scratch->slot_cnt;
  new_ei->excluded_stake = excluded_stake;
  new_ei->vote_keyed_lsched = vote_keyed_lsched;

  new_ei->lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( new_ei->_lsched, epoch, new_ei->start_slot, new_ei->slot_cnt,
                                                                unchanged_staked_cnt, info->vote_stake_weight, excluded_stake, vote_keyed_lsched ) );
  new_ei->sdest  = fd_shred_dest_join   ( fd_shred_dest_new   ( new_ei->_sdest, info->shred_dest, j,
                                                                new_ei->lsched, info->identity_key,  excluded_stake ) );
  log_summary( "stake update", info );
}

fd_shred_dest_weighted_t * fd_stake_ci_dest_add_init( fd_stake_ci_t * info ) { return info->shred_dest; }

static inline void
fd_stake_ci_dest_add_fini_impl( fd_stake_ci_t       * info,
                                ulong                 cnt,
                                fd_per_epoch_info_t * ei ) {
  /* Initially we start with one list containing S+U staked and unstaked
     destinations jumbled together.  In order to update sdest, we need
     to convert the list to S' staked destinations (taken from the
     existing sdest, though possibly updated) followed by U unstaked
     destinations.

     It's possible to do this in place, but at a cost of additional
     complexity (similar to memcpy vs memmove).  Rather than do that, we
     build the combined list in shred_dest_temp. */

  ulong found_unstaked_cnt = 0UL;
  int   any_new_unstaked   = 0;

  ulong const staked_cnt = fd_shred_dest_cnt_staked( ei->sdest );
  ulong j = staked_cnt;

  for( ulong i=0UL; i<cnt; i++ ) {
    fd_shred_dest_idx_t idx = fd_shred_dest_pubkey_to_idx( ei->sdest, &(info->shred_dest[ i ].pubkey) );
    fd_shred_dest_weighted_t * dest = fd_shred_dest_idx_to_dest( ei->sdest, idx );
    if( FD_UNLIKELY( (dest->stake_lamports==0UL)&(j<MAX_SHRED_DESTS) ) ) {
      /* Copy this destination to the unstaked part of the new list.
         This also handles the new unstaked case */
      info->shred_dest_temp[ j ] = info->shred_dest[ i ];
      info->shred_dest_temp[ j ].stake_lamports = 0UL;
      j++;
    }

    if( FD_LIKELY( idx!=FD_SHRED_DEST_NO_DEST ) ) {
      dest->ip4  = info->shred_dest[ i ].ip4;
      dest->port = info->shred_dest[ i ].port;
    }

    any_new_unstaked   |= (idx==FD_SHRED_DEST_NO_DEST);
    found_unstaked_cnt += (ulong)((idx!=FD_SHRED_DEST_NO_DEST) & (dest->stake_lamports==0UL));
  }

  if( FD_LIKELY( !any_new_unstaked && found_unstaked_cnt==fd_shred_dest_cnt_unstaked( ei->sdest ) ) ) {
    /* Because any_new_unstaked==0, the set of unstaked nodes in this
       update is fully contained in the set of unstaked nodes in the
       sdest.  Then additionally, because the sets are the same size,
       they must actually be equal.  In this case, we've already updated
       the existing shred_dest_weighted with the newest contact info we
       have, so there's nothing else to do. */
    return;
  }

  /* Otherwise something more significant changed and we need to
     regenerate the sdest.  At this point, elements [staked_cnt, j) now
     contain all the current unstaked destinations. */

  /* Copy staked nodes to [0, staked_cnt). We've already applied the
     updated contact info to these. */
  for( ulong i=0UL; i<staked_cnt; i++ )
    info->shred_dest_temp[ i ] = *fd_shred_dest_idx_to_dest( ei->sdest, (fd_shred_dest_idx_t)i );

  /* The staked nodes are sorted properly because we use the index from
     sdest.  We need to sort the unstaked nodes by pubkey though. */
  sort_pubkey_inplace( info->shred_dest_temp + staked_cnt, j - staked_cnt );

  fd_shred_dest_delete( fd_shred_dest_leave( ei->sdest ) );

  ei->sdest  = fd_shred_dest_join( fd_shred_dest_new( ei->_sdest, info->shred_dest_temp, j, ei->lsched, info->identity_key,
                                                      ei->excluded_stake ) );

  if( FD_UNLIKELY( ei->sdest==NULL ) ) {
    /* Happens if the identity key is not present, which can only happen
       if the current validator's stake is not in the top 40,200.  We
       could initialize ei->sdest to a dummy value, but having the wrong
       stake weights could lead to potentially slashable issues
       elsewhere (e.g. we might product a block when we're not actually
       leader).  We're just going to terminate in this case. */
    FD_LOG_ERR(( "Too many validators have higher stake than this validator.  Cannot continue." ));
  }
}


void
fd_stake_ci_dest_add_fini( fd_stake_ci_t * info,
                           ulong           cnt ) {
  /* The Rust side uses tvu_peers which typically excludes the local
     validator.  In some cases, after a set-identity, it might still
     include the local validator though.  If it doesn't include it, we
     need to add the local validator back. */
  FD_TEST( cnt<MAX_SHRED_DESTS );
  ulong i=0UL;
  for(; i<cnt; i++ ) if( FD_UNLIKELY( 0==memcmp( info->shred_dest[ i ].pubkey.uc, info->identity_key, 32UL ) ) ) break;

  if( FD_LIKELY( i==cnt ) ) {
    fd_shred_dest_weighted_t self_dests = { .pubkey = info->identity_key[ 0 ], .ip4 = SELF_DUMMY_IP };
    info->shred_dest[ cnt++ ] = self_dests;
  } else {
    info->shred_dest[ i ].ip4 = SELF_DUMMY_IP;
  }

  /* Update both of them */
  fd_stake_ci_dest_add_fini_impl( info, cnt, info->epoch_info + 0UL );
  fd_stake_ci_dest_add_fini_impl( info, cnt, info->epoch_info + 1UL );

  log_summary( "dest update", info );
}


/* Returns a value in [0, 2) if found, and ULONG_MAX if not */
static inline ulong
fd_stake_ci_get_idx_for_slot( fd_stake_ci_t const * info,
                              ulong                 slot ) {
  fd_per_epoch_info_t const * ei = info->epoch_info;
  ulong idx = ULONG_MAX;
  for( ulong i=0UL; i<2UL; i++ ) idx = fd_ulong_if( (ei[i].start_slot<=slot) & (slot-ei[i].start_slot<ei[i].slot_cnt), i, idx );
  return idx;
}


void
fd_stake_ci_set_identity( fd_stake_ci_t *     info,
                          fd_pubkey_t const * identity_key ) {
  /* None of the stakes are changing, so we just need to regenerate the
     sdests, sightly adjusting the destination IP addresses.  The only
     corner case is if the new identity is not present. */
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_per_epoch_info_t * ei = info->epoch_info+i;

    fd_shred_dest_idx_t old_idx = fd_shred_dest_pubkey_to_idx( ei->sdest, info->identity_key );
    fd_shred_dest_idx_t new_idx = fd_shred_dest_pubkey_to_idx( ei->sdest, identity_key       );

    FD_TEST( old_idx!=FD_SHRED_DEST_NO_DEST );

    if( FD_LIKELY( new_idx!=FD_SHRED_DEST_NO_DEST ) ) {
      fd_shred_dest_idx_to_dest( ei->sdest, old_idx )->ip4 = 0U;
      fd_shred_dest_idx_to_dest( ei->sdest, new_idx )->ip4 = SELF_DUMMY_IP;

      fd_shred_dest_update_source( ei->sdest, new_idx );
    } else {
      ulong staked_cnt   = fd_shred_dest_cnt_staked  ( ei->sdest );
      ulong unstaked_cnt = fd_shred_dest_cnt_unstaked( ei->sdest );
      if( FD_UNLIKELY( staked_cnt+unstaked_cnt==MAX_SHRED_DESTS ) ) {
        FD_LOG_ERR(( "too many validators in shred table to add a new validator with set-identity" ));
      }
      /* We'll add identity_key as a new unstaked validator.  First copy
         all the staked ones, then place the new validator in the spot
         where it belongs according to lexicographic order. */
      ulong j=0UL;
      for(; j<staked_cnt; j++ ) info->shred_dest_temp[ j ] = *fd_shred_dest_idx_to_dest( ei->sdest, (fd_shred_dest_idx_t)j );
      for(; j<staked_cnt+unstaked_cnt; j++ ) {
        fd_shred_dest_weighted_t * wj = fd_shred_dest_idx_to_dest( ei->sdest, (fd_shred_dest_idx_t)j );
        if( FD_UNLIKELY( (memcmp( wj->pubkey.uc, identity_key->uc, 32UL )>=0) ) ) break;
        info->shred_dest_temp[ j ] = *wj;
      }

      info->shred_dest_temp[ j ].pubkey         = *identity_key;
      info->shred_dest_temp[ j ].stake_lamports = 0UL;
      info->shred_dest_temp[ j ].ip4            = SELF_DUMMY_IP;

      for(; j<staked_cnt+unstaked_cnt; j++ ) info->shred_dest_temp[ j+1UL ] = *fd_shred_dest_idx_to_dest( ei->sdest, (fd_shred_dest_idx_t)j );

      fd_shred_dest_delete( fd_shred_dest_leave( ei->sdest ) );

      ei->sdest  = fd_shred_dest_join( fd_shred_dest_new( ei->_sdest, info->shred_dest_temp, j+1UL, ei->lsched, identity_key,
                                                          ei->excluded_stake ) );
      FD_TEST( ei->sdest );
    }

  }
  *info->identity_key = *identity_key;
}

void
refresh_sdest( fd_stake_ci_t *            info,
               fd_shred_dest_weighted_t * shred_dest_temp,
               ulong                      cnt,
               ulong                      staked_cnt,
               fd_per_epoch_info_t *      ei ) {
  sort_pubkey_inplace( shred_dest_temp + staked_cnt, cnt - staked_cnt );

  fd_shred_dest_delete( fd_shred_dest_leave( ei->sdest ) );
  ei->sdest = fd_shred_dest_join( fd_shred_dest_new( ei->_sdest, shred_dest_temp, cnt, ei->lsched, info->identity_key, ei->excluded_stake ) );
  if( FD_UNLIKELY( ei->sdest==NULL ) ) {
    FD_LOG_ERR(( "Too many validators have higher stake than this validator.  Cannot continue." ));
  }
}

void
ci_dest_add_one_unstaked( fd_stake_ci_t *            info,
                          fd_shred_dest_weighted_t * new_entry,
                          fd_per_epoch_info_t *      ei ) {
  if( fd_shred_dest_cnt_all( ei->sdest )>=MAX_SHRED_DESTS ) {
    FD_LOG_WARNING(( "Too many validators in shred table to add a new validator." ));
  }
  ulong cur_cnt = fd_shred_dest_cnt_all( ei->sdest );
  for( ulong i=0UL; i<cur_cnt; i++ ) {
    info->shred_dest_temp[ i ] = *fd_shred_dest_idx_to_dest( ei->sdest, (fd_shred_dest_idx_t)i );
  }

  /* TODO: Alternative batched copy using memcpy. Check with Philip if safe */
  // fd_shred_dest_weighted_t * cur_dest = ei->sdest->all_destinations;
  // fd_memcpy( info->shred_dest_temp, cur_dest, sizeof(fd_shred_dest_weighted_t)*cur_cnt );
  info->shred_dest_temp[ cur_cnt++ ] = *new_entry;
  refresh_sdest( info, info->shred_dest_temp, cur_cnt, fd_shred_dest_cnt_staked( ei->sdest ), ei );
}

void
ci_dest_update_impl( fd_stake_ci_t *       info,
                     fd_pubkey_t const *   pubkey,
                     uint                  ip4,
                     ushort                port,
                     fd_per_epoch_info_t * ei ) {
  fd_shred_dest_idx_t idx = fd_shred_dest_pubkey_to_idx( ei->sdest, pubkey );
  if( idx==FD_SHRED_DEST_NO_DEST ) {
    fd_shred_dest_weighted_t new_entry = { .pubkey = *pubkey, .ip4 = ip4, .port = port, .stake_lamports = 0UL };
    ci_dest_add_one_unstaked( info, &new_entry, ei );
    return;
  }
  fd_shred_dest_weighted_t * dest = fd_shred_dest_idx_to_dest( ei->sdest, idx );
  dest->ip4                       = ip4;
  dest->port                      = port;
}

void
ci_dest_remove_impl( fd_stake_ci_t *       info,
                     fd_pubkey_t const *   pubkey,
                     fd_per_epoch_info_t * ei ) {
  fd_shred_dest_idx_t idx = fd_shred_dest_pubkey_to_idx( ei->sdest, pubkey );
  if( FD_UNLIKELY( idx==FD_SHRED_DEST_NO_DEST ) ) return;

  fd_shred_dest_weighted_t * dest = fd_shred_dest_idx_to_dest( ei->sdest, idx );
  if( FD_UNLIKELY( dest->stake_lamports>0UL ) ) {
    /* A staked entry is not "removed", instead its "stale" address is
       retained */
    return;
  }

  ulong cur_cnt = fd_shred_dest_cnt_all( ei->sdest );
  for( ulong i=0UL, j=0UL; i<cur_cnt; i++ ) {
    if( FD_UNLIKELY( i==idx ) ) continue;
    info->shred_dest_temp[ j++ ] = *fd_shred_dest_idx_to_dest( ei->sdest, (fd_shred_dest_idx_t) i );
  }
  /* TODO: Alternative batched copy using memcpy. Check with Philip if this is safe */
  // fd_shred_dest_weighted_t * cur_dest = ei->sdest->all_destinations;
  // fd_memcpy( info->shred_dest_temp, cur_dest, sizeof(fd_shred_dest_weighted_t)*(idx) );
  // fd_memcpy( info->shred_dest_temp + idx, cur_dest + idx + 1UL, sizeof(fd_shred_dest_weighted_t)*(cur_cnt - idx - 1UL) );
  refresh_sdest( info, info->shred_dest_temp, cur_cnt-1UL, fd_shred_dest_cnt_staked( ei->sdest ), ei );
}

void
fd_stake_ci_dest_update( fd_stake_ci_t *       info,
                         fd_pubkey_t const *   pubkey,
                         uint                  ip4,
                         ushort                port ) {
  ci_dest_update_impl( info, pubkey, ip4, port, info->epoch_info+0UL );
  ci_dest_update_impl( info, pubkey, ip4, port, info->epoch_info+1UL );
}

void
fd_stake_ci_dest_remove( fd_stake_ci_t * info,
                         fd_pubkey_t const * pubkey ) {
  ci_dest_remove_impl( info, pubkey, info->epoch_info+0UL );
  ci_dest_remove_impl( info, pubkey, info->epoch_info+1UL );

}


fd_shred_dest_t *
fd_stake_ci_get_sdest_for_slot( fd_stake_ci_t const * info,
                                ulong                 slot ) {
  ulong idx = fd_stake_ci_get_idx_for_slot( info, slot );
  return idx!=ULONG_MAX ? info->epoch_info[ idx ].sdest : NULL;
}

fd_epoch_leaders_t *
fd_stake_ci_get_lsched_for_slot( fd_stake_ci_t const * info,
                                 ulong                 slot ) {
  ulong idx = fd_stake_ci_get_idx_for_slot( info, slot );
  return idx!=ULONG_MAX ? info->epoch_info[ idx ].lsched : NULL;
}
