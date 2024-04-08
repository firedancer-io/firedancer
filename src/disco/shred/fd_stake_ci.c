#include "fd_stake_ci.h"
#include "../../util/net/fd_ip4.h" /* Just for debug */

#define SORT_NAME sort_pubkey
#define SORT_KEY_T fd_shred_dest_weighted_t
#define SORT_BEFORE(a,b) (memcmp( (a).pubkey.uc, (b).pubkey.uc, 32UL )<0)
#include "../../util/tmpl/fd_sort.c"

/* We don't have or need real contact info for the local validator, but
   we want to be able to distinguish it from staked nodes with no
   contact info. */
#define SELF_DUMMY_IP 1U

void *
fd_stake_ci_new( void             * mem,
                fd_pubkey_t const * identity_key ) {
  fd_stake_ci_t * info = (fd_stake_ci_t *)mem;

  fd_stake_weight_t dummy_stakes[ 1 ] = {{ .key = {{0}}, .stake = 1UL }};
  fd_shred_dest_weighted_t dummy_dests[ 1 ] = {{ .pubkey = *identity_key, .ip4 = SELF_DUMMY_IP }};

  /* Initialize first 2 to satisfy invariants */
  info->stake_weight[ 0 ] = dummy_stakes[ 0 ];
  info->shred_dest  [ 0 ] = dummy_dests [ 0 ];
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_per_epoch_info_t * ei = info->epoch_info + i;
    ei->epoch      = i;
    ei->start_slot = 0UL;
    ei->slot_cnt   = 0UL;

    ei->lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( ei->_lsched, 0UL, 0UL, 1UL, 1UL,    info->stake_weight       ) );
    ei->sdest  = fd_shred_dest_join   ( fd_shred_dest_new   ( ei->_sdest,  info->shred_dest, 1UL, ei->lsched, identity_key ) );
  }
  info->identity_key[ 0 ] = *identity_key;

  return (void *)info;
}

fd_stake_ci_t * fd_stake_ci_join( void * mem ) { return (fd_stake_ci_t *)mem; }

void * fd_stake_ci_leave ( fd_stake_ci_t * info ) { return (void *)info; }
void * fd_stake_ci_delete( void          * mem  ) { return mem;          }


void
fd_stake_ci_stake_msg_init( fd_stake_ci_t * info,
                            uchar const   * new_message ) {
  ulong const * hdr = fd_type_pun_const( new_message );

  ulong epoch               = hdr[ 0 ];
  ulong staked_cnt          = hdr[ 1 ];
  ulong start_slot          = hdr[ 2 ];
  ulong slot_cnt            = hdr[ 3 ];

  if( FD_UNLIKELY( staked_cnt > MAX_SHRED_DESTS ) )
    FD_LOG_ERR(( "The stakes -> Firedancer splice sent a malformed update with %lu stakes in it,"
                 " but the maximum allowed is %lu", staked_cnt, MAX_SHRED_DESTS ));

  info->scratch->epoch      = epoch;
  info->scratch->start_slot = start_slot;
  info->scratch->slot_cnt   = slot_cnt;
  info->scratch->staked_cnt = staked_cnt;

  fd_memcpy( info->stake_weight, hdr+4UL, sizeof(fd_stake_weight_t)*staked_cnt );
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
  new_ei->epoch      = epoch;
  new_ei->start_slot = info->scratch->start_slot;
  new_ei->slot_cnt   = info->scratch->slot_cnt;

  new_ei->lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( new_ei->_lsched, epoch, new_ei->start_slot, new_ei->slot_cnt,
                                                                staked_cnt, info->stake_weight ) );
  new_ei->sdest  = fd_shred_dest_join   ( fd_shred_dest_new   ( new_ei->_sdest, info->shred_dest, j,
                                                                new_ei->lsched, info->identity_key ) );
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
    if( FD_UNLIKELY( dest->stake_lamports==0UL ) ) {
      /* Copy this destination to the unstaked part of the new list */
      info->shred_dest_temp[ j ] = info->shred_dest[ i ];
      info->shred_dest_temp[ j ].stake_lamports = 0UL;
      j++;
    }

    if( FD_LIKELY( idx!=FD_SHRED_DEST_NO_DEST ) ) {
      dest->ip4  = info->shred_dest[ i ].ip4;
      dest->port = info->shred_dest[ i ].port;
      memcpy( dest->mac_addr, info->shred_dest[ i ].mac_addr, 6UL );
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

  ei->sdest  = fd_shred_dest_join( fd_shred_dest_new( ei->_sdest, info->shred_dest_temp, j, ei->lsched, info->identity_key ) );
}


void
fd_stake_ci_dest_add_fini( fd_stake_ci_t * info,
                           ulong           cnt ) {
  /* The Rust side uses tvu_peers which excludes the local validator.
     Add the local validator back. */
  FD_TEST( cnt<MAX_SHRED_DESTS );
  fd_shred_dest_weighted_t self_dests[ 1 ] = {{ .pubkey = info->identity_key[ 0 ], .ip4 = SELF_DUMMY_IP }};
  info->shred_dest[ cnt++ ] = self_dests[ 0 ];

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
