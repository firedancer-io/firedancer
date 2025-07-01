#include "fd_stake_ci.h"
#include "../../util/net/fd_ip4.h" /* Just for debug */

/* A simple alias for readability */
static inline fd_shred_dest_stake_ci_n_t *
get_stake_ci_n( fd_shred_dest_stake_ci_n_t * base, ulong idx, ulong user_ci_cnt ) {
  return fd_shred_dest_stake_ci_n_get_idx( base, idx, user_ci_cnt );
}

typedef struct {
  fd_pubkey_t pubkey;
  ulong       idx;
} sort_pubkey_t;

#define SORT_NAME sort_pubkey
#define SORT_KEY_T sort_pubkey_t
#define SORT_BEFORE(a,b) (memcmp( (a).pubkey.uc, (b).pubkey.uc, 32UL )<0)
#include "../../util/tmpl/fd_sort.c"

static void
sort_unstaked( fd_shred_dest_stake_ci_n_t * unstaked_base, ulong cnt, ulong user_ci_cnt ) {
  sort_pubkey_t buf[ cnt ];
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_shred_dest_stake_ci_n_t const * dest = get_stake_ci_n( unstaked_base, i, user_ci_cnt );
    buf[ i ].pubkey = dest->pubkey;
    buf[ i ].idx = i;
  }

  sort_pubkey_inplace( buf, cnt );

  ulong const user_sz = fd_shred_dest_stake_ci_n_footprint( user_ci_cnt );

  for( ulong i=0UL; i<cnt; i++ ) {
    /* Skip if already processed (marked with cnt) or already in correct position */
    if( buf[i].idx == cnt || buf[i].idx == i ) continue;

    /* Follow the cycle starting from position i */
    uchar temp[user_sz];
    fd_memcpy( temp, get_stake_ci_n( unstaked_base, i, user_ci_cnt ), user_sz );

    ulong current = i;
    while( buf[current].idx != i ) {
      ulong next = buf[current].idx;
      fd_memcpy( get_stake_ci_n( unstaked_base, current, user_ci_cnt ), get_stake_ci_n( unstaked_base, next, user_ci_cnt ), user_sz );
      buf[current].idx = cnt;
      current = next;
    }

    /* Complete the cycle */
    fd_memcpy( get_stake_ci_n( unstaked_base, current, user_ci_cnt ), temp, user_sz );
    buf[current].idx = cnt;
  }
}

/* We don't have or need real contact info for the local validator, but
   we want to be able to distinguish it from staked nodes with no
   contact info. */
#define SELF_DUMMY_IP 1U

void *
fd_stake_ci_new( void              * mem,
                 fd_pubkey_t const * identity_key,
                 ulong               user_ci_cnt ) {
  ulong const user_sz = fd_shred_dest_stake_ci_n_footprint( user_ci_cnt );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stake_ci_t * info = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stake_ci_t), sizeof(fd_stake_ci_t) );

  info->shred_dest        = FD_SCRATCH_ALLOC_APPEND( l,
                                                     alignof(fd_shred_dest_stake_ci_n_t),
                                                     user_sz*MAX_SHRED_DESTS );
  info->shred_dest_temp   = FD_SCRATCH_ALLOC_APPEND( l,
                                                     alignof(fd_shred_dest_stake_ci_n_t),
                                                     user_sz*MAX_SHRED_DESTS );

  /* Initialize dummy stakes and contact info */
  info->stake_weight[ 0 ] = (fd_stake_weight_t){ .key = {{0}}, .stake = 1UL };
  fd_memset( info->shred_dest, 0, user_sz );
  info->shred_dest[0].pubkey = *identity_key;
  for( ulong i=0UL; i<user_ci_cnt; i++ ) {
    info->shred_dest[0].sock_addr[ i ].addr = SELF_DUMMY_IP;
  }

  /* Initialize first 2 to satisfy invariants */
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_per_epoch_info_t * ei = FD_SCRATCH_ALLOC_APPEND( l,
                                                        alignof(fd_per_epoch_info_t),
                                                        fd_per_epoch_info_footprint( user_ci_cnt ) );
    void * sdest_mem   = fd_per_epoch_info_sdest_mem( ei );

    ei->epoch          = i;
    ei->start_slot     = 0UL;
    ei->slot_cnt       = 0UL;
    ei->excluded_stake = 0UL;

    ei->lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( ei->_lsched, 0UL, 0UL, 1UL, 1UL,    info->stake_weight,       0UL ) );
    ei->sdest  = fd_shred_dest_join   ( fd_shred_dest_new   ( sdest_mem, info->shred_dest, 1UL, ei->lsched, identity_key, 0UL, user_ci_cnt ) );

    info->epoch_info[ i ] = ei;
  }

  info->identity_key[ 0 ] = *identity_key;
  info->user_ci_cnt       = user_ci_cnt;

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

  fd_memcpy( info->stake_weight, msg->weights, msg->staked_cnt*sizeof(fd_stake_weight_t) );
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

static inline int
has_ci( fd_shred_dest_stake_ci_n_t const * dest, ulong user_ci_cnt ) {
  ulong retval = 0;
  for( ulong i=0UL; i<user_ci_cnt; i++ ) {
    retval |= dest->sock_addr[ i ].l;
  }
  return (int)( retval>>32 | retval );
}

void
fd_stake_ci_stake_msg_fini( fd_stake_ci_t * info ) {
  /* The grossness here is a sign our abstractions are wrong and need to
     be fixed instead of just patched.  We need to generate weighted
     shred destinations using a combination of the new stake information
     and whatever contact info we previously knew. */
  ulong epoch                  = info->scratch->epoch;
  ulong staked_cnt             = info->scratch->staked_cnt;
  ulong user_ci_cnt            = info->user_ci_cnt;
  ulong user_sz                = fd_shred_dest_stake_ci_n_footprint( user_ci_cnt );

  /* Just take the first one arbitrarily because they both have the same
     contact info, other than possibly some staked nodes with no contact
     info. */
  fd_shred_dest_t * existing_sdest    = info->epoch_info[0]->sdest;
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
    fd_shred_dest_idx_t          old_idx = fd_shred_dest_pubkey_to_idx( existing_sdest, &(info->stake_weight[ i ].key) );
    fd_shred_dest_stake_ci_n_t * in_prev = fd_shred_dest_idx_to_dest( existing_sdest, old_idx );
    fd_shred_dest_stake_ci_n_t * info_e  = get_stake_ci_n( info->shred_dest, i, user_ci_cnt );
    fd_memcpy( info_e, in_prev, user_sz );
    if( FD_UNLIKELY( old_idx==FD_SHRED_DEST_NO_DEST ) ) {
      /* We got the generic empty entry, so fixup the pubkey */
      info_e->pubkey = info->stake_weight[ i ].key;
    } else {
      unhit_set_remove( unhit, old_idx );
    }
    info_e->stake_lamports = info->stake_weight[ i ].stake;
  }

  int any_destaked = 0;
  ulong j = staked_cnt;
  for( ulong idx=unhit_set_iter_init( unhit ); (idx<existing_dest_cnt) & (!unhit_set_iter_done( idx )) & (j<MAX_SHRED_DESTS);
             idx=unhit_set_iter_next( unhit, idx ) ) {
    fd_shred_dest_stake_ci_n_t * in_prev = fd_shred_dest_idx_to_dest( existing_sdest, (fd_shred_dest_idx_t)idx );
    if( FD_LIKELY( has_ci( in_prev, user_ci_cnt ) ) ) {
      fd_shred_dest_stake_ci_n_t * info_e  = get_stake_ci_n( info->shred_dest, j, user_ci_cnt );
      fd_memcpy( info_e, in_prev, user_sz );
      any_destaked |= (in_prev->stake_lamports > 0UL);
      info_e->stake_lamports = 0UL;
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
    fd_shred_dest_stake_ci_n_t * unstaked_base = get_stake_ci_n( info->shred_dest, staked_cnt, user_ci_cnt );
    sort_unstaked( unstaked_base, j - staked_cnt, user_ci_cnt );
  }

  /* Now we have a plausible shred_dest list. */

  /* Clear the existing info */
  fd_per_epoch_info_t * new_ei = info->epoch_info[ epoch % 2UL ];
  fd_shred_dest_delete   ( fd_shred_dest_leave   ( new_ei->sdest  ) );
  fd_epoch_leaders_delete( fd_epoch_leaders_leave( new_ei->lsched ) );

  /* And create the new one */
  ulong excluded_stake = info->scratch->excluded_stake;
  void * sdest_mem = fd_per_epoch_info_sdest_mem( new_ei );

  new_ei->epoch          = epoch;
  new_ei->start_slot     = info->scratch->start_slot;
  new_ei->slot_cnt       = info->scratch->slot_cnt;
  new_ei->excluded_stake = excluded_stake;

  new_ei->lsched = fd_epoch_leaders_join( fd_epoch_leaders_new( new_ei->_lsched, epoch, new_ei->start_slot, new_ei->slot_cnt,
                                                                staked_cnt, info->stake_weight,     excluded_stake ) );
  new_ei->sdest  = fd_shred_dest_join   ( fd_shred_dest_new   ( sdest_mem, info->shred_dest, j,
                                                                new_ei->lsched, info->identity_key, excluded_stake, user_ci_cnt ) );
  log_summary( "stake update", info );
}

fd_shred_dest_stake_ci_n_t * fd_stake_ci_dest_add_init( fd_stake_ci_t * info ) { return info->shred_dest; }

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

  ulong const user_ci_cnt = info->user_ci_cnt;
  ulong const user_sz     = fd_shred_dest_stake_ci_n_footprint( user_ci_cnt );
  ulong const staked_cnt  = fd_shred_dest_cnt_staked( ei->sdest );

  ulong j = staked_cnt;
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_shred_dest_stake_ci_n_t * shred_dest_e = get_stake_ci_n( info->shred_dest, i, user_ci_cnt );
    fd_shred_dest_idx_t          idx          = fd_shred_dest_pubkey_to_idx( ei->sdest, &(shred_dest_e->pubkey) );
    fd_shred_dest_stake_ci_n_t * dest         = fd_shred_dest_idx_to_dest( ei->sdest, idx );

    if( FD_UNLIKELY( (dest->stake_lamports==0UL)&(j<MAX_SHRED_DESTS) ) ) {
      /* Copy this destination to the unstaked part of the new list.
         This also handles the new unstaked case */
      fd_shred_dest_stake_ci_n_t * shred_dest_temp_e  = get_stake_ci_n( info->shred_dest_temp, j, user_ci_cnt );
      fd_memcpy( shred_dest_temp_e, shred_dest_e, user_sz );
      shred_dest_temp_e->stake_lamports = 0UL;
      j++;
    }

    if( FD_LIKELY( idx!=FD_SHRED_DEST_NO_DEST ) ) {
      fd_memcpy( dest->sock_addr, shred_dest_e->sock_addr, user_ci_cnt*sizeof(fd_ip4_port_t) );
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
  for( ulong i=0UL; i<staked_cnt; i++ ) {
    fd_shred_dest_stake_ci_n_t * shred_dest_temp_e = get_stake_ci_n( info->shred_dest_temp, i, user_ci_cnt );
    fd_memcpy( shred_dest_temp_e, fd_shred_dest_idx_to_dest( ei->sdest, (fd_shred_dest_idx_t)i ), user_sz );
  }

  /* The staked nodes are sorted properly because we use the index from
     sdest.  We need to sort the unstaked nodes by pubkey though. */
  fd_shred_dest_stake_ci_n_t * unstaked_base = get_stake_ci_n( info->shred_dest_temp, staked_cnt, user_ci_cnt );
  sort_unstaked( unstaked_base, j - staked_cnt, user_ci_cnt );

  fd_shred_dest_delete( fd_shred_dest_leave( ei->sdest ) );

  void * sdest_mem = fd_per_epoch_info_sdest_mem( ei );
  ei->sdest  = fd_shred_dest_join( fd_shred_dest_new( sdest_mem, info->shred_dest_temp, j, ei->lsched, info->identity_key,
                                                      ei->excluded_stake, user_ci_cnt ) );

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
  ulong const user_ci_cnt = info->user_ci_cnt;
  ulong i=0UL;
  for(; i<cnt; i++ ) {
    fd_shred_dest_stake_ci_n_t const * shred_dest_e = get_stake_ci_n( info->shred_dest, i, user_ci_cnt );
    if( FD_UNLIKELY( 0==memcmp( shred_dest_e->pubkey.uc, info->identity_key, 32UL ) ) ) break;
  }

  fd_shred_dest_stake_ci_n_t * stake_ci_n_e;
  if( FD_LIKELY( i==cnt ) ) {
    stake_ci_n_e = get_stake_ci_n( info->shred_dest, cnt, user_ci_cnt );
    stake_ci_n_e->pubkey = info->identity_key[0];
    cnt++;
  } else {
    stake_ci_n_e = get_stake_ci_n( info->shred_dest, i, user_ci_cnt );
  }

  for( ulong j=0UL; j<info->user_ci_cnt; j++ ) {
    stake_ci_n_e->sock_addr[ j ].addr = SELF_DUMMY_IP;
  }

  /* Update both of them */
  fd_stake_ci_dest_add_fini_impl( info, cnt, info->epoch_info[0] );
  fd_stake_ci_dest_add_fini_impl( info, cnt, info->epoch_info[1] );

  log_summary( "dest update", info );
}


/* Returns a value in [0, 2) if found, and ULONG_MAX if not */
static inline ulong
fd_stake_ci_get_idx_for_slot( fd_stake_ci_t const * info,
                              ulong                 slot ) {
  fd_per_epoch_info_t * const * ei = info->epoch_info;
  ulong idx = ULONG_MAX;
  for( ulong i=0UL; i<2UL; i++ ) idx = fd_ulong_if( (ei[i]->start_slot<=slot) & (slot-ei[i]->start_slot<ei[i]->slot_cnt), i, idx );
  return idx;
}


void
fd_stake_ci_set_identity( fd_stake_ci_t *     info,
                          fd_pubkey_t const * identity_key ) {
  /* None of the stakes are changing, so we just need to regenerate the
     sdests, sightly adjusting the destination IP addresses.  The only
     corner case is if the new identity is not present. */
  ulong const user_ci_cnt = info->user_ci_cnt;
  ulong const user_sz = fd_shred_dest_stake_ci_n_footprint( user_ci_cnt );

  for( ulong i=0UL; i<2UL; i++ ) {
    fd_per_epoch_info_t * ei = info->epoch_info[i];

    fd_shred_dest_idx_t old_idx = fd_shred_dest_pubkey_to_idx( ei->sdest, info->identity_key );
    fd_shred_dest_idx_t new_idx = fd_shred_dest_pubkey_to_idx( ei->sdest, identity_key       );

    FD_TEST( old_idx!=FD_SHRED_DEST_NO_DEST );

    if( FD_LIKELY( new_idx!=FD_SHRED_DEST_NO_DEST ) ) {
      fd_shred_dest_stake_ci_n_t * old_dest = fd_shred_dest_idx_to_dest( ei->sdest, old_idx );
      fd_shred_dest_stake_ci_n_t * new_dest = fd_shred_dest_idx_to_dest( ei->sdest, new_idx );
      for( ulong j=0UL; j<user_ci_cnt; j++ ) {
        old_dest->sock_addr[ j ].addr = 0U;
        new_dest->sock_addr[ j ].addr = SELF_DUMMY_IP;
      }

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
      for(; j<staked_cnt; j++ ) {
        fd_shred_dest_stake_ci_n_t * shred_dest_temp_e = get_stake_ci_n( info->shred_dest_temp, j, user_ci_cnt );
        fd_memcpy( shred_dest_temp_e, fd_shred_dest_idx_to_dest( ei->sdest, (fd_shred_dest_idx_t)j ), user_sz );
      }
      for(; j<staked_cnt+unstaked_cnt; j++ ) {
        fd_shred_dest_stake_ci_n_t * wj = fd_shred_dest_idx_to_dest( ei->sdest, (fd_shred_dest_idx_t)j );
        if( FD_UNLIKELY( (memcmp( wj->pubkey.uc, identity_key->uc, 32UL )>=0) ) ) break;
        fd_memcpy( get_stake_ci_n( info->shred_dest_temp, j, user_ci_cnt ), wj, user_sz );
      }

      do {
        fd_shred_dest_stake_ci_n_t * shred_dest_temp_e = get_stake_ci_n( info->shred_dest_temp, j, user_ci_cnt );
        shred_dest_temp_e->pubkey = *identity_key;
        shred_dest_temp_e->stake_lamports = 0UL;
        for( ulong k=0UL; k<user_ci_cnt; k++ ) {
          shred_dest_temp_e->sock_addr[ k ].addr = SELF_DUMMY_IP;
        }
      } while( 0 );

      for(; j<staked_cnt+unstaked_cnt; j++ ) {
        fd_shred_dest_stake_ci_n_t * shred_dest_temp_e = get_stake_ci_n( info->shred_dest_temp, j+1UL, user_ci_cnt );
        fd_memcpy( shred_dest_temp_e, fd_shred_dest_idx_to_dest( ei->sdest, (fd_shred_dest_idx_t)j ), user_sz );
      }

      fd_shred_dest_delete( fd_shred_dest_leave( ei->sdest ) );

      void * sdest_mem = fd_per_epoch_info_sdest_mem( ei );
      ei->sdest  = fd_shred_dest_join( fd_shred_dest_new( sdest_mem, info->shred_dest_temp, j+1UL, ei->lsched, identity_key,
                                                          ei->excluded_stake, user_ci_cnt ) );
      FD_TEST( ei->sdest );
    }

  }
  *info->identity_key = *identity_key;
}


fd_shred_dest_t *
fd_stake_ci_get_sdest_for_slot( fd_stake_ci_t const * info,
                                ulong                 slot ) {
  ulong idx = fd_stake_ci_get_idx_for_slot( info, slot );
  return idx!=ULONG_MAX ? info->epoch_info[ idx ]->sdest : NULL;
}

fd_epoch_leaders_t *
fd_stake_ci_get_lsched_for_slot( fd_stake_ci_t const * info,
                                 ulong                 slot ) {
  ulong idx = fd_stake_ci_get_idx_for_slot( info, slot );
  return idx!=ULONG_MAX ? info->epoch_info[ idx ]->lsched : NULL;
}
