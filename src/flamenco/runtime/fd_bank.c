#include "fd_bank.h"
#include "../events/fd_event_runtime.h"
#include "fd_runtime_const.h"
#include "../rewards/fd_stake_rewards.h"
#include "sysvar/fd_sysvar_cache.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"

#include <errno.h>
#include <unistd.h>

/* Each collector override set retains at most three epoch tags.
   Fork width controls logical forks, not the two-set RAM cache. */
#define FD_COLLECTOR_OVERRIDES_MAX (3UL*FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS)

FD_STATIC_ASSERT( FD_COLLECTOR_OVERRIDES_MAX_FORK_WIDTH==FD_BANKS_MAX_BANKS, collector_overrides_fork_width );
#define FD_BANKS_STAKE_REWARDS_CACHE_CNT (2UL)

FD_STATIC_ASSERT( FD_BANKS_MAX_BANKS<USHORT_MAX, epoch_credits_fork_id_width );

fd_lthash_value_t const *
fd_bank_lthash_locking_query( fd_bank_t * bank ) {
  fd_rwlock_read( &bank->lthash_lock );
  return &bank->f.lthash;
}

void
fd_bank_lthash_end_locking_query( fd_bank_t * bank ) {
  fd_rwlock_unread( &bank->lthash_lock );
}

fd_lthash_value_t *
fd_bank_lthash_locking_modify( fd_bank_t * bank ) {
  fd_rwlock_write( &bank->lthash_lock );
  return &bank->f.lthash;
}

void
fd_bank_lthash_end_locking_modify( fd_bank_t * bank ) {
  fd_rwlock_unwrite( &bank->lthash_lock );
}

ulong
fd_banks_align( void ) {
  return FD_BANKS_ALIGN;
}

static fd_bank_t *
fd_banks_get_bank_pool( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->pool_offset );
}

static fd_bank_idx_seq_t *
fd_banks_get_dead_banks_deque( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->dead_banks_deque_offset );
}

static fd_epoch_leaders_t *
fd_banks_get_epoch_leaders( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->epoch_leaders_offset );
}

static fd_stake_delegations_t *
fd_banks_get_stake_delegations( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->stake_delegations_offset );
}

static fd_vote_stakes_t *
fd_banks_get_vote_stakes( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->vote_stakes_offset );
}

static fd_bank_cost_tracker_t *
fd_banks_get_cost_tracker_pool( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->cost_tracker_pool_offset );
}

static uchar *
fd_banks_get_cost_tracker_cache( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->cost_tracker_cache_offset );
}

static inline ulong
fd_banks_cost_tracker_cache_cnt( fd_banks_t const * banks_data ) {
  return fd_ulong_min( banks_data->max_fork_width, FD_BANKS_COST_TRACKER_CACHE_CNT );
}

static void
fd_banks_cost_tracker_disk_read( void * dst,
                                 ulong  pool_idx ) {
  ulong off = pool_idx * FD_COST_TRACKER_FOOTPRINT;
  ulong got = 0UL;
  while( got<FD_COST_TRACKER_FOOTPRINT ) {
    long n = pread( FD_COST_TRACKER_FD, (uchar *)dst+got, FD_COST_TRACKER_FOOTPRINT-got, (long)(off+got) );
    if( FD_UNLIKELY( n<0L ) ) {
      if( FD_LIKELY( errno==EINTR ) ) continue;
      FD_LOG_CRIT(( "pread(cost tracker spill file, fd=%d) failed (%i-%s)", FD_COST_TRACKER_FD, errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( !n ) ) {
      FD_LOG_CRIT(( "unexpected EOF in cost tracker spill file (tracker=%lu offset=%lu size=%lu)",
                    pool_idx, off+got, FD_COST_TRACKER_FOOTPRINT-got ));
    }
    got += (ulong)n;
  }
}

static void
fd_banks_cost_tracker_disk_write( void const * src,
                                  ulong        pool_idx ) {
  ulong off = pool_idx * FD_COST_TRACKER_FOOTPRINT;
  ulong put = 0UL;
  while( put<FD_COST_TRACKER_FOOTPRINT ) {
    long n = pwrite( FD_COST_TRACKER_FD, (uchar const *)src+put, FD_COST_TRACKER_FOOTPRINT-put, (long)(off+put) );
    if( FD_LIKELY( n>0L ) ) {
      put += (ulong)n;
      continue;
    }
    if( FD_UNLIKELY( n<0L && errno==EINTR ) ) continue;
    if( FD_UNLIKELY( !n ) ) errno = EIO;
    FD_LOG_CRIT(( "pwrite(cost tracker spill file, fd=%d) failed (%i-%s)", FD_COST_TRACKER_FD, errno, fd_io_strerror( errno ) ));
  }
}

static ulong
fd_banks_cost_tracker_acquire( fd_banks_t * banks_data ) {
  fd_bank_cost_tracker_t * pool = fd_banks_get_cost_tracker_pool( banks_data );
  fd_rwlock_write( &banks_data->cost_tracker_cache_lock );
  FD_CHECK_CRIT( fd_bank_cost_tracker_pool_free( pool ),
                 "invariant violation: no free cost tracker pool elements" );
  ulong pool_idx = fd_bank_cost_tracker_pool_idx_acquire( pool );
  fd_bank_cost_tracker_pool_ele( pool, pool_idx )->disk_valid = 0U;
  fd_rwlock_unwrite( &banks_data->cost_tracker_cache_lock );
  return pool_idx;
}

static void
fd_banks_cost_tracker_release( fd_banks_t * banks_data,
                               ulong        pool_idx ) {
  fd_bank_cost_tracker_t * pool = fd_banks_get_cost_tracker_pool( banks_data );
  FD_CHECK_CRIT( pool_idx!=fd_bank_cost_tracker_pool_idx_null( pool ),
                 "invariant violation: releasing null cost tracker" );

  fd_rwlock_write( &banks_data->cost_tracker_cache_lock );
  ulong cache_cnt = fd_banks_cost_tracker_cache_cnt( banks_data );
  for( ulong i=0UL; i<cache_cnt; i++ ) {
    if( banks_data->cost_tracker_cache_pool_idx[i]!=pool_idx ) continue;
    FD_CHECK_CRIT( !banks_data->cost_tracker_cache_pin_cnt[i],
                   "invariant violation: releasing pinned cost tracker" );
    banks_data->cost_tracker_cache_pool_idx[i] = ULONG_MAX;
    banks_data->cost_tracker_cache_lru_slot[i] = 0UL;
    banks_data->cost_tracker_cache_dirty[i]    = 0U;
    break;
  }
  fd_bank_cost_tracker_pool_ele( pool, pool_idx )->disk_valid = 0U;
  fd_bank_cost_tracker_pool_idx_release( pool, pool_idx );
  fd_rwlock_unwrite( &banks_data->cost_tracker_cache_lock );
}

static fd_collector_overrides_t *
fd_banks_get_collector_overrides( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->collector_overrides_offset );
}

static fd_epoch_credits_t *
fd_banks_get_epoch_credits_cache( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->epoch_credits_cache_offset );
}

static ulong *
fd_banks_get_epoch_credits_len( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->epoch_credits_len_offset );
}

static ulong *
fd_banks_get_epoch_credits_refcnt( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->epoch_credits_refcnt_offset );
}

static uchar *
fd_banks_get_epoch_credits_disk_valid( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->epoch_credits_disk_valid_offset );
}

static inline ulong
fd_banks_epoch_credits_cache_cnt( fd_banks_t const * banks_data ) {
  return fd_ulong_min( banks_data->max_total_banks, FD_BANKS_EPOCH_CREDITS_CACHE_CNT );
}

static inline ulong
fd_banks_epoch_credits_set_sz( void ) {
  return sizeof(fd_epoch_credits_t) * FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS;
}

static inline ulong
fd_banks_epoch_credits_set_cnt( fd_banks_t const * banks_data ) {
  return banks_data->max_total_banks;
}

static void
fd_banks_epoch_credits_disk_read( void * dst,
                                  ulong  set_idx,
                                  ulong  sz ) {
  ulong off = set_idx * fd_banks_epoch_credits_set_sz();
  ulong got = 0UL;
  while( got<sz ) {
    long n = pread( FD_EPOCH_CREDITS_FD, (uchar *)dst+got, sz-got, (long)(off+got) );
    if( FD_UNLIKELY( n<0L ) ) {
      if( FD_LIKELY( errno==EINTR ) ) continue;
      FD_LOG_CRIT(( "pread(epoch credits spill file, fd=%d) failed (%i-%s)", FD_EPOCH_CREDITS_FD, errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( !n ) ) {
      FD_LOG_CRIT(( "unexpected EOF in epoch credits spill file (set=%lu offset=%lu size=%lu)", set_idx, off+got, sz-got ));
    }
    got += (ulong)n;
  }
}

static void
fd_banks_epoch_credits_disk_write( void const * src,
                                   ulong        set_idx,
                                   ulong        sz ) {
  ulong off = set_idx * fd_banks_epoch_credits_set_sz();
  ulong put = 0UL;
  while( put<sz ) {
    long n = pwrite( FD_EPOCH_CREDITS_FD, (uchar const *)src+put, sz-put, (long)(off+put) );
    if( FD_LIKELY( n>0L ) ) {
      put += (ulong)n;
      continue;
    }
    if( FD_UNLIKELY( n<0L && errno==EINTR ) ) continue;
    if( FD_UNLIKELY( !n ) ) errno = EIO;
    FD_LOG_CRIT(( "pwrite(epoch credits spill file, fd=%d) failed (%i-%s)", FD_EPOCH_CREDITS_FD, errno, fd_io_strerror( errno ) ));
  }
}

static void
fd_banks_epoch_credits_invalidate_locked( fd_banks_t * banks_data,
                                          ulong        set_idx ) {
  ulong cache_cnt = fd_banks_epoch_credits_cache_cnt( banks_data );
  for( ulong i=0UL; i<cache_cnt; i++ ) {
    if( banks_data->epoch_credits_cache_set_idx[i]!=set_idx ) continue;
    FD_CHECK_CRIT( !banks_data->epoch_credits_cache_pin_cnt[i],
                   "invariant violation: invalidating pinned epoch credits set" );
    banks_data->epoch_credits_cache_set_idx[i] = ULONG_MAX;
    banks_data->epoch_credits_cache_lru[i]     = 0UL;
    banks_data->epoch_credits_cache_dirty[i]   = 0U;
    break;
  }

  fd_banks_get_epoch_credits_len( banks_data )[set_idx]        = 0UL;
  fd_banks_get_epoch_credits_disk_valid( banks_data )[set_idx] = 0U;
}

static void
fd_banks_epoch_credits_acquire_locked( fd_banks_t * banks_data,
                                       ulong        set_idx ) {
  FD_CHECK_CRIT( set_idx<fd_banks_epoch_credits_set_cnt( banks_data ),
                 "invariant violation: invalid epoch credits set index" );
  fd_banks_get_epoch_credits_refcnt( banks_data )[set_idx]++;
}

static void
fd_banks_epoch_credits_release_locked( fd_banks_t * banks_data,
                                       ulong        set_idx ) {
  ulong * refcnt = fd_banks_get_epoch_credits_refcnt( banks_data ) + set_idx;
  FD_CHECK_CRIT( *refcnt, "invariant violation: releasing an unreferenced epoch credits set" );
  (*refcnt)--;
  if( FD_UNLIKELY( !*refcnt ) ) fd_banks_epoch_credits_invalidate_locked( banks_data, set_idx );
}

static void
fd_banks_epoch_credits_acquire( fd_banks_t * banks_data,
                                ushort       fork_id ) {
  fd_rwlock_write( &banks_data->epoch_credits_lock );
  fd_banks_epoch_credits_acquire_locked( banks_data, (ulong)fork_id );
  fd_rwlock_unwrite( &banks_data->epoch_credits_lock );
}

static void
fd_banks_epoch_credits_release( fd_banks_t * banks_data,
                                ushort       fork_id ) {
  fd_rwlock_write( &banks_data->epoch_credits_lock );
  fd_banks_epoch_credits_release_locked( banks_data, (ulong)fork_id );
  fd_rwlock_unwrite( &banks_data->epoch_credits_lock );
}

static fd_stake_rewards_t *
fd_banks_get_stake_rewards( fd_banks_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->stake_rewards_offset );
}

fd_bank_epoch_credits_view_t *
fd_bank_epoch_credits_view_init( fd_bank_epoch_credits_view_t * view,
                                 fd_bank_t *                    bank,
                                 int                            write ) {
  if( FD_UNLIKELY( !view || !bank ) ) return NULL;

  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank - bank->banks_data_offset );
  ulong set_idx = (ulong)bank->epoch_credits_fork_id;

  for(;;) {
    fd_rwlock_write( &banks_data->epoch_credits_lock );

    ulong set_cnt = fd_banks_epoch_credits_set_cnt( banks_data );
    FD_CHECK_CRIT( set_idx<set_cnt && fd_banks_get_epoch_credits_refcnt( banks_data )[set_idx],
                   "invariant violation: viewing unreferenced epoch credits set" );

    ulong cache_cnt = fd_banks_epoch_credits_cache_cnt( banks_data );
    ulong cache_idx = ULONG_MAX;
    for( ulong i=0UL; i<cache_cnt; i++ ) {
      if( banks_data->epoch_credits_cache_set_idx[i]==set_idx ) {
        cache_idx = i;
        break;
      }
    }

    if( FD_UNLIKELY( cache_idx==ULONG_MAX ) ) {
      ulong oldest_lru = ULONG_MAX;
      for( ulong i=0UL; i<cache_cnt; i++ ) {
        if( banks_data->epoch_credits_cache_pin_cnt[i] ) continue;
        if( banks_data->epoch_credits_cache_set_idx[i]==ULONG_MAX ) {
          cache_idx = i;
          break;
        }
        if( banks_data->epoch_credits_cache_lru[i]<oldest_lru ) {
          oldest_lru = banks_data->epoch_credits_cache_lru[i];
          cache_idx  = i;
        }
      }

      if( FD_UNLIKELY( cache_idx==ULONG_MAX ) ) {
        fd_rwlock_unwrite( &banks_data->epoch_credits_lock );
        FD_SPIN_PAUSE();
        continue;
      }

      fd_epoch_credits_t * cache = fd_banks_get_epoch_credits_cache( banks_data ) +
          cache_idx * FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS;
      ulong evicted_set_idx = banks_data->epoch_credits_cache_set_idx[cache_idx];
      if( FD_LIKELY( evicted_set_idx!=ULONG_MAX ) ) {
        if( banks_data->epoch_credits_cache_dirty[cache_idx] ) {
          ulong evicted_len = fd_banks_get_epoch_credits_len( banks_data )[evicted_set_idx];
          FD_CHECK_CRIT( evicted_len<=FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS,
                         "invariant violation: invalid epoch credits length" );
          fd_banks_epoch_credits_disk_write( cache, evicted_set_idx, evicted_len*sizeof(fd_epoch_credits_t) );
          fd_banks_get_epoch_credits_disk_valid( banks_data )[evicted_set_idx] = 1U;
        }
      }

      ulong len = fd_banks_get_epoch_credits_len( banks_data )[set_idx];
      FD_CHECK_CRIT( len<=FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS,
                     "invariant violation: invalid epoch credits length" );
      if( fd_banks_get_epoch_credits_disk_valid( banks_data )[set_idx] ) {
        fd_banks_epoch_credits_disk_read( cache, set_idx, len*sizeof(fd_epoch_credits_t) );
      } else {
        FD_CHECK_CRIT( !len, "invariant violation: epoch credits set has no resident or disk data" );
      }

      banks_data->epoch_credits_cache_set_idx[cache_idx] = set_idx;
      banks_data->epoch_credits_cache_dirty[cache_idx]   = 0U;
    }

    banks_data->epoch_credits_cache_pin_cnt[cache_idx]++;
    banks_data->epoch_credits_cache_lru[cache_idx] = ++banks_data->epoch_credits_lru;
    fd_banks_epoch_credits_acquire_locked( banks_data, set_idx );

    fd_epoch_credits_t * credits = fd_banks_get_epoch_credits_cache( banks_data ) +
        cache_idx * FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS;
    ulong len = fd_banks_get_epoch_credits_len( banks_data )[set_idx];
    if( FD_UNLIKELY( write && !len ) ) fd_memset( credits, 0, fd_banks_epoch_credits_set_sz() );

    *view = (fd_bank_epoch_credits_view_t) {
      .credits   = credits,
      .banks     = banks_data,
      .len       = len,
      .set_idx   = set_idx,
      .cache_idx = cache_idx,
      .write     = !!write
    };

    fd_rwlock_unwrite( &banks_data->epoch_credits_lock );
    return view;
  }
}

void
fd_bank_epoch_credits_view_fini( fd_bank_epoch_credits_view_t * view ) {
  if( FD_UNLIKELY( !view || !view->credits ) ) return;

  fd_banks_t * banks_data = view->banks;
  fd_rwlock_write( &banks_data->epoch_credits_lock );

  FD_CHECK_CRIT( view->cache_idx<fd_banks_epoch_credits_cache_cnt( banks_data ) &&
                 banks_data->epoch_credits_cache_set_idx[view->cache_idx]==view->set_idx &&
                 banks_data->epoch_credits_cache_pin_cnt[view->cache_idx],
                 "invariant violation: invalid epoch credits view" );

  if( view->write ) {
    FD_CHECK_CRIT( view->len<=FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS,
                   "invariant violation: invalid epoch credits length" );
    fd_banks_get_epoch_credits_len( banks_data )[view->set_idx] = view->len;
    fd_banks_get_epoch_credits_disk_valid( banks_data )[view->set_idx] = 0U;
    banks_data->epoch_credits_cache_dirty[view->cache_idx] = 1U;
  }

  banks_data->epoch_credits_cache_pin_cnt[view->cache_idx]--;
  fd_banks_epoch_credits_release_locked( banks_data, view->set_idx );
  fd_rwlock_unwrite( &banks_data->epoch_credits_lock );

  view->credits = NULL;
  view->banks   = NULL;
}

void
fd_bank_epoch_credits_new_fork( fd_bank_t * bank ) {
  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank - bank->banks_data_offset );

  fd_rwlock_write( &banks_data->epoch_credits_lock );

  if( FD_LIKELY( bank->epoch_credits_fork_id!=USHORT_MAX ) ) {
    fd_banks_epoch_credits_release_locked( banks_data, (ulong)bank->epoch_credits_fork_id );
    bank->epoch_credits_fork_id = USHORT_MAX;
  }

  ulong   set_cnt = fd_banks_epoch_credits_set_cnt( banks_data );
  ulong * refcnt  = fd_banks_get_epoch_credits_refcnt( banks_data );

  ulong free_id = ULONG_MAX;
  for( ulong i=0UL; i<set_cnt; i++ ) {
    if( FD_UNLIKELY( !refcnt[ i ] ) ) {
      free_id = i;
      break;
    }
  }
  FD_CHECK_CRIT( free_id!=ULONG_MAX, "invariant violation: no free epoch credits sets" );

  bank->epoch_credits_fork_id = (ushort)free_id;
  fd_banks_epoch_credits_acquire_locked( banks_data, free_id );
  fd_banks_get_epoch_credits_len( banks_data )[free_id]        = 0UL;
  fd_banks_get_epoch_credits_disk_valid( banks_data )[free_id] = 0U;

  fd_rwlock_unwrite( &banks_data->epoch_credits_lock );
}

static void
fd_bank_epoch_credits_clear( fd_bank_t * bank ) {
  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank - bank->banks_data_offset );
  ulong set_idx = (ulong)bank->epoch_credits_fork_id;

  fd_rwlock_write( &banks_data->epoch_credits_lock );
  FD_CHECK_CRIT( set_idx<fd_banks_epoch_credits_set_cnt( banks_data ) &&
                 fd_banks_get_epoch_credits_refcnt( banks_data )[set_idx],
                 "invariant violation: clearing unreferenced epoch credits set" );

  fd_banks_get_epoch_credits_len( banks_data )[set_idx]        = 0UL;
  fd_banks_get_epoch_credits_disk_valid( banks_data )[set_idx] = 0U;
  ulong cache_cnt = fd_banks_epoch_credits_cache_cnt( banks_data );
  for( ulong i=0UL; i<cache_cnt; i++ ) {
    if( banks_data->epoch_credits_cache_set_idx[i]==set_idx ) {
      banks_data->epoch_credits_cache_dirty[i] = 0U;
      break;
    }
  }
  fd_rwlock_unwrite( &banks_data->epoch_credits_lock );
}

fd_collector_overrides_t *
fd_bank_collector_overrides( fd_bank_t const * bank ) {
  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank - bank->banks_data_offset );
  return fd_banks_get_collector_overrides( banks_data );
}

fd_stake_delegations_t *
fd_bank_stake_delegations_modify( fd_bank_t * bank ) {
  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank - bank->banks_data_offset );
  return fd_banks_get_stake_delegations( banks_data );
}

fd_stake_rewards_t const *
fd_bank_stake_rewards_query( fd_bank_t * bank ) {
  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank - bank->banks_data_offset );
  return fd_type_pun_const( fd_banks_get_stake_rewards( banks_data ) );
}

fd_stake_rewards_t *
fd_bank_stake_rewards_modify( fd_bank_t * bank ) {
  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank - bank->banks_data_offset );
  return fd_banks_get_stake_rewards( banks_data );
}

fd_epoch_leaders_t const *
fd_bank_epoch_leaders_query( fd_bank_t const * bank,
                             ulong             epoch ) {
  FD_TEST( bank->f.epoch==epoch || bank->f.epoch==epoch-1UL );
  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank - bank->banks_data_offset );
  return (fd_epoch_leaders_t const *)fd_type_pun( (uchar *)fd_banks_get_epoch_leaders( banks_data ) + (epoch % 2UL) * banks_data->epoch_leaders_footprint );
}

fd_epoch_leaders_t *
fd_bank_epoch_leaders_modify( fd_bank_t * bank,
                              ulong       epoch ) {
  FD_TEST( bank->f.epoch==epoch || bank->f.epoch==epoch-1UL );
  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank - bank->banks_data_offset );
  return (fd_epoch_leaders_t *)fd_type_pun( (uchar *)fd_banks_get_epoch_leaders( banks_data ) + (epoch % 2UL) * banks_data->epoch_leaders_footprint );
}

fd_vote_stakes_t *
fd_bank_vote_stakes( fd_bank_t const * bank ) {
  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank - bank->banks_data_offset );
  return fd_banks_get_vote_stakes( banks_data );
}

fd_bank_cost_tracker_view_t *
fd_bank_cost_tracker_view_init( fd_bank_cost_tracker_view_t * view,
                                fd_bank_t *                   bank,
                                int                           write ) {
  if( FD_UNLIKELY( !view || !bank ) ) return NULL;

  fd_banks_t * banks_data = fd_type_pun( (uchar *)bank - bank->banks_data_offset );
  fd_bank_cost_tracker_t * pool = fd_banks_get_cost_tracker_pool( banks_data );
  ulong pool_idx = bank->cost_tracker_pool_idx;
  FD_CHECK_CRIT( pool_idx!=fd_bank_cost_tracker_pool_idx_null( pool ),
                 "invariant violation: viewing null cost tracker" );

  for(;;) {
    fd_rwlock_write( &banks_data->cost_tracker_cache_lock );

    ulong cache_cnt = fd_banks_cost_tracker_cache_cnt( banks_data );
    ulong cache_idx = ULONG_MAX;
    for( ulong i=0UL; i<cache_cnt; i++ ) {
      if( banks_data->cost_tracker_cache_pool_idx[i]==pool_idx ) {
        cache_idx = i;
        break;
      }
    }

    if( FD_UNLIKELY( cache_idx==ULONG_MAX ) ) {
      ulong oldest_lru = ULONG_MAX;
      for( ulong i=0UL; i<cache_cnt; i++ ) {
        if( banks_data->cost_tracker_cache_pin_cnt[i] ) continue;
        if( banks_data->cost_tracker_cache_pool_idx[i]==ULONG_MAX ) {
          cache_idx = i;
          break;
        }
        if( banks_data->cost_tracker_cache_lru_slot[i]<oldest_lru ) {
          oldest_lru = banks_data->cost_tracker_cache_lru_slot[i];
          cache_idx  = i;
        }
      }

      if( FD_UNLIKELY( cache_idx==ULONG_MAX ) ) {
        fd_rwlock_unwrite( &banks_data->cost_tracker_cache_lock );
        FD_SPIN_PAUSE();
        continue;
      }

      uchar * cache = fd_banks_get_cost_tracker_cache( banks_data ) + cache_idx*FD_COST_TRACKER_FOOTPRINT;
      ulong evicted_pool_idx = banks_data->cost_tracker_cache_pool_idx[cache_idx];
      if( FD_LIKELY( evicted_pool_idx!=ULONG_MAX ) ) {
        if( banks_data->cost_tracker_cache_dirty[cache_idx] ) {
          fd_banks_cost_tracker_disk_write( cache, evicted_pool_idx );
          fd_bank_cost_tracker_pool_ele( pool, evicted_pool_idx )->disk_valid = 1U;
        }
      }

      if( fd_bank_cost_tracker_pool_ele( pool, pool_idx )->disk_valid ) {
        fd_banks_cost_tracker_disk_read( cache, pool_idx );
      }
      FD_CHECK_CRIT( fd_cost_tracker_join( cache ),
                     "invariant violation: invalid cost tracker cache entry" );

      banks_data->cost_tracker_cache_pool_idx[cache_idx] = pool_idx;
      banks_data->cost_tracker_cache_dirty[cache_idx]    = 0U;
    }

    banks_data->cost_tracker_cache_pin_cnt[cache_idx]++;
    banks_data->cost_tracker_cache_lru_slot[cache_idx] = ++banks_data->cost_tracker_cache_lru;

    *view = (fd_bank_cost_tracker_view_t) {
      .tracker   = fd_cost_tracker_join( fd_banks_get_cost_tracker_cache( banks_data ) + cache_idx*FD_COST_TRACKER_FOOTPRINT ),
      .banks     = banks_data,
      .pool_idx  = pool_idx,
      .cache_idx = cache_idx,
      .write     = !!write
    };

    fd_rwlock_unwrite( &banks_data->cost_tracker_cache_lock );
    return view;
  }
}

void
fd_bank_cost_tracker_view_fini( fd_bank_cost_tracker_view_t * view ) {
  if( FD_UNLIKELY( !view || !view->tracker ) ) return;

  fd_banks_t * banks_data = view->banks;
  fd_rwlock_write( &banks_data->cost_tracker_cache_lock );
  FD_CHECK_CRIT( view->cache_idx<fd_banks_cost_tracker_cache_cnt( banks_data ) &&
                 banks_data->cost_tracker_cache_pool_idx[view->cache_idx]==view->pool_idx &&
                 banks_data->cost_tracker_cache_pin_cnt[view->cache_idx],
                 "invariant violation: invalid cost tracker view" );

  if( view->write ) banks_data->cost_tracker_cache_dirty[view->cache_idx] = 1U;
  banks_data->cost_tracker_cache_pin_cnt[view->cache_idx]--;
  fd_rwlock_unwrite( &banks_data->cost_tracker_cache_lock );

  view->tracker = NULL;
  view->banks   = NULL;
}

fd_bank_t *
fd_banks_root( fd_banks_t * banks ) {
  return fd_banks_pool_ele( fd_banks_get_bank_pool( banks ), banks->root_idx );
}

fd_bank_t *
fd_banks_bank_query( fd_banks_t * banks,
                     ulong        bank_idx ) {
  fd_bank_t * bank = fd_banks_pool_ele( fd_banks_get_bank_pool( banks ), bank_idx );
  if( FD_UNLIKELY( bank->state==FD_BANK_STATE_INACTIVE ) ) return NULL;
  return bank;
}

fd_bank_t *
fd_banks_get_parent( fd_banks_t * banks,
                     fd_bank_t *  bank ) {
  if( FD_UNLIKELY( bank->parent_idx==ULONG_MAX ) ) return NULL;
  return fd_banks_pool_ele( fd_banks_get_bank_pool( banks ), bank->parent_idx );
}

int
fd_banks_can_start_bank( fd_banks_t * banks ) {
  if( FD_UNLIKELY( fd_banks_pool_free( fd_banks_get_bank_pool( banks ) )==0UL ) ) return 0;
  if( FD_UNLIKELY( banks->curr_fork_width>=banks->max_fork_width ) ) return 0;
  return 1;
}

ulong
fd_banks_pool_used_cnt( fd_banks_t * banks ) {
  return fd_banks_pool_used( fd_banks_get_bank_pool( banks ) );
}

ulong
fd_banks_pool_max_cnt( fd_banks_t * banks ) {
  return fd_banks_pool_max( fd_banks_get_bank_pool( banks ) );
}

void
fd_banks_stake_delegations_evict_bank_fork( fd_banks_t * banks,
                                            fd_bank_t *  bank ) {
  if( bank->stake_delegations_fork_id!=USHORT_MAX ) {
    fd_stake_delegations_t * sd = fd_banks_get_stake_delegations( banks );
    fd_stake_delegations_evict_fork( sd, bank->stake_delegations_fork_id );
    bank->stake_delegations_fork_id = USHORT_MAX;
  }
}

static void
fd_banks_vote_stakes_evict_bank_fork( fd_banks_t * banks,
                                      fd_bank_t *  bank ) {
  if( bank->vote_stakes_fork_id!=ULONG_MAX ) {
    fd_vote_stakes_purge_fork( fd_banks_get_vote_stakes( banks ), bank->vote_stakes_fork_id );
    bank->vote_stakes_fork_id = ULONG_MAX;
  }
}

ulong
fd_banks_footprint( ulong max_total_banks,
                    ulong max_fork_width,
                    ulong max_stake_accounts,
                    ulong max_vote_accounts ) {

  /* max_fork_width is used in the macro below. */

  ulong epoch_leaders_footprint = FD_EPOCH_LEADERS_FOOTPRINT( max_vote_accounts, FD_RUNTIME_SLOTS_PER_EPOCH );;
  ulong cost_tracker_cache_cnt  = fd_ulong_min( max_fork_width, FD_BANKS_COST_TRACKER_CACHE_CNT );
  ulong epoch_credits_cache_cnt = fd_ulong_min( max_total_banks, FD_BANKS_EPOCH_CREDITS_CACHE_CNT );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_banks_align(),                  sizeof(fd_banks_t) );
  l = FD_LAYOUT_APPEND( l, fd_stake_delegations_align(),      fd_stake_delegations_footprint( max_stake_accounts, max_total_banks ) );
  l = FD_LAYOUT_APPEND( l, fd_vote_stakes_align(),             fd_vote_stakes_footprint( max_total_banks, max_fork_width ) );
  l = FD_LAYOUT_APPEND( l, FD_EPOCH_LEADERS_ALIGN,            2UL * epoch_leaders_footprint );
  l = FD_LAYOUT_APPEND( l, fd_banks_pool_align(),             fd_banks_pool_footprint( max_total_banks ) );
  l = FD_LAYOUT_APPEND( l, fd_banks_dead_align(),             fd_banks_dead_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_bank_cost_tracker_pool_align(), fd_bank_cost_tracker_pool_footprint( max_fork_width ) );
  l = FD_LAYOUT_APPEND( l, fd_cost_tracker_align(),           fd_ulong_sat_mul( FD_COST_TRACKER_FOOTPRINT, cost_tracker_cache_cnt ) );
  l = FD_LAYOUT_APPEND( l, fd_stake_rewards_align(),          fd_stake_rewards_footprint( max_stake_accounts, max_total_banks, FD_BANKS_STAKE_REWARDS_CACHE_CNT ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_epoch_credits_t),       fd_ulong_sat_mul( fd_banks_epoch_credits_set_sz(), epoch_credits_cache_cnt ) );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),                    sizeof(ulong) * max_total_banks );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),                    sizeof(ulong) * max_total_banks );
  l = FD_LAYOUT_APPEND( l, alignof(uchar),                    sizeof(uchar) * max_total_banks );
  l = FD_LAYOUT_APPEND( l, fd_collector_overrides_align(),    fd_collector_overrides_footprint( FD_COLLECTOR_OVERRIDES_MAX ) );
  return FD_LAYOUT_FINI( l, fd_banks_align() );
}

void *
fd_banks_new( void * shmem,
              int    stake_delegations_fd,
              ulong  max_total_banks,
              ulong  max_fork_width,
              ulong  max_stake_accounts,
              ulong  max_disk_records,
              ulong  max_vote_accounts,
              ulong  bench_max_cost_per_block,
              ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_banks_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( max_total_banks>FD_BANKS_MAX_BANKS ) ) {
    FD_LOG_WARNING(( "max_total_banks is too large" ));
    return NULL;
  }
  if( FD_UNLIKELY( max_fork_width>FD_BANKS_MAX_BANKS ) ) {
    FD_LOG_WARNING(( "max_fork_width is too large" ));
    return NULL;
  }
  /* The collector override store reserves one membership bit for the
     root in addition to max_fork_width child fork bits. */
  if( FD_UNLIKELY( max_fork_width>FD_COLLECTOR_OVERRIDES_MAX_FORK_WIDTH ) ) {
    FD_LOG_WARNING(( "max_fork_width must be at most %lu", FD_COLLECTOR_OVERRIDES_MAX_FORK_WIDTH ));
    return NULL;
  }

  ulong epoch_leaders_footprint = FD_EPOCH_LEADERS_FOOTPRINT( max_vote_accounts, FD_RUNTIME_SLOTS_PER_EPOCH );
  ulong cost_tracker_cache_cnt  = fd_ulong_min( max_fork_width, FD_BANKS_COST_TRACKER_CACHE_CNT );
  ulong epoch_credits_cache_cnt = fd_ulong_min( max_total_banks, FD_BANKS_EPOCH_CREDITS_CACHE_CNT );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_banks_t * banks_data              = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_align(),                  sizeof(fd_banks_t) );
  void *       stake_delegations_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_align(),      fd_stake_delegations_footprint( max_stake_accounts, max_total_banks ) );
  void *       vote_stakes_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_stakes_align(),             fd_vote_stakes_footprint( max_total_banks, max_fork_width ) );
  void *       epoch_leaders_mem       = FD_SCRATCH_ALLOC_APPEND( l, FD_EPOCH_LEADERS_ALIGN,            2UL * epoch_leaders_footprint );
  void *       pool_mem                = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_pool_align(),             fd_banks_pool_footprint( max_total_banks ) );
  void *       dead_banks_deque_mem    = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_dead_align(),             fd_banks_dead_footprint() );
  void *       cost_tracker_pool_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_cost_tracker_pool_align(), fd_bank_cost_tracker_pool_footprint( max_fork_width ) );
  void *       cost_tracker_cache_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_cost_tracker_align(),           fd_ulong_sat_mul( FD_COST_TRACKER_FOOTPRINT, cost_tracker_cache_cnt ) );
  void *       stake_rewards_pool_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_rewards_align(),          fd_stake_rewards_footprint( max_stake_accounts, max_total_banks, FD_BANKS_STAKE_REWARDS_CACHE_CNT ) );
  void *       epoch_credits_mem       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_epoch_credits_t),       fd_ulong_sat_mul( fd_banks_epoch_credits_set_sz(), epoch_credits_cache_cnt ) );
  void *       epoch_credits_len_mem   = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),                    sizeof(ulong) * max_total_banks );
  void *       epoch_credits_rc_mem    = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),                    sizeof(ulong) * max_total_banks );
  void *       epoch_credits_valid_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(uchar),                    sizeof(uchar) * max_total_banks );
  void *       collector_overrides_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_collector_overrides_align(),    fd_collector_overrides_footprint( FD_COLLECTOR_OVERRIDES_MAX ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_banks_align() ) != (ulong)banks_data + fd_banks_footprint( max_total_banks, max_fork_width, max_stake_accounts, max_vote_accounts ) ) ) {
    FD_LOG_WARNING(( "fd_banks_new: bad layout" ));
    return NULL;
  }

  void * pool = fd_banks_pool_new( pool_mem, max_total_banks );
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "Failed to create bank pool" ));
    return NULL;
  }

  fd_bank_t * bank_pool = fd_banks_pool_join( pool );
  if( FD_UNLIKELY( !bank_pool ) ) {
    FD_LOG_WARNING(( "Failed to join bank pool" ));
    return NULL;
  }

  fd_bank_idx_seq_t * banks_dead_deque = fd_banks_dead_join( fd_banks_dead_new( dead_banks_deque_mem ) );
  if( FD_UNLIKELY( !banks_dead_deque ) ) {
    FD_LOG_WARNING(( "Failed to create banks dead deque" ));
    return NULL;
  }
  banks_data->dead_banks_deque_offset = (ulong)banks_dead_deque - (ulong)banks_data;

  banks_data->epoch_leaders_offset           = (ulong)epoch_leaders_mem - (ulong)banks_data;
  banks_data->epoch_leaders_footprint        = epoch_leaders_footprint;
  banks_data->pool_offset                    = (ulong)bank_pool - (ulong)banks_data;
  banks_data->epoch_credits_cache_offset     = (ulong)epoch_credits_mem - (ulong)banks_data;
  banks_data->epoch_credits_len_offset       = (ulong)epoch_credits_len_mem - (ulong)banks_data;
  banks_data->epoch_credits_refcnt_offset    = (ulong)epoch_credits_rc_mem - (ulong)banks_data;
  banks_data->epoch_credits_disk_valid_offset = (ulong)epoch_credits_valid_mem - (ulong)banks_data;
  fd_memset( epoch_credits_len_mem,   0, sizeof(ulong) * max_total_banks );
  fd_memset( epoch_credits_rc_mem,    0, sizeof(ulong) * max_total_banks );
  fd_memset( epoch_credits_valid_mem, 0, sizeof(uchar) * max_total_banks );
  fd_rwlock_new( &banks_data->epoch_credits_lock );
  banks_data->epoch_credits_lru = 0UL;
  for( ulong i=0UL; i<FD_BANKS_EPOCH_CREDITS_CACHE_CNT; i++ ) {
    banks_data->epoch_credits_cache_set_idx[i] = ULONG_MAX;
    banks_data->epoch_credits_cache_pin_cnt[i] = 0UL;
    banks_data->epoch_credits_cache_lru[i]     = 0UL;
    banks_data->epoch_credits_cache_dirty[i]   = 0U;
  }

  /* Create the pools for the non-inlined fields.  Also new() and join()
     each of the elements in the pool as well as set up the lock for
     each of the pools. */

  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join(
      fd_stake_delegations_new( stake_delegations_mem, stake_delegations_fd, seed, max_stake_accounts, max_disk_records, max_total_banks ),
      stake_delegations_fd );
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_WARNING(( "Unable to create stake delegations root" ));
    return NULL;
  }
  banks_data->stake_delegations_offset = (ulong)stake_delegations - (ulong)banks_data;

  fd_vote_stakes_t * vote_stakes = fd_vote_stakes_join( fd_vote_stakes_new( vote_stakes_mem, max_total_banks, max_fork_width, seed ) );
  if( FD_UNLIKELY( !vote_stakes ) ) {
    FD_LOG_WARNING(( "Unable to create vote stakes" ));
    return NULL;
  }
  banks_data->vote_stakes_offset = (ulong)vote_stakes - (ulong)banks_data;

  fd_bank_cost_tracker_t * cost_tracker_pool = fd_bank_cost_tracker_pool_join( fd_bank_cost_tracker_pool_new( cost_tracker_pool_mem, max_fork_width ) );
  if( FD_UNLIKELY( !cost_tracker_pool ) ) {
    FD_LOG_WARNING(( "Failed to create cost tracker pool" ));
    return NULL;
  }
  banks_data->cost_tracker_pool_offset = (ulong)cost_tracker_pool - (ulong)banks_data;

  for( ulong i=0UL; i<max_fork_width; i++ ) {
    fd_bank_cost_tracker_pool_ele( cost_tracker_pool, i )->disk_valid = 0U;
  }

  banks_data->cost_tracker_cache_offset = (ulong)cost_tracker_cache_mem - (ulong)banks_data;
  fd_rwlock_new( &banks_data->cost_tracker_cache_lock );
  banks_data->cost_tracker_cache_lru = 0UL;
  for( ulong i=0UL; i<FD_BANKS_COST_TRACKER_CACHE_CNT; i++ ) {
    banks_data->cost_tracker_cache_pool_idx[i] = ULONG_MAX;
    banks_data->cost_tracker_cache_pin_cnt[i]  = 0UL;
    banks_data->cost_tracker_cache_lru_slot[i] = 0UL;
    banks_data->cost_tracker_cache_dirty[i]    = 0U;
  }
  for( ulong i=0UL; i<cost_tracker_cache_cnt; i++ ) {
    void * cost_tracker_mem = (uchar *)cost_tracker_cache_mem + i*FD_COST_TRACKER_FOOTPRINT;
    fd_memset( cost_tracker_mem, 0, FD_COST_TRACKER_FOOTPRINT );
    if( FD_UNLIKELY( !fd_cost_tracker_join( fd_cost_tracker_new( cost_tracker_mem, bench_max_cost_per_block, seed ) ) ) ) {
      FD_LOG_WARNING(( "Failed to create cost tracker" ));
      return NULL;
    }
  }

  fd_stake_rewards_t * stake_rewards = fd_stake_rewards_join( fd_stake_rewards_new( stake_rewards_pool_mem, max_stake_accounts, max_total_banks, FD_BANKS_STAKE_REWARDS_CACHE_CNT ) );
  if( FD_UNLIKELY( !stake_rewards ) ) {
    FD_LOG_WARNING(( "Failed to create stake rewards" ));
    return NULL;
  }
  banks_data->stake_rewards_offset = (ulong)stake_rewards - (ulong)banks_data;

  fd_collector_overrides_t * collector_overrides = fd_collector_overrides_join( fd_collector_overrides_new( collector_overrides_mem, FD_COLLECTOR_OVERRIDES_MAX, seed ) );
  if( FD_UNLIKELY( !collector_overrides ) ) {
    FD_LOG_WARNING(( "Failed to create collector overrides" ));
    return NULL;
  }
  banks_data->collector_overrides_offset = (ulong)collector_overrides - (ulong)banks_data;

  /* For each bank, set the offset back to banks_data and initialize
     per-bank state. */

  fd_bank_cost_tracker_t * cost_tracker_pool_init = fd_banks_get_cost_tracker_pool( banks_data );

  for( ulong i=0UL; i<max_total_banks; i++ ) {

    fd_bank_t * bank = fd_banks_pool_ele( bank_pool, i );

    fd_rwlock_new( &bank->lthash_lock );

    bank->idx               = i;
    bank->state             = FD_BANK_STATE_INACTIVE;
    bank->banks_data_offset = (ulong)bank - (ulong)banks_data;

    bank->cost_tracker_pool_idx = fd_bank_cost_tracker_pool_idx_null( cost_tracker_pool_init );
    bank->vote_stakes_fork_id   = ULONG_MAX;
  }

  banks_data->report_runtime_diffs = 0;
  banks_data->max_total_banks    = max_total_banks;
  banks_data->max_fork_width     = max_fork_width;
  banks_data->max_stake_accounts = max_stake_accounts;
  banks_data->max_vote_accounts  = max_vote_accounts;
  banks_data->root_idx           = ULONG_MAX;
  banks_data->evict_rr_idx       = seed;
  banks_data->prunable_idx       = ULONG_MAX;
  banks_data->curr_fork_width    = 0UL;
  banks_data->bank_seq           = 1UL;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( banks_data->magic ) = FD_BANKS_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_banks_t *
fd_banks_join( void * banks_data_mem ) {
  fd_banks_t * banks_data  = (fd_banks_t *)banks_data_mem;

  if( FD_UNLIKELY( !banks_data ) ) {
    FD_LOG_WARNING(( "NULL banks data" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)banks_data, fd_banks_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned banks" ));
    return NULL;
  }

  if( FD_UNLIKELY( banks_data->magic!=FD_BANKS_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid banks magic" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, banks_data );
  banks_data                   = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_align(),                  sizeof(fd_banks_t) );
  void * stake_delegations_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_align(),      fd_stake_delegations_footprint( banks_data->max_stake_accounts, banks_data->max_total_banks ) );
  void * vote_stakes_mem       = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_stakes_align(),             fd_vote_stakes_footprint( banks_data->max_total_banks, banks_data->max_fork_width ) );
  void * epoch_leaders_mem     = FD_SCRATCH_ALLOC_APPEND( l, FD_EPOCH_LEADERS_ALIGN,            2UL * banks_data->epoch_leaders_footprint );
  void * pool_mem              = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_pool_align(),             fd_banks_pool_footprint( banks_data->max_total_banks ) );
  void * dead_banks_deque_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_banks_dead_align(),             fd_banks_dead_footprint() );
  void * cost_tracker_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_cost_tracker_pool_align(), fd_bank_cost_tracker_pool_footprint( banks_data->max_fork_width ) );
  void * cost_tracker_cache_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_cost_tracker_align(),          fd_ulong_sat_mul( FD_COST_TRACKER_FOOTPRINT, fd_banks_cost_tracker_cache_cnt( banks_data ) ) );
  void * stake_rewards_mem     = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_rewards_align(),          fd_stake_rewards_footprint( banks_data->max_stake_accounts, banks_data->max_total_banks, FD_BANKS_STAKE_REWARDS_CACHE_CNT ) );
  void * epoch_credits_mem     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_epoch_credits_t),       fd_ulong_sat_mul( fd_banks_epoch_credits_set_sz(), fd_banks_epoch_credits_cache_cnt( banks_data ) ) );
  void * epoch_credits_len_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),                    sizeof(ulong) * banks_data->max_total_banks );
  void * epoch_credits_rc_mem  = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),                    sizeof(ulong) * banks_data->max_total_banks );
  void * epoch_credits_valid_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(uchar),                  sizeof(uchar) * banks_data->max_total_banks );
  void * collector_overrides_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_collector_overrides_align(),  fd_collector_overrides_footprint( FD_COLLECTOR_OVERRIDES_MAX ) );
  (void)epoch_credits_len_mem;
  (void)epoch_credits_rc_mem;
  (void)epoch_credits_valid_mem;
  (void)collector_overrides_mem;

  FD_SCRATCH_ALLOC_FINI( l, fd_banks_align() );

  fd_bank_t * banks_pool = fd_banks_get_bank_pool( banks_data );
  if( FD_UNLIKELY( !banks_pool ) ) {
    FD_LOG_WARNING(( "Failed to join bank pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( banks_pool!=fd_banks_pool_join( pool_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join bank pool" ));
    return NULL;
  }

  fd_bank_idx_seq_t * banks_dead_deque = fd_banks_dead_join( dead_banks_deque_mem );
  if( FD_UNLIKELY( !banks_dead_deque ) ) {
    FD_LOG_WARNING(( "Failed to join banks dead deque" ));
    return NULL;
  }

  if( FD_UNLIKELY( epoch_leaders_mem!=fd_banks_get_epoch_leaders( banks_data ) ) ) {
    FD_LOG_WARNING(( "Failed to join epoch leaders mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( stake_delegations_mem!=fd_banks_get_stake_delegations( banks_data ) ) ) {
    FD_LOG_WARNING(( "Failed to join stake delegations root mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( vote_stakes_mem!=(void *)fd_banks_get_vote_stakes( banks_data ) ) ) {
    FD_LOG_WARNING(( "Failed to join vote stakes" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_vote_stakes_join( vote_stakes_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join vote stakes" ));
    return NULL;
  }

  fd_bank_cost_tracker_t * cost_tracker_pool = fd_banks_get_cost_tracker_pool( banks_data );
  if( FD_UNLIKELY( !cost_tracker_pool ) ) {
    FD_LOG_WARNING(( "Failed to join cost tracker pool" ));
    return NULL;
  }

  if( FD_UNLIKELY( cost_tracker_pool!=fd_bank_cost_tracker_pool_join( cost_tracker_pool_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join cost tracker pool" ));
    return NULL;
  }
  if( FD_UNLIKELY( cost_tracker_cache_mem!=(void *)fd_banks_get_cost_tracker_cache( banks_data ) ) ) {
    FD_LOG_WARNING(( "Failed to join cost tracker cache" ));
    return NULL;
  }
  for( ulong i=0UL; i<fd_banks_cost_tracker_cache_cnt( banks_data ); i++ ) {
    if( FD_UNLIKELY( !fd_cost_tracker_join( (uchar *)cost_tracker_cache_mem + i*FD_COST_TRACKER_FOOTPRINT ) ) ) {
      FD_LOG_WARNING(( "Failed to join cost tracker cache entry" ));
      return NULL;
    }
  }

  if( FD_UNLIKELY( epoch_credits_mem!=(void *)fd_banks_get_epoch_credits_cache( banks_data ) ) ) {
    FD_LOG_WARNING(( "Failed to join epoch credits" ));
    return NULL;
  }
  if( FD_UNLIKELY( epoch_credits_len_mem!=(void *)fd_banks_get_epoch_credits_len( banks_data ) ||
                   epoch_credits_rc_mem!=(void *)fd_banks_get_epoch_credits_refcnt( banks_data ) ||
                   epoch_credits_valid_mem!=(void *)fd_banks_get_epoch_credits_disk_valid( banks_data ) ) ) {
    FD_LOG_WARNING(( "Failed to join epoch credits metadata" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_stake_rewards_join( stake_rewards_mem ) ) ) {
    FD_LOG_WARNING(( "Failed to join stake rewards" ));
    return NULL;
  }

  return banks_data;
}

fd_bank_t *
fd_banks_init_bank( fd_banks_t * banks ) {

  fd_bank_t * bank_pool = fd_banks_get_bank_pool( banks );
  FD_CHECK_CRIT( fd_banks_pool_free( bank_pool )!=0UL, "invariant violation: no free bank pool elements" );

  fd_bank_t * bank = fd_banks_pool_ele_acquire( bank_pool );
  bank->bank_seq = FD_ATOMIC_FETCH_AND_ADD( &banks->bank_seq, 1UL );

  ulong null_idx    = fd_banks_pool_idx_null( bank_pool );
  bank->idx         = fd_banks_pool_idx( bank_pool, bank );
  bank->next        = null_idx;
  bank->parent_idx  = null_idx;
  bank->child_idx   = null_idx;
  bank->sibling_idx = null_idx;

  fd_memset( &bank->f, 0, sizeof(bank->f) );
  bank->f.alpenglow_migration_slot        = ULONG_MAX;
  fd_event_runtime_slot_diffs_reset( bank->idx );
  bank->stake_rewards_fork_id             = USHORT_MAX;
  bank->epoch_credits_fork_id             = 0;
  fd_banks_epoch_credits_acquire( banks, bank->epoch_credits_fork_id );
  bank->stake_delegations_fork_id         = USHORT_MAX;
  bank->parent_accdb_fork_id.val          = USHORT_MAX;
  bank->cost_tracker_pool_idx             = fd_bank_cost_tracker_pool_idx_null( fd_banks_get_cost_tracker_pool( banks ) );
  bank->first_fec_set_received_nanos      = fd_log_wallclock();
  bank->preparation_begin_nanos           = 0L;
  bank->first_transaction_scheduled_nanos = 0L;
  bank->last_transaction_finished_nanos   = 0L;
  bank->block_completed_nanos             = 0L;

  fd_vote_stakes_t * vote_stakes = fd_banks_get_vote_stakes( banks );
  fd_vote_stakes_reset( vote_stakes );
  bank->vote_stakes_fork_id = fd_vote_stakes_init( vote_stakes, 0UL );
  bank->collector_overrides_fork_id = fd_collector_overrides_get_root_idx( fd_banks_get_collector_overrides( banks ) );

  bank->state     = FD_BANK_STATE_FROZEN;
  bank->refcnt    = 0UL;
  bank->is_leader = 0;

  banks->root_idx = bank->idx;
  banks->curr_fork_width = 1UL;
  banks->prunable_idx    = null_idx;

  FD_LOG_DEBUG(( "init bank (idx=%lu, stake_rewards_idx=%u, stake_delegations_idx=%u)",
                 bank->idx,
                 bank->stake_rewards_fork_id,
                 bank->stake_delegations_fork_id ));

  return bank;
}

fd_bank_t *
fd_banks_clone_from_parent( fd_banks_t * banks,
                            ulong        child_bank_idx ) {

  fd_bank_t * bank_pool  = fd_banks_get_bank_pool( banks );
  fd_bank_t * child_bank = fd_banks_pool_ele( bank_pool, child_bank_idx );
  FD_CHECK_CRIT( child_bank->state==FD_BANK_STATE_INIT, "invariant violation: bank is not initialized" );

  fd_bank_t * parent_bank = fd_banks_pool_ele( bank_pool, child_bank->parent_idx );
  FD_CHECK_CRIT( parent_bank->state==FD_BANK_STATE_FROZEN || parent_bank->state==FD_BANK_STATE_PRUNABLE, "invariant violation: parent bank is not frozen or prunable" );

  child_bank->cost_tracker_pool_idx = fd_banks_cost_tracker_acquire( banks );

  child_bank->f                           = parent_bank->f;
  child_bank->vote_stakes_fork_id         = fd_vote_stakes_new_fork( fd_banks_get_vote_stakes( banks ), parent_bank->vote_stakes_fork_id, parent_bank->f.epoch );
  child_bank->collector_overrides_fork_id = parent_bank->collector_overrides_fork_id;
  child_bank->stake_rewards_fork_id       = parent_bank->stake_rewards_fork_id;
  child_bank->epoch_credits_fork_id       = parent_bank->epoch_credits_fork_id;
  if( FD_UNLIKELY( child_bank->stake_rewards_fork_id!=USHORT_MAX ) ) {
    fd_stake_rewards_acquire( fd_banks_get_stake_rewards( banks ), child_bank->stake_rewards_fork_id );
  }
  fd_banks_epoch_credits_acquire( banks, child_bank->epoch_credits_fork_id );
  child_bank->stake_delegations_fork_id   = fd_stake_delegations_new_fork( fd_banks_get_stake_delegations( banks ) );
  child_bank->f.block_height              = parent_bank->f.block_height + 1UL;
  child_bank->f.tick_height               = parent_bank->f.max_tick_height;
  child_bank->f.parent_slot               = parent_bank->f.slot;
  child_bank->f.parent_signature_cnt      = parent_bank->f.signature_count;
  child_bank->f.parent_txn_count          = parent_bank->f.parent_txn_count + parent_bank->f.txn_count;
  child_bank->f.prev_bank_hash            = parent_bank->f.bank_hash;
  child_bank->f.execution_fees            = 0UL;
  child_bank->f.priority_fees             = 0UL;
  child_bank->f.tips                      = 0UL;
  child_bank->f.signature_count           = 0UL;
  child_bank->f.total_compute_units_used  = 0UL;
  child_bank->f.shred_cnt                 = 0UL;
  child_bank->f.txn_count                 = 0UL;
  child_bank->f.nonvote_txn_count         = 0UL;
  child_bank->f.failed_txn_count          = 0UL;
  child_bank->f.nonvote_failed_txn_count  = 0UL;
  child_bank->f.identity_vote_idx         = ULONG_MAX;

  child_bank->state = FD_BANK_STATE_REPLAYABLE;

  FD_LOG_DEBUG(( "cloning bank (idx=%lu, parent_idx=%lu, stake_rewards_idx=%u, stake_delegations_idx=%u)",
                 child_bank_idx,
                 parent_bank->idx,
                 child_bank->stake_rewards_fork_id,
                 child_bank->stake_delegations_fork_id ));

  return child_bank;
}

ulong
fd_banks_stake_delegations_fork_ids( fd_banks_t *      banks,
                                     fd_bank_t const * bank,
                                     ushort *          fork_ids ) {
  fd_bank_t * bank_pool = fd_banks_get_bank_pool( banks );

  ulong fork_id_cnt = 0UL;
  fd_bank_t const * curr_bank = fd_banks_pool_ele( bank_pool, bank->idx );
  while( !!curr_bank ) {
    if( curr_bank->stake_delegations_fork_id!=USHORT_MAX ) {
      fork_ids[ fork_id_cnt++ ] = curr_bank->stake_delegations_fork_id;
    }
    curr_bank = fd_banks_pool_ele( bank_pool, curr_bank->parent_idx );
  }

  for( ulong i=0UL; i<fork_id_cnt/2UL; i++ ) {
    ushort tmp                    = fork_ids[ i ];
    fork_ids[ i ]                 = fork_ids[ fork_id_cnt-1UL-i ];
    fork_ids[ fork_id_cnt-1UL-i ] = tmp;
  }

  return fork_id_cnt;
}

/* fd_bank_stake_delegation_apply_deltas applies all of the stake
   delegations for the entire direct ancestry from the bank to the
   root into a full fd_stake_delegations_t object. */

static inline void
fd_bank_apply_deltas( fd_banks_t *                         banks,
                      fd_bank_t *                          bank,
                      fd_stake_delegations_delta_stats_t * stake_delegations_delta_stats ) {

  fd_stake_delegations_t * stake_delegations = fd_banks_get_stake_delegations( banks );

  /* The stake_delegations root has crossed an epoch boundary.  The
     stake totals for the current root need to be updated. */
  fd_bank_t * old_root = fd_banks_root( banks );
  if( old_root->f.epoch!=bank->f.epoch ) {
    stake_delegations->effective_stake    = bank->f.total_effective_stake;
    stake_delegations->activating_stake   = bank->f.total_activating_stake;
    stake_delegations->deactivating_stake = bank->f.total_deactivating_stake;
  }

  /* Naively what we want to do is iterate from the old root to the new
     root and apply the delta to the full state iteratively. */

  /* Gather all fork IDs from the old root to the new root.  The old
     root has no fork ID because its delta was applied previously. */
  ushort pool_indices[ banks->max_total_banks ];
  ulong  pool_indices_len = fd_banks_stake_delegations_fork_ids( banks, bank, pool_indices );

  fd_stake_history_t stake_history_[1];
  fd_stake_history_t const * stake_history = fd_sysvar_cache_stake_history_view( &bank->f.sysvar_cache, stake_history_ );
  /* stake_history may be NULL */
  for( ulong i=0UL; i<pool_indices_len; i++ ) {
    ushort idx = pool_indices[ i ];
    FD_LOG_DEBUG(( "applying stake delegation delta (sd_fork_idx=%u)", idx ));
  }
  fd_stake_delegations_apply_fork_deltas( bank->f.epoch, stake_history, &bank->f.warmup_cooldown_rate_epoch,
                                          FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 ),
                                          stake_delegations, pool_indices, pool_indices_len, stake_delegations_delta_stats );
}

fd_stake_delegations_t *
fd_banks_stake_delegations_root_query( fd_banks_t * banks ) {
  return fd_banks_get_stake_delegations( banks );
}

void
fd_banks_advance_root( fd_banks_t * banks,
                       ulong        root_bank_idx ) {

  fd_bank_t * bank_pool = fd_banks_get_bank_pool( banks );

  /* We want to replace the old root with the new root. This means we
     have to remove banks that aren't descendants of the new root. */

  fd_bank_t * old_root = fd_banks_root( banks );
  FD_CHECK_CRIT( old_root->refcnt==0UL, "refcnt for old root bank is nonzero" );

  fd_bank_t * new_root = fd_banks_pool_ele( bank_pool, root_bank_idx );

  fd_stake_delegations_delta_stats_t stake_delegations_delta_stats = {0};
  fd_bank_apply_deltas( banks, new_root, &stake_delegations_delta_stats );

  fd_stake_delegations_t * stake_delegations = fd_banks_get_stake_delegations( banks );
  ulong                    stake_delegations_prunes = 0UL;
  if( FD_UNLIKELY( old_root->f.epoch!=new_root->f.epoch && FD_FEATURE_ACTIVE_BANK( new_root, remove_inactive_stakes ) ) ) {
    fd_stake_history_t         stake_history_[1];
    fd_stake_history_t const * stake_history = fd_sysvar_cache_stake_history_view( &new_root->f.sysvar_cache, stake_history_ );
    stake_delegations_prunes = fd_stake_delegations_prune_inactive_root( stake_delegations, new_root->f.epoch, stake_history, &new_root->f.warmup_cooldown_rate_epoch,
                                                                         FD_FEATURE_ACTIVE_BANK( new_root, upgrade_bpf_stake_program_to_v5_1 ),
                                                                         banks->report_runtime_diffs ? new_root : NULL );
  }

  fd_stake_delegations_evict_fork( stake_delegations, new_root->stake_delegations_fork_id );
  new_root->stake_delegations_fork_id = USHORT_MAX;

  if( FD_UNLIKELY( banks->report_runtime_diffs ) ) {
    /* Epoch-boundary prunes are emitted as remove-kind rows, so fold
       them into the rooted removal count. */
    stake_delegations_delta_stats.removes = fd_ulong_sat_add( stake_delegations_delta_stats.removes, stake_delegations_prunes );
    stake_delegations_delta_stats.root_cnt = fd_ulong_sat_sub( stake_delegations_delta_stats.root_cnt, stake_delegations_prunes );
    fd_event_runtime_rooted_emit( new_root, old_root->f.slot, stake_delegations,
                                  &stake_delegations_delta_stats );
  }

  /* Now that the deltas have been applied, we can remove all nodes
     that are not direct descendants of the new root. */
  fd_bank_t * head = fd_banks_pool_ele( bank_pool, old_root->idx );
  head->next       = ULONG_MAX;
  fd_bank_t * tail = head;
  ulong pruned_leaf_cnt = 0UL;

  while( head ) {
    fd_bank_t * child = fd_banks_pool_ele( bank_pool, head->child_idx );

    while( FD_LIKELY( child ) ) {

      if( FD_LIKELY( child!=new_root ) ) {
        if( FD_UNLIKELY( child->refcnt!=0UL ) ) {
          FD_LOG_CRIT(( "refcnt for child bank at index %lu is %lu", child->idx, child->refcnt ));
        }

        /* Update tail pointers */
        tail->next = child->idx;
        tail       = fd_banks_pool_ele( bank_pool, tail->next );
        tail->next = fd_banks_pool_idx_null( bank_pool );
      }

      child = fd_banks_pool_ele( bank_pool, child->sibling_idx );
    }

    fd_bank_t * next = fd_banks_pool_ele( bank_pool, head->next );
    if( head->child_idx==fd_banks_pool_idx_null( bank_pool ) ) pruned_leaf_cnt++;

    /* It is possible for a bank that never finished replaying to be
       pruned away.  If the bank was never frozen, then it's possible
       that the bank still owns a cost tracker pool element.  If this
       is the case, we need to release the pool element. */
    fd_bank_cost_tracker_t * cost_tracker_pool = fd_banks_get_cost_tracker_pool( banks );
    if( head->cost_tracker_pool_idx!=fd_bank_cost_tracker_pool_idx_null( cost_tracker_pool ) ) {
      FD_LOG_DEBUG(( "releasing cost tracker pool element for bank at index %lu", head->idx ));
      fd_banks_cost_tracker_release( banks, head->cost_tracker_pool_idx );
      head->cost_tracker_pool_idx = fd_bank_cost_tracker_pool_idx_null( cost_tracker_pool );
    }

    ulong prev_epoch = fd_slot_to_epoch( &head->f.epoch_schedule, head->f.parent_slot, NULL );
    ulong new_epoch  = fd_slot_to_epoch( &head->f.epoch_schedule, head->f.slot, NULL );
    /* collector_overrides are allocated only at epoch boundaries.
       Non-boundary banks inherit their parent's fork ids but don't own
       them.  Stake rewards forks are reference counted instead, so
       every bank releases its own below. */
    if( FD_UNLIKELY( prev_epoch!=new_epoch ) ) {
      if( FD_LIKELY( head->collector_overrides_fork_id!=USHORT_MAX &&
                     head->collector_overrides_fork_id!=new_root->collector_overrides_fork_id ) ) {
        fd_collector_overrides_purge_child( fd_banks_get_collector_overrides( banks ), head->collector_overrides_fork_id );
      }
    }
    if( FD_LIKELY( head->stake_rewards_fork_id!=USHORT_MAX ) ) {
      fd_stake_rewards_release( fd_banks_get_stake_rewards( banks ), head->stake_rewards_fork_id );
    }
    if( FD_LIKELY( head->epoch_credits_fork_id!=USHORT_MAX ) ) {
      fd_banks_epoch_credits_release( banks, head->epoch_credits_fork_id );
      head->epoch_credits_fork_id = USHORT_MAX;
    }
    head->stake_rewards_fork_id       = USHORT_MAX;
    head->collector_overrides_fork_id = USHORT_MAX;

    if( head->stake_delegations_fork_id!=USHORT_MAX ) {
      FD_LOG_DEBUG(( "evicting stake delegation fork (bank_idx=%lu, fork_idx=%u)", head->idx, head->stake_delegations_fork_id ));
      fd_stake_delegations_evict_fork( stake_delegations, head->stake_delegations_fork_id );
      head->stake_delegations_fork_id = USHORT_MAX;
    }

    fd_banks_vote_stakes_evict_bank_fork( banks, head );

    if( FD_UNLIKELY( head->state==FD_BANK_STATE_PRUNABLE ) ) {
      FD_TEST( banks->prunable_idx==head->idx );
      banks->prunable_idx = fd_banks_pool_idx_null( bank_pool );
    }
    head->state = FD_BANK_STATE_INACTIVE;
    fd_banks_pool_ele_release( bank_pool, head );
    head = next;
  }

  /* new_root is detached from old_root and becomes the only root.
     Clear sibling_idx too so traversals cannot follow a stale link to
     a bank index that was just pruned and later reused. */
  new_root->parent_idx  = ULONG_MAX;
  new_root->sibling_idx = ULONG_MAX;
  banks->root_idx       = new_root->idx;
  FD_TEST( banks->curr_fork_width>pruned_leaf_cnt );
  banks->curr_fork_width -= pruned_leaf_cnt;

  fd_collector_overrides_advance_root( fd_banks_get_collector_overrides( banks ), new_root->collector_overrides_fork_id );
}

/* Is the fork tree starting at the given bank entirely eligible for
   pruning?  Returns 1 for yes, 0 for no.

   See comment in fd_replay_tile.c for more details on safe pruning. */
static int
fd_banks_subtree_can_be_pruned( fd_bank_t * bank_pool,
                                fd_bank_t * bank ) {

  if( bank->refcnt!=0UL ) return 0;

  /* Recursively check all children. */
  ulong child_idx = bank->child_idx;
  while( child_idx!=fd_banks_pool_idx_null( bank_pool ) ) {
    fd_bank_t * child = fd_banks_pool_ele( bank_pool, child_idx );
    if( !fd_banks_subtree_can_be_pruned( bank_pool, child ) ) return 0;
    child_idx = child->sibling_idx;
  }

  return 1;
}

int
fd_banks_advance_root_prepare( fd_banks_t * banks,
                               ulong        target_bank_idx,
                               ulong *      advanceable_bank_idx_out ) {
  /* TODO: An optimization here is to do a single traversal of the tree
     that would mark minority forks as dead while accumulating
     refcnts to determine which bank is the highest advanceable. */

  fd_bank_t * bank_pool = fd_banks_get_bank_pool( banks );

  fd_bank_t * root = fd_banks_root( banks );

  /* Early exit if target is the same as the old root. */
  if( FD_UNLIKELY( root->idx==target_bank_idx ) ) {
    FD_LOG_WARNING(( "target bank_idx %lu is the same as the old root's bank index %lu", target_bank_idx, root->idx ));
    return 0;
  }

  /* Early exit if the root bank still has a reference to it, we can't
     advance from it unti it's released. */
  if( FD_UNLIKELY( root->refcnt!=0UL ) ) {
    return 0;
  }

  fd_bank_t * target_bank = fd_banks_pool_ele( bank_pool, target_bank_idx );

  /* Walk from target_bank up to root, recording the direct child of
     root on the path (prev).  We only advance root by one level. */

  fd_bank_t * curr = target_bank;
  fd_bank_t * prev = NULL;
  while( curr && curr!=root ) {
    prev = curr;
    curr = fd_banks_pool_ele( bank_pool, curr->parent_idx );
  }

  /* If we didn't reach the old root or there is no parent, target is
     not a descendant. */
  if( FD_UNLIKELY( !curr || prev->parent_idx!=root->idx ) ) {
    FD_LOG_CRIT(( "invariant violation: target bank_idx %lu is not a direct descendant of root bank_idx %lu %lu %lu", target_bank_idx, root->idx, prev->idx, prev->parent_idx ));
  }

  /* We will at most advance our root bank by one.  This means we can
     advance our root bank by one if each of the siblings of the
     potential new root are eligible for pruning.  Each of the sibling
     subtrees can be pruned if the subtrees have no active references on
     their bank. */
  ulong advance_candidate_idx = prev->idx;
  ulong child_idx = root->child_idx;
  while( child_idx!=fd_banks_pool_idx_null( bank_pool ) ) {
    fd_bank_t * child_bank = fd_banks_pool_ele( bank_pool, child_idx );
    if( child_idx!=advance_candidate_idx ) {
      if( !fd_banks_subtree_can_be_pruned( bank_pool, child_bank ) ) {
        return 0;
      }
    }
    child_idx = child_bank->sibling_idx;
  }

  fd_bank_t * cand = fd_banks_pool_ele( bank_pool, advance_candidate_idx );
  FD_CHECK_CRIT( cand->state==FD_BANK_STATE_FROZEN, "advancing root to non-frozen bank" );

  *advanceable_bank_idx_out = advance_candidate_idx;
  return 1;
}

fd_bank_t *
fd_banks_new_bank( fd_banks_t * banks,
                   ulong        parent_bank_idx,
                   long         now,
                   uchar        is_leader ) {

  fd_bank_t * bank_pool = fd_banks_get_bank_pool( banks );
  FD_CHECK_CRIT( fd_banks_pool_free( bank_pool )!=0UL, "invariant violation: no free bank indices available" );

  ulong       child_bank_idx = fd_banks_pool_idx_acquire( bank_pool );
  fd_bank_t * child_bank     = fd_banks_pool_ele( bank_pool, child_bank_idx );
  FD_CHECK_CRIT( child_bank->state==FD_BANK_STATE_INACTIVE, "invariant violation: bank for bank index is already initialized" );

  ulong null_idx = fd_banks_pool_idx_null( bank_pool );

  child_bank->bank_seq    = FD_ATOMIC_FETCH_AND_ADD( &banks->bank_seq, 1UL );
  child_bank->parent_idx  = null_idx;
  child_bank->child_idx   = null_idx;
  child_bank->sibling_idx = null_idx;
  child_bank->next        = null_idx;
  child_bank->state       = FD_BANK_STATE_INIT;
  child_bank->refcnt      = 0UL;
  child_bank->is_leader   = is_leader;
  fd_event_runtime_slot_diffs_reset( child_bank->idx );
  child_bank->f.block_id  = (fd_hash_t){0};

  child_bank->collector_overrides_fork_id = USHORT_MAX;
  child_bank->stake_rewards_fork_id       = USHORT_MAX;
  child_bank->epoch_credits_fork_id       = USHORT_MAX;
  child_bank->stake_delegations_fork_id   = USHORT_MAX;
  child_bank->vote_stakes_fork_id         = ULONG_MAX;
  child_bank->parent_accdb_fork_id.val    = USHORT_MAX;

  /* Then make sure that the parent bank is valid.  PRUNABLE parents are
     rejected so eviction victims remain leaves until pruned. */

  fd_bank_t * parent_bank = fd_banks_pool_ele( bank_pool, parent_bank_idx );
  FD_CHECK_CRIT( parent_bank->state!=FD_BANK_STATE_INACTIVE &&
                 parent_bank->state!=FD_BANK_STATE_DEAD &&
                 parent_bank->state!=FD_BANK_STATE_PRUNABLE,
                 "invariant violation: parent bank is dead, inactive, or prunable" );

  /* Link node->parent */
  child_bank->parent_idx = parent_bank_idx;
  /* Link parent->node and sibling->node */
  if( FD_LIKELY( parent_bank->child_idx==null_idx ) ) {
    /* This is the first child so set as left-most child */
    parent_bank->child_idx = child_bank_idx;

  } else {
    /* Already have children so iterate to right-most sibling. */
    fd_bank_t * curr_bank = fd_banks_pool_ele( bank_pool, parent_bank->child_idx );
    while( curr_bank->sibling_idx != null_idx ) curr_bank = fd_banks_pool_ele( bank_pool, curr_bank->sibling_idx );
    /* Link to right-most sibling. */
    curr_bank->sibling_idx = child_bank_idx;
    banks->curr_fork_width++;
  }

  child_bank->first_fec_set_received_nanos      = now;
  child_bank->preparation_begin_nanos           = 0L;
  child_bank->first_transaction_scheduled_nanos = 0L;
  child_bank->last_transaction_finished_nanos   = 0L;
  child_bank->block_completed_nanos             = 0L;

  return child_bank;
}

/* Mark everything in the fork tree starting at the given bank dead. */

static ulong
fd_banks_subtree_mark_dead( fd_banks_t * banks,
                            fd_bank_t *  bank_pool,
                            fd_bank_t *  bank,
                            ulong *      opt_idxs ) {
  if( FD_UNLIKELY( !bank ) ) FD_LOG_CRIT(( "invariant violation: bank is NULL" ));

  if( FD_UNLIKELY( bank->state==FD_BANK_STATE_DEAD ) ) return 0UL;

  ulong idxs_cnt = 0UL;
  if( FD_UNLIKELY( bank->state==FD_BANK_STATE_PRUNABLE ) ) {
    FD_TEST( banks->prunable_idx==bank->idx );
    banks->prunable_idx = fd_banks_pool_idx_null( bank_pool );
  }
  bank->state = FD_BANK_STATE_DEAD;
  fd_banks_dead_push_head( fd_banks_get_dead_banks_deque( banks ), (fd_bank_idx_seq_t){ .idx = bank->idx, .seq = bank->bank_seq } );
  if( opt_idxs ) opt_idxs[ idxs_cnt ] = bank->idx;
  idxs_cnt++;

  /* Recursively mark all children as dead. */
  ulong child_idx = bank->child_idx;
  while( child_idx!=fd_banks_pool_idx_null( bank_pool ) ) {
    fd_bank_t * child      = fd_banks_pool_ele( bank_pool, child_idx );
    ulong *     child_idxs = opt_idxs ? opt_idxs+idxs_cnt : NULL;
    idxs_cnt += fd_banks_subtree_mark_dead( banks, bank_pool, child, child_idxs );
    child_idx = child->sibling_idx;
  }

  return idxs_cnt;
}

void
fd_banks_mark_bank_dead( fd_banks_t * banks,
                         ulong        bank_idx,
                         ulong *      opt_idxs,
                         ulong *      opt_idxs_cnt ) {
  fd_bank_t * bank_pool = fd_banks_get_bank_pool( banks );
  fd_bank_t * bank      = fd_banks_pool_ele( bank_pool, bank_idx );

  ulong idxs_cnt = fd_banks_subtree_mark_dead( banks, bank_pool, bank, opt_idxs );
  if( opt_idxs_cnt ) *opt_idxs_cnt = idxs_cnt;
}

static int
fd_banks_prune_one_leaf( fd_banks_t *                   banks,
                         fd_bank_t *                    bank_pool,
                         fd_bank_t *                    bank,
                         fd_banks_prune_cancel_info_t * cancel ) {
  ulong       null_idx    = fd_banks_pool_idx_null( bank_pool );
  fd_bank_t * parent_bank = fd_banks_pool_ele( bank_pool, bank->parent_idx );
  FD_TEST( bank->child_idx==null_idx );
  int started_replaying = bank->stake_delegations_fork_id!=USHORT_MAX;
  int is_new_fork       = parent_bank->child_idx!=bank->idx || bank->sibling_idx!=null_idx;

  if( parent_bank->child_idx==bank->idx ) {
    parent_bank->child_idx = bank->sibling_idx;
  } else {
    fd_bank_t * curr_bank = fd_banks_pool_ele( bank_pool, parent_bank->child_idx );
    while( curr_bank->sibling_idx!=bank->idx ) curr_bank = fd_banks_pool_ele( bank_pool, curr_bank->sibling_idx );
    curr_bank->sibling_idx = bank->sibling_idx;
  }
  bank->parent_idx  = null_idx;
  bank->sibling_idx = null_idx;
  if( FD_LIKELY( is_new_fork ) ) {
    FD_TEST( banks->curr_fork_width>1UL );
    banks->curr_fork_width--;
  }

  if( FD_UNLIKELY( bank->cost_tracker_pool_idx!=null_idx ) ) {
    fd_banks_cost_tracker_release( banks, bank->cost_tracker_pool_idx );
    bank->cost_tracker_pool_idx = null_idx;
  }

  fd_stake_delegations_t * stake_delegations = fd_banks_get_stake_delegations( banks );
  fd_stake_delegations_evict_fork( stake_delegations, bank->stake_delegations_fork_id );
  bank->stake_delegations_fork_id = USHORT_MAX;
  fd_banks_vote_stakes_evict_bank_fork( banks, bank );

  ulong prev_epoch = fd_slot_to_epoch( &bank->f.epoch_schedule, bank->f.parent_slot, NULL );
  ulong new_epoch  = fd_slot_to_epoch( &bank->f.epoch_schedule, bank->f.slot, NULL );
  /* Only prune collector_overrides for epoch boundary banks.  Stake
     rewards forks are reference counted instead, so every bank releases
     its own below. */
  if( FD_UNLIKELY( prev_epoch!=new_epoch ) ) {
    if( FD_LIKELY( bank->collector_overrides_fork_id!=USHORT_MAX ) ) {
      fd_collector_overrides_purge_child( fd_banks_get_collector_overrides( banks ), bank->collector_overrides_fork_id );
    }
  }
  if( FD_LIKELY( bank->stake_rewards_fork_id!=USHORT_MAX ) ) {
    fd_stake_rewards_release( fd_banks_get_stake_rewards( banks ), bank->stake_rewards_fork_id );
  }
  if( FD_LIKELY( bank->epoch_credits_fork_id!=USHORT_MAX ) ) {
    fd_banks_epoch_credits_release( banks, bank->epoch_credits_fork_id );
    bank->epoch_credits_fork_id = USHORT_MAX;
  }
  bank->collector_overrides_fork_id = USHORT_MAX;
  bank->stake_rewards_fork_id       = USHORT_MAX;

  if( FD_LIKELY( cancel ) ) {
    cancel->bank_idx = bank->idx;
    if( FD_LIKELY( started_replaying ) ) {
      cancel->txncache_fork_id  = bank->txncache_fork_id;
      cancel->progcache_fork_id = bank->progcache_fork_id;
      cancel->accdb_fork_id     = bank->accdb_fork_id;
      cancel->slot              = bank->f.slot;
      cancel->bank_seq          = bank->bank_seq;
    }
  }

  if( FD_UNLIKELY( bank->state==FD_BANK_STATE_PRUNABLE ) ) {
    FD_TEST( banks->prunable_idx==bank->idx );
    banks->prunable_idx = null_idx;
  }
  bank->state = FD_BANK_STATE_INACTIVE;

  fd_banks_pool_ele_release( bank_pool, bank );
  return 1+started_replaying;
}

int
fd_banks_prune_one_bank( fd_banks_t *                   banks,
                         fd_banks_prune_cancel_info_t * cancel ) {
  fd_bank_idx_seq_t * dead_banks_queue = fd_banks_get_dead_banks_deque( banks );
  fd_bank_t *         bank_pool        = fd_banks_get_bank_pool( banks );
  ulong               null_idx         = fd_banks_pool_idx_null( bank_pool );
  while( !fd_banks_dead_empty( dead_banks_queue ) ) {
    fd_bank_idx_seq_t * head = fd_banks_dead_peek_head( dead_banks_queue );
    fd_bank_t *         bank = fd_banks_pool_ele( bank_pool, head->idx );
    if( bank->state==FD_BANK_STATE_INACTIVE || bank->bank_seq!=head->seq ) {
      fd_banks_dead_pop_head( dead_banks_queue );
      continue;
    } else if( bank->refcnt!=0UL ) {
      break;
    }

    FD_LOG_DEBUG(( "pruning dead bank (idx=%lu)", bank->idx ));

    fd_banks_dead_pop_head( dead_banks_queue );
    return fd_banks_prune_one_leaf( banks, bank_pool, bank, cancel );
  }

  if( FD_LIKELY( banks->prunable_idx==null_idx ) ) return 0;

  fd_bank_t * bank = fd_banks_pool_ele( bank_pool, banks->prunable_idx );
  FD_TEST( bank->state==FD_BANK_STATE_PRUNABLE );
  if( FD_UNLIKELY( bank->refcnt!=0UL ) ) return 0;

  FD_LOG_DEBUG(( "pruning evictable bank (idx=%lu)", bank->idx ));
  return fd_banks_prune_one_leaf( banks, bank_pool, bank, cancel );
}

void
fd_banks_mark_bank_frozen( fd_bank_t * bank ) {
  fd_banks_t * banks = fd_type_pun( (uchar *)bank - bank->banks_data_offset );

  FD_CHECK_CRIT( bank->state==FD_BANK_STATE_REPLAYABLE, "invariant violation: bank is not replayable" );
  bank->state = FD_BANK_STATE_FROZEN;

  FD_CHECK_CRIT( bank->cost_tracker_pool_idx!=ULONG_MAX, "invariant violation: cost tracker pool index is null" );
  fd_banks_cost_tracker_release( banks, bank->cost_tracker_pool_idx );
  bank->cost_tracker_pool_idx = ULONG_MAX;
}

static fd_bank_t *
fd_banks_get_evictable_private( fd_banks_t *      banks,
                                fd_bank_t *       bank_pool,
                                ulong             bank_idx,
                                fd_bank_t const * protected_bank,
                                ulong *           evictable_cnt,
                                ulong *           target ) {
  /* Return any leaf node that is eligible for eviction.  We consider
     a bank to be eligibile iff:
     - it is a leaf
     - it's not the root,
     - it's not the leader
     - the state is INIT, REPLAYABLE, or FROZEN */

  ulong null_idx = fd_banks_pool_idx_null( bank_pool );
  if( bank_idx==null_idx ) return NULL;

  fd_bank_t * bank = fd_banks_pool_ele( bank_pool, bank_idx );

  ulong child_idx = bank->child_idx;
  while( child_idx!=null_idx ) {
    fd_bank_t * evictable = fd_banks_get_evictable_private( banks, bank_pool, child_idx, protected_bank, evictable_cnt, target );
    if( FD_LIKELY( evictable ) ) return evictable;
    fd_bank_t * child = fd_banks_pool_ele( bank_pool, child_idx );
    child_idx = child->sibling_idx;
  }

  if( bank->child_idx!=null_idx ) return NULL;
  if( bank->idx==banks->root_idx ) return NULL;
  if( bank==protected_bank ) return NULL;
  if( bank->is_leader ) return NULL;
  if( bank->state==FD_BANK_STATE_INACTIVE || bank->state==FD_BANK_STATE_DEAD || bank->state==FD_BANK_STATE_PRUNABLE ) return NULL;

  if( FD_LIKELY( evictable_cnt ) ) {
    (*evictable_cnt)++;
    return NULL;
  }

  if( FD_LIKELY( (*target)-- ) ) return NULL;
  return bank;
}

ulong
fd_banks_get_evictable_bank( fd_banks_t *      banks,
                             fd_bank_t const * protected_bank ) {
  fd_bank_t * bank_pool = fd_banks_get_bank_pool( banks );
  ulong       null_idx  = fd_banks_pool_idx_null( bank_pool );

  if( FD_UNLIKELY( banks->prunable_idx!=null_idx ) ) return ULONG_MAX;

  fd_bank_t * root = fd_banks_root( banks );
  if( FD_UNLIKELY( root->child_idx==null_idx ) ) return ULONG_MAX;

  ulong evictable_cnt = 0UL;
  fd_banks_get_evictable_private( banks, bank_pool, banks->root_idx, protected_bank, &evictable_cnt, NULL );
  if( FD_UNLIKELY( !evictable_cnt ) ) return ULONG_MAX;

  ulong target = banks->evict_rr_idx++ % evictable_cnt;
  fd_bank_t * evictable = fd_banks_get_evictable_private( banks, bank_pool, banks->root_idx, protected_bank, NULL, &target );
  if( FD_UNLIKELY( !evictable ) ) FD_LOG_CRIT(( "invariant violation: evictable bank not found" ));

  /* Eviction only selects leaves, and prunable_idx is a single pending
     victim.  Non-leaf prunables would break both invariants. */
  FD_TEST( evictable->child_idx==null_idx );
  evictable->state = FD_BANK_STATE_PRUNABLE;
  banks->prunable_idx = evictable->idx;
  return evictable->idx;
}

void
fd_banks_clear_bank( fd_banks_t * banks,
                     fd_bank_t *  bank ) {

  fd_memset( &bank->f, 0, sizeof(bank->f) );
  bank->f.alpenglow_migration_slot = ULONG_MAX;
  fd_event_runtime_slot_diffs_reset( bank->idx );

  fd_vote_stakes_t * vote_stakes = fd_banks_get_vote_stakes( banks );
  fd_banks_vote_stakes_evict_bank_fork( banks, bank );
  bank->vote_stakes_fork_id = fd_vote_stakes_init( vote_stakes, 0UL );

  /* We need to acquire a cost tracker element. */
  fd_bank_cost_tracker_t * cost_tracker_pool = fd_banks_get_cost_tracker_pool( banks );
  if( FD_UNLIKELY( bank->cost_tracker_pool_idx!=fd_bank_cost_tracker_pool_idx_null( cost_tracker_pool ) ) ) {
    fd_banks_cost_tracker_release( banks, bank->cost_tracker_pool_idx );
  }
  bank->cost_tracker_pool_idx = fd_banks_cost_tracker_acquire( banks );

  if( FD_UNLIKELY( bank->stake_rewards_fork_id!=USHORT_MAX ) ) {
    fd_stake_rewards_release( fd_banks_get_stake_rewards( banks ), bank->stake_rewards_fork_id );
    bank->stake_rewards_fork_id = USHORT_MAX;
  }

  /* Resetting the override store invalidates any fork id the bank
     acquired at an epoch boundary; re-sync it to the new root. */
  fd_collector_overrides_t * collector_overrides = fd_banks_get_collector_overrides( banks );
  fd_collector_overrides_reset( collector_overrides );
  bank->collector_overrides_fork_id = fd_collector_overrides_get_root_idx( collector_overrides );

  fd_bank_epoch_credits_clear( bank );
}

void
fd_banks_clear( fd_banks_t * banks ) {

  fd_bank_t *              bank_pool         = fd_banks_get_bank_pool( banks );
  fd_bank_cost_tracker_t * cost_tracker_pool = fd_banks_get_cost_tracker_pool( banks );

  for( ulong i=0UL; i<banks->max_total_banks; i++ ) {
    fd_bank_t * bank = fd_banks_pool_ele( bank_pool, i );
    bank->state                 = FD_BANK_STATE_INACTIVE;
    bank->cost_tracker_pool_idx = fd_bank_cost_tracker_pool_idx_null( cost_tracker_pool );
    bank->vote_stakes_fork_id   = ULONG_MAX;
    bank->epoch_credits_fork_id = USHORT_MAX;
  }

  fd_banks_pool_reset( bank_pool );
  fd_rwlock_write( &banks->cost_tracker_cache_lock );
  fd_bank_cost_tracker_pool_reset( cost_tracker_pool );
  for( ulong i=0UL; i<banks->max_fork_width; i++ ) {
    fd_bank_cost_tracker_pool_ele( cost_tracker_pool, i )->disk_valid = 0U;
  }
  banks->cost_tracker_cache_lru = 0UL;
  for( ulong i=0UL; i<FD_BANKS_COST_TRACKER_CACHE_CNT; i++ ) {
    FD_CHECK_CRIT( !banks->cost_tracker_cache_pin_cnt[i],
                   "invariant violation: clearing pinned cost tracker cache" );
    banks->cost_tracker_cache_pool_idx[i] = ULONG_MAX;
    banks->cost_tracker_cache_lru_slot[i] = 0UL;
    banks->cost_tracker_cache_dirty[i]    = 0U;
  }
  fd_rwlock_unwrite( &banks->cost_tracker_cache_lock );
  fd_banks_dead_remove_all( fd_banks_get_dead_banks_deque( banks ) );
  banks->evict_rr_idx = 0UL;
  banks->prunable_idx = fd_banks_pool_idx_null( bank_pool );

  fd_stake_delegations_reset( fd_banks_get_stake_delegations( banks ) );
  fd_vote_stakes_reset( fd_banks_get_vote_stakes( banks ) );
  fd_collector_overrides_reset( fd_banks_get_collector_overrides( banks ) );

  fd_stake_rewards_clear( fd_banks_get_stake_rewards( banks ) );

  fd_rwlock_write( &banks->epoch_credits_lock );
  ulong epoch_credits_set_cnt = fd_banks_epoch_credits_set_cnt( banks );
  fd_memset( fd_banks_get_epoch_credits_len( banks ),       0, sizeof(ulong) * epoch_credits_set_cnt );
  fd_memset( fd_banks_get_epoch_credits_refcnt( banks ),    0, sizeof(ulong) * epoch_credits_set_cnt );
  fd_memset( fd_banks_get_epoch_credits_disk_valid( banks ), 0, sizeof(uchar) * epoch_credits_set_cnt );
  banks->epoch_credits_lru = 0UL;
  for( ulong i=0UL; i<FD_BANKS_EPOCH_CREDITS_CACHE_CNT; i++ ) {
    FD_CHECK_CRIT( !banks->epoch_credits_cache_pin_cnt[i],
                   "invariant violation: clearing pinned epoch credits cache" );
    banks->epoch_credits_cache_set_idx[i] = ULONG_MAX;
    banks->epoch_credits_cache_lru[i]     = 0UL;
    banks->epoch_credits_cache_dirty[i]   = 0U;
  }
  fd_rwlock_unwrite( &banks->epoch_credits_lock );

  banks->root_idx        = ULONG_MAX;
  banks->curr_fork_width = 0UL;
  banks->bank_seq        = 1UL; /* start at 1 so 0 is reserved as an invalid bank_seq sentinel */
}
