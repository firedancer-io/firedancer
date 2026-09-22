#include "fd_stake_delegations_private.h"
#include "fd_stakes.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../events/fd_event_runtime.h"
#include "../../util/fd_hash32.h"

#include <errno.h>
#include <unistd.h>

static inline uint *
get_buckets( fd_stake_delegations_t * stake_delegations ) {
  return (uint *)((uchar *)stake_delegations + fd_ulong_align_up( sizeof(*stake_delegations), alignof(uint) ));
}

static inline page_t *
get_pages( fd_stake_delegations_t * stake_delegations ) {
  return (page_t *)((uchar *)stake_delegations + stake_delegations->pages_offset);
}

static inline frame_t *
get_frames( fd_stake_delegations_t * stake_delegations ) {
  return (frame_t *)((uchar *)stake_delegations + stake_delegations->frames_offset);
}

static inline fork_t *
get_forks( fd_stake_delegations_t * stake_delegations ) {
  return (fork_t *)((uchar *)stake_delegations + stake_delegations->forks_offset);
}

static inline ulong *
get_descends( fd_stake_delegations_t * stake_delegations,
              ushort                   fork ) {
  ulong descends_words = (stake_delegations->max_live_slots+63UL)>>6;
  return (ulong *)((uchar *)stake_delegations + stake_delegations->descends_offset) + (ulong)fork*descends_words;
}

static inline uchar *
get_data( fd_stake_delegations_t * stake_delegations,
          uint                     frame ) {
  return (uchar *)stake_delegations + stake_delegations->data_offset + (ulong)frame*FD_STAKE_DELEGATIONS_PAGE_SZ;
}

static void
nonfull_remove( fd_stake_delegations_t * stake_delegations,
                uint                     page ) {
  page_t * pages = get_pages( stake_delegations );
  page_t * p     = pages+page;
  uint *   head  = &stake_delegations->nonfull[p->role][p->frame!=UINT_MAX];
  if( p->prev==UINT_MAX ) {
    *head = p->next;
  } else {
    pages[p->prev].next = p->next;
  }
  if( p->next!=UINT_MAX ) pages[p->next].prev = p->prev;
  p->prev = p->next = UINT_MAX;
}

static void
nonfull_insert( fd_stake_delegations_t * stake_delegations,
                uint                     page ) {
  page_t * pages = get_pages( stake_delegations );
  page_t * p     = pages+page;
  uint *   head  = &stake_delegations->nonfull[p->role][p->frame!=UINT_MAX];
  p->prev = UINT_MAX;
  p->next = *head;
  if( *head!=UINT_MAX ) pages[*head].prev = page;
  *head = page;
}

/* Complete scalar page transfers.  Partial direct I/O can continue only
   on a full page boundary, covering every supported startup alignment.
   Never publish a partial disk image. */
static void
page_io( fd_stake_delegations_t * stake_delegations,
         uint                     page,
         uchar *                  data,
         int                      writing ) {
  ulong done = 0UL;
  ulong off  = (ulong)page*FD_STAKE_DELEGATIONS_PAGE_SZ;
  while( done<FD_STAKE_DELEGATIONS_PAGE_SZ ) {
    long n = writing ? pwrite( stake_delegations->disk_fd, data+done, FD_STAKE_DELEGATIONS_PAGE_SZ-done, (off_t)(off+done) )
                     : pread ( stake_delegations->disk_fd, data+done, FD_STAKE_DELEGATIONS_PAGE_SZ-done, (off_t)(off+done) );
    if( FD_UNLIKELY( n<0L ) ) {
      if( errno==EINTR ) continue;
      FD_LOG_ERR(( "stake delegations %s() failed (%i-%s), page %u", writing ? "pwrite" : "pread", errno, fd_io_strerror( errno ), page ));
    }
    if( FD_UNLIKELY( !n ) ) FD_LOG_ERR(( "stake delegations %s made no progress, page %u", writing ? "write" : "read", page ));
    done += (ulong)n;
    if( FD_UNLIKELY( done<FD_STAKE_DELEGATIONS_PAGE_SZ && (done & (FD_STAKE_DELEGATIONS_PAGE_SZ-1UL)) ) ) {
      FD_LOG_ERR(( "stake delegations short unaligned %s, page %u", writing ? "write" : "read", page ));
    }
  }
}

static uint
page_fault( fd_stake_delegations_t * stake_delegations,
            uint                     page ) {
  page_t *  pages  = get_pages( stake_delegations );
  frame_t * frames = get_frames( stake_delegations );
  page_t *  p      = pages+page;
  if( FD_LIKELY( p->frame!=UINT_MAX ) ) return p->frame;
  fd_racesan_hook( "stake_delegations_cache:pre_fault" );
  uint frame = stake_delegations->free_frame;
  if( frame!=UINT_MAX ) {
    stake_delegations->free_frame = frames[frame].next;
  } else {
    for(;;) {
      frame                       = stake_delegations->clock_hand;
      stake_delegations->clock_hand = (frame+1U)%stake_delegations->frame_max;
      if( !frames[frame].referenced ) break;
      frames[frame].referenced = 0U;
    }
    uint     victim = frames[frame].page;
    page_t * v      = pages+victim;
    if( v->flags & PAGE_DIRTY ) {
      page_io( stake_delegations, victim, get_data( stake_delegations, frame ), 1 );
      v->flags = PAGE_WRITTEN;
    }
    if( v->cnt<128U ) nonfull_remove( stake_delegations, victim );
    v->frame = UINT_MAX;
    if( v->cnt<128U ) nonfull_insert( stake_delegations, victim );
  }
  if( p->flags & PAGE_WRITTEN ) {
    page_io( stake_delegations, page, get_data( stake_delegations, frame ), 0 );
  } else {
    fd_memset( get_data( stake_delegations, frame ), 0, FD_STAKE_DELEGATIONS_PAGE_SZ );
  }
  if( p->cnt<128U ) nonfull_remove( stake_delegations, page );
  p->frame = frame;
  if( p->cnt<128U ) nonfull_insert( stake_delegations, page );
  frames[frame].page       = page;
  frames[frame].referenced = 0U;
  fd_racesan_hook( "stake_delegations_cache:post_fault" );
  return frame;
}

static fd_stake_delegation_t *
record( fd_stake_delegations_t * stake_delegations,
        uint                     idx,
        int                      reference ) {
  uint page  = idx>>7;
  uint frame = get_pages( stake_delegations )[page].frame;
  if( FD_UNLIKELY( frame==UINT_MAX ) ) {
    frame = page_fault( stake_delegations, page );
  }
  if( reference ) get_frames( stake_delegations )[frame].referenced = 1U;
  return (fd_stake_delegation_t *)get_data( stake_delegations, frame ) + (idx & 127U);
}

static void
dirty( fd_stake_delegations_t * stake_delegations,
       uint                     idx ) {
  get_pages( stake_delegations )[idx>>7].flags |= PAGE_DIRTY;
}

/* Prefer free slots on resident pages before faulting another page. */
static uint
reserve( fd_stake_delegations_t * stake_delegations,
         uchar                    role ) {
  uint page = stake_delegations->nonfull[role][1];
  if( page==UINT_MAX ) {
    page = stake_delegations->nonfull[role][0];
    if( page!=UINT_MAX ) {
      page_fault( stake_delegations, page );
    } else {
      page = stake_delegations->free_page;
      if( page!=UINT_MAX ) {
        stake_delegations->free_page = get_pages( stake_delegations )[page].next;
      } else {
        FD_CHECK_CRIT( stake_delegations->page_wmk<stake_delegations->page_max, "stake delegations logical page capacity exhausted" );
        page = stake_delegations->page_wmk++;
      }
      page_t * p = get_pages( stake_delegations )+page;
      *p = (page_t){
        .frame = UINT_MAX,
        .prev  = UINT_MAX,
        .next  = UINT_MAX,
        .role  = role
      };
      nonfull_insert( stake_delegations, page );
      page_fault( stake_delegations, page );
    }
  }
  page_t * p    = get_pages( stake_delegations )+page;
  uint     word = p->used[0]==ULONG_MAX;
  uint     bit  = (uint)fd_ulong_find_lsb( ~p->used[word] );
  fd_racesan_hook( "stake_delegations_alloc:pre_reserve" );
  p->used[word] |= 1UL<<bit;
  p->cnt++;
  fd_racesan_hook( "stake_delegations_alloc:post_reserve" );
  if( p->cnt==128U ) nonfull_remove( stake_delegations, page );
  return (page<<7) + 64U*word + bit;
}

static void
release( fd_stake_delegations_t * stake_delegations,
         uint                     idx ) {
  uint                    page = idx>>7;
  page_t *                p    = get_pages( stake_delegations )+page;
  fd_stake_delegation_t * d    = record( stake_delegations, idx, 0 );
  d->flags = 0;
  dirty( stake_delegations, idx );
  if( p->cnt==128U ) nonfull_insert( stake_delegations, page );
  p->used[(idx & 127U)>>6] &= ~(1UL<<(idx & 63U));
  p->cnt--;
  if( FD_UNLIKELY( !p->cnt ) ) {
    nonfull_remove( stake_delegations, page );
    if( p->frame!=UINT_MAX ) {
      frame_t * f = get_frames( stake_delegations )+p->frame;
      f->page        = UINT_MAX;
      f->next        = stake_delegations->free_frame;
      stake_delegations->free_frame = p->frame;
    }
    *p = (page_t){
      .frame = UINT_MAX,
      .prev  = UINT_MAX,
      .next  = stake_delegations->free_page
    };
    stake_delegations->free_page = page;
  }
}

static void
publish( fd_stake_delegations_t *      stake_delegations,
         uint                          idx,
         fd_stake_delegation_t const * d ) {
  fd_stake_delegation_t * dst = record( stake_delegations, idx, 1 );
  fd_racesan_hook( "stake_delegations_record:pre_publish" );
  *dst = *d;
  fd_racesan_hook( "stake_delegations_record:post_publish" );
  dirty( stake_delegations, idx );
}

static uint
bucket( fd_stake_delegations_t * stake_delegations,
        fd_pubkey_t const *      key ) {
  return fd_hash32( key->uc, stake_delegations->seed ) & (uint)(FD_STAKE_DELEGATIONS_BUCKET_CNT-1UL);
}

/* UINT_MAX means the key is absent. */
static uint
find_root( fd_stake_delegations_t * stake_delegations,
           fd_pubkey_t const *      key ) {
  uint idx = get_buckets( stake_delegations )[bucket( stake_delegations, key )];
  while( idx!=UINT_MAX ) {
    fd_stake_delegation_t const * d = record( stake_delegations, idx, 1 );
    if( fd_pubkey_eq( &d->stake_account, key ) ) return idx;
    idx = d->next_;
  }
  return UINT_MAX;
}

static uint
insert_root( fd_stake_delegations_t * stake_delegations,
             fd_pubkey_t const *      key ) {
  uint idx = reserve( stake_delegations, PAGE_ROOT );
  uint b   = bucket( stake_delegations, key );
  fd_stake_delegation_t d = {
    .stake_account = *key,
    .next_         = get_buckets( stake_delegations )[b],
    .delta_head    = UINT_MAX,
    .fork_id       = USHORT_MAX,
    .flags         = FD_STAKE_DELEGATION_IN_USE
  };
  publish( stake_delegations, idx, &d );
  fd_racesan_hook( "stake_delegations_bucket:pre_publish" );
  get_buckets( stake_delegations )[b] = idx;
  fd_racesan_hook( "stake_delegations_bucket:post_publish" );
  return idx;
}

static void
remove_root( fd_stake_delegations_t * stake_delegations,
             uint                     idx ) {
  fd_stake_delegation_t d = *record( stake_delegations, idx, 0 );
  FD_TEST( d.delta_head==UINT_MAX );
  uint b    = bucket( stake_delegations, &d.stake_account );
  uint prev = UINT_MAX;
  uint cur  = get_buckets( stake_delegations )[b];
  while( cur!=idx ) {
    FD_CHECK_CRIT( cur!=UINT_MAX, "missing stake delegation root" );
    prev = cur;
    cur  = record( stake_delegations, cur, 0 )->next_;
  }
  if( prev==UINT_MAX ) {
    get_buckets( stake_delegations )[b] = d.next_;
  } else {
    record( stake_delegations, prev, 0 )->next_ = d.next_;
    dirty( stake_delegations, prev );
  }
  if( d.flags & FD_STAKE_DELEGATION_ROOT_PRESENT ) stake_delegations->root_cnt--;
  release( stake_delegations, idx );
}

static void
reset( fd_stake_delegations_t * stake_delegations ) {
  ulong descends_words = (stake_delegations->max_live_slots+63UL)>>6;
  fd_memset( get_buckets( stake_delegations ),      255, FD_STAKE_DELEGATIONS_BUCKET_CNT*sizeof(uint) );
  fd_memset( get_pages( stake_delegations ),          0, (ulong)stake_delegations->page_max*sizeof(page_t) );
  fd_memset( get_forks( stake_delegations ),          0, stake_delegations->max_live_slots*sizeof(fork_t) );
  fd_memset( get_descends( stake_delegations, 0 ),    0, stake_delegations->max_live_slots*descends_words*sizeof(ulong) );
  for( uint i=0U; i<stake_delegations->frame_max; i++ ) {
    get_frames( stake_delegations )[i] = (frame_t){
      .page = UINT_MAX,
      .next = i+1U<stake_delegations->frame_max ? i+1U : UINT_MAX
    };
  }
  stake_delegations->page_wmk   = 0U;
  stake_delegations->free_page  = UINT_MAX;
  stake_delegations->free_frame = 0U;
  stake_delegations->clock_hand = 0U;
  fd_memset( stake_delegations->nonfull, 255, sizeof(stake_delegations->nonfull) );
  stake_delegations->root_fork = 0;
  get_forks( stake_delegations )[0] = (fork_t){
    .delta_head = UINT_MAX,
    .parent     = USHORT_MAX,
    .in_use     = 1
  };
  stake_delegations->root_cnt          = 0UL;
  stake_delegations->effective_stake   = stake_delegations->activating_stake = stake_delegations->deactivating_stake = 0UL;
  stake_delegations->fp_warmed_awarded = stake_delegations->context_valid = 0;
  stake_delegations->root_epoch        = stake_delegations->root_history_len = 0UL;
  stake_delegations->root_rate_epoch   = ULONG_MAX;
  stake_delegations->boot              = 1;
}

ulong
fd_stake_delegations_align( void ) {
  return FD_STAKE_DELEGATIONS_ALIGN;
}

ulong
fd_stake_delegations_footprint( ulong max_records,
                                ulong max_live_slots,
                                ulong cache_bytes ) {
  if( FD_UNLIKELY( !max_records || max_records>((ulong)UINT_MAX-127UL) ||
                   !max_live_slots || max_live_slots>FD_STAKE_DELEGATIONS_FORK_MAX ||
                   cache_bytes<FD_STAKE_DELEGATIONS_PAGE_SZ || cache_bytes%FD_STAKE_DELEGATIONS_PAGE_SZ ||
                   cache_bytes/FD_STAKE_DELEGATIONS_PAGE_SZ>UINT_MAX ) ) return 0UL;
  ulong page_max  = (max_records+127UL)>>7;
  ulong frame_max = cache_bytes/FD_STAKE_DELEGATIONS_PAGE_SZ;
  ulong l         = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_stake_delegations_t),  sizeof(fd_stake_delegations_t) );
  l = FD_LAYOUT_APPEND( l, alignof(uint),                   FD_STAKE_DELEGATIONS_BUCKET_CNT*sizeof(uint) );
  l = FD_LAYOUT_APPEND( l, alignof(page_t),                 page_max*sizeof(page_t) );
  l = FD_LAYOUT_APPEND( l, alignof(frame_t),                frame_max*sizeof(frame_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fork_t),                 max_live_slots*sizeof(fork_t) );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),                  max_live_slots*((max_live_slots+63UL)>>6)*sizeof(ulong) );
  l = FD_LAYOUT_APPEND( l, FD_STAKE_DELEGATIONS_ALIGN,      cache_bytes );
  return FD_LAYOUT_FINI( l, FD_STAKE_DELEGATIONS_ALIGN );
}

void *
fd_stake_delegations_new( void * mem,
                          int    disk_fd,
                          ulong  seed,
                          ulong  max_records,
                          ulong  max_live_slots,
                          ulong  cache_bytes ) {
  ulong footprint = fd_stake_delegations_footprint( max_records, max_live_slots, cache_bytes );
  if( FD_UNLIKELY( !mem || !fd_ulong_is_aligned( (ulong)mem, FD_STAKE_DELEGATIONS_ALIGN ) || !footprint || disk_fd<0 ) ) return NULL;
  fd_stake_delegations_t * sd = mem;
  fd_memset( sd, 0, sizeof(*sd) );
  sd->seed           = seed;
  sd->max_live_slots = max_live_slots;
  sd->page_max       = (uint)((max_records+127UL)>>7);
  sd->frame_max      = (uint)(cache_bytes/FD_STAKE_DELEGATIONS_PAGE_SZ);
  sd->disk_fd        = disk_fd;
  ulong descends_words = (max_live_slots+63UL)>>6;
  ulong l              = fd_ulong_align_up( sizeof(*sd), alignof(uint) ) + FD_STAKE_DELEGATIONS_BUCKET_CNT*sizeof(uint);
#define APPEND(member,align,size) do {          \
    l = fd_ulong_align_up( l, (align) );        \
    sd->member = l;                            \
    l += (size);                              \
  } while(0)
  APPEND( pages_offset,    alignof(page_t),                 (ulong)sd->page_max*sizeof(page_t) );
  APPEND( frames_offset,   alignof(frame_t),                (ulong)sd->frame_max*sizeof(frame_t) );
  APPEND( forks_offset,    alignof(fork_t),                 max_live_slots*sizeof(fork_t) );
  APPEND( descends_offset, alignof(ulong),                  max_live_slots*descends_words*sizeof(ulong) );
  APPEND( data_offset,     FD_STAKE_DELEGATIONS_ALIGN,      cache_bytes );
#undef APPEND
  FD_TEST( fd_ulong_align_up( l, FD_STAKE_DELEGATIONS_ALIGN )==footprint );
  fd_rwlock_new( &sd->lock );
  reset( sd );
  FD_COMPILER_MFENCE();
  sd->magic = FD_STAKE_DELEGATIONS_MAGIC;
  FD_LOG_INFO(( "stake delegations: %lu bytes, %lu record slots, %u pages, %u frames, %lu forks",
                footprint, (ulong)sd->page_max*128UL, sd->page_max, sd->frame_max, max_live_slots ));
  return mem;
}

fd_stake_delegations_t *
fd_stake_delegations_join( void * mem,
                           int    disk_fd ) {
  if( FD_UNLIKELY( !mem || !fd_ulong_is_aligned( (ulong)mem, FD_STAKE_DELEGATIONS_ALIGN ) ) ) return NULL;
  fd_stake_delegations_t * sd = mem;
  if( FD_UNLIKELY( sd->magic!=FD_STAKE_DELEGATIONS_MAGIC || sd->disk_fd!=disk_fd ) ) return NULL;
  return sd;
}

void
fd_stake_delegations_reset( fd_stake_delegations_t * stake_delegations ) {
  fd_rwlock_write( &stake_delegations->lock );
  reset( stake_delegations );
  fd_rwlock_unwrite( &stake_delegations->lock );
}

static int
ancestor( fd_stake_delegations_t * stake_delegations,
          ushort                   fork,
          ushort                   parent ) {
  return !!(get_descends( stake_delegations, fork )[parent>>6] & (1UL<<(parent & 63)));
}

ushort
fd_stake_delegations_root_fork_id( fd_stake_delegations_t const * stake_delegations ) {
  return stake_delegations->root_fork;
}

ushort
fd_stake_delegations_attach_child( fd_stake_delegations_t * stake_delegations,
                                   ushort                   parent ) {
  fd_rwlock_write( &stake_delegations->lock );
  fork_t * forks = get_forks( stake_delegations );
  FD_CHECK_CRIT( parent<stake_delegations->max_live_slots && forks[parent].in_use,
                 "invalid stake delegations parent" );
  ushort id = 0;
  while( id<stake_delegations->max_live_slots && forks[id].in_use ) id++;
  FD_CHECK_CRIT( id<stake_delegations->max_live_slots, "stake delegations fork capacity exhausted" );
  forks[id] = (fork_t){
    .delta_head = UINT_MAX,
    .parent     = parent,
    .in_use     = 1
  };
  ulong descends_words = (stake_delegations->max_live_slots+63UL)>>6;
  fd_memcpy( get_descends( stake_delegations, id ), get_descends( stake_delegations, parent ), descends_words*sizeof(ulong) );
  get_descends( stake_delegations, id )[parent>>6] |= 1UL<<(parent & 63);
  stake_delegations->boot = 0;
  fd_rwlock_unwrite( &stake_delegations->lock );
  return id;
}

static void
check_mutable( fd_stake_delegations_t * stake_delegations,
               ushort                   fork ) {
  FD_CHECK_CRIT( fork<stake_delegations->max_live_slots && fork!=stake_delegations->root_fork && get_forks( stake_delegations )[fork].in_use,
                 "stake delegations fork is not mutable" );
}

/* Preserve the existing record links when replacing a fork payload. */
static void
replace_delta( fd_stake_delegations_t *      stake_delegations,
               uint                          idx,
               fd_stake_delegation_t const * src ) {
  fd_stake_delegation_t * dst = record( stake_delegations, idx, 1 );
  dst->vote_account         = src->vote_account;
  dst->stake                = src->stake;
  dst->lamports             = src->lamports;
  dst->credits_observed     = src->credits_observed;
  dst->acc_dlen             = src->acc_dlen;
  dst->activation_epoch     = src->activation_epoch;
  dst->deactivation_epoch   = src->deactivation_epoch;
  dst->warmup_cooldown_rate = src->warmup_cooldown_rate;
  dst->state                = FD_STAKE_DELEGATION_STATE_UNKNOWN;
  dst->flags                = src->flags;
  dirty( stake_delegations, idx );
}

static void
fork_upsert( fd_stake_delegations_t *      stake_delegations,
             ushort                        fork,
             fd_stake_delegation_t const * src ) {
  fd_rwlock_write( &stake_delegations->lock );
  check_mutable( stake_delegations, fork );
  uint root = find_root( stake_delegations, &src->stake_account );
  if( root==UINT_MAX ) root = insert_root( stake_delegations, &src->stake_account );
  uint head = record( stake_delegations, root, 1 )->delta_head;
  uint idx  = head;
  while( idx!=UINT_MAX ) {
    fd_stake_delegation_t const * d = record( stake_delegations, idx, 1 );
    if( d->fork_id==fork ) {
      replace_delta( stake_delegations, idx, src );
      fd_rwlock_unwrite( &stake_delegations->lock );
      return;
    }
    idx = d->next_;
  }
  idx = reserve( stake_delegations, PAGE_DELTA );
  fd_stake_delegation_t d = *src;
  fork_t *              f = get_forks( stake_delegations )+fork;
  d.fork_id   = fork;
  d.next_     = head;
  d.fork_next = f->delta_head;
  publish( stake_delegations, idx, &d );
  f->delta_head = idx;
  /* Delta allocation can evict the root page. */
  record( stake_delegations, root, 1 )->delta_head = idx;
  dirty( stake_delegations, root );
  fd_rwlock_unwrite( &stake_delegations->lock );
}

void
fd_stake_delegations_fork_update( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork,
                                  fd_pubkey_t const *      stake_account,
                                  fd_pubkey_t const *      vote_account,
                                  ulong                    stake,
                                  ulong                    activation_epoch,
                                  ulong                    deactivation_epoch,
                                  ulong                    credits_observed,
                                  ulong                    lamports,
                                  uint                     acc_dlen,
                                  uchar                    warmup_cooldown_rate ) {
  FD_CHECK_ERR( activation_epoch  <USHORT_MAX || activation_epoch  ==ULONG_MAX, "activation_epoch overflow"   );
  FD_CHECK_ERR( deactivation_epoch<USHORT_MAX || deactivation_epoch==ULONG_MAX, "deactivation_epoch overflow" );
  fd_stake_delegation_t d = {
    .stake_account        = *stake_account,
    .vote_account         = *vote_account,
    .stake                = stake,
    .lamports             = lamports,
    .credits_observed     = credits_observed,
    .acc_dlen             = acc_dlen,
    .activation_epoch     = (ushort)activation_epoch,
    .deactivation_epoch   = (ushort)deactivation_epoch,
    .warmup_cooldown_rate = warmup_cooldown_rate,
    .flags                = FD_STAKE_DELEGATION_IN_USE
  };
  fork_upsert( stake_delegations, fork, &d );
}

void
fd_stake_delegations_fork_remove( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork,
                                  fd_pubkey_t const *      stake_account ) {
  fd_stake_delegation_t d = {
    .stake_account = *stake_account,
    .flags         = FD_STAKE_DELEGATION_IN_USE|FD_STAKE_DELEGATION_TOMBSTONE
  };
  fork_upsert( stake_delegations, fork, &d );
}

static fd_stake_history_entry_t
root_status( fd_stake_delegations_t *      stake_delegations,
             fd_stake_delegation_t const * d ) {
  fd_stake_history_t history = {
    .entries = stake_delegations->root_history,
    .len     = stake_delegations->root_history_len
  };
  return fd_stake_delegation_activation_status( d, stake_delegations->root_epoch, &history, &stake_delegations->root_rate_epoch, stake_delegations->root_fixed_point );
}

static void
subtract_root( fd_stake_delegations_t *      stake_delegations,
               fd_stake_delegation_t const * d ) {
  if( !stake_delegations->context_valid || !(d->flags & FD_STAKE_DELEGATION_ROOT_PRESENT) ) return;
  fd_stake_history_entry_t status = root_status( stake_delegations, d );
  stake_delegations->effective_stake    -= status.effective;
  stake_delegations->activating_stake   -= status.activating;
  stake_delegations->deactivating_stake -= status.deactivating;
}

static void
add_root( fd_stake_delegations_t * stake_delegations,
          fd_stake_delegation_t *  d ) {
  d->state = FD_STAKE_DELEGATION_STATE_UNKNOWN;
  if( !stake_delegations->context_valid ) return;
  fd_stake_history_entry_t status = root_status( stake_delegations, d );
  stake_delegations->effective_stake    += status.effective;
  stake_delegations->activating_stake   += status.activating;
  stake_delegations->deactivating_stake += status.deactivating;
  fd_stake_history_t history = {
    .entries = stake_delegations->root_history,
    .len     = stake_delegations->root_history_len
  };
  if( fd_sysvar_stake_history_is_contiguous( &history ) ) d->state = fd_stake_delegation_classify( d, status, stake_delegations->root_epoch );
  if( d->state==FD_STAKE_DELEGATION_STATE_WARMED && !stake_delegations->root_fixed_point ) stake_delegations->fp_warmed_awarded = 1;
}

static void
store_root( fd_stake_delegations_t *      stake_delegations,
            uint                          idx,
            fd_stake_delegation_t const * src ) {
  fd_stake_delegation_t old = *record( stake_delegations, idx, 0 );
  subtract_root( stake_delegations, &old );
  fd_stake_delegation_t d = *src;
  d.next_      = old.next_;
  d.delta_head = old.delta_head;
  d.fork_id    = USHORT_MAX;
  d.flags      = FD_STAKE_DELEGATION_IN_USE|FD_STAKE_DELEGATION_ROOT_PRESENT;
  if( !(old.flags & FD_STAKE_DELEGATION_ROOT_PRESENT) ) {
    stake_delegations->root_cnt++;
  }
  add_root( stake_delegations, &d );
  publish( stake_delegations, idx, &d );
}

static void
delete_root( fd_stake_delegations_t * stake_delegations,
             uint                     idx ) {
  fd_stake_delegation_t d = *record( stake_delegations, idx, 0 );
  if( d.flags & FD_STAKE_DELEGATION_ROOT_PRESENT ) {
    subtract_root( stake_delegations, &d );
    d.flags = FD_STAKE_DELEGATION_IN_USE;
    d.state = FD_STAKE_DELEGATION_STATE_UNKNOWN;
    stake_delegations->root_cnt--;
    publish( stake_delegations, idx, &d );
  }
  if( d.delta_head==UINT_MAX ) remove_root( stake_delegations, idx );
}

void
fd_stake_delegations_root_update( fd_stake_delegations_t * stake_delegations,
                                  fd_pubkey_t const *      stake_account,
                                  fd_pubkey_t const *      vote_account,
                                  ulong                    stake,
                                  ulong                    activation_epoch,
                                  ulong                    deactivation_epoch,
                                  ulong                    credits_observed,
                                  ulong                    lamports,
                                  uint                     acc_dlen,
                                  uchar                    warmup_cooldown_rate ) {
  fd_rwlock_write( &stake_delegations->lock );
  FD_CHECK_CRIT( stake_delegations->boot, "stake delegations root_update after boot" );
  FD_CHECK_ERR( activation_epoch  <USHORT_MAX || activation_epoch  ==ULONG_MAX, "activation_epoch overflow"   );
  FD_CHECK_ERR( deactivation_epoch<USHORT_MAX || deactivation_epoch==ULONG_MAX, "deactivation_epoch overflow" );
  fd_stake_delegation_t d = {
    .stake_account        = *stake_account,
    .vote_account         = *vote_account,
    .stake                = stake,
    .lamports             = lamports,
    .credits_observed     = credits_observed,
    .acc_dlen             = acc_dlen,
    .activation_epoch     = (ushort)activation_epoch,
    .deactivation_epoch   = (ushort)deactivation_epoch,
    .warmup_cooldown_rate = warmup_cooldown_rate
  };
  uint root = find_root( stake_delegations, stake_account );
  if( root==UINT_MAX ) root = insert_root( stake_delegations, stake_account );
  store_root( stake_delegations, root, &d );
  fd_rwlock_unwrite( &stake_delegations->lock );
}

fd_stake_delegations_view_t *
fd_stake_delegations_view_begin( fd_stake_delegations_view_t * view,
                                 fd_stake_delegations_t *      stake_delegations,
                                 ushort                        fork ) {
  fd_rwlock_write( &stake_delegations->lock );
  FD_CHECK_CRIT( fork<stake_delegations->max_live_slots && get_forks( stake_delegations )[fork].in_use,
                 "invalid stake delegations view" );
  *view = (fd_stake_delegations_view_t){
    .sd       = stake_delegations,
    .fork_id  = fork,
    .page_wmk = stake_delegations->page_wmk
  };
  fd_racesan_hook( "stake_delegations_view:admitted" );
  return view;
}

void
fd_stake_delegations_view_end( fd_stake_delegations_view_t * view ) {
  fd_rwlock_unwrite( &view->sd->lock );
  view->sd = NULL;
}

/* The view holds the store lock.  Copy records before another access
   can fault and replace their frame, even under exclusive access. */
static void
iter_fill( fd_stake_delegations_iter_t * iter ) {
  fd_stake_delegations_view_t * view              = iter->view;
  fd_stake_delegations_t *      stake_delegations = view->sd;
  ulong                         limit             = (ulong)view->page_wmk*128UL;
  iter->batch_idx = iter->batch_cnt = 0UL;
  while( iter->cursor<limit && iter->batch_cnt<FD_STAKE_DELEGATIONS_ITER_BATCH ) {
    uint root = (uint)iter->cursor++;
    if( get_pages( stake_delegations )[root>>7].role!=PAGE_ROOT ) {
      iter->cursor = ((ulong)(root>>7)+1UL)*128UL;
      continue;
    }
    fd_stake_delegation_t selected = *record( stake_delegations, root, 0 );
    if( !(selected.flags & FD_STAKE_DELEGATION_IN_USE) ) continue;
    uint next  = selected.delta_head;
    int  found = !!(selected.flags & FD_STAKE_DELEGATION_ROOT_PRESENT);
    if( !view->use_stable_tags ) selected.state = FD_STAKE_DELEGATION_STATE_UNKNOWN;
    while( next!=UINT_MAX ) {
      fd_stake_delegation_t const * d = record( stake_delegations, next, 0 );
      if( d->fork_id==view->fork_id || ancestor( stake_delegations, view->fork_id, d->fork_id ) ) {
        selected = *d;
        found    = !(selected.flags & FD_STAKE_DELEGATION_TOMBSTONE);
        break;
      }
      next = d->next_;
    }
    if( !found ) continue;
    iter->batch[iter->batch_cnt]   = selected;
    iter->indices[iter->batch_cnt] = root;
    iter->batch_cnt++;
  }
  if( iter->batch_cnt ) iter->idx = iter->indices[0];
}

fd_stake_delegations_iter_t *
fd_stake_delegations_iter_init( fd_stake_delegations_iter_t * iter,
                                fd_stake_delegations_view_t * view ) {
  iter->view   = view;
  iter->cursor = 0UL;
  iter_fill( iter );
  return iter;
}

void
fd_stake_delegations_iter_next( fd_stake_delegations_iter_t * iter ) {
  iter->batch_idx++;
  if( iter->batch_idx==iter->batch_cnt ) {
    iter_fill( iter );
  } else {
    iter->idx = iter->indices[iter->batch_idx];
  }
}

void
fd_stake_delegations_view_totals( fd_stake_delegations_view_t * view,
                                  ulong                         epoch,
                                  fd_stake_history_t const *    history,
                                  ulong *                       rate_epoch,
                                  int                           fixed_point,
                                  fd_stake_history_entry_t *    totals ) {
  *totals = (fd_stake_history_entry_t){
    .epoch = epoch
  };
  fd_stake_delegations_iter_t iter[1];
  for( fd_stake_delegations_iter_init( iter, view ); !fd_stake_delegations_iter_done( iter ); fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_history_entry_t s = fd_stake_delegation_activation_status( fd_stake_delegations_iter_ele( iter ), epoch, history, rate_epoch, fixed_point );
    totals->effective    += s.effective;
    totals->activating   += s.activating;
    totals->deactivating += s.deactivating;
  }
}

/* Tree/cache exclusive.  Every access which can fault retains only
   copied records and logical links from preceding accesses. */
static uint
unlink_delta( fd_stake_delegations_t *      stake_delegations,
              uint                          idx,
              fd_stake_delegation_t const * d ) {
  uint root = find_root( stake_delegations, &d->stake_account );
  FD_CHECK_CRIT( root!=UINT_MAX, "stake delegation delta without root slot" );
  uint prev = UINT_MAX;
  uint cur  = record( stake_delegations, root, 0 )->delta_head;
  while( cur!=idx ) {
    FD_CHECK_CRIT( cur!=UINT_MAX, "missing stake delegation delta" );
    prev = cur;
    cur  = record( stake_delegations, cur, 0 )->next_;
  }
  if( prev==UINT_MAX ) {
    record( stake_delegations, root, 0 )->delta_head = d->next_;
    dirty( stake_delegations, root );
  } else {
    record( stake_delegations, prev, 0 )->next_ = d->next_;
    dirty( stake_delegations, prev );
  }
  release( stake_delegations, idx );
  return root;
}

static void
cancel_one( fd_stake_delegations_t * stake_delegations,
            ushort                   fork ) {
  fork_t * f   = get_forks( stake_delegations )+fork;
  uint     idx = f->delta_head;
  while( idx!=UINT_MAX ) {
    fd_stake_delegation_t d    = *record( stake_delegations, idx, 0 );
    uint                  root = unlink_delta( stake_delegations, idx, &d );
    fd_stake_delegation_t r    = *record( stake_delegations, root, 0 );
    if( !(r.flags & FD_STAKE_DELEGATION_ROOT_PRESENT) && r.delta_head==UINT_MAX ) remove_root( stake_delegations, root );
    idx = d.fork_next;
  }
  *f = (fork_t){0};
}

/* Rebuild ancestry from the surviving immutable parent relation.
   No record pages are scanned. */
static void
rebuild_tree( fd_stake_delegations_t * stake_delegations ) {
  fork_t * forks          = get_forks( stake_delegations );
  ulong    descends_words = (stake_delegations->max_live_slots+63UL)>>6;
  for( ushort id=0; id<stake_delegations->max_live_slots; id++ ) {
    fd_memset( get_descends( stake_delegations, id ), 0, descends_words*sizeof(ulong) );
  }
  for( ushort id=0; id<stake_delegations->max_live_slots; id++ ) {
    if( !forks[id].in_use || id==stake_delegations->root_fork ) continue;
    ushort parent = forks[id].parent;
    FD_TEST( parent<stake_delegations->max_live_slots && forks[parent].in_use );
    for( ushort p=parent; p!=USHORT_MAX; p=forks[p].parent ) get_descends( stake_delegations, id )[p>>6] |= 1UL<<(p & 63);
  }
}

void
fd_stake_delegations_cancel_fork( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork ) {
  fd_rwlock_write( &stake_delegations->lock );
  FD_CHECK_CRIT( fork<stake_delegations->max_live_slots && fork!=stake_delegations->root_fork && get_forks( stake_delegations )[fork].in_use,
                 "invalid stake delegations cancellation" );
  for( ushort id=0; id<stake_delegations->max_live_slots; id++ ) {
    if( get_forks( stake_delegations )[id].in_use && (id==fork || ancestor( stake_delegations, id, fork )) ) cancel_one( stake_delegations, id );
  }
  rebuild_tree( stake_delegations );
  fd_rwlock_unwrite( &stake_delegations->lock );
}

static void
set_context( fd_stake_delegations_t *   stake_delegations,
             ulong                      epoch,
             fd_stake_history_t const * history,
             ulong *                    rate_epoch,
             int                        fixed_point ) {
  ulong len = history ? history->len : 0UL;
  FD_CHECK_CRIT( len<=FD_SYSVAR_STAKE_HISTORY_CAP, "stake delegation history exceeds bounded context" );
  stake_delegations->root_epoch       = epoch;
  stake_delegations->root_rate_epoch  = rate_epoch ? *rate_epoch : ULONG_MAX;
  stake_delegations->root_fixed_point = fixed_point;
  stake_delegations->root_history_len = len;
  if( len ) fd_memcpy( stake_delegations->root_history, history->entries, len*sizeof(fd_stake_history_entry_t) );
  stake_delegations->context_valid = 1;
}

static int
same_context( fd_stake_delegations_t *   stake_delegations,
              ulong                      epoch,
              fd_stake_history_t const * history,
              ulong *                    rate_epoch,
              int                        fixed_point ) {
  ulong len = history ? history->len : 0UL;
  return stake_delegations->context_valid && stake_delegations->root_epoch==epoch && stake_delegations->root_rate_epoch==(rate_epoch ? *rate_epoch : ULONG_MAX) &&
         stake_delegations->root_fixed_point==fixed_point && stake_delegations->root_history_len==len &&
         (!len || !memcmp( stake_delegations->root_history, history->entries, len*sizeof(fd_stake_history_entry_t) ));
}

static void
recompute( fd_stake_delegations_t * stake_delegations ) {
  stake_delegations->effective_stake   = stake_delegations->activating_stake = stake_delegations->deactivating_stake = 0UL;
  stake_delegations->fp_warmed_awarded = 0;
  for( uint page=0U; page<stake_delegations->page_wmk; page++ ) {
    if( get_pages( stake_delegations )[page].role!=PAGE_ROOT ) continue;
    for( uint slot=0U; slot<128U; slot++ ) {
      uint                  idx = (page<<7)+slot;
      fd_stake_delegation_t d   = *record( stake_delegations, idx, 0 );
      if( !(d.flags & FD_STAKE_DELEGATION_ROOT_PRESENT) ) continue;
      add_root( stake_delegations, &d );
      publish( stake_delegations, idx, &d );
    }
  }
}

static ulong
prune( fd_stake_delegations_t *   stake_delegations,
       ulong                      epoch,
       fd_stake_history_t const * history,
       ulong *                    rate_epoch,
       int                        fixed_point,
       fd_bank_t const *          emit_bank ) {
  ulong count      = 0UL;
  ulong prev_epoch = epoch ? epoch-1UL : 0UL;
  for( uint page=0U; page<stake_delegations->page_wmk; page++ ) {
    if( get_pages( stake_delegations )[page].role!=PAGE_ROOT ) continue;
    for( uint slot=0U; slot<128U; slot++ ) {
      if( get_pages( stake_delegations )[page].role!=PAGE_ROOT ) break;
      uint                  idx = (page<<7)+slot;
      fd_stake_delegation_t d   = *record( stake_delegations, idx, 0 );
      if( !(d.flags & FD_STAKE_DELEGATION_ROOT_PRESENT) ) continue;
      if( !fd_stake_delegation_is_inactive( &d, epoch, history, rate_epoch, fixed_point ) ||
          !fd_stake_delegation_is_inactive( &d, prev_epoch, history, rate_epoch, fixed_point ) ) continue;
      if( FD_UNLIKELY( emit_bank ) ) fd_event_runtime_stake_delegation_remove_emit( emit_bank, d.stake_account.uc );
      delete_root( stake_delegations, idx );
      count++;
    }
  }
  return count;
}

void
fd_stake_delegations_advance_root( fd_stake_delegations_t *             stake_delegations,
                                   ushort                               fork,
                                   ulong                                epoch,
                                   fd_stake_history_t const *           history,
                                   ulong *                              rate_epoch,
                                   int                                  fixed_point,
                                   int                                  prune_inactive,
                                   fd_bank_t const *                    emit_bank,
                                   fd_stake_delegations_delta_stats_t * stats ) {
  fd_rwlock_write( &stake_delegations->lock );
  fork_t * forks = get_forks( stake_delegations );
  FD_CHECK_CRIT( fork<stake_delegations->max_live_slots && forks[fork].in_use && ancestor( stake_delegations, fork, stake_delegations->root_fork ),
                 "stake delegations root destination is not a descendant" );
  ushort path[ FD_STAKE_DELEGATIONS_FORK_MAX ];
  ulong path_cnt = 0UL;
  for( ushort id=fork; id!=stake_delegations->root_fork; id=forks[id].parent ) path[path_cnt++] = id;

  /* Cancel branches outside the path and destination subtree.  Ancestry
     remains intact until every release decision has been made. */
  for( ushort id=0; id<stake_delegations->max_live_slots; id++ ) {
    if( !forks[id].in_use || id==fork || ancestor( stake_delegations, fork, id ) || ancestor( stake_delegations, id, fork ) ) continue;
    cancel_one( stake_delegations, id );
  }
  if( !same_context( stake_delegations, epoch, history, rate_epoch, fixed_point ) ) {
    set_context( stake_delegations, epoch, history, rate_epoch, fixed_point );
    recompute( stake_delegations );
  }
  ulong upserts = 0UL;
  ulong removes = 0UL;
  for( ulong p=path_cnt; p; p-- ) {
    ushort id  = path[p-1UL];
    uint   idx = forks[id].delta_head;
    while( idx!=UINT_MAX ) {
      fd_stake_delegation_t d    = *record( stake_delegations, idx, 0 );
      uint                  root = unlink_delta( stake_delegations, idx, &d );
      if( d.flags & FD_STAKE_DELEGATION_TOMBSTONE ) {
        delete_root( stake_delegations, root );
        removes++;
      } else {
        store_root( stake_delegations, root, &d );
        upserts++;
      }
      idx = d.fork_next;
    }
    forks[id].delta_head = UINT_MAX;
  }
  /* Prune once at the externally visible transition, after the complete
     ancestry fold.  Descendant deltas keep absent root slots alive. */
  if( prune_inactive ) removes += prune( stake_delegations, epoch, history, rate_epoch, fixed_point, emit_bank );
  ushort old_root = stake_delegations->root_fork;
  for( ulong p=1UL; p<path_cnt; p++ ) cancel_one( stake_delegations, path[p] );
  cancel_one( stake_delegations, old_root );
  stake_delegations->root_fork      = fork;
  forks[fork].parent = USHORT_MAX;
  rebuild_tree( stake_delegations );
  if( stats ) {
    stats->upserts += upserts;
    stats->removes += removes;
    stats->root_cnt = stake_delegations->root_cnt;
  }
  fd_rwlock_unwrite( &stake_delegations->lock );
}

ulong
fd_stake_delegations_prune_inactive_root( fd_stake_delegations_t *   stake_delegations,
                                          ulong                      epoch,
                                          fd_stake_history_t const * history,
                                          ulong *                    rate_epoch,
                                          int                        fixed_point,
                                          fd_bank_t const *          emit_bank ) {
  fd_rwlock_write( &stake_delegations->lock );
  if( !same_context( stake_delegations, epoch, history, rate_epoch, fixed_point ) ) {
    set_context( stake_delegations, epoch, history, rate_epoch, fixed_point );
    recompute( stake_delegations );
  }
  ulong cnt = prune( stake_delegations, epoch, history, rate_epoch, fixed_point, emit_bank );
  fd_rwlock_unwrite( &stake_delegations->lock );
  return cnt;
}

void
fd_stake_delegations_invalidate_warmed( fd_stake_delegations_t * stake_delegations ) {
  fd_rwlock_write( &stake_delegations->lock );
  for( uint page=0U; page<stake_delegations->page_wmk; page++ ) {
    if( get_pages( stake_delegations )[page].role!=PAGE_ROOT ) continue;
    for( uint slot=0U; slot<128U; slot++ ) {
      uint                    idx = (page<<7)+slot;
      fd_stake_delegation_t * d   = record( stake_delegations, idx, 0 );
      if( !(d->flags & FD_STAKE_DELEGATION_ROOT_PRESENT) || d->state!=FD_STAKE_DELEGATION_STATE_WARMED ) continue;
      d->state = FD_STAKE_DELEGATION_STATE_UNKNOWN;
      dirty( stake_delegations, idx );
    }
  }
  stake_delegations->fp_warmed_awarded = 0;
  fd_rwlock_unwrite( &stake_delegations->lock );
}

void
fd_stake_delegations_refresh( fd_stake_delegations_t *   stake_delegations,
                              ulong                      epoch,
                              fd_stake_history_t const * history,
                              ulong *                    rate_epoch,
                              int                        fixed_point,
                              int                        remove_inactive_stakes,
                              fd_accdb_t *               accdb,
                              fd_accdb_fork_id_t         fork_id ) {
  fd_rwlock_write( &stake_delegations->lock );
  set_context( stake_delegations, epoch, history, rate_epoch, fixed_point );
  /* Snapshot totals are rebuilt from account data.  Copies keep batch
     keys and payloads valid while later records evict earlier pages. */
  stake_delegations->effective_stake   = stake_delegations->activating_stake = stake_delegations->deactivating_stake = 0UL;
  stake_delegations->fp_warmed_awarded = 0;
#define BATCH 64UL
  fd_stake_delegation_t batch[ BATCH ];
  uint                 indices[ BATCH ];
  uchar const *        keys[ BATCH ];
  int                  writable[ BATCH ] = {0};
  fd_acc_t             acc[ BATCH ];
  ulong cursor = 0UL;
  ulong limit  = (ulong)stake_delegations->page_wmk*128UL;
  while( cursor<limit ) {
    ulong cnt = 0UL;
    while( cursor<limit && cnt<BATCH ) {
      uint idx = (uint)cursor++;
      if( get_pages( stake_delegations )[idx>>7].role!=PAGE_ROOT ) {
        cursor = ((ulong)(idx>>7)+1UL)*128UL;
        continue;
      }
      fd_stake_delegation_t d = *record( stake_delegations, idx, 0 );
      if( !(d.flags & FD_STAKE_DELEGATION_ROOT_PRESENT) ) continue;
      batch[cnt]   = d;
      indices[cnt] = idx;
      keys[cnt]    = batch[cnt].stake_account.uc;
      cnt++;
    }
    if( !cnt ) continue;
    fd_accdb_acquire( accdb, fork_id, cnt, keys, writable, acc );
    for( ulong i=0UL; i<cnt; i++ ) {
      fd_stake_delegation_t *  d      = batch+i;
      fd_stake_state_t const * state  = acc[i].lamports ? fd_stakes_get_state( acc+i ) : NULL;
      int                      remove = !state || state->stake_type!=FD_STAKE_STATE_STAKE;
      if( !remove ) {
        fd_delegation_t const * src        = &state->stake.stake.delegation;
        ulong                   prev_epoch = epoch ? epoch-1UL : 0UL;
        remove = remove_inactive_stakes &&
          fd_delegation_is_inactive( src, epoch, history, rate_epoch, fixed_point ) &&
          fd_delegation_is_inactive( src, prev_epoch, history, rate_epoch, fixed_point );
        if( !remove ) {
          FD_CHECK_ERR( (long)src->activation_epoch  <USHORT_MAX, "activation_epoch overflow"   );
          FD_CHECK_ERR( (long)src->deactivation_epoch<USHORT_MAX, "deactivation_epoch overflow" );
          d->vote_account         = src->voter_pubkey;
          d->stake                = src->stake;
          d->lamports             = acc[i].lamports;
          d->credits_observed     = state->stake.stake.credits_observed;
          d->acc_dlen             = (uint)acc[i].data_len;
          d->activation_epoch     = (ushort)src->activation_epoch;
          d->deactivation_epoch   = (ushort)src->deactivation_epoch;
          d->warmup_cooldown_rate = fd_stake_warmup_cooldown_rate( epoch, rate_epoch );
        }
      }
      /* Defer store mutation until all accdb references are released. */
      if( remove ) d->flags &= (uchar)~FD_STAKE_DELEGATION_ROOT_PRESENT;
    }
    fd_accdb_release( accdb, cnt, acc );
    for( ulong i=0UL; i<cnt; i++ ) {
      fd_stake_delegation_t * d = batch+i;
      if( !(d->flags & FD_STAKE_DELEGATION_ROOT_PRESENT) ) {
        stake_delegations->context_valid = 0;
        delete_root( stake_delegations, indices[i] );
        stake_delegations->context_valid = 1;
      } else {
        /* Earlier removals in this batch may have changed this root's
           bucket linkage.  The copied payload must not restore it. */
        fd_stake_delegation_t const * current = record( stake_delegations, indices[i], 0 );
        d->next_      = current->next_;
        d->delta_head = current->delta_head;
        add_root( stake_delegations, d );
        publish( stake_delegations, indices[i], d );
      }
    }
  }
#undef BATCH
  fd_rwlock_unwrite( &stake_delegations->lock );
}
