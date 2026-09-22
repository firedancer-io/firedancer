#include "fd_stake_delegations_private.h"
#include "fd_stakes.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../events/fd_event_runtime.h"
#include "../../util/fd_hash32.h"

#include <errno.h>
#include <unistd.h>

static inline uint *
get_buckets( fd_stake_delegations_t * sd ) {
  return (uint *)((uchar *)sd + fd_ulong_align_up( sizeof(*sd), alignof(uint) ));
}

static inline page_t *
get_pages( fd_stake_delegations_t * sd ) {
  return (page_t *)((uchar *)sd + sd->pages_offset);
}

static inline frame_t *
get_frames( fd_stake_delegations_t * sd ) {
  return (frame_t *)((uchar *)sd + sd->frames_offset);
}

static inline fork_t *
get_forks( fd_stake_delegations_t * sd ) {
  return (fork_t *)((uchar *)sd + sd->forks_offset);
}

static inline ulong *
get_descends( fd_stake_delegations_t * sd,
              ushort                   fork ) {
  ulong descends_words = (sd->max_live_slots+63UL)>>6;
  return (ulong *)((uchar *)sd + sd->descends_offset) + (ulong)fork*descends_words;
}

static inline stripe_t *
get_stripes( fd_stake_delegations_t * sd ) {
  return (stripe_t *)((uchar *)sd + sd->stripes_offset);
}

static inline uchar *
get_data( fd_stake_delegations_t * sd,
          uint                     frame ) {
  return (uchar *)sd + sd->data_offset + (ulong)frame*FD_STAKE_DELEGATIONS_PAGE_SZ;
}

static void
spin_lock( uint * lock ) {
  fd_racesan_hook( "stake_delegations_spin:pre_acquire" );
  while( __atomic_exchange_n( lock, 1U, __ATOMIC_ACQUIRE ) ) {
    fd_racesan_hook( "stake_delegations_spin:wait" );
    FD_SPIN_PAUSE();
  }
  fd_racesan_hook( "stake_delegations_spin:post_acquire" );
}

static void
spin_unlock( uint * lock ) {
  fd_racesan_hook( "stake_delegations_spin:pre_release" );
  __atomic_store_n( lock, 0U, __ATOMIC_RELEASE );
}

static void
exclusive_begin( fd_stake_delegations_t * sd ) {
  fd_rwlock_write( &sd->tree_lock );
  fd_rwlock_write( &sd->cache_lock );
}

static void
exclusive_end( fd_stake_delegations_t * sd ) {
  fd_rwlock_unwrite( &sd->cache_lock );
  fd_rwlock_unwrite( &sd->tree_lock );
}

static void
nonfull_remove( fd_stake_delegations_t * sd,
                uint                     page ) {
  page_t * pages = get_pages( sd );
  page_t * p     = pages+page;
  uint *   head  = &sd->nonfull[p->role][p->frame!=UINT_MAX];
  if( p->prev==UINT_MAX ) {
    *head = p->next;
  } else {
    pages[p->prev].next = p->next;
  }
  if( p->next!=UINT_MAX ) pages[p->next].prev = p->prev;
  p->prev = p->next = UINT_MAX;
}

static void
nonfull_insert( fd_stake_delegations_t * sd,
                uint                     page ) {
  page_t * pages = get_pages( sd );
  page_t * p     = pages+page;
  uint *   head  = &sd->nonfull[p->role][p->frame!=UINT_MAX];
  p->prev = UINT_MAX;
  p->next = *head;
  if( *head!=UINT_MAX ) pages[*head].prev = page;
  *head = page;
}

/* Complete scalar page transfers.  Partial direct I/O can continue only
   on a full page boundary, covering every supported startup alignment.
   Never publish a partial disk image. */
static void
page_io( fd_stake_delegations_t * sd,
         uint                     page,
         uchar *                  data,
         int                      writing ) {
  ulong done = 0UL;
  ulong off  = (ulong)page*FD_STAKE_DELEGATIONS_PAGE_SZ;
  while( done<FD_STAKE_DELEGATIONS_PAGE_SZ ) {
    long n = writing ? pwrite( sd->disk_fd, data+done, FD_STAKE_DELEGATIONS_PAGE_SZ-done, (off_t)(off+done) )
                     : pread ( sd->disk_fd, data+done, FD_STAKE_DELEGATIONS_PAGE_SZ-done, (off_t)(off+done) );
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
page_fault( fd_stake_delegations_t * sd,
            uint                     page ) {
  page_t *  pages  = get_pages( sd );
  frame_t * frames = get_frames( sd );
  page_t *  p      = pages+page;
  if( FD_LIKELY( p->frame!=UINT_MAX ) ) return p->frame;
  fd_racesan_hook( "stake_delegations_cache:pre_fault" );
  uint frame = sd->free_frame;
  if( frame!=UINT_MAX ) {
    sd->free_frame = frames[frame].next;
  } else {
    for(;;) {
      frame          = sd->clock_hand;
      sd->clock_hand = (frame+1U)%sd->frame_max;
      if( !__atomic_exchange_n( &frames[frame].referenced, 0U, __ATOMIC_RELAXED ) ) break;
    }
    uint     victim = frames[frame].page;
    page_t * v      = pages+victim;
    if( __atomic_load_n( &v->flags, __ATOMIC_RELAXED ) & PAGE_DIRTY ) {
      page_io( sd, victim, get_data( sd, frame ), 1 );
      v->flags = PAGE_WRITTEN;
    }
    if( v->cnt<128U ) nonfull_remove( sd, victim );
    v->frame = UINT_MAX;
    if( v->cnt<128U ) nonfull_insert( sd, victim );
  }
  if( p->flags & PAGE_WRITTEN ) {
    page_io( sd, page, get_data( sd, frame ), 0 );
  } else {
    fd_memset( get_data( sd, frame ), 0, FD_STAKE_DELEGATIONS_PAGE_SZ );
  }
  if( p->cnt<128U ) nonfull_remove( sd, page );
  p->frame = frame;
  if( p->cnt<128U ) nonfull_insert( sd, page );
  frames[frame].page       = page;
  frames[frame].referenced = 0U;
  fd_racesan_hook( "stake_delegations_cache:post_fault" );
  return frame;
}

static fd_stake_delegation_t *
record( fd_stake_delegations_t * sd,
        uint                     idx,
        int                      cold,
        int                      reference ) {
  uint page  = idx>>7;
  uint frame = get_pages( sd )[page].frame;
  if( FD_UNLIKELY( frame==UINT_MAX ) ) {
    if( !cold ) return NULL;
    frame = page_fault( sd, page );
  }
  if( reference ) __atomic_store_n( &get_frames( sd )[frame].referenced, 1U, __ATOMIC_RELAXED );
  return (fd_stake_delegation_t *)get_data( sd, frame ) + (idx & 127U);
}

static void
dirty( fd_stake_delegations_t * sd,
       uint                     idx ) {
  __atomic_fetch_or( &get_pages( sd )[idx>>7].flags, PAGE_DIRTY, __ATOMIC_RELAXED );
}

/* The allocator lock protects reservations and non-full lists.  Hot
   reservations never initialize a page or perform I/O.  Cache exclusive
   excludes every allocator and can move list membership without it. */
static uint
reserve( fd_stake_delegations_t * sd,
         uchar                    role,
         int                      cold ) {
  if( !cold ) spin_lock( &sd->allocator_lock );
  uint page = sd->nonfull[role][1];
  if( page==UINT_MAX && cold ) {
    page = sd->nonfull[role][0];
    if( page!=UINT_MAX ) {
      page_fault( sd, page );
    } else {
      page = sd->free_page;
      if( page!=UINT_MAX ) {
        sd->free_page = get_pages( sd )[page].next;
      } else {
        FD_CHECK_CRIT( sd->page_wmk<sd->page_max, "stake delegations logical page capacity exhausted" );
        page = sd->page_wmk++;
      }
      page_t * p = get_pages( sd )+page;
      *p = (page_t){
        .frame = UINT_MAX,
        .prev  = UINT_MAX,
        .next  = UINT_MAX,
        .role  = role
      };
      nonfull_insert( sd, page );
      page_fault( sd, page );
    }
  }
  if( page==UINT_MAX ) {
    spin_unlock( &sd->allocator_lock );
    return UINT_MAX;
  }
  page_t * p    = get_pages( sd )+page;
  uint     word = p->used[0]==ULONG_MAX;
  uint     bit  = (uint)fd_ulong_find_lsb( ~p->used[word] );
  fd_racesan_hook( "stake_delegations_alloc:pre_reserve" );
  p->used[word] |= 1UL<<bit;
  p->cnt++;
  fd_racesan_hook( "stake_delegations_alloc:post_reserve" );
  if( p->cnt==128U ) nonfull_remove( sd, page );
  if( !cold ) spin_unlock( &sd->allocator_lock );
  return (page<<7) + 64U*word + bit;
}

static void
release( fd_stake_delegations_t * sd,
         uint                     idx ) {
  uint                    page = idx>>7;
  page_t *                p    = get_pages( sd )+page;
  fd_stake_delegation_t * d    = record( sd, idx, 1, 0 );
  __atomic_store_n( &d->flags, 0, __ATOMIC_RELEASE );
  dirty( sd, idx );
  if( p->cnt==128U ) nonfull_insert( sd, page );
  p->used[(idx & 127U)>>6] &= ~(1UL<<(idx & 63U));
  p->cnt--;
  if( FD_UNLIKELY( !p->cnt ) ) {
    nonfull_remove( sd, page );
    if( p->frame!=UINT_MAX ) {
      frame_t * f = get_frames( sd )+p->frame;
      f->page        = UINT_MAX;
      f->next        = sd->free_frame;
      sd->free_frame = p->frame;
    }
    *p = (page_t){
      .frame = UINT_MAX,
      .prev  = UINT_MAX,
      .next  = sd->free_page
    };
    sd->free_page = page;
  }
}

static void
publish( fd_stake_delegations_t *      sd,
         uint                          idx,
         fd_stake_delegation_t const * d ) {
  fd_stake_delegation_t * dst = record( sd, idx, 1, 1 );
  ulong                   off = offsetof( fd_stake_delegation_t, flags );
  fd_memcpy( dst, d, off );
  fd_memcpy( (uchar *)dst+off+1UL, (uchar const *)d+off+1UL, sizeof(*d)-off-1UL );
  fd_racesan_hook( "stake_delegations_record:pre_publish" );
  __atomic_store_n( &dst->flags, d->flags, __ATOMIC_RELEASE );
  fd_racesan_hook( "stake_delegations_record:post_publish" );
  dirty( sd, idx );
}

static uint
bucket( fd_stake_delegations_t * sd,
        fd_pubkey_t const *      key ) {
  return fd_hash32( key->uc, sd->seed ) & (uint)(FD_STAKE_DELEGATIONS_BUCKET_CNT-1UL);
}

/* UINT_MAX means absent, UINT_MAX-1 means a hot lookup needs a fault. */
static uint
find_root( fd_stake_delegations_t * sd,
           fd_pubkey_t const *      key,
           int                      cold ) {
  uint idx = __atomic_load_n( get_buckets( sd )+bucket( sd, key ), __ATOMIC_ACQUIRE );
  while( idx!=UINT_MAX ) {
    fd_stake_delegation_t const * d = record( sd, idx, cold, 1 );
    if( !d ) return UINT_MAX-1U;
    if( fd_pubkey_eq( &d->stake_account, key ) ) return idx;
    idx = d->next_;
  }
  return UINT_MAX;
}

static uint
insert_root( fd_stake_delegations_t * sd,
             fd_pubkey_t const *      key,
             int                      cold ) {
  uint idx = reserve( sd, PAGE_ROOT, cold );
  if( idx==UINT_MAX ) return UINT_MAX;
  uint b = bucket( sd, key );
  fd_stake_delegation_t d = {
    .stake_account = *key,
    .next_         = get_buckets( sd )[b],
    .delta_head    = UINT_MAX,
    .fork_id       = USHORT_MAX,
    .flags         = FD_STAKE_DELEGATION_IN_USE
  };
  publish( sd, idx, &d );
  fd_racesan_hook( "stake_delegations_bucket:pre_publish" );
  __atomic_store_n( get_buckets( sd )+b, idx, __ATOMIC_RELEASE );
  fd_racesan_hook( "stake_delegations_bucket:post_publish" );
  return idx;
}

static void
remove_root( fd_stake_delegations_t * sd,
             uint                     idx ) {
  fd_stake_delegation_t d = *record( sd, idx, 1, 0 );
  FD_TEST( d.delta_head==UINT_MAX );
  uint b    = bucket( sd, &d.stake_account );
  uint prev = UINT_MAX;
  uint cur  = get_buckets( sd )[b];
  while( cur!=idx ) {
    FD_CHECK_CRIT( cur!=UINT_MAX, "missing stake delegation root" );
    prev = cur;
    cur  = record( sd, cur, 1, 0 )->next_;
  }
  if( prev==UINT_MAX ) {
    get_buckets( sd )[b] = d.next_;
  } else {
    record( sd, prev, 1, 0 )->next_ = d.next_;
    dirty( sd, prev );
  }
  if( d.flags & FD_STAKE_DELEGATION_ROOT_PRESENT ) sd->root_cnt--;
  release( sd, idx );
}

static void
reset( fd_stake_delegations_t * sd ) {
  ulong descends_words = (sd->max_live_slots+63UL)>>6;
  fd_memset( get_buckets( sd ),      255, FD_STAKE_DELEGATIONS_BUCKET_CNT*sizeof(uint) );
  fd_memset( get_pages( sd ),          0, (ulong)sd->page_max*sizeof(page_t) );
  fd_memset( get_forks( sd ),          0, sd->max_live_slots*sizeof(fork_t) );
  fd_memset( get_descends( sd, 0 ),    0, sd->max_live_slots*descends_words*sizeof(ulong) );
  for( uint i=0U; i<sd->frame_max; i++ ) {
    get_frames( sd )[i] = (frame_t){
      .page = UINT_MAX,
      .next = i+1U<sd->frame_max ? i+1U : UINT_MAX
    };
  }
  sd->page_wmk   = 0U;
  sd->free_page  = UINT_MAX;
  sd->free_frame = 0U;
  sd->clock_hand = 0U;
  fd_memset( sd->nonfull, 255, sizeof(sd->nonfull) );
  sd->root_fork = 0;
  get_forks( sd )[0] = (fork_t){
    .delta_head = UINT_MAX,
    .parent     = USHORT_MAX,
    .in_use     = 1
  };
  sd->root_cnt          = 0UL;
  sd->effective_stake   = sd->activating_stake = sd->deactivating_stake = 0UL;
  sd->fp_warmed_awarded = sd->context_valid = 0;
  sd->root_epoch        = sd->root_history_len = 0UL;
  sd->root_rate_epoch   = ULONG_MAX;
  sd->boot              = 1;
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
  l = FD_LAYOUT_APPEND( l, alignof(stripe_t),               FD_STAKE_DELEGATIONS_STRIPE_CNT*sizeof(stripe_t) );
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
  APPEND( stripes_offset,  alignof(stripe_t),               FD_STAKE_DELEGATIONS_STRIPE_CNT*sizeof(stripe_t) );
  APPEND( data_offset,     FD_STAKE_DELEGATIONS_ALIGN,      cache_bytes );
#undef APPEND
  FD_TEST( fd_ulong_align_up( l, FD_STAKE_DELEGATIONS_ALIGN )==footprint );
  fd_memset( get_stripes( sd ), 0, FD_STAKE_DELEGATIONS_STRIPE_CNT*sizeof(stripe_t) );
  fd_rwlock_new( &sd->tree_lock );
  fd_rwlock_new( &sd->cache_lock );
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
fd_stake_delegations_reset( fd_stake_delegations_t * sd ) {
  exclusive_begin( sd );
  reset( sd );
  exclusive_end( sd );
}

static int
ancestor( fd_stake_delegations_t * sd,
          ushort                   fork,
          ushort                   parent ) {
  return !!(get_descends( sd, fork )[parent>>6] & (1UL<<(parent & 63)));
}

ushort
fd_stake_delegations_root_fork_id( fd_stake_delegations_t const * sd ) {
  return sd->root_fork;
}

ushort
fd_stake_delegations_attach_child( fd_stake_delegations_t * sd,
                                   ushort                   parent ) {
  exclusive_begin( sd );
  fork_t * forks = get_forks( sd );
  FD_CHECK_CRIT( parent<sd->max_live_slots && forks[parent].in_use,
                 "invalid stake delegations parent" );
  ushort id = 0;
  while( id<sd->max_live_slots && forks[id].in_use ) id++;
  FD_CHECK_CRIT( id<sd->max_live_slots, "stake delegations fork capacity exhausted" );
  forks[id] = (fork_t){
    .delta_head = UINT_MAX,
    .parent     = parent,
    .in_use     = 1
  };
  ulong descends_words = (sd->max_live_slots+63UL)>>6;
  fd_memcpy( get_descends( sd, id ), get_descends( sd, parent ), descends_words*sizeof(ulong) );
  get_descends( sd, id )[parent>>6] |= 1UL<<(parent & 63);
  sd->boot = 0;
  exclusive_end( sd );
  return id;
}

static void
check_mutable( fd_stake_delegations_t * sd,
               ushort                   fork ) {
  FD_CHECK_CRIT( fork<sd->max_live_slots && fork!=sd->root_fork && get_forks( sd )[fork].in_use,
                 "stake delegations fork is not mutable" );
  FD_CHECK_CRIT( !get_forks( sd )[fork].views, "stake delegations write to viewed fork" );
}

/* Only payload bytes and the atomic flags change on overwrite.  A view
   skips sibling versions using immutable fork_id/next_ before inspecting
   payload; no selected version can have an admitted writer. */
static void
replace_delta( fd_stake_delegations_t *      sd,
               uint                          idx,
               fd_stake_delegation_t const * src,
               int                           cold ) {
  fd_stake_delegation_t * dst = record( sd, idx, cold, 1 );
  dst->vote_account         = src->vote_account;
  dst->stake                = src->stake;
  dst->lamports             = src->lamports;
  dst->credits_observed     = src->credits_observed;
  dst->acc_dlen             = src->acc_dlen;
  dst->activation_epoch     = src->activation_epoch;
  dst->deactivation_epoch   = src->deactivation_epoch;
  dst->warmup_cooldown_rate = src->warmup_cooldown_rate;
  dst->state                = FD_STAKE_DELEGATION_STATE_UNKNOWN;
  __atomic_store_n( &dst->flags, src->flags, __ATOMIC_RELEASE );
  dirty( sd, idx );
}

static int
upsert( fd_stake_delegations_t *      sd,
        ushort                        fork,
        fd_stake_delegation_t const * src,
        int                           cold ) {
  check_mutable( sd, fork );
  uint root = find_root( sd, &src->stake_account, cold );
  if( root==UINT_MAX-1U ) return 0;
  if( root==UINT_MAX ) {
    root = insert_root( sd, &src->stake_account, cold );
    if( root==UINT_MAX ) return 0;
  }
  fd_stake_delegation_t * r = record( sd, root, cold, 1 );
  if( !r ) return 0;
  uint head = __atomic_load_n( &r->delta_head, __ATOMIC_ACQUIRE );
  uint idx  = head;
  while( idx!=UINT_MAX ) {
    fd_stake_delegation_t const * d = record( sd, idx, cold, 1 );
    if( !d ) return 0;
    if( d->fork_id==fork ) {
      replace_delta( sd, idx, src, cold );
      return 1;
    }
    idx = d->next_;
  }
  idx = reserve( sd, PAGE_DELTA, cold );
  if( idx==UINT_MAX ) return 0;
  fd_stake_delegation_t d = *src;
  d.fork_id = fork;
  d.next_   = head;
  fork_t * f         = get_forks( sd )+fork;
  uint     fork_head = __atomic_load_n( &f->delta_head, __ATOMIC_ACQUIRE );
  d.fork_next = fork_head;
  publish( sd, idx, &d );
  fd_stake_delegation_t * dst = record( sd, idx, cold, 1 );
  fd_racesan_hook( "stake_delegations_fork:pre_cas" );
  while( !__atomic_compare_exchange_n( &f->delta_head, &fork_head, idx, 0, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE ) ) {
    dst->fork_next = fork_head;
    fd_racesan_hook( "stake_delegations_fork:retry_cas" );
  }
  fd_racesan_hook( "stake_delegations_fork:post_cas" );
  /* Reacquire after delta allocation, which can evict the root. */
  r = record( sd, root, cold, 1 );
  fd_racesan_hook( "stake_delegations_key:pre_publish" );
  __atomic_store_n( &r->delta_head, idx, __ATOMIC_RELEASE );
  fd_racesan_hook( "stake_delegations_key:post_publish" );
  dirty( sd, root );
  return 1;
}

static void
fork_upsert( fd_stake_delegations_t *      sd,
             ushort                        fork,
             fd_stake_delegation_t const * src ) {
  fd_rwlock_read( &sd->tree_lock );
  fd_rwlock_read( &sd->cache_lock );
  uint * stripe = &get_stripes( sd )[bucket( sd, &src->stake_account ) & (FD_STAKE_DELEGATIONS_STRIPE_CNT-1UL)].lock;
  spin_lock( stripe );
  int done = upsert( sd, fork, src, 0 );
  spin_unlock( stripe );
  fd_rwlock_unread( &sd->cache_lock );
  if( FD_UNLIKELY( !done ) ) {
    fd_rwlock_write( &sd->cache_lock );
    FD_TEST( upsert( sd, fork, src, 1 ) );
    fd_rwlock_unwrite( &sd->cache_lock );
  }
  fd_rwlock_unread( &sd->tree_lock );
}

void
fd_stake_delegations_fork_update( fd_stake_delegations_t * sd,
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
  fork_upsert( sd, fork, &d );
}

void
fd_stake_delegations_fork_remove( fd_stake_delegations_t * sd,
                                  ushort                   fork,
                                  fd_pubkey_t const *      stake_account ) {
  fd_stake_delegation_t d = {
    .stake_account = *stake_account,
    .flags         = FD_STAKE_DELEGATION_IN_USE|FD_STAKE_DELEGATION_TOMBSTONE
  };
  fork_upsert( sd, fork, &d );
}

static fd_stake_history_entry_t
root_status( fd_stake_delegations_t *      sd,
             fd_stake_delegation_t const * d ) {
  fd_stake_history_t history = {
    .entries = sd->root_history,
    .len     = sd->root_history_len
  };
  return fd_stake_delegation_activation_status( d, sd->root_epoch, &history, &sd->root_rate_epoch, sd->root_fixed_point );
}

static void
subtract_root( fd_stake_delegations_t *      sd,
               fd_stake_delegation_t const * d ) {
  if( !sd->context_valid || !(d->flags & FD_STAKE_DELEGATION_ROOT_PRESENT) ) return;
  fd_stake_history_entry_t status = root_status( sd, d );
  sd->effective_stake    -= status.effective;
  sd->activating_stake   -= status.activating;
  sd->deactivating_stake -= status.deactivating;
}

static void
add_root( fd_stake_delegations_t * sd,
          fd_stake_delegation_t *  d ) {
  d->state = FD_STAKE_DELEGATION_STATE_UNKNOWN;
  if( !sd->context_valid ) return;
  fd_stake_history_entry_t status = root_status( sd, d );
  sd->effective_stake    += status.effective;
  sd->activating_stake   += status.activating;
  sd->deactivating_stake += status.deactivating;
  fd_stake_history_t history = {
    .entries = sd->root_history,
    .len     = sd->root_history_len
  };
  if( fd_sysvar_stake_history_is_contiguous( &history ) ) d->state = fd_stake_delegation_classify( d, status, sd->root_epoch );
  if( d->state==FD_STAKE_DELEGATION_STATE_WARMED && !sd->root_fixed_point ) sd->fp_warmed_awarded = 1;
}

static void
store_root( fd_stake_delegations_t *      sd,
            uint                          idx,
            fd_stake_delegation_t const * src ) {
  fd_stake_delegation_t old = *record( sd, idx, 1, 0 );
  subtract_root( sd, &old );
  fd_stake_delegation_t d = *src;
  d.next_      = old.next_;
  d.delta_head = old.delta_head;
  d.fork_id    = USHORT_MAX;
  d.flags      = FD_STAKE_DELEGATION_IN_USE|FD_STAKE_DELEGATION_ROOT_PRESENT;
  if( !(old.flags & FD_STAKE_DELEGATION_ROOT_PRESENT) ) {
    sd->root_cnt++;
  }
  add_root( sd, &d );
  publish( sd, idx, &d );
}

static void
delete_root( fd_stake_delegations_t * sd,
             uint                     idx ) {
  fd_stake_delegation_t d = *record( sd, idx, 1, 0 );
  if( d.flags & FD_STAKE_DELEGATION_ROOT_PRESENT ) {
    subtract_root( sd, &d );
    d.flags = FD_STAKE_DELEGATION_IN_USE;
    d.state = FD_STAKE_DELEGATION_STATE_UNKNOWN;
    sd->root_cnt--;
    publish( sd, idx, &d );
  }
  if( d.delta_head==UINT_MAX ) remove_root( sd, idx );
}

void
fd_stake_delegations_root_update( fd_stake_delegations_t * sd,
                                  fd_pubkey_t const *      stake_account,
                                  fd_pubkey_t const *      vote_account,
                                  ulong                    stake,
                                  ulong                    activation_epoch,
                                  ulong                    deactivation_epoch,
                                  ulong                    credits_observed,
                                  ulong                    lamports,
                                  uint                     acc_dlen,
                                  uchar                    warmup_cooldown_rate ) {
  exclusive_begin( sd );
  FD_CHECK_CRIT( sd->boot, "stake delegations root_update after boot" );
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
  uint root = find_root( sd, stake_account, 1 );
  if( root==UINT_MAX ) root = insert_root( sd, stake_account, 1 );
  store_root( sd, root, &d );
  exclusive_end( sd );
}

fd_stake_delegations_view_t *
fd_stake_delegations_view_begin( fd_stake_delegations_view_t * view,
                                 fd_stake_delegations_t *      sd,
                                 ushort                        fork ) {
  fd_rwlock_read( &sd->tree_lock );
  fd_rwlock_write( &sd->cache_lock );
  FD_CHECK_CRIT( fork<sd->max_live_slots && get_forks( sd )[fork].in_use,
                 "invalid stake delegations view" );
  get_forks( sd )[fork].views++;
  *view = (fd_stake_delegations_view_t){
    .sd       = sd,
    .fork_id  = fork,
    .page_wmk = sd->page_wmk
  };
  fd_rwlock_unwrite( &sd->cache_lock );
  fd_racesan_hook( "stake_delegations_view:admitted" );
  return view;
}

void
fd_stake_delegations_view_end( fd_stake_delegations_view_t * view ) {
  fd_stake_delegations_t * sd = view->sd;
  fd_rwlock_write( &sd->cache_lock );
  FD_TEST( get_forks( sd )[view->fork_id].views );
  get_forks( sd )[view->fork_id].views--;
  fd_rwlock_unwrite( &sd->cache_lock );
  fd_rwlock_unread( &sd->tree_lock );
  view->sd = NULL;
}

/* The iterator retains a logical chain cursor across bounded cache-lock
   chunks.  A long chain with no visible version cannot monopolize cache
   exclusive, and a one-frame scan never restarts its chain on a fault.
   Newly prepended sibling deltas are invisible to this view. */
static void
iter_fill( fd_stake_delegations_iter_t * iter ) {
  fd_stake_delegations_view_t * view  = iter->view;
  fd_stake_delegations_t *      sd    = view->sd;
  ulong                         limit = (ulong)view->page_wmk*128UL;
  iter->batch_idx = iter->batch_cnt = 0UL;
  int cold = 0;
  fd_rwlock_read( &sd->cache_lock );
  ulong work = 0UL;
  while( iter->cursor<limit && iter->batch_cnt<FD_STAKE_DELEGATIONS_ITER_BATCH ) {
    if( work++==256UL ) {
      if( cold ) fd_rwlock_unwrite( &sd->cache_lock );
      else       fd_rwlock_unread( &sd->cache_lock );
      cold = 0;
      work = 0UL;
      fd_rwlock_read( &sd->cache_lock );
    }
    uint root = (uint)iter->cursor;
    uint idx  = iter->resolving && iter->chain!=UINT_MAX ? iter->chain : root;
    if( !iter->resolving && get_pages( sd )[root>>7].role!=PAGE_ROOT ) {
      iter->cursor = ((ulong)(root>>7)+1UL)*128UL;
      continue;
    }
    fd_stake_delegation_t const * d = record( sd, idx, cold, 0 );
    if( !d ) {
      fd_rwlock_unread( &sd->cache_lock );
      fd_rwlock_write( &sd->cache_lock );
      cold = 1;
      continue;
    }
    if( !iter->resolving ) {
      iter->root_flags = __atomic_load_n( &d->flags, __ATOMIC_ACQUIRE );
      if( !(iter->root_flags & FD_STAKE_DELEGATION_IN_USE) ) {
        iter->cursor++;
        continue;
      }
      iter->chain     = __atomic_load_n( &d->delta_head, __ATOMIC_ACQUIRE );
      iter->resolving = 1;
      if( iter->chain!=UINT_MAX ) continue;
    }
    int                     found = 0;
    fd_stake_delegation_t * out   = iter->batch+iter->batch_cnt;
    if( iter->chain!=UINT_MAX ) {
      if( d->fork_id!=view->fork_id && !ancestor( sd, view->fork_id, d->fork_id ) ) {
        iter->chain = d->next_;
        continue;
      }
      if( !(__atomic_load_n( &d->flags, __ATOMIC_ACQUIRE ) & FD_STAKE_DELEGATION_TOMBSTONE) ) {
        *out = *d;
        found = 1;
      }
    } else if( iter->root_flags & FD_STAKE_DELEGATION_ROOT_PRESENT ) {
      /* Siblings may atomically prepend delta_head while cache shared.
         Copy the immutable root payload around that atomic field. */
      fd_memcpy( out, d, offsetof(fd_stake_delegation_t, delta_head) );
      out->delta_head           = UINT_MAX;
      out->activation_epoch     = d->activation_epoch;
      out->deactivation_epoch   = d->deactivation_epoch;
      out->fork_id              = d->fork_id;
      out->flags                = iter->root_flags;
      out->warmup_cooldown_rate = d->warmup_cooldown_rate;
      out->state                = view->use_stable_tags ? d->state : FD_STAKE_DELEGATION_STATE_UNKNOWN;
      found                     = 1;
    }
    iter->resolving = 0;
    iter->cursor++;
    if( found ) iter->indices[iter->batch_cnt++] = root;
  }
  if( cold ) fd_rwlock_unwrite( &sd->cache_lock );
  else       fd_rwlock_unread( &sd->cache_lock );
  if( iter->batch_cnt ) iter->idx = iter->indices[0];
}

fd_stake_delegations_iter_t *
fd_stake_delegations_iter_init( fd_stake_delegations_iter_t * iter,
                                fd_stake_delegations_view_t * view ) {
  iter->view      = view;
  iter->cursor    = 0UL;
  iter->resolving = 0;
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
unlink_delta( fd_stake_delegations_t *      sd,
              uint                          idx,
              fd_stake_delegation_t const * d ) {
  uint root = find_root( sd, &d->stake_account, 1 );
  FD_CHECK_CRIT( root!=UINT_MAX, "stake delegation delta without root slot" );
  uint prev = UINT_MAX;
  uint cur  = record( sd, root, 1, 0 )->delta_head;
  while( cur!=idx ) {
    FD_CHECK_CRIT( cur!=UINT_MAX, "missing stake delegation delta" );
    prev = cur;
    cur  = record( sd, cur, 1, 0 )->next_;
  }
  if( prev==UINT_MAX ) {
    record( sd, root, 1, 0 )->delta_head = d->next_;
    dirty( sd, root );
  } else {
    record( sd, prev, 1, 0 )->next_ = d->next_;
    dirty( sd, prev );
  }
  release( sd, idx );
  return root;
}

static void
cancel_one( fd_stake_delegations_t * sd,
            ushort                   fork ) {
  fork_t * f   = get_forks( sd )+fork;
  uint     idx = f->delta_head;
  while( idx!=UINT_MAX ) {
    fd_stake_delegation_t d    = *record( sd, idx, 1, 0 );
    uint                  root = unlink_delta( sd, idx, &d );
    fd_stake_delegation_t r    = *record( sd, root, 1, 0 );
    if( !(r.flags & FD_STAKE_DELEGATION_ROOT_PRESENT) && r.delta_head==UINT_MAX ) remove_root( sd, root );
    idx = d.fork_next;
  }
  *f = (fork_t){0};
}

/* Rebuild ancestry from the surviving immutable parent relation.
   No record pages are scanned. */
static void
rebuild_tree( fd_stake_delegations_t * sd ) {
  fork_t * forks          = get_forks( sd );
  ulong    descends_words = (sd->max_live_slots+63UL)>>6;
  for( ushort id=0; id<sd->max_live_slots; id++ ) {
    fd_memset( get_descends( sd, id ), 0, descends_words*sizeof(ulong) );
  }
  for( ushort id=0; id<sd->max_live_slots; id++ ) {
    if( !forks[id].in_use || id==sd->root_fork ) continue;
    ushort parent = forks[id].parent;
    FD_TEST( parent<sd->max_live_slots && forks[parent].in_use );
    for( ushort p=parent; p!=USHORT_MAX; p=forks[p].parent ) get_descends( sd, id )[p>>6] |= 1UL<<(p & 63);
  }
}

void
fd_stake_delegations_cancel_fork( fd_stake_delegations_t * sd,
                                  ushort                   fork ) {
  exclusive_begin( sd );
  FD_CHECK_CRIT( fork<sd->max_live_slots && fork!=sd->root_fork && get_forks( sd )[fork].in_use,
                 "invalid stake delegations cancellation" );
  for( ushort id=0; id<sd->max_live_slots; id++ ) {
    if( get_forks( sd )[id].in_use && (id==fork || ancestor( sd, id, fork )) ) cancel_one( sd, id );
  }
  rebuild_tree( sd );
  exclusive_end( sd );
}

static void
set_context( fd_stake_delegations_t *   sd,
             ulong                      epoch,
             fd_stake_history_t const * history,
             ulong *                    rate_epoch,
             int                        fixed_point ) {
  ulong len = history ? history->len : 0UL;
  FD_CHECK_CRIT( len<=FD_SYSVAR_STAKE_HISTORY_CAP, "stake delegation history exceeds bounded context" );
  sd->root_epoch       = epoch;
  sd->root_rate_epoch  = rate_epoch ? *rate_epoch : ULONG_MAX;
  sd->root_fixed_point = fixed_point;
  sd->root_history_len = len;
  if( len ) fd_memcpy( sd->root_history, history->entries, len*sizeof(fd_stake_history_entry_t) );
  sd->context_valid = 1;
}

static int
same_context( fd_stake_delegations_t *   sd,
              ulong                      epoch,
              fd_stake_history_t const * history,
              ulong *                    rate_epoch,
              int                        fixed_point ) {
  ulong len = history ? history->len : 0UL;
  return sd->context_valid && sd->root_epoch==epoch && sd->root_rate_epoch==(rate_epoch ? *rate_epoch : ULONG_MAX) &&
         sd->root_fixed_point==fixed_point && sd->root_history_len==len &&
         (!len || !memcmp( sd->root_history, history->entries, len*sizeof(fd_stake_history_entry_t) ));
}

static void
recompute( fd_stake_delegations_t * sd ) {
  sd->effective_stake   = sd->activating_stake = sd->deactivating_stake = 0UL;
  sd->fp_warmed_awarded = 0;
  for( uint page=0U; page<sd->page_wmk; page++ ) {
    if( get_pages( sd )[page].role!=PAGE_ROOT ) continue;
    for( uint slot=0U; slot<128U; slot++ ) {
      uint                  idx = (page<<7)+slot;
      fd_stake_delegation_t d   = *record( sd, idx, 1, 0 );
      if( !(d.flags & FD_STAKE_DELEGATION_ROOT_PRESENT) ) continue;
      add_root( sd, &d );
      publish( sd, idx, &d );
    }
  }
}

static ulong
prune( fd_stake_delegations_t *   sd,
       ulong                      epoch,
       fd_stake_history_t const * history,
       ulong *                    rate_epoch,
       int                        fixed_point,
       fd_bank_t const *          emit_bank ) {
  ulong count      = 0UL;
  ulong prev_epoch = epoch ? epoch-1UL : 0UL;
  for( uint page=0U; page<sd->page_wmk; page++ ) {
    if( get_pages( sd )[page].role!=PAGE_ROOT ) continue;
    for( uint slot=0U; slot<128U; slot++ ) {
      if( get_pages( sd )[page].role!=PAGE_ROOT ) break;
      uint                  idx = (page<<7)+slot;
      fd_stake_delegation_t d   = *record( sd, idx, 1, 0 );
      if( !(d.flags & FD_STAKE_DELEGATION_ROOT_PRESENT) ) continue;
      if( !fd_stake_delegation_is_inactive( &d, epoch, history, rate_epoch, fixed_point ) ||
          !fd_stake_delegation_is_inactive( &d, prev_epoch, history, rate_epoch, fixed_point ) ) continue;
      if( FD_UNLIKELY( emit_bank ) ) fd_event_runtime_stake_delegation_remove_emit( emit_bank, d.stake_account.uc );
      delete_root( sd, idx );
      count++;
    }
  }
  return count;
}

void
fd_stake_delegations_advance_root( fd_stake_delegations_t *             sd,
                                   ushort                               fork,
                                   ulong                                epoch,
                                   fd_stake_history_t const *           history,
                                   ulong *                              rate_epoch,
                                   int                                  fixed_point,
                                   int                                  prune_inactive,
                                   fd_bank_t const *                    emit_bank,
                                   fd_stake_delegations_delta_stats_t * stats ) {
  exclusive_begin( sd );
  fork_t * forks = get_forks( sd );
  FD_CHECK_CRIT( fork<sd->max_live_slots && forks[fork].in_use && ancestor( sd, fork, sd->root_fork ),
                 "stake delegations root destination is not a descendant" );
  ushort path[ FD_STAKE_DELEGATIONS_FORK_MAX ];
  ulong path_cnt = 0UL;
  for( ushort id=fork; id!=sd->root_fork; id=forks[id].parent ) path[path_cnt++] = id;

  /* Cancel branches outside the path and destination subtree.  Ancestry
     remains intact until every release decision has been made. */
  for( ushort id=0; id<sd->max_live_slots; id++ ) {
    if( !forks[id].in_use || id==fork || ancestor( sd, fork, id ) || ancestor( sd, id, fork ) ) continue;
    cancel_one( sd, id );
  }
  if( !same_context( sd, epoch, history, rate_epoch, fixed_point ) ) {
    set_context( sd, epoch, history, rate_epoch, fixed_point );
    recompute( sd );
  }
  ulong upserts = 0UL;
  ulong removes = 0UL;
  for( ulong p=path_cnt; p; p-- ) {
    ushort id  = path[p-1UL];
    uint   idx = forks[id].delta_head;
    while( idx!=UINT_MAX ) {
      fd_stake_delegation_t d    = *record( sd, idx, 1, 0 );
      uint                  root = unlink_delta( sd, idx, &d );
      if( d.flags & FD_STAKE_DELEGATION_TOMBSTONE ) {
        delete_root( sd, root );
        removes++;
      } else {
        store_root( sd, root, &d );
        upserts++;
      }
      idx = d.fork_next;
    }
    forks[id].delta_head = UINT_MAX;
  }
  /* Prune once at the externally visible transition, after the complete
     ancestry fold.  Descendant deltas keep absent root slots alive. */
  if( prune_inactive ) removes += prune( sd, epoch, history, rate_epoch, fixed_point, emit_bank );
  ushort old_root = sd->root_fork;
  for( ulong p=1UL; p<path_cnt; p++ ) cancel_one( sd, path[p] );
  cancel_one( sd, old_root );
  sd->root_fork      = fork;
  forks[fork].parent = USHORT_MAX;
  rebuild_tree( sd );
  if( stats ) {
    stats->upserts += upserts;
    stats->removes += removes;
    stats->root_cnt = sd->root_cnt;
  }
  exclusive_end( sd );
}

ulong
fd_stake_delegations_prune_inactive_root( fd_stake_delegations_t *   sd,
                                          ulong                      epoch,
                                          fd_stake_history_t const * history,
                                          ulong *                    rate_epoch,
                                          int                        fixed_point,
                                          fd_bank_t const *          emit_bank ) {
  exclusive_begin( sd );
  if( !same_context( sd, epoch, history, rate_epoch, fixed_point ) ) {
    set_context( sd, epoch, history, rate_epoch, fixed_point );
    recompute( sd );
  }
  ulong cnt = prune( sd, epoch, history, rate_epoch, fixed_point, emit_bank );
  exclusive_end( sd );
  return cnt;
}

void
fd_stake_delegations_invalidate_warmed( fd_stake_delegations_t * sd ) {
  exclusive_begin( sd );
  for( uint page=0U; page<sd->page_wmk; page++ ) {
    if( get_pages( sd )[page].role!=PAGE_ROOT ) continue;
    for( uint slot=0U; slot<128U; slot++ ) {
      uint                    idx = (page<<7)+slot;
      fd_stake_delegation_t * d   = record( sd, idx, 1, 0 );
      if( !(d->flags & FD_STAKE_DELEGATION_ROOT_PRESENT) || d->state!=FD_STAKE_DELEGATION_STATE_WARMED ) continue;
      d->state = FD_STAKE_DELEGATION_STATE_UNKNOWN;
      dirty( sd, idx );
    }
  }
  sd->fp_warmed_awarded = 0;
  exclusive_end( sd );
}

void
fd_stake_delegations_refresh( fd_stake_delegations_t *   sd,
                              ulong                      epoch,
                              fd_stake_history_t const * history,
                              ulong *                    rate_epoch,
                              int                        fixed_point,
                              int                        remove_inactive_stakes,
                              fd_accdb_t *               accdb,
                              fd_accdb_fork_id_t         fork_id ) {
  exclusive_begin( sd );
  set_context( sd, epoch, history, rate_epoch, fixed_point );
  /* Snapshot totals are rebuilt from account data.  Copies keep batch
     keys and payloads valid while later records evict earlier pages. */
  sd->effective_stake   = sd->activating_stake = sd->deactivating_stake = 0UL;
  sd->fp_warmed_awarded = 0;
#define BATCH 64UL
  fd_stake_delegation_t batch[ BATCH ];
  uint                 indices[ BATCH ];
  uchar const *        keys[ BATCH ];
  int                  writable[ BATCH ] = {0};
  fd_acc_t             acc[ BATCH ];
  ulong cursor = 0UL;
  ulong limit  = (ulong)sd->page_wmk*128UL;
  while( cursor<limit ) {
    ulong cnt = 0UL;
    while( cursor<limit && cnt<BATCH ) {
      uint idx = (uint)cursor++;
      if( get_pages( sd )[idx>>7].role!=PAGE_ROOT ) {
        cursor = ((ulong)(idx>>7)+1UL)*128UL;
        continue;
      }
      fd_stake_delegation_t d = *record( sd, idx, 1, 0 );
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
        sd->context_valid = 0;
        delete_root( sd, indices[i] );
        sd->context_valid = 1;
      } else {
        /* Earlier removals in this batch may have changed this root's
           bucket linkage.  The copied payload must not restore it. */
        fd_stake_delegation_t const * current = record( sd, indices[i], 1, 0 );
        d->next_      = current->next_;
        d->delta_head = current->delta_head;
        add_root( sd, d );
        publish( sd, indices[i], d );
      }
    }
  }
#undef BATCH
  exclusive_end( sd );
}
