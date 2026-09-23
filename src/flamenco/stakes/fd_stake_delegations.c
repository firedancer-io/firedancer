#include "fd_stake_delegations_private.h"
#include "fd_stakes.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../events/fd_event_runtime.h"
#include "../../util/fd_hash32.h"

#include <errno.h>
#include <unistd.h>

#define POOL_NAME  fork_pool
#define POOL_T     fork_t
#define POOL_NEXT  parent
#define POOL_IDX_T ushort
#include "../../util/tmpl/fd_pool.c"

#define POOL_NAME  page_pool
#define POOL_T     page_t
#define POOL_NEXT  next
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

#define POOL_NAME  frame_pool
#define POOL_T     frame_t
#define POOL_NEXT  next
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

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
          uint                     frame_idx ) {
  return (uchar *)stake_delegations + stake_delegations->data_offset + (ulong)frame_idx*FD_STAKE_DELEGATIONS_PAGE_SZ;
}

static uint *
partial_head( fd_stake_delegations_t * stake_delegations,
              page_t const *           page ) {
  int resident = page->frame!=UINT_MAX;
  if( page->role==PAGE_ROOT ) return resident ? &stake_delegations->partial_root_resident_head  : &stake_delegations->partial_root_evicted_head;
  else                        return resident ? &stake_delegations->partial_delta_resident_head : &stake_delegations->partial_delta_evicted_head;
}

static void
partial_remove( fd_stake_delegations_t * stake_delegations,
                uint                     page_idx ) {
  page_t * pages = get_pages( stake_delegations );
  page_t * page  = pages+page_idx;
  uint *   head  = partial_head( stake_delegations, page );
  if( page->prev==UINT_MAX ) {
    *head = page->next;
  } else {
    pages[page->prev].next = page->next;
  }
  if( page->next!=UINT_MAX ) pages[page->next].prev = page->prev;
  page->prev = page->next = UINT_MAX;
}

static void
partial_insert( fd_stake_delegations_t * stake_delegations,
                uint                     page_idx ) {
  page_t * pages = get_pages( stake_delegations );
  page_t * page  = pages+page_idx;
  uint *   head  = partial_head( stake_delegations, page );
  page->prev = UINT_MAX;
  page->next = *head;
  if( *head!=UINT_MAX ) pages[*head].prev = page_idx;
  *head = page_idx;
}

/* Complete scalar page transfers.  Partial direct I/O can continue only
   on a full page boundary, covering every supported startup alignment.
   Never publish a partial disk image. */
static void
page_io( fd_stake_delegations_t * stake_delegations,
         uint                     page_idx,
         uchar *                  data,
         int                      writing ) {
  ulong done = 0UL;
  ulong off  = (ulong)page_idx*FD_STAKE_DELEGATIONS_PAGE_SZ;
  while( done<FD_STAKE_DELEGATIONS_PAGE_SZ ) {
    long transferred = writing ? pwrite( stake_delegations->disk_fd, data+done, FD_STAKE_DELEGATIONS_PAGE_SZ-done, (off_t)(off+done) )
                               : pread ( stake_delegations->disk_fd, data+done, FD_STAKE_DELEGATIONS_PAGE_SZ-done, (off_t)(off+done) );
    if( FD_UNLIKELY( transferred<0L ) ) {
      if( errno==EINTR ) continue;
      FD_LOG_ERR(( "stake delegations %s() failed (%i-%s), page %u", writing ? "pwrite" : "pread", errno, fd_io_strerror( errno ), page_idx ));
    }
    if( FD_UNLIKELY( !transferred ) ) FD_LOG_ERR(( "stake delegations %s made no progress, page %u", writing ? "write" : "read", page_idx ));
    done += (ulong)transferred;
    if( FD_UNLIKELY( done<FD_STAKE_DELEGATIONS_PAGE_SZ && (done & (FD_STAKE_DELEGATIONS_PAGE_SZ-1UL)) ) ) {
      FD_LOG_ERR(( "stake delegations short unaligned %s, page %u", writing ? "write" : "read", page_idx ));
    }
  }
}

static uint
page_fault( fd_stake_delegations_t * stake_delegations,
            uint                     page_idx ) {
  page_t *  pages  = get_pages( stake_delegations );
  frame_t * frames = get_frames( stake_delegations );
  page_t *  page   = pages+page_idx;
  if( FD_LIKELY( page->frame!=UINT_MAX ) ) return page->frame;
  fd_racesan_hook( "stake_delegations_cache:pre_fault" );

  uint frame_idx;
  if( FD_LIKELY( frame_pool_free( frames ) ) ) {
    frame_idx = (uint)frame_pool_idx_acquire( frames );
  } else {
    frame_idx                      = stake_delegations->next_victim;
    stake_delegations->next_victim = (frame_idx+1U)%stake_delegations->frame_max;
    uint     victim_idx = frames[frame_idx].page;
    page_t * victim     = pages+victim_idx;
    if( victim->flags & PAGE_DIRTY ) {
      page_io( stake_delegations, victim_idx, get_data( stake_delegations, frame_idx ), 1 );
      victim->flags = PAGE_WRITTEN;
    }
    /* Move page to evicted list */
    if( victim->cnt<128U ) partial_remove( stake_delegations, victim_idx );
    victim->frame = UINT_MAX;
    if( victim->cnt<128U ) partial_insert( stake_delegations, victim_idx );
  }

  /* Fresh pages have no allocated records.  publish() initializes each
     slot before use; scans skip free slots using the page bitmap. */
  if( page->flags & PAGE_WRITTEN ) page_io( stake_delegations, page_idx, get_data( stake_delegations, frame_idx ), 0 );

  /* Move the page to the resident list */
  if( page->cnt<128U ) partial_remove( stake_delegations, page_idx );
  page->frame = frame_idx;
  if( page->cnt<128U ) partial_insert( stake_delegations, page_idx );
  frames[frame_idx].page = page_idx;
  fd_racesan_hook( "stake_delegations_cache:post_fault" );
  return frame_idx;
}

static fd_stake_delegation_t *
record( fd_stake_delegations_t * stake_delegations,
        uint                     idx ) {
  page_t * pages     = get_pages( stake_delegations );
  uint     page_idx  = idx>>7;
  uint     frame_idx = pages[page_idx].frame;
  if( FD_UNLIKELY( frame_idx==UINT_MAX ) ) {
    frame_idx = page_fault( stake_delegations, page_idx );
  }
  fd_stake_delegation_t * records = (fd_stake_delegation_t *)get_data( stake_delegations, frame_idx );
  return records + (idx & 127U);
}

static void
dirty( fd_stake_delegations_t * stake_delegations,
       uint                     idx ) {
  page_t * pages = get_pages( stake_delegations );
  pages[idx>>7].flags |= PAGE_DIRTY;
}

/* Prefer free slots on resident pages before faulting another page. */
static uint
reserve( fd_stake_delegations_t * stake_delegations,
         uchar                    role ) {
  page_t * pages    = get_pages( stake_delegations );
  uint     resident = role==PAGE_ROOT ? stake_delegations->partial_root_resident_head : stake_delegations->partial_delta_resident_head;
  uint     evicted  = role==PAGE_ROOT ? stake_delegations->partial_root_evicted_head  : stake_delegations->partial_delta_evicted_head;
  uint     page_idx = resident!=UINT_MAX ? resident : evicted;

  /* If there's no partially used page, look for a new one */
  if( FD_UNLIKELY( page_idx==UINT_MAX ) ) {
    FD_CHECK_CRIT( page_pool_free( pages ), "stake delegations logical page capacity exhausted" );
    page_idx                    = (uint)page_pool_idx_acquire( pages );
    stake_delegations->page_wmk = fd_uint_max( stake_delegations->page_wmk, page_idx+1U );
    pages[page_idx] = (page_t){
      .frame = UINT_MAX,
      .prev  = UINT_MAX,
      .next  = UINT_MAX,
      .role  = role
    };
    /* Insert new page into the partially used page list. */
    partial_insert( stake_delegations, page_idx );
  }
  /* No-op if already resident. */
  page_fault( stake_delegations, page_idx );
  /* Claim the lowest free slot in the page's 128-bit bitmap. */
  page_t * page = pages+page_idx;
  uint     word = page->used[0]==ULONG_MAX;
  uint     bit  = (uint)fd_ulong_find_lsb( ~page->used[word] );
  fd_racesan_hook( "stake_delegations_alloc:pre_reserve" );
  page->used[word] |= 1UL<<bit;
  page->cnt++;
  fd_racesan_hook( "stake_delegations_alloc:post_reserve" );
  if( page->cnt==128U ) partial_remove( stake_delegations, page_idx );
  return (page_idx<<7) + 64U*word + bit;
}

static void
release( fd_stake_delegations_t * stake_delegations,
         uint                     idx ) {
  page_t *  pages    = get_pages( stake_delegations );
  frame_t * frames   = get_frames( stake_delegations );
  uint      page_idx = idx>>7;
  page_t *  page     = pages+page_idx;
  if( page->cnt==128U ) partial_insert( stake_delegations, page_idx );
  page->used[(idx & 127U)>>6] &= ~(1UL<<(idx & 63U));
  page->cnt--;
  if( FD_UNLIKELY( !page->cnt ) ) {
    partial_remove( stake_delegations, page_idx );
    if( page->frame!=UINT_MAX ) {
      frames[page->frame].page = UINT_MAX;
      frame_pool_idx_release( frames, page->frame );
    }
    *page = (page_t){
      .frame = UINT_MAX,
      .prev  = UINT_MAX
    };
    page_pool_idx_release( pages, page_idx );
  }
}

static void
publish( fd_stake_delegations_t *      stake_delegations,
         uint                          idx,
         fd_stake_delegation_t const * delegation ) {
  fd_stake_delegation_t * dst = record( stake_delegations, idx );
  fd_racesan_hook( "stake_delegations_record:pre_publish" );
  *dst = *delegation;
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
  uint * buckets = get_buckets( stake_delegations );
  uint   idx     = buckets[ bucket( stake_delegations, key ) ];
  while( idx!=UINT_MAX ) {
    fd_stake_delegation_t const * delegation = record( stake_delegations, idx );
    if( fd_pubkey_eq( &delegation->stake_account, key ) ) return idx;
    idx = delegation->next_;
  }
  return UINT_MAX;
}

static uint
insert_root( fd_stake_delegations_t * stake_delegations,
             fd_pubkey_t const *      key ) {
  uint * buckets    = get_buckets( stake_delegations );
  uint   idx        = reserve( stake_delegations, PAGE_ROOT );
  uint   bucket_idx = bucket( stake_delegations, key );
  fd_stake_delegation_t delegation = {
    .stake_account = *key,
    .next_         = buckets[bucket_idx],
    .delta_head    = UINT_MAX,
    .fork_id       = USHORT_MAX
  };
  publish( stake_delegations, idx, &delegation );
  fd_racesan_hook( "stake_delegations_bucket:pre_publish" );
  buckets[bucket_idx] = idx;
  fd_racesan_hook( "stake_delegations_bucket:post_publish" );
  return idx;
}

static void
remove_root( fd_stake_delegations_t * stake_delegations,
             uint                     idx ) {
  fd_stake_delegation_t delegation = *record( stake_delegations, idx );
  FD_TEST( delegation.delta_head==UINT_MAX );
  uint * buckets    = get_buckets( stake_delegations );
  uint   bucket_idx = bucket( stake_delegations, &delegation.stake_account );
  uint   prev       = UINT_MAX;
  uint   cur        = buckets[bucket_idx];
  while( cur!=idx ) {
    FD_CHECK_CRIT( cur!=UINT_MAX, "missing stake delegation root" );
    prev = cur;
    cur  = record( stake_delegations, cur )->next_;
  }
  if( prev==UINT_MAX ) {
    buckets[bucket_idx] = delegation.next_;
  } else {
    record( stake_delegations, prev )->next_ = delegation.next_;
    dirty( stake_delegations, prev );
  }
  if( delegation.flags & FD_STAKE_DELEGATION_ROOT_PRESENT ) stake_delegations->root_cnt--;
  release( stake_delegations, idx );
}

static void
reset( fd_stake_delegations_t * stake_delegations ) {
  ulong     descends_words = (stake_delegations->max_live_slots+63UL)>>6;
  page_t *  pages          = get_pages( stake_delegations );
  frame_t * frames         = get_frames( stake_delegations );
  fork_t *  forks          = get_forks( stake_delegations );
  fd_memset( get_buckets( stake_delegations ),      255, FD_STAKE_DELEGATIONS_BUCKET_CNT*sizeof(uint) );
  fd_memset( pages,                                   0, (ulong)stake_delegations->page_max*sizeof(page_t) );
  fd_memset( forks,                                   0, stake_delegations->max_live_slots*sizeof(fork_t) );
  fd_memset( get_descends( stake_delegations, 0 ),    0, stake_delegations->max_live_slots*descends_words*sizeof(ulong) );
  page_pool_reset( pages );
  fork_pool_reset( forks );
  for( uint frame_idx=0U; frame_idx<stake_delegations->frame_max; frame_idx++ ) {
    frames[frame_idx] = (frame_t){
      .page = UINT_MAX
    };
  }
  frame_pool_reset( frames );
  stake_delegations->page_wmk   = 0U;
  stake_delegations->next_victim = 0U;
  stake_delegations->partial_root_resident_head  = UINT_MAX;
  stake_delegations->partial_root_evicted_head   = UINT_MAX;
  stake_delegations->partial_delta_resident_head = UINT_MAX;
  stake_delegations->partial_delta_evicted_head  = UINT_MAX;
  stake_delegations->root_fork = (ushort)fork_pool_idx_acquire( forks );
  forks[stake_delegations->root_fork] = (fork_t){
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
  ulong layout    = FD_LAYOUT_INIT;
  layout = FD_LAYOUT_APPEND( layout, alignof(fd_stake_delegations_t),  sizeof(fd_stake_delegations_t) );
  layout = FD_LAYOUT_APPEND( layout, alignof(uint),                   FD_STAKE_DELEGATIONS_BUCKET_CNT*sizeof(uint) );
  layout = FD_LAYOUT_APPEND( layout, page_pool_align(),               page_pool_footprint( page_max ) );
  layout = FD_LAYOUT_APPEND( layout, frame_pool_align(),              frame_pool_footprint( frame_max ) );
  layout = FD_LAYOUT_APPEND( layout, fork_pool_align(),               fork_pool_footprint( max_live_slots ) );
  layout = FD_LAYOUT_APPEND( layout, alignof(ulong),                  max_live_slots*((max_live_slots+63UL)>>6)*sizeof(ulong) );
  layout = FD_LAYOUT_APPEND( layout, FD_STAKE_DELEGATIONS_ALIGN,      cache_bytes );
  return FD_LAYOUT_FINI( layout, FD_STAKE_DELEGATIONS_ALIGN );
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
  ulong offset         = fd_ulong_align_up( sizeof(*sd), alignof(uint) ) + FD_STAKE_DELEGATIONS_BUCKET_CNT*sizeof(uint);
#define APPEND(member,align,size) do {             \
    offset = fd_ulong_align_up( offset, (align) ); \
    sd->member = offset;                           \
    offset += (size);                              \
  } while(0)
  APPEND( pages_offset,    page_pool_align(),               page_pool_footprint( sd->page_max ) );
  APPEND( frames_offset,   frame_pool_align(),              frame_pool_footprint( sd->frame_max ) );
  APPEND( forks_offset,    fork_pool_align(),               fork_pool_footprint( max_live_slots ) );
  APPEND( descends_offset, alignof(ulong),                  max_live_slots*descends_words*sizeof(ulong) );
  APPEND( data_offset,     FD_STAKE_DELEGATIONS_ALIGN,      cache_bytes );
#undef APPEND
  FD_TEST( fd_ulong_align_up( offset, FD_STAKE_DELEGATIONS_ALIGN )==footprint );
  page_t * pages = page_pool_join( page_pool_new( (uchar *)sd+sd->pages_offset, sd->page_max ) );
  FD_TEST( pages );
  sd->pages_offset = (ulong)((uchar *)pages - (uchar *)sd);
  frame_t * frames = frame_pool_join( frame_pool_new( (uchar *)sd+sd->frames_offset, sd->frame_max ) );
  FD_TEST( frames );
  sd->frames_offset = (ulong)((uchar *)frames - (uchar *)sd);
  fork_t * forks = fork_pool_join( fork_pool_new( (uchar *)sd+sd->forks_offset, max_live_slots ) );
  FD_TEST( forks );
  sd->forks_offset = (ulong)((uchar *)forks - (uchar *)sd);
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
  ulong * descends = get_descends( stake_delegations, fork );
  return !!(descends[parent>>6] & (1UL<<(parent & 63)));
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
  FD_CHECK_CRIT( fork_pool_free( forks ), "stake delegations fork capacity exhausted" );
  ushort id = (ushort)fork_pool_idx_acquire( forks );
  forks[id] = (fork_t){
    .delta_head = UINT_MAX,
    .parent     = parent,
    .in_use     = 1
  };
  ulong   descends_words = (stake_delegations->max_live_slots+63UL)>>6;
  ulong * descends       = get_descends( stake_delegations, id );
  fd_memcpy( descends, get_descends( stake_delegations, parent ), descends_words*sizeof(ulong) );
  descends[parent>>6] |= 1UL<<(parent & 63);
  stake_delegations->boot = 0;
  fd_rwlock_unwrite( &stake_delegations->lock );
  return id;
}

static void
fork_upsert( fd_stake_delegations_t * stake_delegations,
             ushort                   fork,
             fd_stake_delegation_t *  src ) {
  fd_rwlock_write( &stake_delegations->lock );
  /* Find the account's root slot, creating a placeholder if needed. */
  uint root = find_root( stake_delegations, &src->stake_account );
  if( root==UINT_MAX ) root = insert_root( stake_delegations, &src->stake_account );

  /* Replace this fork's existing delta if the account has a delta. */
  uint head = record( stake_delegations, root )->delta_head;
  uint idx  = head;
  while( idx!=UINT_MAX ) {
    fd_stake_delegation_t * delta = record( stake_delegations, idx );
    if( delta->fork_id==fork ) {
      /* Copy only the payload; the record links stay. */
      delta->vote_account         = src->vote_account;
      delta->stake                = src->stake;
      delta->lamports             = src->lamports;
      delta->credits_observed     = src->credits_observed;
      delta->acc_dlen             = src->acc_dlen;
      delta->activation_epoch     = src->activation_epoch;
      delta->deactivation_epoch   = src->deactivation_epoch;
      delta->warmup_cooldown_rate = src->warmup_cooldown_rate;
      delta->state                = FD_STAKE_DELEGATION_STATE_UNKNOWN;
      delta->flags                = src->flags;
      dirty( stake_delegations, idx );
      fd_rwlock_unwrite( &stake_delegations->lock );
      return;
    }
    idx = delta->next_;
  }

  /* Prepend a new delta to both the account's and the fork's lists. */
  idx = reserve( stake_delegations, PAGE_DELTA );
  fork_t * forks = get_forks( stake_delegations );
  src->fork_id   = fork;
  src->next_     = head;
  src->fork_next = forks[fork].delta_head;
  publish( stake_delegations, idx, src );
  forks[fork].delta_head = idx;

  /* Reacquire the root record: delta allocation can evict its page. */
  record( stake_delegations, root )->delta_head = idx;
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
  fd_stake_delegation_t delegation = {
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
  fork_upsert( stake_delegations, fork, &delegation );
}

void
fd_stake_delegations_fork_remove( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork,
                                  fd_pubkey_t const *      stake_account ) {
  fd_stake_delegation_t delegation = {
    .stake_account = *stake_account,
    .flags         = FD_STAKE_DELEGATION_TOMBSTONE
  };
  fork_upsert( stake_delegations, fork, &delegation );
}

static fd_stake_history_entry_t
root_status( fd_stake_delegations_t *      stake_delegations,
             fd_stake_delegation_t const * delegation ) {
  fd_stake_history_t history = {
    .entries = stake_delegations->root_history,
    .len     = stake_delegations->root_history_len
  };
  return fd_stake_delegation_activation_status( delegation, stake_delegations->root_epoch, &history, &stake_delegations->root_rate_epoch, stake_delegations->root_fixed_point );
}

static void
subtract_root( fd_stake_delegations_t *      stake_delegations,
               fd_stake_delegation_t const * delegation ) {
  if( !stake_delegations->context_valid || !(delegation->flags & FD_STAKE_DELEGATION_ROOT_PRESENT) ) return;
  fd_stake_history_entry_t status = root_status( stake_delegations, delegation );
  stake_delegations->effective_stake    -= status.effective;
  stake_delegations->activating_stake   -= status.activating;
  stake_delegations->deactivating_stake -= status.deactivating;
}

static void
add_root( fd_stake_delegations_t * stake_delegations,
          fd_stake_delegation_t *  delegation ) {
  delegation->state = FD_STAKE_DELEGATION_STATE_UNKNOWN;
  if( !stake_delegations->context_valid ) return;
  fd_stake_history_entry_t status = root_status( stake_delegations, delegation );
  stake_delegations->effective_stake    += status.effective;
  stake_delegations->activating_stake   += status.activating;
  stake_delegations->deactivating_stake += status.deactivating;
  fd_stake_history_t history = {
    .entries = stake_delegations->root_history,
    .len     = stake_delegations->root_history_len
  };
  if( fd_sysvar_stake_history_is_contiguous( &history ) ) delegation->state = fd_stake_delegation_classify( delegation, status, stake_delegations->root_epoch );
  if( delegation->state==FD_STAKE_DELEGATION_STATE_WARMED && !stake_delegations->root_fixed_point ) stake_delegations->fp_warmed_awarded = 1;
}

static void
store_root( fd_stake_delegations_t *      stake_delegations,
            uint                          idx,
            fd_stake_delegation_t const * src ) {
  fd_stake_delegation_t old = *record( stake_delegations, idx );
  subtract_root( stake_delegations, &old );
  fd_stake_delegation_t delegation = *src;
  delegation.next_      = old.next_;
  delegation.delta_head = old.delta_head;
  delegation.fork_id    = USHORT_MAX;
  delegation.flags      = FD_STAKE_DELEGATION_ROOT_PRESENT;
  if( !(old.flags & FD_STAKE_DELEGATION_ROOT_PRESENT) ) {
    stake_delegations->root_cnt++;
  }
  add_root( stake_delegations, &delegation );
  publish( stake_delegations, idx, &delegation );
}

static void
delete_root( fd_stake_delegations_t * stake_delegations,
             uint                     idx ) {
  fd_stake_delegation_t delegation = *record( stake_delegations, idx );
  if( delegation.flags & FD_STAKE_DELEGATION_ROOT_PRESENT ) {
    subtract_root( stake_delegations, &delegation );
    delegation.flags = 0;
    delegation.state = FD_STAKE_DELEGATION_STATE_UNKNOWN;
    stake_delegations->root_cnt--;
    publish( stake_delegations, idx, &delegation );
  }
  if( delegation.delta_head==UINT_MAX ) remove_root( stake_delegations, idx );
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
  fd_stake_delegation_t delegation = {
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
  store_root( stake_delegations, root, &delegation );
  fd_rwlock_unwrite( &stake_delegations->lock );
}

fd_stake_delegations_view_t *
fd_stake_delegations_view_begin( fd_stake_delegations_view_t * view,
                                 fd_stake_delegations_t *      stake_delegations,
                                 ushort                        fork ) {
  fd_rwlock_write( &stake_delegations->lock );
  fork_t * forks = get_forks( stake_delegations );
  FD_CHECK_CRIT( fork<stake_delegations->max_live_slots && forks[fork].in_use,
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
  page_t *                      pages             = get_pages( stake_delegations );
  ulong                         limit             = (ulong)view->page_wmk*128UL;
  iter->batch_idx = iter->batch_cnt = 0UL;
  while( iter->cursor<limit && iter->batch_cnt<FD_STAKE_DELEGATIONS_ITER_BATCH ) {
    uint root = (uint)iter->cursor++;
    if( pages[root>>7].role!=PAGE_ROOT ) {
      iter->cursor = ((ulong)(root>>7)+1UL)*128UL;
      continue;
    }
    if( !(pages[root>>7].used[(root & 127U)>>6] & (1UL<<(root & 63U))) ) continue;
    fd_stake_delegation_t selected = *record( stake_delegations, root );
    uint next  = selected.delta_head;
    int  found = !!(selected.flags & FD_STAKE_DELEGATION_ROOT_PRESENT);
    if( !view->use_stable_tags ) selected.state = FD_STAKE_DELEGATION_STATE_UNKNOWN;
    while( next!=UINT_MAX ) {
      fd_stake_delegation_t const * delta = record( stake_delegations, next );
      if( delta->fork_id==view->fork_id || ancestor( stake_delegations, view->fork_id, delta->fork_id ) ) {
        selected = *delta;
        found    = !(selected.flags & FD_STAKE_DELEGATION_TOMBSTONE);
        break;
      }
      next = delta->next_;
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
    fd_stake_history_entry_t status = fd_stake_delegation_activation_status( fd_stake_delegations_iter_ele( iter ), epoch, history, rate_epoch, fixed_point );
    totals->effective    += status.effective;
    totals->activating   += status.activating;
    totals->deactivating += status.deactivating;
  }
}

/* Tree/cache exclusive.  Every access which can fault retains only
   copied records and logical links from preceding accesses. */
static uint
unlink_delta( fd_stake_delegations_t *      stake_delegations,
              uint                          idx,
              fd_stake_delegation_t const * delta ) {
  uint root = find_root( stake_delegations, &delta->stake_account );
  FD_CHECK_CRIT( root!=UINT_MAX, "stake delegation delta without root slot" );
  uint prev = UINT_MAX;
  uint cur  = record( stake_delegations, root )->delta_head;
  while( cur!=idx ) {
    FD_CHECK_CRIT( cur!=UINT_MAX, "missing stake delegation delta" );
    prev = cur;
    cur  = record( stake_delegations, cur )->next_;
  }
  if( prev==UINT_MAX ) {
    record( stake_delegations, root )->delta_head = delta->next_;
    dirty( stake_delegations, root );
  } else {
    record( stake_delegations, prev )->next_ = delta->next_;
    dirty( stake_delegations, prev );
  }
  release( stake_delegations, idx );
  return root;
}

static void
cancel_one( fd_stake_delegations_t * stake_delegations,
            ushort                   fork ) {
  fork_t * forks = get_forks( stake_delegations );
  uint     idx   = forks[fork].delta_head;
  while( idx!=UINT_MAX ) {
    fd_stake_delegation_t delta       = *record( stake_delegations, idx );
    uint                  root        = unlink_delta( stake_delegations, idx, &delta );
    fd_stake_delegation_t root_record = *record( stake_delegations, root );
    if( !(root_record.flags & FD_STAKE_DELEGATION_ROOT_PRESENT) && root_record.delta_head==UINT_MAX ) remove_root( stake_delegations, root );
    idx = delta.fork_next;
  }
  forks[fork] = (fork_t){0};
  fork_pool_idx_release( forks, fork );
}

void
fd_stake_delegations_cancel_fork( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork ) {
  fd_rwlock_write( &stake_delegations->lock );
  fork_t * forks = get_forks( stake_delegations );
  FD_CHECK_CRIT( fork<stake_delegations->max_live_slots && fork!=stake_delegations->root_fork && forks[fork].in_use,
                 "invalid stake delegations cancellation" );
  cancel_one( stake_delegations, fork );
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
  page_t * pages = get_pages( stake_delegations );
  for( uint page_idx=0U; page_idx<stake_delegations->page_wmk; page_idx++ ) {
    if( pages[page_idx].role!=PAGE_ROOT ) continue;
    for( uint slot=0U; slot<128U; slot++ ) {
      if( !(pages[page_idx].used[slot>>6] & (1UL<<(slot & 63U))) ) continue;
      uint                  idx        = (page_idx<<7)+slot;
      fd_stake_delegation_t delegation = *record( stake_delegations, idx );
      if( !(delegation.flags & FD_STAKE_DELEGATION_ROOT_PRESENT) ) continue;
      add_root( stake_delegations, &delegation );
      publish( stake_delegations, idx, &delegation );
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
  page_t * pages      = get_pages( stake_delegations );
  ulong    count      = 0UL;
  ulong    prev_epoch = epoch ? epoch-1UL : 0UL;
  for( uint page_idx=0U; page_idx<stake_delegations->page_wmk; page_idx++ ) {
    if( pages[page_idx].role!=PAGE_ROOT ) continue;
    for( uint slot=0U; slot<128U; slot++ ) {
      if( pages[page_idx].role!=PAGE_ROOT ) break;
      if( !(pages[page_idx].used[slot>>6] & (1UL<<(slot & 63U))) ) continue;
      uint                  idx        = (page_idx<<7)+slot;
      fd_stake_delegation_t delegation = *record( stake_delegations, idx );
      if( !(delegation.flags & FD_STAKE_DELEGATION_ROOT_PRESENT) ) continue;
      if( !fd_stake_delegation_is_inactive( &delegation, epoch, history, rate_epoch, fixed_point ) ||
          !fd_stake_delegation_is_inactive( &delegation, prev_epoch, history, rate_epoch, fixed_point ) ) continue;
      if( FD_UNLIKELY( emit_bank ) ) fd_event_runtime_stake_delegation_remove_emit( emit_bank, delegation.stake_account.uc );
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
  for( ulong path_idx=path_cnt; path_idx; path_idx-- ) {
    ushort id  = path[path_idx-1UL];
    uint   idx = forks[id].delta_head;
    while( idx!=UINT_MAX ) {
      fd_stake_delegation_t delta = *record( stake_delegations, idx );
      uint                  root  = unlink_delta( stake_delegations, idx, &delta );
      if( delta.flags & FD_STAKE_DELEGATION_TOMBSTONE ) {
        delete_root( stake_delegations, root );
        removes++;
      } else {
        store_root( stake_delegations, root, &delta );
        upserts++;
      }
      idx = delta.fork_next;
    }
    forks[id].delta_head = UINT_MAX;
  }
  /* Prune once at the externally visible transition, after the complete
     ancestry fold.  Descendant deltas keep absent root slots alive. */
  if( prune_inactive ) removes += prune( stake_delegations, epoch, history, rate_epoch, fixed_point, emit_bank );
  ushort old_root = stake_delegations->root_fork;
  for( ulong path_idx=1UL; path_idx<path_cnt; path_idx++ ) cancel_one( stake_delegations, path[path_idx] );
  cancel_one( stake_delegations, old_root );
  stake_delegations->root_fork      = fork;
  forks[fork].parent = USHORT_MAX;

  /* Rebuild ancestry from the surviving parent links. */
  ulong descends_words = (stake_delegations->max_live_slots+63UL)>>6;
  for( ushort id=0; id<stake_delegations->max_live_slots; id++ ) {
    fd_memset( get_descends( stake_delegations, id ), 0, descends_words*sizeof(ulong) );
  }
  for( ushort id=0; id<stake_delegations->max_live_slots; id++ ) {
    if( !forks[id].in_use || id==stake_delegations->root_fork ) continue;
    ushort parent = forks[id].parent;
    FD_TEST( parent<stake_delegations->max_live_slots && forks[parent].in_use );
    ulong * descends = get_descends( stake_delegations, id );
    for( ushort ancestor_id=parent; ancestor_id!=USHORT_MAX; ancestor_id=forks[ancestor_id].parent ) {
      descends[ancestor_id>>6] |= 1UL<<(ancestor_id & 63);
    }
  }

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

fd_stake_history_entry_t
fd_stake_delegations_root_totals( fd_stake_delegations_t const * stake_delegations ) {
  return (fd_stake_history_entry_t){
    .epoch        = stake_delegations->root_epoch,
    .effective    = stake_delegations->effective_stake,
    .activating   = stake_delegations->activating_stake,
    .deactivating = stake_delegations->deactivating_stake
  };
}

int
fd_stake_delegations_fp_warmed_awarded( fd_stake_delegations_t const * stake_delegations ) {
  return stake_delegations->fp_warmed_awarded;
}

void
fd_stake_delegations_invalidate_warmed( fd_stake_delegations_t * stake_delegations ) {
  fd_rwlock_write( &stake_delegations->lock );
  page_t * pages = get_pages( stake_delegations );
  for( uint page_idx=0U; page_idx<stake_delegations->page_wmk; page_idx++ ) {
    if( pages[page_idx].role!=PAGE_ROOT ) continue;
    for( uint slot=0U; slot<128U; slot++ ) {
      if( !(pages[page_idx].used[slot>>6] & (1UL<<(slot & 63U))) ) continue;
      uint                    idx        = (page_idx<<7)+slot;
      fd_stake_delegation_t * delegation = record( stake_delegations, idx );
      if( !(delegation->flags & FD_STAKE_DELEGATION_ROOT_PRESENT) || delegation->state!=FD_STAKE_DELEGATION_STATE_WARMED ) continue;
      delegation->state = FD_STAKE_DELEGATION_STATE_UNKNOWN;
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
  page_t * pages  = get_pages( stake_delegations );
  ulong    cursor = 0UL;
  ulong    limit  = (ulong)stake_delegations->page_wmk*128UL;
  while( cursor<limit ) {
    ulong cnt = 0UL;
    while( cursor<limit && cnt<BATCH ) {
      uint idx = (uint)cursor++;
      if( pages[idx>>7].role!=PAGE_ROOT ) {
        cursor = ((ulong)(idx>>7)+1UL)*128UL;
        continue;
      }
      if( !(pages[idx>>7].used[(idx & 127U)>>6] & (1UL<<(idx & 63U))) ) continue;
      fd_stake_delegation_t delegation = *record( stake_delegations, idx );
      if( !(delegation.flags & FD_STAKE_DELEGATION_ROOT_PRESENT) ) continue;
      batch[cnt]   = delegation;
      indices[cnt] = idx;
      keys[cnt]    = batch[cnt].stake_account.uc;
      cnt++;
    }
    if( !cnt ) continue;
    fd_accdb_acquire( accdb, fork_id, cnt, keys, writable, acc );
    for( ulong batch_idx=0UL; batch_idx<cnt; batch_idx++ ) {
      fd_stake_delegation_t *  delegation = batch+batch_idx;
      fd_stake_state_t const * state      = acc[batch_idx].lamports ? fd_stakes_get_state( acc+batch_idx ) : NULL;
      int                      remove     = !state || state->stake_type!=FD_STAKE_STATE_STAKE;
      if( !remove ) {
        fd_delegation_t const * src        = &state->stake.stake.delegation;
        ulong                   prev_epoch = epoch ? epoch-1UL : 0UL;
        remove = remove_inactive_stakes &&
          fd_delegation_is_inactive( src, epoch, history, rate_epoch, fixed_point ) &&
          fd_delegation_is_inactive( src, prev_epoch, history, rate_epoch, fixed_point );
        if( !remove ) {
          FD_CHECK_ERR( (long)src->activation_epoch  <USHORT_MAX, "activation_epoch overflow"   );
          FD_CHECK_ERR( (long)src->deactivation_epoch<USHORT_MAX, "deactivation_epoch overflow" );
          delegation->vote_account         = src->voter_pubkey;
          delegation->stake                = src->stake;
          delegation->lamports             = acc[batch_idx].lamports;
          delegation->credits_observed     = state->stake.stake.credits_observed;
          delegation->acc_dlen             = (uint)acc[batch_idx].data_len;
          delegation->activation_epoch     = (ushort)src->activation_epoch;
          delegation->deactivation_epoch   = (ushort)src->deactivation_epoch;
          delegation->warmup_cooldown_rate = fd_stake_warmup_cooldown_rate( epoch, rate_epoch );
        }
      }
      /* Defer store mutation until all accdb references are released. */
      if( remove ) delegation->flags &= (uchar)~FD_STAKE_DELEGATION_ROOT_PRESENT;
    }
    fd_accdb_release( accdb, cnt, acc );
    for( ulong batch_idx=0UL; batch_idx<cnt; batch_idx++ ) {
      fd_stake_delegation_t * delegation = batch+batch_idx;
      if( !(delegation->flags & FD_STAKE_DELEGATION_ROOT_PRESENT) ) {
        stake_delegations->context_valid = 0;
        delete_root( stake_delegations, indices[batch_idx] );
        stake_delegations->context_valid = 1;
      } else {
        /* Earlier removals in this batch may have changed this root's
           bucket linkage.  The copied payload must not restore it. */
        fd_stake_delegation_t const * current = record( stake_delegations, indices[batch_idx] );
        delegation->next_      = current->next_;
        delegation->delta_head = current->delta_head;
        add_root( stake_delegations, delegation );
        publish( stake_delegations, indices[batch_idx], delegation );
      }
    }
  }
#undef BATCH
  fd_rwlock_unwrite( &stake_delegations->lock );
}
