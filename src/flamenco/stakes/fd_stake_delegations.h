#ifndef HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h
#define HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h

#include "../runtime/sysvar/fd_sysvar_base.h"
#include "../accdb/fd_accdb.h"
#include "../fd_rwlock.h"

#define FD_STAKE_DELEGATIONS_MAGIC (0xF17EDA2CE757A3E0) /* FIREDANCER STAKE V0 */
#define FD_STAKE_DELEGATIONS_ALIGN      (16384UL)
#define FD_STAKE_DELEGATIONS_PAGE_SZ    (16384UL)
#define FD_STAKE_DELEGATIONS_FORK_MAX   (4096UL)
#define FD_STAKE_DELEGATIONS_BUCKET_CNT (1UL<<22)
#define FD_STAKE_DELEGATIONS_STRIPE_CNT (4096UL)
#define FD_STAKE_DELEGATIONS_FD         (123457)

/* The store owns a fork tree and a shared pool of typed record pages.
   Persistent links use logical record indices.  Every joining process
   must install the same backing file at disk_fd.

   After boot, production structural mutations are owned by replay.
   A boundary view doing accdb acquires cannot overlap an independent
   structural writer: execution may hold accdb references while entering
   this store.  The scheduler drains removed banks before ID release.
   Callers stop writing a parent before attaching a child, and quiesce
   the selected fork before opening a view.  The store tracks allocation
   and open views, not bank execution state. */

#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 (0)
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 (1)
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_025      (0.25)
#define FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_009      (0.09)

/* fd_stake_warmup_cooldown_rate gives the warmup/cooldown rate enum
   for a given epoch.  In Agave, the per-delegation warmup_cooldown_rate
   field was deprecated (since v1.16.7) and unused in calculations.
   The rate is always determined by the epoch. */

static inline uchar
fd_stake_warmup_cooldown_rate( ulong   current_epoch,
                               ulong * new_rate_activation_epoch ) {
  ulong activation_epoch = new_rate_activation_epoch ? *new_rate_activation_epoch : ULONG_MAX;
  return current_epoch<activation_epoch
    ? (uchar)FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025
    : (uchar)FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009;
}

#define FD_STAKE_DELEGATION_STATE_UNKNOWN ((uchar)0)
#define FD_STAKE_DELEGATION_STATE_WARMING ((uchar)1)
#define FD_STAKE_DELEGATION_STATE_WARMED  ((uchar)2)
#define FD_STAKE_DELEGATION_STATE_COOLING ((uchar)3)
#define FD_STAKE_DELEGATION_STATE_COOLED  ((uchar)4)

#define FD_STAKE_DELEGATION_IN_USE       ((uchar)1)
#define FD_STAKE_DELEGATION_ROOT_PRESENT ((uchar)2)
#define FD_STAKE_DELEGATION_TOMBSTONE    ((uchar)4)

struct fd_stake_delegation {
  fd_pubkey_t stake_account;
  fd_pubkey_t vote_account;
  ulong       stake;
  ulong       lamports;
  ulong       credits_observed;
  uint        acc_dlen;
  uint        next_;
  union {
    uint      delta_head;
    uint      fork_next;
  };
  ushort      activation_epoch;
  ushort      deactivation_epoch;
  ushort      fork_id;
  uchar       flags;
  uchar       warmup_cooldown_rate;
  uchar       state;
  uchar       pad[19];
};
typedef struct fd_stake_delegation fd_stake_delegation_t;

FD_STATIC_ASSERT( sizeof(fd_stake_delegation_t)==128UL, fd_stake_delegation_size );
FD_STATIC_ASSERT( alignof(fd_stake_delegation_t)==8UL, fd_stake_delegation_align );

struct fd_stake_delegations {
  /* Identity and immutable configuration */
  ulong magic;
  ulong seed;
  ulong max_live_slots;
  uint  page_max;
  uint  frame_max;
  int   disk_fd;

  /* Packed shared-memory layout */
  ulong pages_offset;
  ulong frames_offset;
  ulong forks_offset;
  ulong descends_offset;
  ulong stripes_offset;
  ulong data_offset;

  /* Record allocator and page cache */
  uint        page_wmk;
  uint        free_page;
  uint        free_frame;
  uint        clock_hand;
  uint        nonfull[3][2];
  uint        allocator_lock;
  fd_rwlock_t cache_lock;

  /* Fork lifecycle */
  ushort      root_fork;
  uchar       boot;
  fd_rwlock_t tree_lock;

  /* Rooted aggregate state */
  ulong root_cnt;
  ulong effective_stake;
  ulong activating_stake;
  ulong deactivating_stake;
  uchar fp_warmed_awarded;

  /* Rooted aggregate calculation context */
  uchar                    context_valid;
  int                      root_fixed_point;
  ulong                    root_epoch;
  ulong                    root_rate_epoch;
  ulong                    root_history_len;
  fd_stake_history_entry_t root_history[ FD_SYSVAR_STAKE_HISTORY_CAP ];
};
typedef struct fd_stake_delegations fd_stake_delegations_t;

/* A view holds tree shared until view_end.  The caller ensures its fork
   and ancestors have no scheduled writers.  Close it before writes to
   that fork or structural mutation.  Other forks can update and page.
   Stable tags require a caller proof of epoch, history and math mode. */
struct fd_stake_delegations_view {
  fd_stake_delegations_t * sd;
  uint                    page_wmk;
  ushort                  fork_id;
  int                     use_stable_tags;
};
typedef struct fd_stake_delegations_view fd_stake_delegations_view_t;

#define FD_STAKE_DELEGATIONS_ITER_BATCH (32UL)
struct fd_stake_delegations_iter {
  fd_stake_delegations_view_t * view;
  ulong                        cursor;
  ulong                        idx;
  ulong                        batch_idx;
  ulong                        batch_cnt;
  uint                         chain;
  uchar                        root_flags;
  uchar                        resolving;
  ulong                        indices[ FD_STAKE_DELEGATIONS_ITER_BATCH ];
  fd_stake_delegation_t         batch[ FD_STAKE_DELEGATIONS_ITER_BATCH ];
};
typedef struct fd_stake_delegations_iter fd_stake_delegations_iter_t;

struct fd_stake_delegations_delta_stats {
  ulong upserts;
  ulong removes;
  ulong root_cnt;
};
typedef struct fd_stake_delegations_delta_stats fd_stake_delegations_delta_stats_t;

FD_PROTOTYPES_BEGIN

static inline double
fd_stake_delegations_warmup_cooldown_rate_to_double( uchar warmup_cooldown_rate ) {
  return warmup_cooldown_rate==FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 ? FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_025 : FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_009;
}

/* Classify stake given the activation status evaluated at the provided
   epoch.  The provided epoch is expected to be >= activation epoch. */
static inline uchar
fd_stake_delegation_classify( fd_stake_delegation_t const * delegation,
                              fd_stake_history_entry_t      activation_status,
                              ulong                         epoch ) {
  /* Activation epoch in Agave's stake program is either clock.epoch, or
     inherited from an existing activation epoch, so activation epoch <=
     current epoch always holds for delegations created by the stake
     program.  Synthetic inputs do not conform to this, so we mark them
     UNKNOWN to force the slow path. */
  if( FD_UNLIKELY( delegation->activation_epoch!=(ushort)USHORT_MAX && epoch<delegation->activation_epoch ) ) {
    return FD_STAKE_DELEGATION_STATE_UNKNOWN;
  }

  if( activation_status.activating>0UL   ) return FD_STAKE_DELEGATION_STATE_WARMING;
  if( activation_status.deactivating>0UL ) return FD_STAKE_DELEGATION_STATE_COOLING;
  if( activation_status.effective==delegation->stake && delegation->deactivation_epoch==(ushort)USHORT_MAX ) return FD_STAKE_DELEGATION_STATE_WARMED;

  /* When evaluated at >= activation_epoch, (0,0,0) implies a fully
     cooled delegation.  One might think that we could simply

     if( activation_status.effective==0UL ) return FD_STAKE_DELEGATION_STATE_COOLED;

     and life would be great.  In an unfortunate turn, Agave has a
     special branch that will assume stake has been fully activated if
     the activation epoch is not found in the stake history sysvar,
     regardless of whether the delegation fully warmed up or not when
     the simulation ran faithfully from the activation epoch.

     https://github.com/solana-program/stake/blob/interface%40v4.3.1/interface/src/state.rs#L969

     This means that a COOLED tag doesn't necessarily survive against
     future stake history sysvars.  As the stake history sysvar window
     advances and evicts older epochs, a delegation's activation epoch
     will eventually be evicted.  At that point an effective stake
     simulation would cooldown from the full delegated amount, which
     might be more than the effective stake simulated at tag time, if
     the delegation only partially warmed up at deactivation epoch.
     This can in theory lead to a nonzero effective stake at the target
     epoch, once the activation epoch is evicted, contradicting the
     COOLED tag.  Note that this is exceedingly hard to pull off as it
     requires that (1) the delegation only partially warmed up at
     deactivation, and (2) the delegation failed to fully cooldown from
     the full delegated amount over the potentially hundreds of epochs
     between deactivation epoch and target epoch.  AKA either warmup or
     cooldown congestion in the cluster over an extended period of time.
     The upshot is that we will only award the COOLED tag when the
     delegation is always COOLED independent of the history sysvar.
     This safe verdict loses by a few millis at the boundary, mostly in
     the refresh_vote_accounts() phase, compared to the naive but unsafe
     classify.

     https://github.com/solana-program/stake/blob/interface%40v4.3.1/interface/src/state.rs#L877
     https://github.com/solana-program/stake/blob/interface%40v4.3.1/interface/src/state.rs#L896

     Note that the same misfortune doesn't apply to the WARMED tag.  The
     sysvar query miss's "assume fully effective" bias means that a
     WARMED delegation stays warmed forever until it's instructed to
     deactivate. */
  if( epoch>(delegation->deactivation_epoch+FD_SYSVAR_STAKE_HISTORY_CAP) || delegation->activation_epoch==delegation->deactivation_epoch || delegation->stake==0UL ) return FD_STAKE_DELEGATION_STATE_COOLED;
  return FD_STAKE_DELEGATION_STATE_UNKNOWN;
}


ulong
fd_stake_delegations_align( void );

ulong
fd_stake_delegations_footprint( ulong max_records,
                                ulong max_live_slots,
                                ulong cache_bytes );

void *
fd_stake_delegations_new( void * mem,
                          int    disk_fd,
                          ulong  seed,
                          ulong  max_records,
                          ulong  max_live_slots,
                          ulong  cache_bytes );
fd_stake_delegations_t *
fd_stake_delegations_join( void * mem,
                           int    disk_fd );

void
fd_stake_delegations_reset( fd_stake_delegations_t * sd );

/* root_update is boot-only.  Attaching the first child ends boot.
   Fork updates accept allocated non-root forks without views.  Callers
   must stop updates to a fork before attaching children to it. */

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
                                  uchar                    warmup_cooldown_rate );

void
fd_stake_delegations_refresh( fd_stake_delegations_t *   stake_delegations,
                              ulong                      epoch,
                              fd_stake_history_t const * stake_history,
                              ulong *                    warmup_cooldown_rate_epoch,
                              int                        use_fixed_point_stake_math,
                              int                        remove_inactive_stakes,
                              fd_accdb_t *               accdb,
                              fd_accdb_fork_id_t         fork_id );

void
fd_stake_delegations_fork_update( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork_idx,
                                  fd_pubkey_t const *      stake_account,
                                  fd_pubkey_t const *      vote_account,
                                  ulong                    stake,
                                  ulong                    activation_epoch,
                                  ulong                    deactivation_epoch,
                                  ulong                    credits_observed,
                                  ulong                    lamports,
                                  uint                     acc_dlen,
                                  uchar                    warmup_cooldown_rate );

/* fd_stake_delegations_fork_remove inserts a tombstone stake delegation
   entry for the given fork.  The function will not actually remove or
   free any resources corresponding to the stake account.  The reason a
   tombstone is stored is because each fork corresponds to a set of
   stake delegation deltas for a given slot.  If an entry already exists
   for the stake account in this fork, it is overwritten in place. */

void
fd_stake_delegations_fork_remove( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork_idx,
                                  fd_pubkey_t const *      stake_account );

ushort
fd_stake_delegations_root_fork_id( fd_stake_delegations_t const * sd );

ushort
fd_stake_delegations_attach_child( fd_stake_delegations_t * sd,
                                   ushort                   parent );

/* Drain bank/scheduler users before cancellation or root advancement,
   and clear released IDs before reusing bank objects. */
void
fd_stake_delegations_cancel_fork( fd_stake_delegations_t * sd,
                                  ushort                   fork );

void
fd_stake_delegations_advance_root( fd_stake_delegations_t *             sd,
                                   ushort                               fork,
                                   ulong                                epoch,
                                   fd_stake_history_t const *           history,
                                   ulong *                              rate_epoch,
                                   int                                  fixed_point,
                                   int                                  prune_inactive,
                                   fd_bank_t const *                    emit_bank,
                                   fd_stake_delegations_delta_stats_t * stats );

fd_stake_delegations_view_t *
fd_stake_delegations_view_begin( fd_stake_delegations_view_t * view,
                                 fd_stake_delegations_t *      sd,
                                 ushort                        fork );

void
fd_stake_delegations_view_end( fd_stake_delegations_view_t * view );

void
fd_stake_delegations_view_totals( fd_stake_delegations_view_t * view,
                                  ulong                         epoch,
                                  fd_stake_history_t const *    history,
                                  ulong *                       rate_epoch,
                                  int                           fixed_point,
                                  fd_stake_history_entry_t *    totals );

/* Iterator records are copies valid until iter_next.  No cache lock is
   held across caller stake math or account-database operations. */
fd_stake_delegations_iter_t *
fd_stake_delegations_iter_init( fd_stake_delegations_iter_t * iter,
                                fd_stake_delegations_view_t * view );

void
fd_stake_delegations_iter_next( fd_stake_delegations_iter_t * iter );

static inline fd_stake_delegation_t const *
fd_stake_delegations_iter_ele( fd_stake_delegations_iter_t const * iter ) {
  return iter->batch + iter->batch_idx;
}

static inline ulong
fd_stake_delegations_iter_idx( fd_stake_delegations_iter_t * iter ) {
  return iter->idx;
}

static inline int
fd_stake_delegations_iter_done( fd_stake_delegations_iter_t * iter ) {
  return iter->batch_idx==iter->batch_cnt;
}

/* Exclusive maintenance operations must run outside views. */
void
fd_stake_delegations_invalidate_warmed( fd_stake_delegations_t * sd );

ulong
fd_stake_delegations_prune_inactive_root( fd_stake_delegations_t *   sd,
                                          ulong                      epoch,
                                          fd_stake_history_t const * history,
                                          ulong *                    rate_epoch,
                                          int                        fixed_point,
                                          fd_bank_t const *          emit_bank );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stake_delegations_h */
