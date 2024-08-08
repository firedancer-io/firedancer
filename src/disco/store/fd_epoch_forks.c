#include "fd_epoch_forks.h"
#include "../../flamenco/runtime/context/fd_exec_epoch_ctx.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"

#define VOTE_ACC_MAX   (2000000UL)

static void
dump( fd_epoch_forks_t * epoch_forks ) {
    for( ulong i = 0UL; i<MAX_EPOCH_FORKS; i++ ) {
        fd_epoch_fork_elem_t * elem = &epoch_forks->forks[ i ];
        FD_LOG_WARNING(("fork elem %lu %lu %lu", elem->parent_slot, elem->epoch, (ulong)elem->epoch_ctx));
    }
}

void
fd_epoch_forks_new( fd_epoch_forks_t * epoch_forks, void * epoch_ctx_base ) {
    for( ulong i=0UL; i<MAX_EPOCH_FORKS; i++ ) {
      fd_epoch_fork_elem_t * epoch_fork = &epoch_forks->forks[i];
      epoch_fork->parent_slot = ULONG_MAX;
      epoch_fork->epoch       = ULONG_MAX;
      epoch_fork->epoch_ctx   = NULL;
    }

    epoch_forks->epoch_ctx_base = (uchar *) epoch_ctx_base;
    epoch_forks->curr_epoch_idx = ULONG_MAX;
}

void
fd_epoch_forks_publish( fd_epoch_forks_t * epoch_forks, fd_ghost_t * ghost, ulong root ) {
  ulong idx = fd_epoch_forks_get_epoch_ctx( epoch_forks, ghost, root, NULL );

  if( FD_LIKELY( idx == epoch_forks->curr_epoch_idx ) ) return;

  for( ulong i=0UL; i<MAX_EPOCH_FORKS; i++ ) {
    if( FD_LIKELY( i != idx && epoch_forks->forks[ i ].parent_slot != ULONG_MAX ) ) {
      epoch_forks->forks[ i ].parent_slot = ULONG_MAX;
      epoch_forks->forks[ i ].epoch       = ULONG_MAX;
      fd_exec_epoch_ctx_delete( fd_exec_epoch_ctx_leave( epoch_forks->forks[ i ].epoch_ctx ) );
      epoch_forks->forks[ i ].epoch_ctx = NULL;
    }
  }

  epoch_forks->curr_epoch_idx = idx;
}

uint
fd_epoch_forks_prepare( fd_epoch_forks_t * epoch_forks, ulong parent_slot, ulong new_epoch, fd_epoch_fork_elem_t ** out_fork ) {
  ulong empty = ULONG_MAX;
  ulong i = 0UL;

  for( ; i<MAX_EPOCH_FORKS; i++ ) {
    if( epoch_forks->forks[ i ].parent_slot == ULONG_MAX ) {
      empty = (empty == ULONG_MAX) ? i : empty;
      continue;
    }
    if( epoch_forks->forks[ i ].epoch == new_epoch && epoch_forks->forks[ i ].parent_slot == parent_slot ) {
      *out_fork = &epoch_forks->forks[ i ];
      return 1;
    }
  }

  if( FD_LIKELY( empty != ULONG_MAX ) ) {
    epoch_forks->forks[ empty ].parent_slot = parent_slot;
    epoch_forks->forks[ empty ].epoch = new_epoch;

    uchar * epoch_ctx_mem = epoch_forks->epoch_ctx_base + (empty * fd_ulong_align_up( fd_exec_epoch_ctx_footprint( VOTE_ACC_MAX ), fd_exec_epoch_ctx_align() ) );
    epoch_forks->forks[ empty ].epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, VOTE_ACC_MAX ) );
    *out_fork = &epoch_forks->forks[ empty ];
  } else {
    dump( epoch_forks );
    FD_LOG_CRIT(("Too many forks for epoch boundary."));
  }

  return 0;
}

ulong
fd_epoch_forks_get_epoch_ctx( fd_epoch_forks_t * epoch_forks, fd_ghost_t * ghost, ulong curr_slot, ulong * opt_prev_slot ) {
  fd_exec_epoch_ctx_t * epoch_ctx = epoch_forks->forks[ epoch_forks->curr_epoch_idx ].epoch_ctx;
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( epoch_ctx );
  ulong epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, curr_slot, NULL );
  if( FD_LIKELY( epoch == epoch_forks->forks[ epoch_forks->curr_epoch_idx ].epoch ) ) return epoch_forks->curr_epoch_idx;

  ulong max_parent_root = 0UL;
  ulong max_idx = ULONG_MAX;
  for( ulong i=0; i<MAX_EPOCH_FORKS; i++ ) {
    fd_epoch_fork_elem_t * elem = &epoch_forks->forks[ i ];
    if( elem->parent_slot == ULONG_MAX ) continue;

    /* check if this fork has a parent in the entries list, and isn't the parent itself. */
    ulong slot = (opt_prev_slot == NULL) ? curr_slot : *opt_prev_slot;
    if( elem->parent_slot != slot && elem->parent_slot >= ghost->root->slot && fd_ghost_is_descendant( ghost, slot, elem->parent_slot ) ) {
      if( elem->parent_slot > max_parent_root ) {
        max_parent_root = elem->parent_slot;
        max_idx = i;
      }
    }
  }

  return (max_idx != ULONG_MAX) ? max_idx : epoch_forks->curr_epoch_idx;
}
