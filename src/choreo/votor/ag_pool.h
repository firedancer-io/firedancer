#ifndef HEADER_fd_src_choreo_votor_ag_pool_h
#define HEADER_fd_src_choreo_votor_ag_pool_h

#include "ag_votor_base.h"
#include "ag_cert.h"
#include "ag_epoch_info.h"
#include "ag_event.h"
#include "ag_slot_state.h"
#include "ag_vote.h"

#define AG_POOL_SUCCESS                ( 0)
#define AG_POOL_ERR_SLOT_OUT_OF_BOUNDS (-1)
#define AG_POOL_ERR_DUPLICATE          (-2)
#define AG_POOL_ERR_SLASHABLE          (-3)
#define AG_POOL_ERR_CERT_VERIFY        (-4)

typedef struct ag_pool ag_pool_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
ag_pool_align( void );

FD_FN_CONST ulong
ag_pool_footprint( ulong slot_max );

void *
ag_pool_new( void * mem,
             ulong  slot_max,
             ulong  seed );

ag_pool_t *
ag_pool_join( void * mem );

void *
ag_pool_leave( ag_pool_t const * pool );

void *
ag_pool_delete( void * mem );

void
ag_pool_init( ag_pool_t * self,
              ulong       slot );

void
ag_pool_fini( ag_pool_t * self );

FD_FN_CONST char const *
ag_pool_strerror( int err );

void
ag_pool_advance_epoch( ag_pool_t *             self,
                       ag_epoch_info_t const * epoch_info,
                       ulong                   epoch_rank,
                       ulong                   epoch_slot );

/* ag_pool_set_ranks replaces our rank in the three epochs the pool
   tracks, for an identity switch, including the rank each live slot
   state was created with.  USHORT_MAX is unranked. */

void
ag_pool_set_ranks( ag_pool_t * self,
                   ulong       prev_epoch_rank,
                   ulong       curr_epoch_rank,
                   ulong       next_epoch_rank );

/* Definition 13. Pool::add_cert */

int
ag_pool_add_cert( ag_pool_t *       self,
                  ag_cert_t const * cert,
                  fd_bls_set_t *    bad );

/* Definition 12. Pool::add_vote */

int
ag_pool_add_vote( ag_pool_t *       self,
                  ag_vote_t const * vote,
                  fd_bls_set_t *    bad );

/* Definition 16. Pool::add_block */

int
ag_pool_add_block( ag_pool_t *           self,
                   ag_block_id_t const * block_id,
                   ag_block_id_t const * parent_id,
                   fd_bls_set_t *        bad );

/* PoolImpl::slot_state, read-only */

ag_slot_state_t const *
ag_pool_slot_state( ag_pool_t const * self,
                    ulong             slot );

/* Section 4.1. Pool::recover_from_standstill */

void
ag_pool_recover_from_standstill( ag_pool_t * self );

/* Definition 14. Pool::finalized_slot */

FD_FN_PURE ulong
ag_pool_finalized_slot( ag_pool_t const * self );

FD_FN_PURE uchar const *
ag_pool_finalized_block_hash( ag_pool_t const * self );

/* Definition 15. Pool::parents_ready */

ag_block_id_t const *
ag_pool_parents_ready( ag_pool_t * self,
                       ulong       slot,
                       ulong *     cnt );

/* Definition 15. Pool::wait_for_parent_ready; slot ULONG_MAX is the pending receiver */

ag_block_id_t
ag_pool_wait_for_parent_ready( ag_pool_t * self,
                               ulong       slot );

int
ag_pool_poll_pool_event( ag_pool_t *       self,
                         ag_event_pool_t * event );

int
ag_pool_poll_repair_event( ag_pool_t *         self,
                           ag_event_repair_t * event );

FD_PROTOTYPES_END

#endif
