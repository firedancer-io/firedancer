#ifndef HEADER_fd_src_choreo_votor_ag_pool_h
#define HEADER_fd_src_choreo_votor_ag_pool_h

#include "ag_votor_base.h"
#include "ag_vote.h"
#include "ag_cert.h"
#include "ag_epoch_info.h"
#include "ag_parent_ready_tracker.h" /* ag_parent_ready_t */

#define AG_POOL_EVENT_PARENT_READY  (0)
#define AG_POOL_EVENT_SAFE_TO_NOTAR (1)
#define AG_POOL_EVENT_SAFE_TO_SKIP  (2)
#define AG_POOL_EVENT_CERT_CREATED  (3)
#define AG_POOL_EVENT_STANDSTILL    (4)

struct ag_standstill {
  ulong       slot;
  ag_cert_t * certs;
  ulong       cert_cnt;
  ag_vote_t * votes;
  ulong       vote_cnt;
};
typedef struct ag_standstill ag_standstill_t;

struct ag_pool_event {
  int kind;
  union {
    ag_parent_ready_t parent_ready;
    ag_block_id_t     safe_to_notar;
    ulong             safe_to_skip;
    ag_cert_t         cert_created;
    ag_standstill_t   standstill;
  } inner;
};
typedef struct ag_pool_event ag_pool_event_t;

#define AG_POOL_SUCCESS                ( 0)
#define AG_POOL_ERR_SLOT_OUT_OF_BOUNDS (-1)
#define AG_POOL_ERR_DUPLICATE          (-2)
#define AG_POOL_ERR_SLASHABLE          (-3)

#define AG_POOL_ERR_HASH_CAPACITY      (-4)

typedef struct ag_pool ag_pool_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST char const *
ag_pool_strerror( int err );

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
ag_pool_advance_epoch( ag_pool_t *             self,
                       ag_epoch_info_t const * epoch_info,
                       ulong                   epoch_rank,
                       ulong                   epoch_slot );

int
ag_pool_add_cert( ag_pool_t *       self,
                  ag_cert_t const * cert );

int
ag_pool_add_vote( ag_pool_t *       self,
                  ag_vote_t const * vote );

void
ag_pool_add_block( ag_pool_t *           self,
                   ag_block_id_t const * block_id,
                   ag_block_id_t const * parent_id );

void
ag_pool_recover_from_standstill( ag_pool_t * self );

FD_FN_PURE ulong
ag_pool_finalized_slot( ag_pool_t const * self );

ag_block_id_t const *
ag_pool_parents_ready( ag_pool_t * self,
                       ulong       slot,
                       ulong *     cnt );

ag_block_id_t
ag_pool_wait_for_parent_ready( ag_pool_t * self,
                               ulong       slot );

FD_PROTOTYPES_END

#endif
