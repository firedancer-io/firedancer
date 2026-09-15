#include "fd_requestor.h"
#include "../repair/fd_repair.h" /* FD_REPAIR_KIND_*, AG_REPAIR_KIND_* */

#define FD_REQUESTOR_MAGIC (0xf17eda2ce7000067UL) /* firedancer requestor v1 */

#define QUEUE_NAME requests
#define QUEUE_T    fd_event_request_t
#include "../../util/tmpl/fd_queue_dynamic.c"

struct fd_requestor {
  fd_event_request_t * requests;      /* queued for the tile, oldest first */

  int                  pending;       /* a check ran and its outcome is not yet reported */
  uint                 outcome;       /* FD_EVENT_REQUESTOR_* once pending */
  ulong                slot;          /* version of the pending check */
  fd_hash_t            block_id;

  int                  block_id_only;

  ulong                request_seq;
  ulong                outcome_seq;
  ulong                magic;
};

FD_FN_CONST ulong
fd_requestor_align( void ) {
  return 128UL;
}

FD_FN_CONST ulong
fd_requestor_footprint( ulong request_max ) {
  if( FD_UNLIKELY( !request_max || !requests_footprint( request_max ) ) ) return 0UL;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_requestor_t), sizeof(fd_requestor_t)            );
  l = FD_LAYOUT_APPEND( l, requests_align(),        requests_footprint( request_max ) );
  return FD_LAYOUT_FINI( l, fd_requestor_align() );
}

void *
fd_requestor_new( void * mem,
                  ulong  request_max ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_requestor_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  ulong footprint = fd_requestor_footprint( request_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad request_max %lu", request_max ));
    return NULL;
  }

  fd_memset( mem, 0, footprint );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_requestor_t * self     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_requestor_t), sizeof(fd_requestor_t)            );
  void *           requests = FD_SCRATCH_ALLOC_APPEND( l, requests_align(),        requests_footprint( request_max ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_requestor_align() )==(ulong)mem+footprint );

  self->requests = requests_join( requests_new( requests, request_max ) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( self->magic ) = FD_REQUESTOR_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_requestor_t *
fd_requestor_join( void * mem ) {
  fd_requestor_t * self = (fd_requestor_t *)mem;
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( self->magic!=FD_REQUESTOR_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return self;
}

void *
fd_requestor_leave( fd_requestor_t const * self ) {
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL requestor" ));
    return NULL;
  }
  return (void *)self;
}

void *
fd_requestor_delete( void * mem ) {
  fd_requestor_t * self = (fd_requestor_t *)mem;
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( self->magic!=FD_REQUESTOR_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  FD_COMPILER_MFENCE();
  FD_VOLATILE( self->magic ) = 0UL;
  FD_COMPILER_MFENCE();
  return mem;
}

void
fd_requestor_set_block_id_only( fd_requestor_t * self,
                                int              block_id_only ) {
  self->block_id_only = !!block_id_only;
}

ulong
fd_requestor_queued_cnt( fd_requestor_t const * self ) {
  return requests_cnt( self->requests );
}

/* Version reads */

/* version_query returns the live, repairable slotv for {slot,
   block_id}, or NULL if it is gone, rooted or abandoned. */

static fd_chainer_slotv_t const *
version_query( fd_chainer_t *    chainer,
               ulong             slot,
               fd_hash_t const * block_id ) {
  if( FD_UNLIKELY( slot<=chainer->root ) ) return NULL;
  fd_chainer_slotv_t const * slotv = fd_chainer_slot_version_query( chainer, slot, block_id );
  if( FD_UNLIKELY( !slotv || slotv->abandoned ) ) return NULL;
  return slotv;
}

static inline int
parent_present( fd_chainer_t *             chainer,
                fd_chainer_slotv_t const * slotv ) {
  return slotv->parent_slot<=chainer->root || !!fd_chainer_slot_version_query( chainer, slotv->parent_slot, &slotv->parent_block_id );
}

/* Queueing */

/* push queues one request for the pending version.  block_id and
   fec_root may be NULL for all-zero.  The queue is sized so a single
   check cannot overflow it. */

static void
push( fd_requestor_t *  self,
      long              now,
      uint              kind,
      uint              idx,
      fd_hash_t const * block_id,
      fd_hash_t const * fec_root ) {
  if( FD_UNLIKELY( requests_full( self->requests ) ) ) FD_LOG_CRIT(( "requestor queue full (%lu): a check queued more than one request per shred", requests_max( self->requests ) ));
  fd_event_request_t req = { .seq = self->request_seq++, .ts = now, .kind = kind, .slot = self->slot, .idx = idx };
  if( block_id ) req.block_id = *block_id;
  if( fec_root ) req.fec_root = *fec_root;
  requests_push( self->requests, req );
}

/* queue_metadata queues the single metadata request the version needs
   and returns 1, or returns 0 if its metadata is settled. */

static int
queue_metadata( fd_requestor_t *           self,
                fd_chainer_t *             chainer,
                fd_chainer_slotv_t const * slotv,
                long                       now ) {
  int verified = !fd_hash_check_zero( &slotv->block_id );

  if( slotv->parent_slot==AG_UNKNOWN_SLOT ) {
    if( verified )             { push( self, now, AG_REPAIR_KIND_PARENT_FEC_COUNT, 0U, &slotv->block_id, NULL ); return 1; }
    if( !self->block_id_only ) { push( self, now, FD_REPAIR_KIND_SHRED,            0U, NULL,             NULL ); return 1; }
  } else if( !parent_present( chainer, slotv ) ) {
    if( !self->block_id_only ) { push( self, now, FD_REPAIR_KIND_ORPHAN,           0U, NULL,             NULL ); return 1; }
  }

  if( slotv->complete_idx==UINT_MAX ) {
    if( verified )             { push( self, now, AG_REPAIR_KIND_PARENT_FEC_COUNT, 0U, &slotv->block_id, NULL ); return 1; }
    if( !self->block_id_only ) { push( self, now, FD_REPAIR_KIND_HIGHEST_SHRED,    0U, NULL,             NULL ); return 1; }
  }
  return 0;
}

/* queue_fill queues a request for every missing shred past the
   buffered prefix (one FecSetRoot per set with no entry) and returns
   how many it queued. */

static ulong
queue_fill( fd_requestor_t *           self,
            fd_chainer_t *             chainer,
            fd_chainer_slotv_t const * slotv,
            long                       now ) {
  if( FD_UNLIKELY( slotv->complete_idx==UINT_MAX ) ) return 0UL; /* metadata rung would have fired */
  int   verified  = !fd_hash_check_zero( &slotv->block_id );
  uint  shred_max = (uint)( chainer->fec_blk_max*FD_FEC_SHRED_CNT );
  uint  idx       = ( slotv->buffered_idx==UINT_MAX ) ? 0U : slotv->buffered_idx + 1U; /* skip the buffered prefix */
  ulong cnt       = 0UL;

  while( idx<=slotv->complete_idx && idx<shred_max ) {
    if( fd_chainer_shred_test( chainer, slotv, idx ) ) { idx++; continue; }
    uint fec_set_idx = idx & ~( (uint)FD_FEC_SHRED_CNT - 1U );

    if( verified ) {
      fd_chainer_fec_t const * fec = fd_chainer_fec_query( chainer, slotv->slot, fec_set_idx, &slotv->block_id );
      if( FD_UNLIKELY( !fec ) ) {
        /* No entry at this set: ask for its root and move to the next
           set.  Its shreds are requested once the sentinel lands and
           the version is checked again. */
        push( self, now, AG_REPAIR_KIND_FEC_ROOT, fec_set_idx, &slotv->block_id, NULL );
        cnt++;
        idx = fec_set_idx + (uint)FD_FEC_SHRED_CNT;
        continue;
      }
      push( self, now, AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID, idx, &slotv->block_id, &fec->merkle_root );
      cnt++;
    } else if( !self->block_id_only ) {
      push( self, now, FD_REPAIR_KIND_SHRED, idx, NULL, NULL );
      cnt++;
    }
    idx++;
  }
  return cnt;
}

/* Event handlers */

void
fd_requestor_handle_schedulor_event( fd_requestor_t *             self,
                                     fd_chainer_t *               chainer,
                                     fd_event_schedulor_t const * event,
                                     long                         now ) {
  if( FD_UNLIKELY( event->kind!=FD_EVENT_SCHEDULER_CHECK_SLOT ) ) FD_LOG_CRIT(( "bad schedulor event kind %u", event->kind ));
  if( FD_UNLIKELY( self->pending ) ) FD_LOG_CRIT(( "requestor handed slot %lu while working slot %lu", event->slot, self->slot ));

  self->pending  = 1;
  self->slot     = event->slot;
  self->block_id = event->block_id;

  fd_chainer_slotv_t const * slotv = version_query( chainer, self->slot, &self->block_id );
  if( FD_UNLIKELY( !slotv ) )                        { self->outcome = FD_EVENT_REQUESTOR_DONE;             return; }
  if( queue_metadata( self, chainer, slotv, now ) )  { self->outcome = FD_EVENT_REQUESTOR_REQUESTED_PARENT; return; }
  ulong cnt = queue_fill( self, chainer, slotv, now );
  self->outcome = cnt ? FD_EVENT_REQUESTOR_REQUESTED : FD_EVENT_REQUESTOR_DONE;
}

void
fd_requestor_handle_chainer_event( fd_requestor_t *           self,
                                   fd_event_chainer_t const * event ) {
  if( FD_LIKELY( event->kind!=FD_EVENT_CHAINER_SLOT_RETIRED ) ) return;
  if( FD_LIKELY( !self->pending ) )                             return;
  if( FD_LIKELY( event->slot!=self->slot || !fd_hash_eq( &event->block_id, &self->block_id ) ) ) return;
  requests_remove_all( self->requests );
  self->outcome = FD_EVENT_REQUESTOR_DONE;
}

int
fd_requestor_stale( fd_chainer_t *             chainer,
                    fd_event_request_t const * request ) {
  ulong             slot     = request->slot;
  fd_hash_t const * block_id = &request->block_id; /* all-zero for positional kinds: the turbine version */
  uint              idx      = request->idx;

  fd_chainer_slotv_t const * slotv = version_query( chainer, slot, block_id );
  if( FD_UNLIKELY( !slotv ) ) return 1; /* version gone, rooted or abandoned */

  switch( request->kind ) {
  case FD_REPAIR_KIND_SHRED:
  case AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID: return fd_chainer_shred_test( chainer, slotv, idx );
  case FD_REPAIR_KIND_HIGHEST_SHRED:      return slotv->complete_idx!=UINT_MAX;
  case FD_REPAIR_KIND_ORPHAN:             return slotv->parent_slot==AG_UNKNOWN_SLOT || parent_present( chainer, slotv );
  case AG_REPAIR_KIND_PARENT_FEC_COUNT:   return slotv->parent_slot!=AG_UNKNOWN_SLOT && slotv->complete_idx!=UINT_MAX;
  case AG_REPAIR_KIND_FEC_ROOT:           return !!fd_chainer_fec_query( chainer, slot, idx, block_id );
  default: FD_LOG_CRIT(( "bad request kind %u", request->kind ));
  }
}

int
fd_requestor_poll_request_event( fd_requestor_t *     self,
                                 fd_chainer_t *       chainer,
                                 long                 now,
                                 fd_event_request_t * event ) {
  while( FD_LIKELY( !requests_empty( self->requests ) ) ) {
    fd_event_request_t req = requests_pop( self->requests );
    if( FD_UNLIKELY( fd_requestor_stale( chainer, &req ) ) ) continue; /* arrived while queued */
    *event    = req;
    event->ts = now;
    return 1;
  }
  return 0;
}

int
fd_requestor_poll_requestor_event( fd_requestor_t *       self,
                                   long                   now,
                                   fd_event_requestor_t * event ) {
  if( FD_LIKELY( !self->pending || !requests_empty( self->requests ) ) ) return 0; /* outcome waits for the last request to leave */
  event->seq      = self->outcome_seq++;
  event->ts       = now;
  event->kind     = self->outcome;
  event->slot     = self->slot;
  event->block_id = self->block_id;
  self->pending   = 0;
  return 1;
}
