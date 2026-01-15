#include "fd_accdb_impl_v2.h"
#include "fd_accdb_sync.h"
#include "fd_accdb_batch.h"
#include "fd_vinyl_req_pool.h"

FD_STATIC_ASSERT( alignof(fd_accdb_user_v2_t)<=alignof(fd_accdb_user_t), layout );
FD_STATIC_ASSERT( sizeof (fd_accdb_user_v2_t)<=sizeof(fd_accdb_user_t),  layout );

static inline void
fd_accdb_load_fork( fd_accdb_user_v1_t *      accdb,
                    fd_funk_txn_xid_t const * xid ) {
  /* Skip if already on the correct fork */
  if( FD_LIKELY( (!!accdb->fork_depth) & (!!fd_funk_txn_xid_eq( &accdb->fork[ 0 ], xid ) ) ) ) return;
  if( FD_UNLIKELY( accdb->base.rw_active ) ) {
    FD_LOG_CRIT(( "Invariant violation: all active account references of an accdb_user must be accessed through the same XID (active XID %lu:%lu, requested XID %lu:%lu)",
                  accdb->fork[0].ul[0], accdb->fork[0].ul[1],
                  xid          ->ul[0], xid          ->ul[1] ));
  }
  fd_accdb_load_fork_slow( accdb, xid ); /* switch fork */
}

void
fd_accdb_user_v2_fini( fd_accdb_user_t * accdb ) {
  fd_accdb_user_v2_t * user = (fd_accdb_user_v2_t *)accdb;

  fd_vinyl_rq_leave( user->vinyl_rq );

  /* superclass destructor */
  user->base.accdb_type = FD_ACCDB_TYPE_V1;
  fd_accdb_user_v1_fini( accdb );
}

fd_accdb_peek_t *
fd_accdb_user_v2_peek( fd_accdb_user_t *         accdb,
                       fd_accdb_peek_t *         peek,
                       fd_funk_txn_xid_t const * xid,
                       void const *              address ) {
  /* FIXME this should query vinyl cache too (via vinyl_meta/vinyl_data) */
  return fd_accdb_user_v1_peek( accdb, peek, xid, address );
}

static void
fd_accdb_user_v2_close_ro( fd_accdb_user_t * accdb_,
                           fd_accdb_ro_t *   ro );

fd_accdb_ro_t *
fd_accdb_user_v2_open_ro( fd_accdb_user_t *         accdb_,
                          fd_accdb_ro_t *           ro,
                          fd_funk_txn_xid_t const * xid,
                          void const *              address ) {
  fd_accdb_user_v2_t * accdb = (fd_accdb_user_v2_t *)accdb_;
  fd_accdb_load_fork( &accdb->v1, xid );

  /* Check whether value is present in funk overlay */

  fd_accdb_peek_t peek[1];
  if( fd_accdb_peek_funk( &accdb->v1, peek, xid, address ) ) {
    if( FD_UNLIKELY( !peek->acc->meta->lamports ) ) return NULL;
    accdb->base.ro_active++;
    *ro = *peek->acc;
    return ro;
  }

  /* Nothing found in funk, query vinyl */
  /* FIXME potential here to do a pre-flight check against vinyl_meta to
     reduce the amount of requests we're sending to vinyl */

  /* Send an ACQUIRE request */

  ulong             batch_idx     = fd_vinyl_req_pool_acquire   ( accdb->vinyl_req_pool );
  fd_vinyl_key_t *  req_key       = fd_vinyl_req_batch_key      ( accdb->vinyl_req_pool, batch_idx );
  ulong *           req_val_gaddr = fd_vinyl_req_batch_val_gaddr( accdb->vinyl_req_pool, batch_idx );
  schar *           req_err       = fd_vinyl_req_batch_err      ( accdb->vinyl_req_pool, batch_idx );
  fd_vinyl_comp_t * comp          = fd_vinyl_req_batch_comp     ( accdb->vinyl_req_pool, batch_idx );
  fd_vinyl_key_init( req_key, address, 32UL );
  memset( comp, 0, sizeof(fd_vinyl_comp_t) );
  fd_vinyl_req_send_batch(
      accdb->vinyl_rq,
      accdb->vinyl_req_pool,
      accdb->vinyl_req_wksp,
      accdb->vinyl_req_id++,
      accdb->vinyl_link_id,
      FD_VINYL_REQ_TYPE_ACQUIRE,
      0UL, /* flags */
      batch_idx,
      1UL, /* batch_cnt */
      0UL  /* val_max */
  );

  /* Poll for completion */

  while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
  FD_COMPILER_MFENCE();
  int comp_err = FD_VOLATILE_CONST( comp->err );
  if( FD_UNLIKELY( comp_err!=FD_VINYL_SUCCESS ) ) {
    FD_LOG_CRIT(( "vinyl tile rejected my ACQUIRE request: %i-%s", comp_err, fd_vinyl_strerror( comp_err ) ));
  }
  int err = FD_VOLATILE_CONST( req_err[0] );
  if( err==FD_VINYL_ERR_KEY ) {  /* not found */
    fd_vinyl_req_pool_release( accdb->vinyl_req_pool, batch_idx );
    return NULL;
  }
  if( FD_UNLIKELY( err!=FD_VINYL_SUCCESS ) ) {
    FD_LOG_CRIT(( "vinyl tile ACQUIRE request failed: %i-%s", err, fd_vinyl_strerror( err ) ));
  }

  /* Return result */

  ulong                     val_gaddr = FD_VOLATILE_CONST( req_val_gaddr[0] );
  fd_account_meta_t const * meta      = fd_wksp_laddr_fast( accdb->vinyl_data_wksp, val_gaddr );
  fd_vinyl_req_pool_release( accdb->vinyl_req_pool, batch_idx );

  accdb->base.ro_active++;
  *ro = (fd_accdb_ro_t) {0};
  memcpy( ro->ref->address, address, 32UL );
  ro->ref->accdb_type = FD_ACCDB_TYPE_V2;
  ro->ref->ref_type   = FD_ACCDB_REF_RO;
  ro->meta            = meta;

  /* Hide tombstones */

  if( FD_UNLIKELY( !meta->lamports ) ) {
    fd_accdb_user_v2_close_ro( accdb_, ro );
    return NULL;
  }

  return ro;
}

static void
fd_accdb_user_v2_close_ro( fd_accdb_user_t * accdb_,
                           fd_accdb_ro_t *   ro ) {
  fd_accdb_user_v2_t * accdb = (fd_accdb_user_v2_t *)accdb_;

  if( ro->ref->accdb_type==FD_ACCDB_TYPE_V1 ) {
    accdb->base.ro_active--;
    return;
  }

  /* Send a RELEASE request */

  ulong             batch_idx     = fd_vinyl_req_pool_acquire   ( accdb->vinyl_req_pool );
  ulong *           req_val_gaddr = fd_vinyl_req_batch_val_gaddr( accdb->vinyl_req_pool, batch_idx );
  schar *           req_err       = fd_vinyl_req_batch_err      ( accdb->vinyl_req_pool, batch_idx );
  fd_vinyl_comp_t * comp          = fd_vinyl_req_batch_comp     ( accdb->vinyl_req_pool, batch_idx );
  req_val_gaddr[0] = fd_wksp_gaddr_fast( accdb->vinyl_data_wksp, (void *)ro->meta );
  memset( comp, 0, sizeof(fd_vinyl_comp_t) );
  fd_vinyl_req_send_batch(
      accdb->vinyl_rq,
      accdb->vinyl_req_pool,
      accdb->vinyl_req_wksp,
      accdb->vinyl_req_id++,
      accdb->vinyl_link_id,
      FD_VINYL_REQ_TYPE_RELEASE,
      0UL, /* flags */
      batch_idx,
      1UL, /* batch_cnt */
      0UL  /* val_max */
  );

  /* Poll for completion */

  while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
  FD_COMPILER_MFENCE();
  int comp_err = FD_VOLATILE_CONST( comp->err );
  if( FD_UNLIKELY( comp_err!=FD_VINYL_SUCCESS ) ) {
    FD_LOG_CRIT(( "vinyl tile rejected my RELEASE request: %i-%s", comp_err, fd_vinyl_strerror( comp_err ) ));
  }
  int err = FD_VOLATILE_CONST( req_err[0] );
  if( FD_UNLIKELY( err!=FD_VINYL_SUCCESS ) ) {
    FD_LOG_CRIT(( "vinyl tile RELEASE request failed: %i-%s", err, fd_vinyl_strerror( err ) ));
  }
  fd_vinyl_req_pool_release( accdb->vinyl_req_pool, batch_idx );

  accdb->base.ro_active--;
}

fd_accdb_rw_t *
fd_accdb_user_v2_open_rw( fd_accdb_user_t *         accdb,
                          fd_accdb_rw_t *           rw,
                          fd_funk_txn_xid_t const * xid,
                          void const *              address,
                          ulong                     data_max,
                          int                       flags ) {
  fd_accdb_user_v2_t * v2 = (fd_accdb_user_v2_t *)accdb;
  fd_accdb_user_v1_t * v1 = &v2->v1;

  int const flag_truncate = !!( flags & FD_ACCDB_FLAG_TRUNCATE );
  if( FD_UNLIKELY( flags & ~(FD_ACCDB_FLAG_CREATE|FD_ACCDB_FLAG_TRUNCATE) ) ) {
    FD_LOG_CRIT(( "invalid flags for open_rw: %#02x", (uint)flags ));
  }

  /* If this account exists in funk, modify it there */

  fd_accdb_rw_t * rw_funk =
      fd_accdb_user_v1_open_rw( accdb, rw, xid, address, data_max, (flags & ~FD_ACCDB_FLAG_CREATE) );
  if( rw_funk ) return rw_funk;

  /* Otherwise, query it from vinyl */

  fd_accdb_ro_t ro_vinyl[1];
  if( !fd_accdb_user_v2_open_ro( accdb, ro_vinyl, xid, address ) ) {
    /* Account truly does not exist */
    return fd_accdb_user_v1_open_rw( accdb, rw, xid, address, data_max, flags );
  }

  /* Account exists, copy it to funk */

  ulong  acc_orig_sz = fd_accdb_ref_data_sz( ro_vinyl );
  ulong  val_sz_min  = sizeof(fd_account_meta_t)+fd_ulong_max( data_max, acc_orig_sz );
  ulong  acc_sz      = flag_truncate ? 0UL : acc_orig_sz;
  ulong  val_sz      = sizeof(fd_account_meta_t)+acc_sz;
  ulong  val_max     = 0UL;
  void * val         = fd_alloc_malloc_at_least( v1->funk->alloc, 16UL, val_sz_min, &val_max );
  if( FD_UNLIKELY( !val ) ) {
    FD_LOG_CRIT(( "Failed to modify account: out of memory allocating %lu bytes", acc_orig_sz ));
  }

  fd_account_meta_t * meta            = val;
  uchar *             data            = (uchar *)( meta+1 );
  ulong               data_max_actual = val_max - sizeof(fd_account_meta_t);
  if( flag_truncate ) fd_accdb_v1_copy_truncated( meta,       ro_vinyl );
  else                fd_accdb_v1_copy_account  ( meta, data, ro_vinyl );
  if( acc_orig_sz<data_max_actual ) {
    /* Zero out trailing data */
    uchar * tail    = data           +acc_orig_sz;
    ulong   tail_sz = data_max_actual-acc_orig_sz;
    fd_memset( tail, 0, tail_sz );
  }
  fd_accdb_user_v2_close_ro( accdb, ro_vinyl );

  fd_accdb_rw_t * res = fd_accdb_v1_prep_create( rw, v1, xid, address, val, val_sz, val_max );
  return res;
}

void
fd_accdb_user_v2_close_ref( fd_accdb_user_t * accdb,
                            fd_accdb_ref_t *  ref ) {
  switch( ref->ref_type ) {
  case FD_ACCDB_REF_RO:
    fd_accdb_user_v2_close_ro( accdb, (fd_accdb_ro_t *)ref );
    break;
  case FD_ACCDB_REF_RW:
    fd_accdb_user_v1_close_rw( accdb, (fd_accdb_rw_t *)ref );
    break;
  default:
    FD_LOG_CRIT(( "invalid ref_type %u in fd_accdb_user_v2_close_ref", (uint)ref->ref_type ));
  }
}

/* ro_pipe state machine

   BATCH: generating request batch
   WAIT:  ACQUIRE batch sent, waiting for completion
   DRAIN: waiting for user to poll responses
   FUNK:  waiting for user to complete funk synchronous read

   On creation, ro_pipe is in BATCH state.
   BATCH->WAIT transitioned when flush is requested or when batch full
   WAIT->DRAIN transitioned when ACQUIRE completion received
   BATCH->FUNK transitioned when a funk sync read overruled vinyl
   FUNK->BATCH transitioned when user completes a funk sync read
   DRAIN->BATCH transitioned when user processed all completions (does
                a blocking RELEASE request) */

struct fd_accdb_v2_ro_pipe {
  fd_accdb_user_v2_t *  accdb;
  fd_vinyl_req_pool_t * pool;
  fd_accdb_ro_t         ro[1];
  fd_funk_txn_xid_t     xid;

  ulong batch_idx;  /* index of req batch */
  uint  req_cnt;    /* batch element count */
  uint  req_comp;   /* index of next completion */
  uint  quota_used; /* number of keys ACQUIRED */
  uint  state;
};

typedef struct fd_accdb_v2_ro_pipe fd_accdb_v2_ro_pipe_t;

FD_STATIC_ASSERT( alignof(fd_accdb_v2_ro_pipe_t)<=alignof(fd_accdb_ro_pipe_t), layout );
FD_STATIC_ASSERT( sizeof(fd_accdb_v2_ro_pipe_t) <=sizeof(fd_accdb_ro_pipe_t),  layout );

#define RO_PIPE_STATE_BATCH 0
#define RO_PIPE_STATE_WAIT  1
#define RO_PIPE_STATE_DRAIN 2
#define RO_PIPE_STATE_FUNK  3

static fd_account_meta_t const fd_account_meta_zero = {0};

fd_accdb_ro_pipe_t *
fd_accdb_user_v2_ro_pipe_init( fd_accdb_ro_pipe_t *      pipe_,
                               fd_accdb_user_t *         accdb_,
                               fd_funk_txn_xid_t const * xid ) {
  fd_accdb_user_v2_t *    accdb = (fd_accdb_user_v2_t *)accdb_;
  fd_accdb_v2_ro_pipe_t * pipe  = (fd_accdb_v2_ro_pipe_t *)pipe_;
  if( FD_UNLIKELY( !accdb ) ) FD_LOG_CRIT(( "NULL accdb" ));
  if( FD_UNLIKELY( accdb->base.accdb_type!=FD_ACCDB_TYPE_V2 ) ) {
    FD_LOG_CRIT(( "invalid accdb type" ));
  }

  fd_vinyl_req_pool_t * req_pool  = accdb->vinyl_req_pool;
  ulong                 batch_idx = fd_vinyl_req_pool_acquire( req_pool );

  *pipe = (fd_accdb_v2_ro_pipe_t) {
    .accdb     = accdb,
    .pool      = req_pool,
    .xid       = *xid,
    .batch_idx = batch_idx,
    .req_cnt   = 0U,
    .req_comp  = 0U,
    .state     = RO_PIPE_STATE_BATCH
  };
  return pipe_;
}

void
fd_accdb_user_v2_ro_pipe_flush( fd_accdb_ro_pipe_t * pipe_ ) {
  fd_accdb_v2_ro_pipe_t * pipe = (fd_accdb_v2_ro_pipe_t *)pipe_;
  if( FD_UNLIKELY( pipe->state != RO_PIPE_STATE_BATCH || !pipe->req_cnt ) ) return;

  fd_vinyl_req_pool_t * req_pool      = pipe->pool;
  fd_accdb_user_v2_t *  accdb         = pipe->accdb;
  fd_vinyl_rq_t *       rq            = accdb->vinyl_rq;
  fd_wksp_t *           req_pool_wksp = accdb->vinyl_req_wksp;

  int   req_type  = FD_VINYL_REQ_TYPE_ACQUIRE;
  ulong req_id    = accdb->vinyl_req_id++;
  ulong link_id   = accdb->vinyl_link_id;
  ulong batch_idx = pipe->batch_idx;
  ulong req_cnt   = pipe->req_cnt;

  memset( fd_vinyl_req_batch_comp( req_pool, batch_idx ), 0, sizeof(fd_vinyl_comp_t) );
  fd_vinyl_req_send_batch( rq, req_pool, req_pool_wksp, req_id, link_id, req_type, 0UL, batch_idx, req_cnt, 0UL );

  pipe->state    = RO_PIPE_STATE_WAIT;
  pipe->req_comp = 0U;
}

void
fd_accdb_user_v2_ro_pipe_enqueue( fd_accdb_ro_pipe_t * pipe_,
                                  void const *         address ) {
  fd_accdb_v2_ro_pipe_t * pipe     = (fd_accdb_v2_ro_pipe_t *)pipe_;
  fd_accdb_user_v2_t *    accdb    = pipe->accdb;
  fd_vinyl_req_pool_t *   req_pool = pipe->pool;
  fd_accdb_ro_t *         ro       = pipe->ro;

  if( FD_UNLIKELY( pipe->state != RO_PIPE_STATE_BATCH ||
                   ro->ref->accdb_type != 0 ) ) {
    FD_LOG_CRIT(( "ro_pipe_enqueue failed: not ready for new requests (poll() required before next request)" ));
  }

  /* Synchronously query funk overlay */

  fd_accdb_load_fork( &accdb->v1, &pipe->xid );
  fd_accdb_peek_t peek[1];
  if( fd_accdb_peek_funk( &accdb->v1, peek, &pipe->xid, address ) ) {
    if( !peek->acc->meta->lamports ) { /* tombstone */
      ro->ref->accdb_type = FD_ACCDB_TYPE_NONE;
      ro->ref->ref_type   = FD_ACCDB_REF_RO;
      memcpy( ro->ref->address, address, 32UL );
      ro->meta = &fd_account_meta_zero;
    } else {
      *ro = *peek->acc;
      accdb->base.ro_active++;
    }
    return;
  }

  /* Enqueue vinyl request */

  ulong batch_idx = pipe->batch_idx;
  ulong req_idx   = pipe->req_cnt;
  ulong req_max   = fd_vinyl_req_batch_key_max( req_pool );
  FD_CRIT( req_idx < req_max, "out-of-bounds req_cnt" );

  fd_vinyl_key_t * key       = fd_vinyl_req_batch_key      ( req_pool, batch_idx ) + req_idx;
  schar *          err       = fd_vinyl_req_batch_err      ( req_pool, batch_idx ) + req_idx;
  ulong *          val_gaddr = fd_vinyl_req_batch_val_gaddr( req_pool, batch_idx ) + req_idx;

  fd_vinyl_key_init( key, address, 32UL );
  *err = 0;
  *val_gaddr = 0UL;

  pipe->req_cnt = (uint)( req_idx+1U );
  if( pipe->req_cnt>=req_max ) {
    fd_accdb_user_v2_ro_pipe_flush( pipe_ );
  }
}

/* fd_accdb_user_v2_ro_wait waits for a previously enqueued ACQUIRE
   request to complete. */

static void
fd_accdb_user_v2_ro_wait( fd_accdb_v2_ro_pipe_t * pipe ) {
  FD_CRIT( pipe->state==RO_PIPE_STATE_WAIT, "unexpected ro_pipe state" );

  fd_vinyl_req_pool_t * req_pool  = pipe->pool;
  ulong                 batch_idx = pipe->batch_idx;
  fd_vinyl_comp_t *     comp      = fd_vinyl_req_batch_comp( req_pool, batch_idx );

  while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
  FD_COMPILER_MFENCE();

  int comp_err = FD_VOLATILE_CONST( comp->err );
  if( FD_UNLIKELY( comp_err!=FD_VINYL_SUCCESS ) ) {
    FD_LOG_CRIT(( "vinyl tile rejected my ACQUIRE request: %i-%s", comp_err, fd_vinyl_strerror( comp_err ) ));
  }
  pipe->state = RO_PIPE_STATE_DRAIN;
}

/* fd_accdb_user_v2_ro_reset sends a RELEASE request (blocking). */

static void
fd_accdb_user_v2_ro_reset( fd_accdb_v2_ro_pipe_t * pipe ) {
  fd_accdb_user_v2_t *  accdb     = pipe->accdb;
  fd_vinyl_req_pool_t * req_pool  = pipe->pool;
  ulong                 batch_idx = pipe->batch_idx;
  ulong                 req_cnt   = pipe->req_cnt;

  memset( pipe->ro, 0, sizeof(fd_accdb_ro_t) );

  /* Send a RELEASE request */

  schar *           req_err = fd_vinyl_req_batch_err ( req_pool, batch_idx );
  fd_vinyl_comp_t * comp    = fd_vinyl_req_batch_comp( req_pool, batch_idx );
  memset( comp, 0, sizeof(fd_vinyl_comp_t) );
  fd_vinyl_req_send_batch(
      accdb->vinyl_rq,
      req_pool,
      accdb->vinyl_req_wksp,
      accdb->vinyl_req_id++,
      accdb->vinyl_link_id,
      FD_VINYL_REQ_TYPE_RELEASE,
      0UL, /* flags */
      batch_idx,
      req_cnt,
      0UL  /* val_max */
  );

  /* Poll for completion */

  while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
  FD_COMPILER_MFENCE();
  int comp_err = FD_VOLATILE_CONST( comp->err );
  if( FD_UNLIKELY( comp_err!=FD_VINYL_SUCCESS ) ) {
    FD_LOG_CRIT(( "vinyl tile rejected my RELEASE request: %i-%s", comp_err, fd_vinyl_strerror( comp_err ) ));
  }

  /* Count successful releases

     The batch we sent includes RELEASE ops for keys that failed to
     ACQUIRE (ERR_KEY), which we expect to fail (ERR_INVAL), due to
     val_gaddr==0 */

  ulong release_cnt = 0UL;
  for( uint req_idx=0U; req_idx<req_cnt; req_idx++ ) {
    release_cnt += ( req_err[ req_idx ]==FD_VINYL_SUCCESS );
  }
  if( FD_UNLIKELY( release_cnt!=pipe->quota_used ) ) {
    FD_LOG_CRIT(( "vinyl tile batch RELEASE request error: %ld pairs failed to release",
                  (long)(pipe->quota_used-release_cnt) ));
  }

  /* Wind up for next iteration */

  FD_TEST( accdb->base.ro_active >= pipe->quota_used );
  accdb->base.ro_active -= (uint)pipe->quota_used;
  pipe->state      = RO_PIPE_STATE_BATCH;
  pipe->req_cnt    = 0U;
  pipe->req_comp   = 0U;
  pipe->quota_used = 0U;
}

fd_accdb_ro_t *
fd_accdb_user_v2_ro_pipe_poll( fd_accdb_ro_pipe_t * pipe_ ) {
  fd_accdb_v2_ro_pipe_t * pipe  = (fd_accdb_v2_ro_pipe_t *)pipe_;
  fd_accdb_user_v2_t *    accdb = pipe->accdb;
  fd_accdb_ro_t *         ro    = pipe->ro;

  switch( pipe->state ) {
  case RO_PIPE_STATE_BATCH:
    /* Deliver a funk synchronous query result early */
    if( ro->ref->accdb_type ) {
      FD_CRIT( ro->ref->accdb_type!=FD_ACCDB_TYPE_V2, "invariant violation" );
      pipe->state = RO_PIPE_STATE_FUNK;
      return ro;
    }
    return NULL;
  case RO_PIPE_STATE_FUNK:
    /* Transition back to vinyl batching */
    fd_accdb_close_ro( (fd_accdb_user_t *)pipe->accdb, ro );
    memset( ro, 0, sizeof(fd_accdb_ro_t) );
    pipe->state = RO_PIPE_STATE_BATCH;
    return NULL;
  case RO_PIPE_STATE_WAIT:
    fd_accdb_user_v2_ro_wait( pipe );
    __attribute__((fallthrough));
  case RO_PIPE_STATE_DRAIN:
    break;
  default:
    FD_LOG_CRIT(( "ro_pipe_poll failed: invalid state %u", pipe->state ));
  }

  /* Deliver a vinyl asynchronous query batch */

  ulong                 batch_idx = pipe->batch_idx;
  fd_vinyl_req_pool_t * req_pool  = pipe->pool;
  ulong                 req_comp  = pipe->req_comp;
  fd_wksp_t *           data_wksp = pipe->accdb->vinyl_data_wksp;

  if( req_comp==pipe->req_cnt ) {
    fd_accdb_user_v2_ro_reset( pipe );
    return NULL;
  }

  fd_vinyl_key_t const * key0       = fd_vinyl_req_batch_key      ( req_pool, batch_idx );
  ulong const *          val_gaddr0 = fd_vinyl_req_batch_val_gaddr( req_pool, batch_idx );
  schar const *          err0       = fd_vinyl_req_batch_err      ( req_pool, batch_idx );

  fd_vinyl_key_t const key       = FD_VOLATILE_CONST( key0      [ req_comp ] );
  int const            err       = FD_VOLATILE_CONST( err0      [ req_comp ] );
  ulong const          val_gaddr = FD_VOLATILE_CONST( val_gaddr0[ req_comp ] );

  memset( ro, 0, sizeof(fd_accdb_ro_t) );
  memcpy( ro->ref->address, key.uc, 32UL );

  if( err==FD_VINYL_ERR_KEY ) {  /* not found */

    ro->ref->accdb_type = FD_ACCDB_TYPE_NONE;
    ro->ref->ref_type   = FD_ACCDB_REF_RO;
    ro->meta = &fd_account_meta_zero;

  } else if( err==FD_VINYL_SUCCESS ) {

    ro->ref->accdb_type = FD_ACCDB_TYPE_V2;
    ro->ref->ref_type   = FD_ACCDB_REF_RO;
    ro->meta            = fd_wksp_laddr_fast( data_wksp, val_gaddr );
    accdb->base.ro_active++;
    pipe->quota_used++;

  } else {
    FD_LOG_CRIT(( "vinyl tile ACQUIRE read request failed: %i-%s", err, fd_vinyl_strerror( err ) ));
  }

  pipe->req_comp = (uint)( req_comp+1UL );
  return ro;
}

void
fd_accdb_user_v2_ro_pipe_fini( fd_accdb_ro_pipe_t * pipe ) {
  fd_accdb_user_v2_ro_pipe_flush( pipe );
  while( fd_accdb_user_v2_ro_pipe_poll( pipe ) ) {}

  fd_accdb_v2_ro_pipe_t * p = (fd_accdb_v2_ro_pipe_t *)pipe;
  fd_vinyl_req_pool_release( p->pool, p->batch_idx );
  memset( p, 0, sizeof(fd_accdb_v2_ro_pipe_t) );
}

fd_accdb_user_vt_t const fd_accdb_user_v2_vt = {
  .fini            = fd_accdb_user_v2_fini,
  .peek            = fd_accdb_user_v2_peek,
  .open_ro         = fd_accdb_user_v2_open_ro,
  .open_rw         = fd_accdb_user_v2_open_rw,
  .close_ref       = fd_accdb_user_v2_close_ref,
  .rw_data_max     = fd_accdb_user_v1_rw_data_max,
  .rw_data_sz_set  = fd_accdb_user_v1_rw_data_sz_set,
  .ro_pipe_init    = fd_accdb_user_v2_ro_pipe_init,
  .ro_pipe_fini    = fd_accdb_user_v2_ro_pipe_fini,
  .ro_pipe_enqueue = fd_accdb_user_v2_ro_pipe_enqueue,
  .ro_pipe_flush   = fd_accdb_user_v2_ro_pipe_flush,
  .ro_pipe_poll    = fd_accdb_user_v2_ro_pipe_poll
};

fd_accdb_user_t *
fd_accdb_user_v2_init( fd_accdb_user_t * accdb_,
                       void *            funk,
                       void *            vinyl_rq,
                       void *            vinyl_data,
                       void *            vinyl_req_pool,
                       ulong             vinyl_link_id ) {
  /* Call superclass constructor */
  if( FD_UNLIKELY( !fd_accdb_user_v1_init( accdb_, funk ) ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( !vinyl_data ) ) {
    FD_LOG_WARNING(( "NULL vinyl_data" ));
    return NULL;
  }

  fd_vinyl_rq_t *       rq       = fd_vinyl_rq_join( vinyl_rq );
  fd_vinyl_req_pool_t * req_pool = fd_vinyl_req_pool_join( vinyl_req_pool );
  if( FD_UNLIKELY( !rq || !req_pool ) ) {
    /* component joins log warning if this is reached */
    FD_LOG_WARNING(( "Failed to initialize database client" ));
    return NULL;
  }

  fd_accdb_user_v2_t * accdb = fd_type_pun( accdb_ );
  accdb->vinyl_req_id    = fd_vinyl_rq_seq( vinyl_rq );
  accdb->vinyl_rq        = rq;
  accdb->vinyl_link_id   = vinyl_link_id;
  accdb->vinyl_data_wksp = vinyl_data;
  accdb->vinyl_req_wksp  = fd_wksp_containing( req_pool );
  accdb->vinyl_req_pool  = req_pool;
  accdb->base.accdb_type = FD_ACCDB_TYPE_V2;
  accdb->base.vt         = &fd_accdb_user_v2_vt;
  return accdb_;
}
