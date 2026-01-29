#include "fd_accdb_admin_v2_private.h"
#include "../fd_flamenco_base.h"
#include "../runtime/fd_runtime_const.h" /* FD_RUNTIME_ACC_SZ_MAX */
#include "../../vinyl/data/fd_vinyl_data.h"

/***********************************************************************

  fd_accdb_admin_v2_root.c contains the account rooting algorithm.

   This algorithm is designed to amortize vinyl I/O latency by
   processing accounts in batches.

   For each batch of accounts, it does the following logic:

   - ACQUIRE batch request for account updates
   - ERASE   batch request for account deletions
   - Spin wait for ACQUIRE completion
   - Copy back modified accounts
   - RELEASE batch request for account updates
   - Spin wait for ACQUIRE, ERASE completions
   - Free records from funk

***********************************************************************/

/* vinyl_spin_wait waits for completion of a vinyl request and asserts
   that all requests completed successfully. */

static void
vinyl_spin_wait( fd_vinyl_comp_t const * comp,
                 fd_vinyl_key_t const *  key0,
                 schar const *           err0,
                 ulong                   cnt,
                 char const *            req_type_cstr ) {

  /* FIXME use a load-acquire here, such that later loads are ordered
           past this load */
  while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
  FD_COMPILER_MFENCE();
  int comp_err = FD_VOLATILE_CONST( comp->err );
  if( FD_UNLIKELY( comp_err!=FD_VINYL_SUCCESS ) ) {
    FD_LOG_CRIT(( "vinyl tile rejected my %s request (%i-%s)",
                  req_type_cstr, comp_err, fd_vinyl_strerror( comp_err ) ));
  }

  for( ulong i=0UL; i<cnt; i++ ) {
    int err = err0[ i ];
    if( FD_UNLIKELY( err!=FD_VINYL_SUCCESS && err!=FD_VINYL_ERR_KEY ) ) {
      FD_BASE58_ENCODE_32_BYTES( key0[i].uc, key_b58 );
      FD_LOG_CRIT(( "vinyl %s request failed for %s (%i-%s)",
                    req_type_cstr, key_b58, err, fd_vinyl_strerror( err ) ));
    }
  }
}

/* funk_rec_write_lock spins until it gains a write lock for a record,
   increments the version number, and returns the updated ver_lock
   value. */

static ulong
fd_funk_rec_admin_lock( fd_funk_rec_t * rec ) {
  ulong * vl = &rec->ver_lock;
  for(;;) {
    ulong const ver_lock = FD_VOLATILE_CONST( *vl );
    ulong const ver      = fd_funk_rec_ver_bits ( ver_lock );
    ulong const lock     = fd_funk_rec_lock_bits( ver_lock );
    if( FD_UNLIKELY( lock ) ) {
      /* Spin while there are active readers */
      /* FIXME kill client after spinning for 30 seconds to prevent silent deadlock */
      FD_SPIN_PAUSE();
      continue;
    }
    ulong const new_ver = fd_funk_rec_ver_inc( ver );
    ulong const new_vl  = fd_funk_rec_ver_lock( new_ver, FD_FUNK_REC_LOCK_MASK );
    if( FD_UNLIKELY( FD_ATOMIC_CAS( vl, ver_lock, new_vl )!=ver_lock ) ) {
      FD_SPIN_PAUSE();
      continue;
    }
    return new_vl;
  }
}

static void
fd_funk_rec_admin_unlock( fd_funk_rec_t * rec,
                          ulong           ver_lock ) {
  FD_VOLATILE( rec->ver_lock ) = fd_funk_rec_ver_lock( fd_funk_rec_ver_bits( ver_lock ), 0UL );
}

static void
funk_remove_rec( fd_funk_t *     funk,
                 fd_funk_rec_t * rec ) {

  /* Step 1: Remove record from map */

  fd_funk_xid_key_pair_t pair = rec->pair;
  fd_funk_rec_query_t query[1];
  int rm_err = fd_funk_rec_map_remove( funk->rec_map, &pair, NULL, query, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( rm_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_funk_rec_map_remove failed (%i-%s)", rm_err, fd_map_strerror( rm_err ) ));
  FD_COMPILER_MFENCE();

  /* Step 2: Acquire admin lock (kick out readers)

     Note: At this point, well-behaving external readers will abandon a
     read-lock attempt if they observe this active write lock.  (An
     admin lock always implies the record is about to die) */

  ulong ver_lock = fd_funk_rec_admin_lock( rec );

  /* Step 3: Free record */

  memset( &rec->pair, 0, sizeof(fd_funk_xid_key_pair_t) );
  FD_COMPILER_MFENCE();
  rec->map_next = FD_FUNK_REC_IDX_NULL;
  fd_funk_val_flush( rec, funk->alloc, funk->wksp );
  fd_funk_rec_admin_unlock( rec, ver_lock );
  fd_funk_rec_pool_release( funk->rec_pool, rec, 1 );
}

/* Main algorithm */

fd_funk_rec_t *
fd_accdb_v2_publish_batch( fd_accdb_admin_v2_t * admin,
                           fd_funk_rec_t *       head ) {

  fd_funk_t *           funk      = admin->v1->funk;        /* unrooted DB */
  fd_wksp_t *           funk_wksp = funk->wksp;             /* shm workspace containing unrooted accounts */
  fd_funk_rec_t *       rec_pool  = funk->rec_pool->ele;    /* funk rec arena */
  fd_vinyl_rq_t *       rq        = admin->vinyl_rq;        /* "request queue "*/
  fd_vinyl_req_pool_t * req_pool  = admin->vinyl_req_pool;  /* "request pool" */
  fd_wksp_t *           req_wksp  = admin->vinyl_req_wksp;  /* shm workspace containing request buffer */
  fd_wksp_t *           data_wksp = admin->vinyl_data_wksp; /* shm workspace containing vinyl data cache */
  ulong                 link_id   = admin->vinyl_link_id;   /* vinyl client ID */

  /* Collect funk request batch */

  fd_funk_rec_t * recs[ FD_ACCDB_ROOT_BATCH_MAX ];
  ulong           rec_cnt;

  for( rec_cnt=0UL; head && rec_cnt<FD_ACCDB_ROOT_BATCH_MAX; rec_cnt++ ) {
    uint next_idx = head->next_idx;
    head->prev_idx = FD_FUNK_REC_IDX_NULL;
    head->next_idx = FD_FUNK_REC_IDX_NULL;

    recs[ rec_cnt ] = head;
    if( fd_funk_rec_idx_is_null( next_idx ) ) {
      head = NULL;
    } else {
      head = &rec_pool[ next_idx ];
    }
  }

  /* Partition batch into ACQUIRE (updates) and ERASE (deletions) */

  ulong acq_cnt = 0UL;
  ulong del_cnt;
  for( ulong i=0UL; i<rec_cnt; i++ ) {
    fd_account_meta_t const * meta = fd_funk_val( recs[ i ], funk_wksp );
    FD_CRIT( meta && recs[ i ]->val_sz>=sizeof(fd_account_meta_t), "corrupt funk_rec" );
    if( meta->lamports ) {
      fd_funk_rec_t * tmp = recs[ i ];
      recs[ i ]       = recs[ acq_cnt ];
      recs[ acq_cnt ] = tmp;
      acq_cnt++;
    }
  }
  del_cnt = rec_cnt - acq_cnt;

  /* Create ACQUIRE and ERASE batch requests */

  ulong            del_batch = fd_vinyl_req_pool_acquire( req_pool ); /* ERASE */
  ulong            acq_batch = fd_vinyl_req_pool_acquire( req_pool ); /* ACQUIRE */
  fd_vinyl_key_t * acq_key0  = fd_vinyl_req_batch_key( req_pool, acq_batch );
  fd_vinyl_key_t * del_key0  = fd_vinyl_req_batch_key( req_pool, del_batch );

  for( ulong i=0UL; i<acq_cnt; i++ ) {
    fd_vinyl_key_init( &acq_key0[ i ], recs[ i         ]->pair.key, 32UL );
  }
  for( ulong i=0UL; i<del_cnt; i++ ) {
    fd_vinyl_key_init( &del_key0[ i ], recs[ acq_cnt+i ]->pair.key, 32UL );
  }

  /* Send off ACQUIRE and ERASE requests */

  fd_vinyl_comp_t * acq_comp       = fd_vinyl_req_batch_comp     ( req_pool, acq_batch );
  fd_vinyl_comp_t * del_comp       = fd_vinyl_req_batch_comp     ( req_pool, del_batch );
  schar *           acq_err0       = fd_vinyl_req_batch_err      ( req_pool, acq_batch );
  schar *           del_err0       = fd_vinyl_req_batch_err      ( req_pool, del_batch );
  ulong *           acq_val_gaddr0 = fd_vinyl_req_batch_val_gaddr( req_pool, acq_batch );

  memset( acq_comp, 0, sizeof(fd_vinyl_comp_t) );
  memset( del_comp, 0, sizeof(fd_vinyl_comp_t) );
  for( ulong i=0UL; i<acq_cnt; i++ ) acq_err0      [ i ] = 0;
  for( ulong i=0UL; i<del_cnt; i++ ) del_err0      [ i ] = 0;
  for( ulong i=0UL; i<acq_cnt; i++ ) {
    fd_account_meta_t const * src_meta = fd_funk_val( recs[ i ], funk_wksp );

    ulong data_sz = src_meta->dlen;
    FD_CRIT( data_sz<=FD_RUNTIME_ACC_SZ_MAX, "oversize account record" );

    acq_val_gaddr0[ i ] = sizeof(fd_account_meta_t) + data_sz;
  }

  fd_vinyl_req_send_batch(
      rq, req_pool, req_wksp,
      admin->vinyl_req_id++, link_id,
      FD_VINYL_REQ_TYPE_ACQUIRE,
      FD_VINYL_REQ_FLAG_MODIFY |
      FD_VINYL_REQ_FLAG_IGNORE |
      FD_VINYL_REQ_FLAG_CREATE,
      acq_batch, acq_cnt
  );
  fd_vinyl_req_send_batch(
      rq, req_pool, req_wksp,
      admin->vinyl_req_id++, link_id,
      FD_VINYL_REQ_TYPE_ERASE,
      0UL,
      del_batch, del_cnt
  );

  /* Spin for ACQUIRE completion */

  vinyl_spin_wait( acq_comp, acq_key0, acq_err0, acq_cnt, "ACQUIRE" );

  /* Copy back modified accounts */

  for( ulong i=0UL; i<acq_cnt; i++ ) {
    fd_account_meta_t const * src_meta = fd_funk_val( recs[ i ], funk_wksp );

    ulong data_sz = src_meta->dlen;
    ulong val_sz  = sizeof(fd_account_meta_t) + data_sz;
    FD_CRIT( data_sz<=FD_RUNTIME_ACC_SZ_MAX, "oversize account record" );

    fd_account_meta_t * dst_meta = fd_wksp_laddr_fast( data_wksp, acq_val_gaddr0[ i ] );
    fd_vinyl_info_t *   val_info = fd_vinyl_data_info( dst_meta );

    fd_memcpy( dst_meta, src_meta, val_sz );
    val_info->val_sz = (uint)val_sz;
  }

  /* Send off RELEASE batch request (reuse acq_batch) */

  memset( acq_comp, 0, sizeof(fd_vinyl_comp_t) );
  for( ulong i=0UL; i<acq_cnt; i++ ) acq_err0[ i ] = 0;
  fd_vinyl_req_send_batch(
      rq, req_pool, req_wksp,
      admin->vinyl_req_id++, link_id,
      FD_VINYL_REQ_TYPE_RELEASE,
      FD_VINYL_REQ_FLAG_MODIFY,
      acq_batch, acq_cnt
  );

  /* Spin for ERASE, RELEASE completions */

  vinyl_spin_wait( del_comp, del_key0, del_err0, del_cnt, "ERASE" );
  fd_vinyl_req_pool_release( req_pool, del_batch );

  vinyl_spin_wait( acq_comp, acq_key0, acq_err0, acq_cnt, "RELEASE" );
  fd_vinyl_req_pool_release( req_pool, acq_batch );

  /* Remove funk records */

  for( ulong i=0UL; i<rec_cnt; i++ ) {
    funk_remove_rec( funk, recs[ i ] );
  }

  /* Update metrics */

  admin->base.root_cnt    += (uint)acq_cnt;
  admin->base.reclaim_cnt += (uint)del_cnt;

  return head;
}
