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
fd_funk_rec_admin_lock( fd_funk_t const * funk,
                        fd_funk_rec_t *   rec ) {
  ulong            rec_idx = (ulong)( rec - funk->rec_pool->ele );
  ulong volatile * vl      = &funk->rec_lock[ rec_idx ];
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
fd_funk_rec_admin_unlock( fd_funk_t const * funk,
                          fd_funk_rec_t *   rec,
                          ulong             ver_lock ) {
  ulong            rec_idx = (ulong)( rec - funk->rec_pool->ele );
  ulong volatile * vl      = &funk->rec_lock[ rec_idx ];
  FD_VOLATILE( *vl ) = fd_funk_rec_ver_lock( fd_funk_rec_ver_bits( ver_lock ), 0UL );
}

static void
funk_free_rec( fd_funk_t *     funk,
               fd_funk_rec_t * rec ) {
  /* Acquire admin lock (kick out readers)

     Note: At this point, well-behaving external readers will abandon a
     read-lock attempt if they observe this active write lock.  (An
     admin lock always implies the record is about to die) */

  FD_COMPILER_MFENCE();
  ulong ver_lock = fd_funk_rec_admin_lock( funk, rec );

  /* Free record */

  memset( &rec->pair, 0, sizeof(fd_funk_xid_key_pair_t) );
  FD_COMPILER_MFENCE();
  rec->map_next = FD_FUNK_REC_IDX_NULL;
  fd_funk_val_flush( rec, funk->alloc, funk->wksp );
  fd_funk_rec_admin_unlock( funk, rec, ver_lock );
  fd_funk_rec_pool_release( funk->rec_pool, rec, 1 );
}

/* funk_gc_chain optimistically deletes all but the newest rooted
   revisions of rec.  This possibly deletes 'rec'.  Returns rec if rec
   is the only known rooted revision, otherwise returns NULL (if rec was
   deleted).  Note that due to edge cases, revisions that are not in the
   oldest tracked slot, may not reliably get cleaned up.  (The oldest
   tracked slot always gets cleaned up, though.) */

static fd_funk_rec_t *
funk_gc_chain( fd_accdb_admin_v2_t * const admin,
               fd_funk_rec_t *       const rec ) {

  fd_accdb_lineage_t * lineage   = admin->root_lineage;
  fd_funk_t *          funk      = admin->v1->funk;
  fd_funk_rec_t *      rec_pool  = funk->rec_pool->ele;
  ulong                rec_max   = funk->rec_pool->ele_max;
  ulong                seed      = funk->rec_map->map->seed;
  ulong                chain_cnt = funk->rec_map->map->chain_cnt;
  ulong                root_slot = lineage->fork[0].ul[0];

  ulong hash      = fd_funk_rec_map_key_hash( &rec->pair, seed );
  ulong chain_idx = (hash & (chain_cnt-1UL) );

  /* Lock rec_map chain */

  int lock_err = fd_funk_rec_map_iter_lock( funk->rec_map, &chain_idx, 1UL, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( lock_err!=FD_MAP_SUCCESS ) ) {
    FD_LOG_CRIT(( "fd_funk_rec_map_iter_lock failed (%i-%s)", lock_err, fd_map_strerror( lock_err ) ));
  }

  fd_funk_rec_map_shmem_private_chain_t * chain =
      fd_funk_rec_map_shmem_private_chain( funk->rec_map->map, 0UL ) + chain_idx;
  ulong ver =
      fd_funk_rec_map_private_vcnt_ver( FD_VOLATILE_CONST( chain->ver_cnt ) );
  FD_CRIT( ver&1UL, "chain is not locked" );

  /* Walk map chain */

  fd_funk_rec_t * found_rec = NULL;
  uint *          pnext     = &chain->head_cidx;
  uint            cur       = *pnext;
  ulong           chain_len = 0UL;
  ulong           iter      = 0UL;
  while( cur!=FD_FUNK_REC_IDX_NULL ) {
    if( FD_UNLIKELY( iter++ > rec_max ) ) FD_LOG_CRIT(( "cycle detected in rec_map chain %lu", chain_idx ));

    /* Is this node garbage? */

    fd_funk_rec_t * node = &funk->rec_pool->ele[ cur ];
    if( FD_UNLIKELY( cur==node->map_next ) ) FD_LOG_CRIT(( "accdb corruption detected: cycle in rec_map chain %lu", chain_idx ));
    cur = node->map_next;
    if( !fd_funk_rec_key_eq( rec->pair.key, node->pair.key ) ) goto retain;
    if( node->pair.xid->ul[0]>root_slot ) goto retain;
    if( !found_rec ) {
      found_rec = node;
      goto retain;
    }

    /* No longer need this node */

    if( node->pair.xid->ul[0] > rec->pair.xid->ul[0] ) {
      /* If this node is newer than the to-be-deleted slot, need to
         remove it from the transaction's record list. */
      uint neigh_prev = node->prev_idx;
      uint neigh_next = node->next_idx;
      if( neigh_prev==FD_FUNK_REC_IDX_NULL ||
          neigh_next==FD_FUNK_REC_IDX_NULL ) {
        /* Node is first or last of transaction -- too bothersome to
           remove it from the transaction's record list */
        goto retain;
      }
      rec_pool[ neigh_next ].prev_idx = neigh_prev;
      rec_pool[ neigh_prev ].next_idx = neigh_next;
    }

    /* Destroy this node */

    funk_free_rec( funk, node );
    *pnext = cur;
    continue;

  retain:
    pnext = &node->map_next;
    chain_len++;
  }

  /* Unlock rec_map chain */

  FD_COMPILER_MFENCE();
  FD_VOLATILE( chain->ver_cnt ) =
      fd_funk_rec_map_private_vcnt( ver+1UL, chain_len );
  FD_COMPILER_MFENCE();
  return found_rec==rec ? found_rec : NULL;
}

/* Main algorithm */

fd_funk_rec_t *
fd_accdb_v2_root_batch( fd_accdb_admin_v2_t * admin,
                        fd_funk_rec_t *       rec0 ) {
  long t_start = fd_tickcount();

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

  fd_funk_rec_t * next = rec0;
  for( rec_cnt=0UL; next && rec_cnt<FD_ACCDB_ROOT_BATCH_MAX; ) {
    fd_funk_rec_t * cur = next;
    if( fd_funk_rec_idx_is_null( cur->next_idx ) ) {
      next = NULL;
    } else {
      next = &rec_pool[ cur->next_idx ];
    }
    cur->prev_idx = FD_FUNK_REC_IDX_NULL;
    cur->next_idx = FD_FUNK_REC_IDX_NULL;

    if( funk_gc_chain( admin, cur ) ) {
      recs[ rec_cnt++ ] = cur;
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
  for( ulong i=0UL; i<acq_cnt; i++ ) acq_err0[ i ] = 0;
  for( ulong i=0UL; i<del_cnt; i++ ) del_err0[ i ] = 0;
  for( ulong i=0UL; i<acq_cnt; i++ ) {
    fd_account_meta_t const * src_meta = fd_funk_val( recs[ i ], funk_wksp );

    ulong data_sz = src_meta->dlen;
    FD_CRIT( data_sz<=FD_RUNTIME_ACC_SZ_MAX, "oversize account record" );

    ulong val_sz = sizeof(fd_account_meta_t) + data_sz;
    acq_val_gaddr0[ i ]      = val_sz;
    admin->base.root_tot_sz += val_sz;
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
  long t_acquire = fd_tickcount();

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
  long t_copy = fd_tickcount();

  /* Spin for ERASE, RELEASE completions */

  vinyl_spin_wait( del_comp, del_key0, del_err0, del_cnt, "ERASE" );
  fd_vinyl_req_pool_release( req_pool, del_batch );

  vinyl_spin_wait( acq_comp, acq_key0, acq_err0, acq_cnt, "RELEASE" );
  fd_vinyl_req_pool_release( req_pool, acq_batch );
  long t_release = fd_tickcount();

  /* Remove funk records */

  for( ulong i=0UL; i<rec_cnt; i++ ) {
    fd_funk_xid_key_pair_t pair = recs[ i ]->pair;
    fd_funk_rec_query_t query[1];
    int rm_err = fd_funk_rec_map_remove( funk->rec_map, &pair, NULL, query, FD_MAP_FLAG_BLOCKING );
    if( FD_UNLIKELY( rm_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_funk_rec_map_remove failed (%i-%s)", rm_err, fd_map_strerror( rm_err ) ));
    funk_free_rec( funk, recs[ i ] );
  }
  long t_gc = fd_tickcount();

  /* Update metrics */

  admin->base.root_cnt    += (uint)acq_cnt;
  admin->base.reclaim_cnt += (uint)del_cnt;
  admin->base.dt_vinyl    += ( t_acquire - t_start ) + ( t_release - t_copy );
  admin->base.dt_copy     += ( t_copy - t_acquire );
  admin->base.dt_gc       += ( t_gc - t_release );

  return next;
}
