#include "fd_accdb_sync.h"
#include "../../funk/fd_funk_rec.h"

#define ACCT_BUF_ALIGN (16UL)

FD_FN_CONST ulong
fd_accdb_client_align( void ) {
  return alignof(fd_accdb_client_t);
}

ulong
fd_accdb_client_footprint( ulong acct_para_max,
                           ulong acct_data_max ) {
  acct_data_max = fd_ulong_align_up( acct_data_max, ACCT_BUF_ALIGN );
  ulong acct_buf_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( acct_para_max, acct_data_max, &acct_buf_sz ) ) ) return 0UL;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_client_t), sizeof(fd_accdb_client_t) );
  l = FD_LAYOUT_APPEND( l, ACCT_BUF_ALIGN,             acct_buf_sz               );
  return FD_LAYOUT_FINI( l, fd_accdb_client_align() );
}

fd_accdb_client_t *
fd_accdb_client_new( void * client_lmem,
                     void * funk_shmem,
                     ulong  acct_para_max,
                     ulong  acct_data_max ) {

  if( FD_UNLIKELY( !client_lmem ) ) {
    FD_LOG_WARNING(( "NULL client_lmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)client_lmem, fd_accdb_client_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned client_lmem" ));
    return NULL;
  }

  fd_accdb_client_t * client = (fd_accdb_client_t *)client_lmem;
  memset( client, 0, sizeof(fd_accdb_client_t) );
  if( FD_UNLIKELY( !fd_funk_join( client->funk, funk_shmem ) ) ) {
    FD_LOG_WARNING(( "Failed to join funk shared memory region" ));
    return NULL;
  }

  /* FIXME allocate buffer */
  (void)acct_para_max; (void)acct_data_max;

  return client;
}

void *
fd_accdb_client_delete( fd_accdb_client_t * client ) {

  if( FD_UNLIKELY( !client ) ) {
    FD_LOG_WARNING(( "NULL client" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_funk_leave( client->funk, NULL ) ) ) {
    FD_LOG_CRIT(( "Failed to detach from funk shared memory region (double free?)" ));
  }
  memset( client, 0, sizeof(fd_accdb_client_t) );

  return client;
}

static fd_funk_txn_t *
fd_accdb_funk_txn_slow( fd_accdb_client_t *       client,
                        fd_funk_txn_xid_t const * txn_xid ) {
  fd_funk_txn_map_t * map = fd_funk_txn_map( client->funk );
  fd_funk_txn_t *     txn = fd_funk_txn_query( txn_xid, map );
  client->recent_funk_txn = txn;
  return txn;
}

static fd_funk_txn_t *
fd_accdb_funk_txn( fd_accdb_client_t *       client,
                   fd_funk_txn_xid_t const * txn_xid ) {

  if( FD_UNLIKELY( !client->recent_funk_txn ) ) {
    return fd_accdb_funk_txn_slow( client, txn_xid );
  }

  /* Peek cached txn's XID */
  fd_funk_txn_xid_t found_xid;
# if FD_HAS_SSE /* prefer atomic copy */
  found_xid.xmm = FD_VOLATILE_CONST( client->recent_funk_txn->xid.xmm );
# else
  found_xid = FD_VOLATILE_CONST( client->recent_funk_txn->xid );
# endif

  /* XID changed */
  if( !fd_funk_txn_xid_eq( txn_xid, &found_xid ) ) return NULL;

  /* FIXME check if transaction is freed */

  return client->recent_funk_txn;
}

fd_accdb_ro_t *
fd_accdb_read_open( fd_accdb_client_t *       client,
                    fd_accdb_ro_t *           ro,
                    fd_funk_txn_xid_t const * txn_id,
                    uchar const *             address ) {
  fd_funk_txn_t * funk_txn = fd_accdb_funk_txn( client, txn_id );

  fd_funk_rec_key_t rec_key = {0};
  memcpy( rec_key.uc, address, 32UL );
  rec_key.uc[ FD_FUNK_REC_KEY_FOOTPRINT-1 ] = FD_FUNK_KEY_TYPE_ACC;

  fd_funk_rec_query_t query[1];
  fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( client->funk, funk_txn, &rec_key, NULL, query );
  if( FD_UNLIKELY( !rec ) ) return NULL;
  if( FD_UNLIKELY( (!!rec->val_sz) & (!rec->val_gaddr) ) ) {
    FD_LOG_CRIT(( "funk record %p invalid: val_sz=%u val_gaddr=0", (void *)rec, rec->val_sz ));
  }

  /* For now, accdb only queries funk, which is assumed to hold all
     accounts (no eviction).  Therefore, no record locking or copying is
     done here yet. */
  fd_account_meta_t const * meta = fd_wksp_laddr_fast( fd_funk_wksp( client->funk ), rec->val_gaddr );

  *ro = (fd_accdb_ro_t) {
    .meta = meta
  };
  ro->ref->rec_gen = fd_funk_rec_gen_query( rec );

  return ro;
}

void
fd_accdb_read_close( fd_accdb_client_t * client,
                     fd_accdb_ro_t *     ro ) {
  /* Overrun detection */
  ulong gen = fd_funk_rec_gen_query( ro->rec );
  if( FD_UNLIKELY( gen!=ro->ref->rec_gen ) ) {
    fd_funk_rec_log_data_race( client->funk, ro->rec, ro->ref->rec_gen );
    FD_LOG_CRIT(( "Funk record access overrun while reading" ));
  }

  /* For now, nothing to do release.  Would unlock the record here in a
     future version. */
}

/* Account Database Write logic ****************************************

   The typical write path sends all changes to funk. */
static void
fd_accdb_write_prepare1( fd_accdb_client_t *       client,
                         fd_accdb_rw_t *           rw,
                         fd_funk_txn_xid_t const * txn_id,
                         void const *              address,
                         ulong                     data_max,
                         int                       zero_init ) {
  ulong val_max = sizeof(fd_account_meta_t)+data_max;

  fd_funk_rec_key_t rec_key = {0};
  memcpy( rec_key.uc, address, 32UL );
  rec_key.uc[ FD_FUNK_REC_KEY_FOOTPRINT-1 ] = FD_FUNK_KEY_TYPE_ACC;

  /* Get funk transaction handle */
  fd_funk_txn_t * funk_txn = fd_accdb_funk_txn( client, txn_id );

  /* Peek linked list tail of transaction */
  uint tail_idx = FD_VOLATILE_CONST( funk_txn->rec_tail_idx );

  fd_alloc_t * alloc = fd_funk_alloc( client->funk );
  fd_wksp_t *  wksp  = fd_funk_wksp ( client->funk );

  /* Query hash map for existing record */
  fd_funk_rec_query_t query[1];
  fd_funk_rec_t const * rec_ro = fd_funk_rec_query_try_global( client->funk, funk_txn, &rec_key, NULL, query );
  fd_funk_rec_t * rec = fd_type_pun( (void *)(ulong)rec_ro );

  void * data_buf;
  if( FD_UNLIKELY( !rec ) ) {  /* record does not exist */

    /* Acquire new record */
    int map_err;
    rec = fd_funk_rec_pool_acquire( client->funk->rec_pool, NULL, 1, &map_err );
    if( FD_UNLIKELY( !rec ) ) FD_LOG_ERR(( "fd_funk_rec_pool_acquire failed (%d), out of memory?", map_err ));

    /* FIXME mark record as used */

    /* Allocate data buffer */
    fd_funk_val_init( rec );
    int truncate_err;
    if( FD_UNLIKELY( !fd_funk_val_truncate( rec, alloc, fd_funk_wksp( client->funk ), 8UL, val_max, &truncate_err ) ) ) {
      FD_LOG_ERR(( "fd_funk_val_truncate failed (%i-%s)", truncate_err, fd_funk_strerror( truncate_err ) ));
    }

    /* FIXME update linked list pointers */

    /* Publish newly acquired record (in gen%2==1 state, i.e. locked)
       Concurrent reads/writes for this record will fail. */
    int insert_err = fd_funk_rec_map_insert( client->funk->rec_map, rec, FD_MAP_FLAG_BLOCKING );
    if( FD_UNLIKELY( insert_err!=FD_MAP_SUCCESS ) ) FD_LOG_ERR(( "fd_funk_rec_map_insert failed (%d)", insert_err ));

    data_buf = fd_wksp_laddr_fast( wksp, rec->val_gaddr );

  } else { /* record already exists, update */

    if( FD_UNLIKELY( (!!rec->val_sz) & (!rec->val_gaddr) ) ) {
      FD_LOG_CRIT(( "funk record %p invalid: val_sz=%u val_gaddr=0", (void *)rec, rec->val_sz ));
    }

    data_buf = fd_wksp_laddr_fast( wksp, rec->val_gaddr );
    if( FD_UNLIKELY( rec->val_sz < val_max ) ) {
      int truncate_err;
      data_buf = fd_funk_val_truncate( rec, alloc, wksp, 8UL, val_max, &truncate_err );
      if( FD_UNLIKELY( !data_buf ) ) {
        FD_LOG_ERR(( "fd_funk_val_truncate failed (%i-%s)", truncate_err, fd_funk_strerror( truncate_err ) ));
      }
    }
  }

  if( zero_init ) {
    fd_memset( data_buf, 0, val_max );
  }


  // /* Resize data buffer if required */

  // fd_funk_rec_key_t rec_key = {0};
  // memcpy( rec_key.uc, address, 32UL );
  // rec_key.uc[ FD_FUNK_REC_KEY_FOOTPRINT-1 ] = FD_FUNK_KEY_TYPE_ACC;

}

void
fd_accdb_write_prepare( fd_accdb_client_t *       client,
                        fd_accdb_rw_t *           rw,
                        fd_funk_txn_xid_t const * txn_id,
                        void const *              address,
                        ulong                     data_sz ) {
  fd_accdb_write_prepare1( client, rw, txn_id, address, data_sz, 0 );
}

void
fd_accdb_modify_prepare( fd_accdb_client_t *       client,
                         fd_accdb_rw_t *           rw,
                         fd_funk_txn_xid_t const * txn_id,
                         void const *              address,
                         ulong                     data_min ) {
  fd_accdb_write_prepare1( client, rw, txn_id, address, data_min, 1 );
}

void
fd_accdb_write_publish( fd_accdb_client_t * client,
                        fd_accdb_rw_t *     write ) {
  /* FIXME consider defering hashmap update until here.  Worse cache
           locality though, since hashmap bits might have dropped out of
           cache after a large data copy */

  /* This write might be a no-op */
}

void
fd_accdb_write( fd_accdb_client_t *       client,
                fd_funk_txn_xid_t const * txn_xid,
                void const *              address,
                fd_accdb_meta_t const *   meta,
                void const *              data,
                ulong                     data_sz ) {
  fd_accdb_rw_t rw[1];
  fd_accdb_write_prepare1( client, rw, txn_xid, address, data_sz, 0 );
}


int
fd_accdb_sestab_is_used( fd_accdb_sestab_t const * sestab,
                         fd_funk_txn_xid_t         needle ) {
  /* FIXME unroll loop */
  for( ulong i=0UL; i<(sestab->session_max); i++ ) {
    fd_accdb_session_t const * sess = &sestab->sessions[ i ];
    fd_funk_txn_xid_t xid;
#   if FD_HAS_SSE
    xid.xmm = FD_VOLATILE_CONST( sess->txn_active.xmm );
#   else
    xid     = FD_VOLATILE_CONST( sess->txn_active     );
#   endif
    if( fd_funk_txn_xid_eq( &xid, &needle ) ) return 1;
  }
  return 0;
}
