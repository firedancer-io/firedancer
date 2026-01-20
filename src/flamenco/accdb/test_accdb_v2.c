#include "fd_accdb_base.h"
#include "fd_accdb_admin_v1.h"
#include "fd_accdb_impl_v2.h"
#include "fd_accdb_admin.h"
#include "fd_accdb_sync.h"
#include "fd_accdb_pipe.h"
#include "../../vinyl/fd_vinyl.h"

#define WKSP_TAG (1UL)

static uchar const s_key_a[ 32 ] = { 1 };  /* a: present in vinyl, account exists */
static uchar const s_key_b[ 32 ] = { 2 };  /* b: present in vinyl, tombstone */
static uchar const s_key_c[ 32 ] = { 3 };  /* c: present in funk,  account exists */
static uchar const s_key_d[ 32 ] = { 4 };  /* d: present in funk,  tombstone*/
static uchar const s_key_e[ 32 ] = { 5 };  /* e: not found */

static int
fd_vinyl_tile( int     argc,
               char ** argv ) {
  (void)argc;
  fd_vinyl_exec( (fd_vinyl_t *)argv );
  return 0;
}

static void
add_account_vinyl( fd_accdb_user_t * accdb_,
                   uchar const *     key,
                   ulong             lamports ) {
  fd_accdb_user_v2_t * accdb = (fd_accdb_user_v2_t *)accdb_;

  /* Start write */
  ulong             batch_idx     = fd_vinyl_req_pool_acquire   ( accdb->vinyl_req_pool );
  fd_vinyl_key_t *  req_key       = fd_vinyl_req_batch_key      ( accdb->vinyl_req_pool, batch_idx );
  ulong *           req_val_gaddr = fd_vinyl_req_batch_val_gaddr( accdb->vinyl_req_pool, batch_idx );
  schar *           req_err       = fd_vinyl_req_batch_err      ( accdb->vinyl_req_pool, batch_idx );
  fd_vinyl_comp_t * comp          = fd_vinyl_req_batch_comp     ( accdb->vinyl_req_pool, batch_idx );
  fd_vinyl_key_init( req_key, key, 32UL );
  memset( comp, 0, sizeof(fd_vinyl_comp_t) );
  ulong val_max = sizeof(fd_account_meta_t) + 32UL;
  fd_vinyl_req_send_batch(
      accdb->vinyl_rq,
      accdb->vinyl_req_pool,
      accdb->vinyl_req_wksp,
      accdb->vinyl_req_id++,
      accdb->vinyl_link_id,
      FD_VINYL_REQ_TYPE_ACQUIRE,
      FD_VINYL_REQ_FLAG_MODIFY | FD_VINYL_REQ_FLAG_CREATE | FD_VINYL_REQ_FLAG_EXCL,
      batch_idx,
      1UL, /* batch_cnt */
      val_max
  );
  while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
  FD_COMPILER_MFENCE();
  int comp_err = FD_VOLATILE_CONST( comp->err );
  if( FD_UNLIKELY( comp_err!=FD_VINYL_SUCCESS ) ) {
    FD_LOG_CRIT(( "vinyl tile rejected my ACQUIRE request: %i-%s", comp_err, fd_vinyl_strerror( comp_err ) ));
  }
  int err = FD_VOLATILE_CONST( req_err[0] );
  if( FD_UNLIKELY( err!=FD_VINYL_SUCCESS ) ) {
    FD_LOG_CRIT(( "vinyl tile ACQUIRE request failed: %i-%s", err, fd_vinyl_strerror( err ) ));
  }

  ulong               val_gaddr = FD_VOLATILE_CONST( req_val_gaddr[0] );
  void *              val       = fd_wksp_laddr_fast( accdb->vinyl_data_wksp, val_gaddr );
  fd_vinyl_info_t *   info      = fd_vinyl_data_info( val );
  fd_account_meta_t * meta      = val;
  uchar *             data      = (uchar *)( meta+1 );

  memset( meta, 0, val_max );
  meta->lamports = lamports;
  meta->dlen     = 32U;
  memcpy( data, key, 32UL );
  info->val_sz = (uint)val_max;

  /* Finish write */
  memset( comp, 0, sizeof(fd_vinyl_comp_t) );
  req_val_gaddr[0] = val_gaddr;
  fd_vinyl_req_send_batch(
      accdb->vinyl_rq,
      accdb->vinyl_req_pool,
      accdb->vinyl_req_wksp,
      accdb->vinyl_req_id++,
      accdb->vinyl_link_id,
      FD_VINYL_REQ_TYPE_RELEASE,
      FD_VINYL_REQ_FLAG_MODIFY,
      batch_idx,
      1UL, /* batch_cnt */
      0UL  /* val_max */
  );
  while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
  FD_COMPILER_MFENCE();
  comp_err = FD_VOLATILE_CONST( comp->err );
  if( FD_UNLIKELY( comp_err!=FD_VINYL_SUCCESS ) ) {
    FD_LOG_CRIT(( "vinyl tile rejected my RELEASE request: %i-%s", comp_err, fd_vinyl_strerror( comp_err ) ));
  }
  err = FD_VOLATILE_CONST( req_err[0] );
  if( FD_UNLIKELY( err!=FD_VINYL_SUCCESS ) ) {
    FD_LOG_CRIT(( "vinyl tile RELEASE request failed: %i-%s", err, fd_vinyl_strerror( err ) ));
  }

  fd_vinyl_req_pool_release( accdb->vinyl_req_pool, batch_idx );
}

static void
add_account_funk( fd_accdb_user_t * accdb_,
                  uchar const *     key,
                  ulong             lamports ) {
  fd_accdb_user_v2_t * accdb = (fd_accdb_user_v2_t *)accdb_;
  fd_funk_t * funk = accdb->funk;

  fd_funk_rec_map_t *  rec_map  = funk->rec_map;
  fd_funk_rec_pool_t * rec_pool = funk->rec_pool;

  fd_funk_rec_t * rec = fd_funk_rec_pool_acquire( rec_pool, NULL, 1, NULL );
  FD_TEST( rec );
  *rec = (fd_funk_rec_t) {
    .next_idx = UINT_MAX,
    .prev_idx = UINT_MAX,
    .ver_lock = fd_funk_rec_ver_lock( 1UL, 0UL )
  };
  fd_funk_txn_xid_set_root( rec->pair.xid );
  memcpy( rec->pair.key->uc, key, 32UL );

  ulong val_sz = sizeof(fd_account_meta_t) + 32UL;
  fd_account_meta_t * meta = fd_funk_val_truncate( rec, funk->alloc, funk->wksp, 16UL, val_sz, NULL );
  FD_TEST( meta ); memset( meta, 0, val_sz );
  uchar * data = (uchar *)( meta+1 );

  meta->lamports = lamports;
  meta->dlen     = 32U;
  memcpy( data, key, 32UL );

  FD_TEST( fd_funk_rec_map_insert( rec_map, rec, 0 )==FD_MAP_SUCCESS );
}

static fd_funk_rec_t *
ref_funk_rec( fd_accdb_ref_t const * ref ) {
  return (fd_funk_rec_t *)ref->user_data;
}

static void
test_account_creation( fd_accdb_user_t *         accdb,
                       fd_funk_txn_xid_t const * xid2,
                       void const *              addr,
                       ulong                     lamports ) {
  fd_accdb_rw_t rw[1];
  fd_accdb_ro_t ro[1];
  FD_TEST( accdb->base.ro_active==0 && accdb->base.rw_active==0 );

  fd_funk_rec_t * rec;

  FD_TEST( fd_accdb_open_rw( accdb, rw, xid2, addr, 16UL, FD_ACCDB_FLAG_CREATE ) );
  FD_TEST( accdb->base.ro_active==0 && accdb->base.rw_active==1 );
  rec = ref_funk_rec( rw->ref );
  FD_TEST( fd_funk_rec_ver_alive( fd_funk_rec_ver_bits( rec->ver_lock ) )==1 );
  FD_TEST( fd_funk_rec_lock_bits( rec->ver_lock )==FD_FUNK_REC_LOCK_MASK ); /* write locked */
  fd_accdb_ref_lamports_set( rw, lamports );
  fd_accdb_close_rw( accdb, rw );
  FD_TEST( fd_funk_rec_ver_alive( fd_funk_rec_ver_bits( rec->ver_lock ) )==1 );
  FD_TEST( fd_funk_rec_lock_bits( rec->ver_lock )==0 );
  FD_TEST( accdb->base.ro_active==0 && accdb->base.rw_active==0 );

  FD_TEST( fd_accdb_open_ro( accdb, ro, xid2, addr ) );
  FD_TEST( accdb->base.ro_active==1 && accdb->base.rw_active==0 );
  rec = ref_funk_rec( ro->ref );
  FD_TEST( fd_funk_rec_ver_alive( fd_funk_rec_ver_bits( rec->ver_lock ) )==1 );
  FD_TEST( fd_funk_rec_lock_bits( rec->ver_lock )==1UL ); /* read lock */
  FD_TEST( fd_accdb_ref_lamports( ro )==lamports );
  fd_accdb_close_ro( accdb, ro );
  FD_TEST( fd_funk_rec_ver_alive( fd_funk_rec_ver_bits( rec->ver_lock ) )==1 );
  FD_TEST( fd_funk_rec_lock_bits( rec->ver_lock )==0 );
  FD_TEST( accdb->base.ro_active==0 && accdb->base.rw_active==0 );

  FD_TEST( fd_accdb_open_rw( accdb, rw, xid2, addr, 16UL, 0 ) );
  rec = ref_funk_rec( rw->ref );
  FD_TEST( fd_funk_rec_ver_alive( fd_funk_rec_ver_bits( rec->ver_lock ) )==1 );
  FD_TEST( fd_funk_rec_lock_bits( rec->ver_lock )==FD_FUNK_REC_LOCK_MASK ); /* write locked */
  fd_accdb_ref_lamports_set( rw, 0UL ); /* delete */
  fd_accdb_close_rw( accdb, rw );
  FD_TEST( fd_funk_rec_ver_alive( fd_funk_rec_ver_bits( rec->ver_lock ) )==1 );
  FD_TEST( fd_funk_rec_lock_bits( rec->ver_lock )==0UL );

  FD_TEST( !fd_accdb_open_rw( accdb, rw, xid2, addr, 16UL, 0 ) );
  FD_TEST( accdb->base.ro_active==0 && accdb->base.rw_active==0 );

  FD_TEST( !fd_accdb_open_ro( accdb, ro, xid2, addr ) );
  FD_TEST( accdb->base.ro_active==0 && accdb->base.rw_active==0 );
}


/* test_truncate verifies open_rw behavior with the TRUNCATE flag set.

   test_truncate_create:   Account does not exist, create new (flags+=CREATE)
   test_truncate_nonexist: Account does not exist, return NULL
   test_truncate_inplace:  Account exists and is mutable, truncate in-place
   test_truncate_copy:     Account exists and is immutable, create new and copy meta */

static void
test_truncate_create( fd_accdb_admin_t * admin,
                      fd_accdb_user_t *  accdb ) {
  fd_funk_txn_xid_t root = fd_accdb_root_get( admin );
  fd_funk_txn_xid_t xid = { .ul={ 1UL, 0UL } };
  fd_accdb_attach_child( admin, &root, &xid );

  fd_funk_rec_key_t key = { .ul={ 42UL } };
  fd_accdb_rw_t rw[1];
  FD_TEST( fd_accdb_open_rw( accdb, rw, &xid, &key, 56UL, FD_ACCDB_FLAG_CREATE|FD_ACCDB_FLAG_TRUNCATE ) );
  FD_TEST( rw->ref->ref_type==FD_ACCDB_REF_RW );
  fd_funk_rec_t * rec = (void *)rw->ref->user_data;
  FD_TEST( rec->val_sz    == sizeof(fd_account_meta_t) );
  FD_TEST( rec->val_max   >= sizeof(fd_account_meta_t)+56UL );
  FD_TEST( rw->meta->dlen == 0UL );
  fd_accdb_close_rw( accdb, rw );

  fd_accdb_cancel( admin, &xid );
}

static void
test_truncate_nonexist( fd_accdb_admin_t * admin,
                        fd_accdb_user_t *  accdb ) {
  fd_funk_txn_xid_t root = fd_accdb_root_get( admin );
  fd_funk_txn_xid_t xid = { .ul={ 2UL, 0UL } };
  fd_accdb_attach_child( admin, &root, &xid );

  fd_funk_rec_key_t key = { .ul={ 42UL } };
  fd_accdb_rw_t rw[1];
  FD_TEST( !fd_accdb_open_rw( accdb, rw, &xid, &key, 42UL, FD_ACCDB_FLAG_TRUNCATE ) );

  fd_accdb_close_rw( accdb, rw );
}

static void
test_truncate_inplace( fd_accdb_admin_t * admin,
                       fd_accdb_user_t *  accdb ) {
  fd_funk_txn_xid_t root = fd_accdb_root_get( admin );
  fd_funk_txn_xid_t xid = { .ul={ 3UL, 0UL } };
  fd_accdb_attach_child( admin, &root, &xid );

  fd_funk_rec_key_t key = { .ul={ 42UL } };
  fd_accdb_rw_t rw[1];
  ulong data_sz_0 = 56UL;
  FD_TEST( fd_accdb_open_rw( accdb, rw, &xid, &key, data_sz_0, FD_ACCDB_FLAG_CREATE ) );
  FD_TEST( rw->ref->ref_type==FD_ACCDB_REF_RW );
  fd_accdb_ref_lamports_set( rw, 32UL );
  fd_accdb_ref_data_set( accdb, rw, "hello", 5UL );
  fd_funk_rec_t * rec = (void *)rw->ref->user_data;
  FD_TEST( rec->val_sz    == sizeof(fd_account_meta_t)+5UL );
  FD_TEST( rec->val_max   >= sizeof(fd_account_meta_t)+data_sz_0 );
  FD_TEST( rw->meta->dlen == 5UL );
  fd_accdb_close_rw( accdb, rw );

  ulong data_sz_1 = 256UL;
  FD_TEST( fd_accdb_open_rw( accdb, rw, &xid, &key, data_sz_1, FD_ACCDB_FLAG_TRUNCATE ) );
  FD_TEST( rw->ref->ref_type==FD_ACCDB_REF_RW );
  rec = (void *)rw->ref->user_data;
  FD_TEST( rec->val_sz    == sizeof(fd_account_meta_t) );
  FD_TEST( rec->val_max   >= sizeof(fd_account_meta_t)+data_sz_1 );
  FD_TEST( rw->meta->dlen == 0UL );
  fd_accdb_close_rw( accdb, rw );

  fd_accdb_close_rw( accdb, rw );
}

static void
test_truncate_copy( fd_accdb_admin_t * admin,
                    fd_accdb_user_t *  accdb ) {
  fd_funk_txn_xid_t root = fd_accdb_root_get( admin );
  fd_funk_txn_xid_t xid1 = { .ul={ 4UL, 0UL } };
  fd_accdb_attach_child( admin, &root, &xid1 );

  fd_funk_rec_key_t key = { .ul={ 42UL } };
  fd_accdb_rw_t rw[1];
  FD_TEST( fd_accdb_open_rw( accdb, rw, &xid1, &key, 56UL, FD_ACCDB_FLAG_CREATE ) );
  FD_TEST( rw->ref->ref_type==FD_ACCDB_REF_RW );
  fd_accdb_ref_lamports_set( rw, 32UL );
  fd_accdb_ref_data_set( accdb, rw, "hello", 5UL );
  fd_funk_rec_t * rec = (void *)rw->ref->user_data;
  FD_TEST( rec->val_sz    == sizeof(fd_account_meta_t)+5UL );
  FD_TEST( rec->val_max   >= sizeof(fd_account_meta_t)+56UL );
  FD_TEST( rw->meta->dlen == 5UL );
  fd_accdb_close_rw( accdb, rw );

  fd_funk_txn_xid_t xid2 = { .ul={ 5UL, 0UL } };
  fd_accdb_attach_child( admin, &xid1, &xid2 );
  FD_TEST( fd_accdb_open_rw( accdb, rw, &xid2, &key, 256UL, FD_ACCDB_FLAG_TRUNCATE ) );
  FD_TEST( rw->ref->ref_type==FD_ACCDB_REF_RW );
  rec = (void *)rw->ref->user_data;
  FD_TEST( rec->val_sz  == sizeof(fd_account_meta_t) );
  FD_TEST( rec->val_max >= sizeof(fd_account_meta_t)+256UL );
  FD_TEST( rw->meta->dlen   == 0UL );
  fd_accdb_close_rw( accdb, rw );

  fd_accdb_cancel( admin, &xid2 );
  fd_accdb_cancel( admin, &xid1 );
}

static void
run_tests( fd_accdb_user_t * accdb ) {
  fd_accdb_user_v2_t *  v2       = (fd_accdb_user_v2_t *)accdb;
  fd_vinyl_req_pool_t * req_pool = v2->vinyl_req_pool;
  FD_TEST( accdb->base.ro_active==0UL );

  add_account_vinyl( accdb, s_key_a, 10000UL );
  add_account_vinyl( accdb, s_key_b,     0UL );
  add_account_vinyl( accdb, s_key_d, 40000UL );
  add_account_funk ( accdb, s_key_c, 20000UL );
  add_account_funk ( accdb, s_key_d,     0UL );

  fd_funk_txn_xid_t xid[1]; fd_funk_txn_xid_set_root( xid );
  fd_accdb_ro_t ro[1];

  FD_TEST( fd_accdb_open_ro( accdb, ro, xid, s_key_a ) );
  FD_TEST( ro->ref->accdb_type==FD_ACCDB_TYPE_V2 );
  FD_TEST( ro->ref->ref_type==FD_ACCDB_REF_RO );
  FD_TEST( accdb->base.ro_active==1UL );
  FD_TEST( fd_accdb_ref_lamports( ro )==10000UL );
  fd_accdb_close_ro( accdb, ro );
  FD_TEST( accdb->base.ro_active==0UL );
  FD_TEST( req_pool->free_cnt==2UL );

  FD_TEST( !fd_accdb_open_ro( accdb, ro, xid, s_key_b ) );

  FD_TEST( fd_accdb_open_ro( accdb, ro, xid, s_key_c ) );
  fd_funk_rec_t * rec = ref_funk_rec( ro->ref );
  FD_TEST( rec->ver_lock==fd_funk_rec_ver_lock( 1UL, 1UL ) );
  FD_TEST( accdb->base.ro_active==1UL );
  FD_TEST( ro->ref->accdb_type==FD_ACCDB_TYPE_V1 );
  FD_TEST( ro->ref->ref_type==FD_ACCDB_REF_RO );
  FD_TEST( fd_accdb_ref_lamports( ro )==20000UL );
  fd_accdb_close_ro( accdb, ro );
  FD_TEST( rec->ver_lock==fd_funk_rec_ver_lock( 1UL, 0UL ) );
  FD_TEST( accdb->base.ro_active==0UL );
  FD_TEST( req_pool->free_cnt==2UL );

  FD_TEST( !fd_accdb_open_ro( accdb, ro, xid, s_key_d ) );

  FD_TEST( !fd_accdb_open_ro( accdb, ro, xid, s_key_e ) );

  /* Test ro_pipe API */

  fd_accdb_ro_t * ro_tmp;
  fd_accdb_ro_pipe_t pipe[1];
  FD_TEST( fd_accdb_ro_pipe_init( pipe, accdb, xid ) );
  FD_TEST( pipe->req_cnt==0UL );
  FD_TEST( pipe->req_max==4UL );
  FD_TEST( req_pool->free_cnt==2UL );

  /* first batch: d, b, c, e */
  fd_accdb_ro_pipe_enqueue( pipe, s_key_d );
  FD_TEST( req_pool->free_cnt==2UL );
  FD_TEST( pipe->req_cnt==1UL );
  FD_TEST( !fd_accdb_ro_pipe_poll( pipe ) );
  fd_accdb_ro_pipe_enqueue( pipe, s_key_b );
  FD_TEST( !fd_accdb_ro_pipe_poll( pipe ) );
  fd_accdb_ro_pipe_enqueue( pipe, s_key_c );
  FD_TEST( !fd_accdb_ro_pipe_poll( pipe ) );
  fd_accdb_ro_pipe_enqueue( pipe, s_key_e );
  FD_TEST( req_pool->free_cnt==2UL );

  /* result for d */
  FD_TEST( (ro_tmp = fd_accdb_ro_pipe_poll( pipe )) );
  FD_TEST( ro_tmp->ref->ref_type==FD_ACCDB_REF_RO );
  FD_TEST( ro_tmp->ref->accdb_type==FD_ACCDB_TYPE_NONE );
  FD_TEST( 0==memcmp( fd_accdb_ref_address( ro_tmp ), s_key_d, 32UL ) );
  FD_TEST( ro_tmp->meta->lamports==0UL );
  FD_TEST( accdb->base.ro_active==3UL );

  /* result for b (tombstone) */
  FD_TEST( (ro_tmp = fd_accdb_ro_pipe_poll( pipe )) );
  FD_TEST( ro_tmp->ref->ref_type==FD_ACCDB_REF_RO );
  FD_TEST( ro_tmp->ref->accdb_type==FD_ACCDB_TYPE_NONE );
  FD_TEST( 0==memcmp( fd_accdb_ref_address( ro_tmp ), s_key_b, 32UL ) );
  FD_TEST( ro_tmp->meta->lamports==0UL );

  /* result for c */
  FD_TEST( (ro_tmp = fd_accdb_ro_pipe_poll( pipe )) );
  FD_TEST( ro_tmp->ref->ref_type==FD_ACCDB_REF_RO );
  FD_TEST( ro_tmp->ref->accdb_type==FD_ACCDB_TYPE_V1 );
  FD_TEST( 0==memcmp( fd_accdb_ref_address( ro_tmp ), s_key_c, 32UL ) );
  FD_TEST( ro_tmp->meta->lamports==20000UL );

  /* result for e (tombstone) */
  FD_TEST( (ro_tmp = fd_accdb_ro_pipe_poll( pipe )) );
  FD_TEST( ro_tmp->ref->accdb_type==FD_ACCDB_TYPE_NONE );
  FD_TEST( 0==memcmp( fd_accdb_ref_address( ro_tmp ), s_key_e, 32UL ) );
  FD_TEST( ro_tmp->meta->lamports==0UL );
  FD_TEST( accdb->base.ro_active==3UL );
  FD_TEST( !fd_accdb_ro_pipe_poll( pipe ) );
  FD_TEST( accdb->base.ro_active==0UL );

  /* result for a */
  fd_accdb_ro_pipe_enqueue( pipe, s_key_a );
  FD_TEST( !fd_accdb_ro_pipe_poll( pipe ) );
  fd_accdb_ro_pipe_flush( pipe );
  FD_TEST( (ro_tmp = fd_accdb_ro_pipe_poll( pipe )) );
  FD_TEST( ro_tmp->ref->accdb_type==FD_ACCDB_TYPE_V2 );
  FD_TEST( 0==memcmp( fd_accdb_ref_address( ro_tmp ), s_key_a, 32UL ) );
  FD_TEST( ro_tmp->meta->lamports==10000UL );
  FD_TEST( accdb->base.ro_active==1UL );
  FD_TEST( !fd_accdb_ro_pipe_poll( pipe ) );
  FD_TEST( accdb->base.ro_active==0UL );

  fd_accdb_ro_pipe_fini( pipe );

  fd_accdb_rw_t rw[1];
  fd_funk_txn_xid_t xid2[1] = {{ .ul={ 1UL, 2UL } }};
  fd_accdb_admin_t admin[1];
  fd_accdb_admin_v1_init( admin, v2->funk->shmem );
  fd_accdb_attach_child( admin, xid, xid2 );
  FD_TEST( accdb->base.ro_active==0 && accdb->base.rw_active==0 );

  /* vinyl tombstone */
  FD_TEST( !fd_accdb_open_rw( accdb, rw, xid2, s_key_b, 16UL, 0 ) );
  FD_TEST( accdb->base.ro_active==0 && accdb->base.rw_active==0 );
  test_account_creation( accdb, xid2, s_key_b, 1UL );

  /* funk tombstone, vinyl exist */
  FD_TEST( !fd_accdb_open_rw( accdb, rw, xid2, s_key_d, 16UL, 0 ) );
  FD_TEST( accdb->base.ro_active==0 && accdb->base.rw_active==0 );
  test_account_creation( accdb, xid2, s_key_d, 2UL );

  /* missing account */
  FD_TEST( !fd_accdb_open_rw( accdb, rw, xid2, s_key_e, 16UL, 0 ) );
  FD_TEST( accdb->base.ro_active==0 && accdb->base.rw_active==0 );
  test_account_creation( accdb, xid2, s_key_e, 4UL );

  /* repeatedly delete and recreate the same account */
  for( ulong i=0UL; i<1024UL; i++ ) {
    test_account_creation( accdb, xid2, s_key_e, 4UL );
  }

  fd_accdb_cancel( admin, xid2 );

  /* Test truncate */

  test_truncate_create  ( admin, accdb );
  test_truncate_nonexist( admin, accdb );
  test_truncate_inplace ( admin, accdb );
  test_truncate_copy    ( admin, accdb );

  /* Open vinyl record as writable */

  xid2->ul[1]++;
  fd_accdb_attach_child( admin, xid, xid2 );
  FD_TEST( fd_accdb_open_rw( accdb, rw, xid2, s_key_a, 0UL, 0 ) );
  FD_TEST( accdb->base.ro_active==0 && accdb->base.rw_active==1 );
  rec = ref_funk_rec( rw->ref );
  FD_TEST( fd_funk_rec_ver_alive( fd_funk_rec_ver_bits( rec->ver_lock ) )==1 );
  FD_TEST( fd_accdb_ref_data_sz( rw->ro )==32UL );
  FD_TEST( 0==memcmp( fd_accdb_ref_data_const( rw->ro ), s_key_a, 32UL ) );
  fd_accdb_close_rw( accdb, rw );
  FD_TEST( accdb->base.ro_active==0 && accdb->base.rw_active==0 );
  FD_TEST( fd_funk_rec_ver_alive( fd_funk_rec_ver_bits( rec->ver_lock ) )==1 );
  fd_accdb_cancel( admin, xid2 );
  FD_TEST( fd_funk_rec_ver_alive( fd_funk_rec_ver_bits( rec->ver_lock ) )==0 );

  /* Open vinyl record as writable (truncate) */

  xid2->ul[1]++;
  fd_accdb_attach_child( admin, xid, xid2 );
  FD_TEST( fd_accdb_open_rw( accdb, rw, xid2, s_key_a, 0UL, FD_ACCDB_FLAG_TRUNCATE ) );
  FD_TEST( accdb->base.ro_active==0 && accdb->base.rw_active==1 );
  rec = ref_funk_rec( rw->ref );
  FD_TEST( fd_funk_rec_ver_alive( fd_funk_rec_ver_bits( rec->ver_lock ) )==1 );
  FD_TEST( fd_accdb_ref_data_sz( rw->ro )==0UL );
  fd_accdb_close_rw( accdb, rw );
  FD_TEST( accdb->base.ro_active==0 && accdb->base.rw_active==0 );
  FD_TEST( fd_funk_rec_ver_alive( fd_funk_rec_ver_bits( rec->ver_lock ) )==1 );
  fd_accdb_cancel( admin, xid2 );
  FD_TEST( fd_funk_rec_ver_alive( fd_funk_rec_ver_bits( rec->ver_lock ) )==0 );

  fd_accdb_admin_fini( admin );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  if( FD_UNLIKELY( fd_tile_cnt() < 2UL ) ) {
    FD_LOG_ERR(( "This test requires at least 2 tiles (use --tile-cpus to configure)" ));
  }

  char const * _wksp       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",        NULL,                   NULL );
  char const * _page_sz    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",     NULL,             "gigantic" );
  ulong        page_cnt    = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",    NULL,                    8UL );
  ulong        near_cpu    = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",    NULL,        fd_log_cpu_id() );
  ulong        tag         = fd_env_strip_cmdline_ulong( &argc, &argv, "--tag",         NULL,               WKSP_TAG );

  /* Vinyl I/O parameters */
  ulong        spad_max    = fd_env_strip_cmdline_ulong( &argc, &argv, "--spad-max",    NULL, fd_vinyl_io_spad_est() );
  ulong        dev_sz      = fd_env_strip_cmdline_ulong( &argc, &argv, "--dev-sz",      NULL,              1UL << 30 );
  ulong        io_seed     = fd_env_strip_cmdline_ulong( &argc, &argv, "--io-seed",     NULL,                 1234UL );

  /* Vinyl cache parameters */
  ulong        line_cnt    = fd_env_strip_cmdline_ulong( &argc, &argv, "--line-cnt",    NULL,                    7UL );
  ulong        ele_max     = fd_env_strip_cmdline_ulong( &argc, &argv, "--ele-max",     NULL,                    8UL );
  ulong        lock_cnt    = fd_env_strip_cmdline_ulong( &argc, &argv, "--lock-cnt",    NULL,                    8UL );
  ulong        probe_max   = ele_max;
  ulong        seed        = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed",        NULL,                 5678UL );
  ulong        obj_sz      = fd_env_strip_cmdline_ulong( &argc, &argv, "--obj-sz",      NULL,              6UL << 30 );

  /* Vinyl runtime parameters */
  ulong        async_min   = fd_env_strip_cmdline_ulong( &argc, &argv, "--async-min",   NULL,                    5UL );
  ulong        async_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--async-max",   NULL,          2UL*async_min );
  ulong        part_thresh = fd_env_strip_cmdline_ulong( &argc, &argv, "--part-thresh", NULL,             64UL << 20 );
  ulong        gc_thresh   = fd_env_strip_cmdline_ulong( &argc, &argv, "--gc-thresh",   NULL,            128UL << 20 );
  int          gc_eager    = fd_env_strip_cmdline_int  ( &argc, &argv, "--gc-eager",    NULL,                      2 );
  char const * _style      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--style",       NULL,                  "lz4" );
  int          level       = fd_env_strip_cmdline_int  ( &argc, &argv, "--level",       NULL,                      0 );

  /* Vinyl client parameters */
  ulong        rq_max      = fd_env_strip_cmdline_ulong( &argc, &argv, "--rq-max",      NULL,                   32UL );
  ulong        cq_max      = fd_env_strip_cmdline_ulong( &argc, &argv, "--cq-max",      NULL,                   32UL );
  ulong        link_id     = fd_env_strip_cmdline_ulong( &argc, &argv, "--link-id",     NULL,                 2345UL );
  ulong        burst_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--burst-max",   NULL,                    1UL );
  ulong        quota_max   = fd_env_strip_cmdline_ulong( &argc, &argv, "--quota-max",   NULL,                    4UL );

  /* Funk (in-memory DB) parameters */
  ulong        txn_max     = fd_env_strip_cmdline_ulong( &argc, &argv, "--txn-max",     NULL,                   32UL );
  ulong        rec_max     = fd_env_strip_cmdline_ulong( &argc, &argv, "--rec-max",     NULL,                  512UL );

  int style = fd_cstr_to_vinyl_bstream_ctl_style( _style );

  FD_LOG_NOTICE(( "Setting up workspace" ));

  fd_wksp_t * wksp;
  if( _wksp ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", _wksp ));
    wksp = fd_wksp_attach( _wksp );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace (--page-sz %s --page-cnt %lu --near-cpu %lu)",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }
  FD_TEST( wksp );

  ulong io_footprint    = fd_vinyl_io_mm_footprint( spad_max );                      FD_TEST( io_footprint    );
  ulong dev_footprint   = fd_ulong_align_dn( dev_sz, FD_VINYL_BSTREAM_BLOCK_SZ );    FD_TEST( dev_footprint   );
  ulong vinyl_footprint = fd_vinyl_footprint();                                      FD_TEST( vinyl_footprint );
  ulong cnc_footprint   = fd_cnc_footprint( FD_VINYL_CNC_APP_SZ );                   FD_TEST( cnc_footprint   );
  ulong meta_footprint  = fd_vinyl_meta_footprint( ele_max, lock_cnt, probe_max );   FD_TEST( meta_footprint  );
  ulong line_footprint  = sizeof(fd_vinyl_line_t) * line_cnt;                        FD_TEST( line_footprint  );
  ulong ele_footprint   = sizeof(fd_vinyl_meta_ele_t) * ele_max;                     FD_TEST( ele_footprint   );
  ulong obj_footprint   = fd_ulong_align_dn( obj_sz, alignof(fd_vinyl_data_obj_t) ); FD_TEST( obj_footprint   );
  ulong rq_footprint    = fd_vinyl_rq_footprint( rq_max );                           FD_TEST( rq_footprint    );
  ulong cq_footprint    = fd_vinyl_cq_footprint( cq_max );                           FD_TEST( cq_footprint    );

  void * _io      = fd_wksp_alloc_laddr( wksp, fd_vinyl_io_mm_align(),       io_footprint,    tag ); FD_TEST( _io      );
  void * _dev     = fd_wksp_alloc_laddr( wksp, FD_VINYL_BSTREAM_BLOCK_SZ,    dev_footprint,   tag ); FD_TEST( _dev     );
  void * _vinyl   = fd_wksp_alloc_laddr( wksp, fd_vinyl_align(),             vinyl_footprint, tag ); FD_TEST( _vinyl   );
  void * _cnc     = fd_wksp_alloc_laddr( wksp, fd_cnc_align(),               cnc_footprint,   tag ); FD_TEST( _cnc     );
  void * _meta    = fd_wksp_alloc_laddr( wksp, fd_vinyl_meta_align(),        meta_footprint,  tag ); FD_TEST( _meta    );
  void * _line    = fd_wksp_alloc_laddr( wksp, alignof(fd_vinyl_line_t),     line_footprint,  tag ); FD_TEST( _line    );
  void * _ele     = fd_wksp_alloc_laddr( wksp, alignof(fd_vinyl_meta_ele_t), ele_footprint,   tag ); FD_TEST( _ele     );
  void * _obj     = fd_wksp_alloc_laddr( wksp, alignof(fd_vinyl_data_obj_t), obj_footprint,   tag ); FD_TEST( _obj     );
  void * _rq      = fd_wksp_alloc_laddr( wksp, fd_vinyl_rq_align(),          rq_footprint,    tag ); FD_TEST( _rq      );
  void * _cq      = fd_wksp_alloc_laddr( wksp, fd_vinyl_cq_align(),          cq_footprint,    tag ); FD_TEST( _cq      );

  fd_vinyl_io_t * io = fd_vinyl_io_mm_init( _io, spad_max, _dev, dev_footprint, 1, "test", 5UL, io_seed );
  FD_TEST( io );

  fd_vinyl_t * vinyl = fd_vinyl_init( NULL, 0UL, 0UL, level, _vinyl,
                                      _cnc,  cnc_footprint,
                                      _meta, meta_footprint,
                                      _line, line_footprint,
                                      _ele,  ele_footprint,
                                      _obj,  obj_footprint,
                                      io, seed, wksp, async_min, async_max,
                                      part_thresh, gc_thresh, gc_eager, style );

  FD_TEST( vinyl );

  FD_LOG_NOTICE(( "Vinyl booting" ));

  fd_tile_exec_t * exec = fd_tile_exec_new( 1UL, fd_vinyl_tile, 0, (char **)vinyl );
  FD_TEST( exec );

  fd_vinyl_rq_t * rq = fd_vinyl_rq_join( fd_vinyl_rq_new( _rq, rq_max ) ); FD_TEST( rq );
  fd_vinyl_cq_t * cq = fd_vinyl_cq_join( fd_vinyl_cq_new( _cq, cq_max ) ); FD_TEST( cq );

  fd_cnc_t * cnc = fd_cnc_join( _cnc ); FD_TEST( cnc );
  FD_TEST( fd_cnc_wait( cnc, FD_VINYL_CNC_SIGNAL_BOOT, (long)5e9, NULL )==FD_VINYL_CNC_SIGNAL_RUN );

  FD_LOG_NOTICE(( "Vinyl running" ));

  ulong funk_seed      = 9876UL;
  ulong funk_footprint = fd_funk_footprint( txn_max, rec_max );
  void * shfunk = fd_wksp_alloc_laddr( wksp, fd_funk_align(), funk_footprint, tag );
  FD_TEST( shfunk );
  FD_TEST( fd_funk_new( shfunk, tag, funk_seed, txn_max, rec_max ) );

  ulong req_pool_footprint = fd_vinyl_req_pool_footprint( 2UL, 4UL );
  FD_TEST( req_pool_footprint );
  void * _req_pool = fd_wksp_alloc_laddr( wksp, fd_vinyl_req_pool_align(), req_pool_footprint, tag );
  FD_TEST( _req_pool );
  void * req_pool = fd_vinyl_req_pool_new( _req_pool, 2UL, 4UL );
  FD_TEST( req_pool );

  FD_LOG_NOTICE(( "Connecting client to vinyl" ));

  FD_TEST( !fd_vinyl_client_join( cnc, rq, cq, wksp, link_id, burst_max, quota_max ) );

  fd_accdb_user_t accdb[1];
  FD_TEST( fd_accdb_user_v2_init( accdb, shfunk, _rq, wksp, req_pool, link_id ) );
  FD_TEST( accdb->base.accdb_type == FD_ACCDB_TYPE_V2 );

  FD_LOG_NOTICE(( "Running tests" ));

  run_tests( accdb );

  FD_LOG_NOTICE(( "Cleaning up" ));

  fd_accdb_admin_t admin[1];
  FD_TEST( fd_accdb_admin_v1_init( admin, shfunk ) );
  fd_accdb_v1_clear( admin );
  fd_accdb_admin_fini( admin );

  fd_accdb_user_fini( accdb );

  FD_TEST( !fd_vinyl_client_leave( cnc, link_id ) );

  FD_LOG_NOTICE(( "Vinyl stopping" ));
  FD_TEST( !fd_vinyl_halt( cnc ) );
  FD_TEST( fd_cnc_leave( cnc )==_cnc );

  fd_tile_exec_delete( exec, NULL );

  FD_TEST( fd_vinyl_cq_delete( fd_vinyl_cq_leave( cq ) )==_cq );
  FD_TEST( fd_vinyl_rq_delete( fd_vinyl_rq_leave( rq ) )==_rq );

  FD_TEST( fd_vinyl_fini( vinyl )==_vinyl );
  FD_TEST( fd_vinyl_io_fini( io )==_io );

  fd_wksp_free_laddr( fd_vinyl_req_pool_delete( req_pool ) );
  fd_wksp_free_laddr( fd_funk_delete( shfunk ) );
  fd_wksp_free_laddr( _cq      );
  fd_wksp_free_laddr( _rq      );
  fd_wksp_free_laddr( _obj     );
  fd_wksp_free_laddr( _ele     );
  fd_wksp_free_laddr( _line    );
  fd_wksp_free_laddr( _meta    );
  fd_wksp_free_laddr( _cnc     );
  fd_wksp_free_laddr( _vinyl   );
  fd_wksp_free_laddr( _dev     );
  fd_wksp_free_laddr( _io      );

  fd_wksp_usage_t wksp_usage;
  FD_TEST( fd_wksp_usage( wksp, NULL, 0UL, &wksp_usage ) );
  FD_TEST( wksp_usage.free_cnt==wksp_usage.total_cnt );

  if( _wksp ) fd_wksp_detach( wksp );
  else        fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
