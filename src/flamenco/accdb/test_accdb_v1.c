#include "fd_accdb_admin.h"
#include "fd_accdb_sync.h"
#include "fd_accdb_impl_v1.h"
#include "../../funk/test_funk_common.h"
#include "../../funk/test_funk_common.c"

#define WKSP_TAG 1UL
#define VERBOSE 0 /* toggle for more debug info */

/* init_funk does extended initialization of unallocated records. */

static void
init_funk( void * shfunk ) {
  fd_funk_t funk[1];
  FD_TEST( fd_funk_join( funk, shfunk ) );

  ulong rec_max = funk->rec_pool->ele_max;
  fd_funk_rec_t * rec_ele = funk->rec_pool->ele;
  for( ulong j=0UL; j<rec_max; j++ ) {
    rec_ele[ j ].pair      = (fd_funk_xid_key_pair_t){0};
    rec_ele[ j ].next_idx  = UINT_MAX;
    rec_ele[ j ].prev_idx  = UINT_MAX;
    rec_ele[ j ].val_sz    = 0;
    rec_ele[ j ].val_max   = 0;
    rec_ele[ j ].val_gaddr = 0UL;
    rec_ele[ j ].tag       = 0UL;
  }

  ulong txn_max = funk->txn_pool->ele_max;
  fd_funk_txn_t * txn_ele = funk->txn_pool->ele;
  for( ulong j=0UL; j<txn_max; j++ ) {
    txn_ele[ j ].parent_cidx       = FD_FUNK_TXN_IDX_NULL;
    txn_ele[ j ].child_head_cidx   = FD_FUNK_TXN_IDX_NULL;
    txn_ele[ j ].child_tail_cidx   = FD_FUNK_TXN_IDX_NULL;
    txn_ele[ j ].sibling_prev_cidx = FD_FUNK_TXN_IDX_NULL;
    txn_ele[ j ].sibling_next_cidx = FD_FUNK_TXN_IDX_NULL;
    txn_ele[ j ].stack_cidx        = FD_FUNK_TXN_IDX_NULL;
    txn_ele[ j ].tag               = 0UL;
    txn_ele[ j ].rec_head_idx      = UINT_MAX;
    txn_ele[ j ].rec_tail_idx      = UINT_MAX;
    txn_ele[ j ].state             = FD_FUNK_TXN_STATE_FREE;
  }

  fd_funk_leave( funk, NULL );
}

/* verify_accdb_empty verifies that a funk instance is empty (no recs
   or txns in maps), and that the backing elements have been initialized
   and returned to object pools.  Also verifies that the funk instance
   has no leaked val allocations. */

static void
visit_rec( fd_funk_rec_t * rec ) {
  FD_TEST( !rec->tag );
  FD_TEST( rec->next_idx==UINT_MAX );
  FD_TEST( rec->prev_idx==UINT_MAX );
  FD_TEST( rec->val_sz==0 );
  FD_TEST( rec->val_max==0 );
  FD_TEST( rec->val_gaddr==0UL );
  FD_TEST( rec->pair.key->ul[ 0 ]==0UL &&
           rec->pair.key->ul[ 1 ]==0UL &&
           rec->pair.key->ul[ 2 ]==0UL &&
           rec->pair.key->ul[ 3 ]==0UL );
  rec->tag = 1;
}

static void
verify_recs_empty( fd_accdb_admin_t * admin ) {
  /* Verify that all hash chains are empty and unlocked */
  fd_funk_rec_map_t * rec_map = admin->funk->rec_map;
  ulong chain_cnt = fd_funk_rec_map_chain_cnt( rec_map );
  fd_funk_rec_map_shmem_private_chain_t * chains = fd_funk_rec_map_shmem_private_chain( rec_map->map, 0UL );
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) {
    FD_TEST(  fd_funk_rec_map_private_vcnt_cnt( chains[ chain_idx ].ver_cnt )   ==0UL );
    FD_TEST( (fd_funk_rec_map_private_vcnt_ver( chains[ chain_idx ].ver_cnt )&1)==0UL );
    FD_TEST( chains[ chain_idx ].head_cidx==UINT_MAX );
  }

  /* Verify that all elements are in object pool */
  fd_funk_rec_pool_t * rec_pool = admin->funk->rec_pool;
  fd_funk_rec_t *      rec_tbl  = rec_pool->ele;
  ulong                rec_max  = rec_pool->ele_max;
  for( ulong i=0UL; i<rec_max; i++ ) rec_tbl[ i ].tag = 0;

  /* Add stack-allocated free objects */
  ulong idx = fd_funk_rec_pool_private_vidx_idx( rec_pool->pool->ver_top );
  while( !fd_funk_rec_pool_idx_is_null( idx ) ) {
    /* Validate that empty item is valid initialized */
    fd_funk_rec_t * rec = rec_tbl+idx;
    FD_TEST( rec>=rec_tbl && rec<(rec_tbl+rec_max) );
    visit_rec( rec );
    idx = rec->map_next;
  }

  /* Add bump-allocated free objects */
  idx = fd_funk_rec_pool_private_vidx_idx( rec_pool->pool->ver_lazy );
  while( !fd_funk_rec_pool_idx_is_null( idx ) ) {
    visit_rec( rec_tbl+idx );
    idx++;
    if( idx>=rec_max ) idx = fd_funk_rec_pool_idx_null();
  }
  for( ulong i=0UL; i<rec_max; i++ ) FD_TEST( rec_tbl[ i ].tag==1 );
}

static void
verify_txns_empty( fd_accdb_admin_t * admin ) {
  /* Verify that all hash chains are empty and unlocked */
  fd_funk_txn_map_t * txn_map = admin->funk->txn_map;
  ulong chain_cnt = fd_funk_txn_map_chain_cnt( txn_map );
  fd_funk_txn_map_shmem_private_chain_t * chains = fd_funk_txn_map_shmem_private_chain( txn_map->map, 0UL );
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) {
    FD_TEST(  fd_funk_txn_map_private_vcnt_cnt( chains[ chain_idx ].ver_cnt )   ==0UL );
    FD_TEST( (fd_funk_txn_map_private_vcnt_ver( chains[ chain_idx ].ver_cnt )&1)==0UL );
    FD_TEST( chains[ chain_idx ].head_cidx==ULONG_MAX );
  }

  /* Verify that all elements are in object pool */
  fd_funk_txn_t * txn_pool = admin->funk->txn_pool->ele;
  ulong txn_max = admin->funk->txn_pool->ele_max;
  for( ulong i=0UL; i<txn_max; i++ ) txn_pool[ i ].tag = 0;
  fd_funk_txn_t * txn = fd_funk_txn_pool_peek( admin->funk->txn_pool );
  while( txn ) {
    /* Validate that empty item is valid initialized */
    FD_TEST( txn>=txn_pool && txn<(txn_pool+txn_max) );
    FD_TEST( !txn->tag );
    FD_TEST( txn->parent_cidx==UINT_MAX );
    if( FD_UNLIKELY( txn->child_head_cidx!=UINT_MAX ) ) FD_LOG_NOTICE(( "txn_idx %lu child_head_cidx %u", (ulong)( txn - txn_pool ), txn->child_head_cidx ));
    FD_TEST( txn->child_head_cidx==UINT_MAX );
    FD_TEST( txn->child_tail_cidx==UINT_MAX );
    FD_TEST( txn->sibling_prev_cidx==UINT_MAX );
    FD_TEST( txn->sibling_next_cidx==UINT_MAX );
    FD_TEST( txn->rec_head_idx==UINT_MAX );
    FD_TEST( txn->rec_tail_idx==UINT_MAX );
    FD_TEST( txn->state==FD_FUNK_TXN_STATE_FREE );
    FD_TEST( txn->lock->value==0 );
    txn->tag = 1;
    txn = txn->map_next==UINT_MAX ? NULL : txn_pool + txn->map_next;
  }
}

static void
verify_accdb_empty( fd_accdb_admin_t * admin ) {
  verify_recs_empty( admin );
  verify_txns_empty( admin );
  FD_TEST( fd_alloc_is_empty( admin->funk->alloc ) );
}

/* test_truncate verifies open_rw behavior with the TRUNCATE flag set.

   test_truncate_create:   Account does not exist, create new (flags+=CREATE)
   test_truncate_nonexist: Account does not exist, return NULL
   test_truncate_inplace:  Account exists and is mutable, truncate in-place
   test_truncate_copy:     Account exists and is immutable, create new and copy meta */

static void
test_truncate_create( fd_accdb_admin_t * admin,
                      fd_accdb_user_t *  accdb ) {
  fd_funk_txn_xid_t root = *fd_funk_last_publish( admin->funk );
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

  fd_accdb_advance_root( admin, &xid );
  fd_accdb_clear( admin );
}

static void
test_truncate_nonexist( fd_accdb_admin_t * admin,
                        fd_accdb_user_t *  accdb ) {
  fd_funk_txn_xid_t root = *fd_funk_last_publish( admin->funk );
  fd_funk_txn_xid_t xid = { .ul={ 2UL, 0UL } };
  fd_accdb_attach_child( admin, &root, &xid );

  fd_funk_rec_key_t key = { .ul={ 42UL } };
  fd_accdb_rw_t rw[1];
  FD_TEST( !fd_accdb_open_rw( accdb, rw, &xid, &key, 42UL, FD_ACCDB_FLAG_TRUNCATE ) );

  fd_accdb_advance_root( admin, &xid );
  fd_accdb_clear( admin );
}

static void
test_truncate_inplace( fd_accdb_admin_t * admin,
                       fd_accdb_user_t *  accdb ) {
  fd_funk_txn_xid_t root = *fd_funk_last_publish( admin->funk );
  fd_funk_txn_xid_t xid = { .ul={ 3UL, 0UL } };
  fd_accdb_attach_child( admin, &root, &xid );

  fd_funk_rec_key_t key = { .ul={ 42UL } };
  fd_accdb_rw_t rw[1];
  ulong data_sz_0 = 56UL;
  FD_TEST( fd_accdb_open_rw( accdb, rw, &xid, &key, data_sz_0, FD_ACCDB_FLAG_CREATE ) );
  FD_TEST( rw->ref->ref_type==FD_ACCDB_REF_RW );
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

  fd_accdb_advance_root( admin, &xid );
  fd_accdb_clear( admin );
}

static void
test_truncate_copy( fd_accdb_admin_t * admin,
                    fd_accdb_user_t *  accdb ) {
  fd_funk_txn_xid_t root = *fd_funk_last_publish( admin->funk );
  fd_funk_txn_xid_t xid1 = { .ul={ 4UL, 0UL } };
  fd_accdb_attach_child( admin, &root, &xid1 );

  fd_funk_rec_key_t key = { .ul={ 42UL } };
  fd_accdb_rw_t rw[1];
  FD_TEST( fd_accdb_open_rw( accdb, rw, &xid1, &key, 56UL, FD_ACCDB_FLAG_CREATE ) );
  FD_TEST( rw->ref->ref_type==FD_ACCDB_REF_RW );
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

  fd_accdb_advance_root( admin, &xid1 );
  fd_accdb_advance_root( admin, &xid2 );
  fd_accdb_clear( admin );
}

static void
test_truncate( fd_wksp_t * wksp ) {
  ulong txn_max =  4UL;
  ulong rec_max = 32UL;
  ulong funk_footprint = fd_funk_footprint( txn_max, rec_max );
  void * shfunk = fd_wksp_alloc_laddr( wksp, fd_funk_align(), funk_footprint, WKSP_TAG );
  FD_TEST( shfunk );
  FD_TEST( fd_funk_new( shfunk, WKSP_TAG, 0UL, txn_max, rec_max ) );
  init_funk( shfunk );
  fd_accdb_admin_t admin[1];
  FD_TEST( fd_accdb_admin_join( admin, shfunk ) );
  fd_accdb_user_t accdb[1];
  FD_TEST( fd_accdb_user_v1_init( accdb, shfunk ) );

  test_truncate_create  ( admin, accdb );
  test_truncate_nonexist( admin, accdb );
  test_truncate_inplace ( admin, accdb );
  test_truncate_copy    ( admin, accdb );

  fd_accdb_user_fini( accdb );
  fd_accdb_admin_leave( admin, NULL );
  fd_wksp_free_laddr( fd_funk_delete( shfunk ) );
}

/* test_random_ops randomly creates fork graph nodes, inserts records,
   and roots nodes.  This test verifies the following:
   - fork tree invariants
   - fork index invariants
   - record replacement/GC when rooting
   Correctness is verified by replicating accdb operations against
   test_funk_common. */

static void
test_random_ops( fd_wksp_t * wksp,
                 fd_rng_t *  rng,
                 ulong       txn_max,
                 ulong       rec_max,
                 ulong       iter_max ) {
  ulong funk_seed      = fd_rng_ulong( rng );
  ulong funk_footprint = fd_funk_footprint( txn_max, rec_max );
  void * shfunk = fd_wksp_alloc_laddr( wksp, fd_funk_align(), funk_footprint, WKSP_TAG );
  FD_TEST( shfunk );
  FD_TEST( fd_funk_new( shfunk, WKSP_TAG, funk_seed, txn_max, rec_max ) );
  init_funk( shfunk );

  funk_t * ref = funk_new();

  fd_accdb_admin_t admin[1];
  FD_TEST( fd_accdb_admin_join( admin, shfunk ) );
  fd_accdb_user_t accdb[1];
  FD_TEST( fd_accdb_user_v1_init( accdb, shfunk ) );
  verify_accdb_empty( admin );
  fd_funk_t * funk = fd_accdb_user_v1_funk( accdb );

  fd_funk_txn_xid_t txid[1];
  fd_funk_rec_key_t tkey[1];

  for( ulong iter=0UL; iter<iter_max; iter++ ) {
    if( !(iter & 16383UL) ) {
      FD_LOG_NOTICE(( "Iter %7lu (txn_cnt %3lu rec_cnt %3lu)", iter, ref->txn_cnt, ref->rec_cnt ));
      fd_accdb_verify( admin );
    }

    uint r = fd_rng_uint( rng );

    uint op = fd_rng_uint_roll( rng, 1U+2U+8U );
    if( op>=3U ) { /* insert (2x as frequent as attach_child) */

      if( FD_UNLIKELY( fd_funk_rec_is_full( funk ) ) ) continue;
      if( FD_UNLIKELY( !ref->txn_cnt               ) ) continue;

      ulong idx = fd_rng_ulong_roll( rng, ref->txn_cnt );
      txn_t * rtxn = ref->txn_map_head; for( ulong rem=idx; rem; rem-- ) rtxn = rtxn->map_next;
      if( txn_is_frozen( rtxn ) ) continue; /* FIXME verify that txn also frozen in real funk */
      ulong rxid = rtxn->xid;

      ulong rkey = (ulong)( r&63U );
      if( rec_query( ref, rtxn, rkey ) ) {
        /* record already exists ... cross-check with funk */
        fd_funk_xid_key_pair_t key[1]; xid_set( key->xid, rxid ); key_set( key->key, rkey );
        fd_funk_rec_map_query_t query[1];
        FD_TEST( fd_funk_rec_map_query_try( funk->rec_map, key, NULL, query, 0 )==FD_MAP_SUCCESS );
        continue;
      }
      rec_insert( ref, rtxn, rkey );

      int err;
      fd_funk_rec_prepare_t prepare[1];
      fd_funk_rec_t * trec = fd_funk_rec_prepare( funk, xid_set( txid, rxid ), key_set( tkey, rkey ), prepare, &err );
      FD_TEST( trec );
      void * val = fd_funk_val_truncate( trec, funk->alloc, funk->wksp, 1UL, 8UL, NULL );
      FD_TEST( val );
      FD_STORE( ulong, val, rkey );
      fd_funk_rec_publish( funk, prepare );
#if VERBOSE
      FD_LOG_DEBUG(( "accdb insert key %lu txn %lu:%lu", rkey, txid->ul[0], txid->ul[1] ));
#endif

    } else if( op>=1U ) { /* attach_child (2x as frequent as advance_root) */

      if( FD_UNLIKELY( fd_funk_txn_is_full( funk ) ) ) continue;

      txn_t *           rparent;
      fd_funk_txn_xid_t tparent;

      ulong idx = fd_rng_ulong_roll( rng, ref->txn_cnt+1UL );
      if( idx<ref->txn_cnt ) { /* Branch off in-prep */
        rparent = ref->txn_map_head; for( ulong rem=idx; rem; rem-- ) rparent = rparent->map_next;
        xid_set( &tparent, rparent->xid );
      } else { /* Branch off last published */
        rparent = NULL;
        fd_funk_txn_xid_copy( &tparent, fd_funk_last_publish( funk ) );
      }

      ulong rxid = xid_unique();
      txn_prepare( ref, rparent, rxid );
      fd_accdb_attach_child( admin, &tparent, xid_set( txid, rxid ) );

    } else { /* advance_root */

      if( FD_UNLIKELY( !ref->txn_cnt ) ) continue;

      txn_t * rtxn;
      for(;;) {  /* cycle until we find a writable txn */
        ulong idx = fd_rng_ulong_roll( rng, ref->txn_cnt );
        rtxn = ref->txn_map_head; for( ulong rem=idx; rem; rem-- ) rtxn = rtxn->map_next;
        if( rtxn->parent ) continue;
        xid_set( txid, rtxn->xid );
        break;
      }

      ulong cnt = txn_publish( ref, rtxn, 0UL ); FD_TEST( cnt==1UL );
      fd_accdb_advance_root( admin, txid );

    }

  }

  fd_accdb_verify( admin );
  fd_accdb_clear( admin );
  verify_accdb_empty( admin );
  fd_accdb_verify( admin );

  fd_accdb_user_fini( accdb );
  fd_accdb_admin_leave( admin, NULL );
  fd_wksp_free_laddr( fd_funk_delete( shfunk ) );

  funk_delete( ref );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
# if VERBOSE
  fd_log_level_stderr_set( 0 );
  fd_log_level_logfile_set( 0 );
# endif

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL,      "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL,             1UL );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        seed     = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed",      NULL,          5678UL );
  ulong        txn_max  = fd_env_strip_cmdline_ulong( &argc, &argv, "--txn-max",   NULL,            32UL );
  uint         rec_max  = fd_env_strip_cmdline_uint(  &argc, &argv, "--rec-max",   NULL,            512U );
  ulong        iter_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-max",  NULL,       1048576UL );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)seed, 0UL ) );

  FD_LOG_NOTICE(( "using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                  _page_sz, page_cnt, near_cpu ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "Unable to attach to wksp" ));

  test_truncate( wksp );
  test_random_ops( wksp, rng, txn_max, rec_max, iter_max );

  /* FIXME leak check */
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
