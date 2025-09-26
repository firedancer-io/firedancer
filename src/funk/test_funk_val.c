#include "fd_funk.h"

#if FD_HAS_HOSTED

#include "test_funk_common.h"

FD_STATIC_ASSERT( FD_FUNK_REC_VAL_MAX==UINT_MAX, unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL,            NULL );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL,      "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL,             1UL );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL,          1234UL );
  ulong        seed     = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed",      NULL,          5678UL );
  ulong        txn_max  = fd_env_strip_cmdline_ulong( &argc, &argv, "--txn-max",   NULL,            32UL );
  uint         rec_max  = fd_env_strip_cmdline_uint(  &argc, &argv, "--rec-max",   NULL,             128 );
  ulong        iter_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-max",  NULL,       1048576UL );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "Unable to attach to wksp" ));

  FD_LOG_NOTICE(( "Testing with --wksp-tag %lu --seed %lu --txn-max %lu --rxn-max %u --iter-max %lu",
                  wksp_tag, seed, txn_max, rec_max, iter_max ));

  void * shfunk = fd_funk_new( fd_wksp_alloc_laddr(
      wksp, fd_funk_align(), fd_funk_footprint( txn_max, rec_max ), wksp_tag ),
      wksp_tag, seed, txn_max, rec_max );
  fd_funk_t tst_[1];
  fd_funk_t * tst = fd_funk_join( tst_, shfunk );
  if( FD_UNLIKELY( !tst ) ) FD_LOG_ERR(( "Unable to create tst" ));

  fd_alloc_t * alloc = fd_funk_alloc( tst );

  funk_t * ref = funk_new();

  for( ulong iter=0UL; iter<iter_max; iter++ ) {
    if( !(iter & 16383UL) ) FD_LOG_NOTICE(( "Iter %7lu (txn_cnt %3lu rec_cnt %3lu)", iter, ref->txn_cnt, ref->rec_cnt ));

  //if( !ref->txn_cnt ) {
  //  FD_LOG_NOTICE(( "***************************************************************" ));
  //  for( rec_t * rrec=ref->rec_head; rrec; rrec=rrec->next ) FD_LOG_NOTICE(( "has %lu", rrec->key ));
  //}

#   define TEST_TAIL_PADDING(start) do {                              \
      uchar const * buf = (uchar const *)fd_funk_val_const( trec, wksp ); \
      ulong         end = fd_funk_val_max( trec );                        \
      uchar         tmp = (uchar)0;                                       \
      for( ulong off=start; off<end; off++ ) tmp |= buf[off];             \
      FD_TEST( !tmp );                                                    \
    } while(0)

#ifdef FD_FUNK_HANDHOLDING
    FD_TEST( !fd_funk_verify( tst ) );
#endif

    fd_funk_txn_xid_t txid[1];
    fd_funk_rec_key_t tkey[1];

    rec_t * rrec = ref->rec_map_head;
    while( rrec ) {

      ulong rxid = rrec->txn ? rrec->txn->xid : ULONG_MAX;
      ulong rkey = rrec->key;

      xid_set( txid, rxid );
      key_set( tkey, rkey );

      fd_funk_rec_query_t rec_query[1];
      fd_funk_rec_t const * trec = fd_funk_rec_query_try( tst, txid, tkey, rec_query );

      void const * _val = (void const *)fd_funk_val( trec, wksp );

      FD_TEST( !fd_funk_rec_query_test( rec_query ) );

      if( rrec->erase ) {

        FD_TEST( !_val );

        FD_TEST( !fd_funk_val_sz   ( trec ) );
        FD_TEST( !fd_funk_val_max  ( trec ) );
        FD_TEST( !fd_funk_val_const( trec, wksp ) );

      } else {

        FD_TEST( _val && FD_LOAD( uint, _val )==rrec->val );

        FD_TEST( fd_funk_val_sz   ( trec       )==sizeof(uint)       );
        FD_TEST( fd_funk_val_max  ( trec       )>=sizeof(uint)       );
        FD_TEST( fd_funk_val_const( trec, wksp )==(void const *)_val );
      }

      rrec = rrec->map_next;
    }

    uint r = fd_rng_uint( rng );

    uint op = fd_rng_uint_roll( rng, 1U+1U+16U+128U+128U );

    if( op>=146U ) { /* Insert 8x prepare rate */

      if( FD_UNLIKELY( fd_funk_rec_is_full( tst ) ) ) continue;

      ulong   idx = fd_rng_ulong_roll( rng, ref->txn_cnt+1UL );
      txn_t * rtxn;
      ulong   rxid;
      if( idx<ref->txn_cnt ) { /* insert into in-prep */
        rtxn = ref->txn_map_head; for( ulong rem=idx; rem; rem-- ) rtxn = rtxn->map_next;
        if( txn_is_frozen( rtxn ) ) continue;
        rxid = rtxn->xid;
      } else { /* insert into last published */
        if( funk_is_frozen( ref ) ) continue;
        rtxn = NULL;
        rxid = ref->last_publish;
      }

      ulong rkey = (ulong)(r & 63U); r >>= 6;
      if( rec_query( ref, rtxn, rkey ) ) continue;

      rec_t * rrec = rec_insert( ref, rtxn, rkey );

      int err = 1;
      fd_funk_rec_prepare_t prepare[1];
      fd_funk_rec_t * trec =
        fd_funk_rec_prepare( tst, xid_set( txid, rxid ), key_set( tkey, rkey ), prepare, &err );
      FD_TEST( trec && !err );

      uint val = (fd_rng_uint( rng )<<2) | 1U;
      rrec->val = val;

      memcpy( fd_funk_val_truncate( trec, alloc, wksp, 0UL, sizeof(val), NULL ), &val, sizeof(val) );

      fd_funk_rec_publish( tst, prepare );

      FD_TEST( FD_LOAD( uint, fd_funk_val( trec, wksp ) )==val );
      TEST_TAIL_PADDING( 4UL );

    } else if( op>=18UL ) { /* Remove and insert at same rate */

      if( FD_UNLIKELY( !ref->rec_cnt ) ) continue;

      ulong   idx = fd_rng_ulong_roll( rng, ref->rec_cnt );
      rec_t * rrec = ref->rec_map_head; for( ulong rem=idx; rem; rem-- ) rrec = rrec->map_next;

      ulong rxid;
      if( rrec->txn ) {
        if( txn_is_frozen( rrec->txn ) ) continue;
        rxid = rrec->txn->xid;
      } else {
        if( funk_is_frozen( ref ) ) continue;
        rxid = ref->last_publish;
      }
      ulong rkey = rrec->key;

      rec_remove( ref, rrec );

      FD_TEST( !fd_funk_rec_remove( tst, xid_set( txid, rxid ), key_set( tkey, rkey ), NULL ) );

    } else if( op>=2 ) { /* Prepare 8x as publish and cancel combined */

      if( FD_UNLIKELY( fd_funk_txn_is_full( tst ) ) ) continue;

      txn_t *           rparent;
      fd_funk_txn_xid_t tparent;

      ulong idx = fd_rng_ulong_roll( rng, ref->txn_cnt+1UL );
      if( idx<ref->txn_cnt ) { /* Branch off in-prep */
        rparent = ref->txn_map_head; for( ulong rem=idx; rem; rem-- ) rparent = rparent->map_next;
        tparent = (fd_funk_txn_xid_t){ .ul={ rparent->xid, rparent->xid } };
      } else { /* Branch off last published */
        rparent = NULL;
        fd_funk_txn_xid_copy( &tparent, fd_funk_last_publish( tst ) );
      }

      ulong rxid = xid_unique();
      txn_prepare( ref, rparent, rxid );
      fd_funk_txn_prepare( tst, &tparent, xid_set( txid, rxid ) );

    } else if( op>=1UL ) { /* Cancel (same rate as publish) */

      if( FD_UNLIKELY( !ref->txn_cnt ) ) continue;

      ulong idx = fd_rng_ulong_roll( rng, ref->txn_cnt );

      txn_t * rtxn = ref->txn_map_head; for( ulong rem=idx; rem; rem-- ) rtxn = rtxn->map_next;
      xid_set( txid, rtxn->xid );

      ulong cnt = ref->txn_cnt; txn_cancel( ref, rtxn ); cnt -= ref->txn_cnt;
      FD_TEST( fd_funk_txn_cancel( tst, txid )==cnt );

    } else { /* Publish (same rate as cancel) */

      if( FD_UNLIKELY( !ref->txn_cnt ) ) continue;

      ulong idx = fd_rng_ulong_roll( rng, ref->txn_cnt );

      txn_t * rtxn = ref->txn_map_head; for( ulong rem=idx; rem; rem-- ) rtxn = rtxn->map_next;
      xid_set( txid, rtxn->xid );

      ulong cnt = txn_publish( ref, rtxn, 0UL );
      FD_TEST( fd_funk_txn_publish( tst, txid )==cnt );

    }
  }

  funk_delete( ref );

  fd_funk_leave( tst, NULL );
  fd_wksp_free_laddr( fd_funk_delete( shfunk ) );
  if( name ) fd_wksp_detach( wksp );
  else       fd_wksp_delete_anonymous( wksp );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED capabilities" ));
  fd_halt();
  return 0;
}

#endif
