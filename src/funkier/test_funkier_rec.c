#include "fd_funkier.h"

#if FD_HAS_HOSTED

FD_STATIC_ASSERT( FD_FUNKIER_REC_ALIGN    == 64UL, unit_test );

FD_STATIC_ASSERT( FD_FUNKIER_REC_FLAG_ERASE==1UL, unit_test );

FD_STATIC_ASSERT( FD_FUNKIER_REC_IDX_NULL==ULONG_MAX, unit_test );

#include "test_funkier_common.h"

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
  ulong        rec_max  = fd_env_strip_cmdline_ulong( &argc, &argv, "--rec-max",   NULL,           128UL );
  ulong        iter_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-max",  NULL,       1048576UL );
  int          verbose  = fd_env_strip_cmdline_int  ( &argc, &argv, "--verbose",   NULL,               0 );

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

  FD_LOG_NOTICE(( "Testing with --wksp-tag %lu --seed %lu --txn-max %lu --rxn-max %lu --iter-max %lu --verbose %i",
                  wksp_tag, seed, txn_max, rec_max, iter_max, verbose ));

  fd_funkier_t * tst = fd_funkier_join( fd_funkier_new( fd_wksp_alloc_laddr( wksp, fd_funkier_align(), fd_funkier_footprint(txn_max, rec_max), wksp_tag ),
                                               wksp_tag, seed, txn_max, rec_max ) );
  if( FD_UNLIKELY( !tst ) ) FD_LOG_ERR(( "Unable to create tst" ));

  fd_funkier_txn_map_t txn_map = fd_funkier_txn_map( tst, wksp );
  fd_funkier_txn_pool_t txn_pool = fd_funkier_txn_pool( tst, wksp );

  funk_t * ref = funk_new();

  for( ulong iter=0UL; iter<iter_max; iter++ ) {
    if( !(iter & 16383UL) ) FD_LOG_NOTICE(( "Iter %7lu (txn_cnt %3lu rec_cnt %3lu)", iter, ref->txn_cnt, ref->rec_cnt ));

  //if( !ref->txn_cnt ) {
  //  FD_LOG_NOTICE(( "***************************************************************" ));
  //  for( rec_t * rrec=ref->rec_head; rrec; rrec=rrec->next ) FD_LOG_NOTICE(( "has %lu", rrec->key ));
  //}

#ifdef FD_FUNKIER_HANDHOLDING
    FD_TEST( !fd_funkier_verify( tst ) );
#endif

    fd_funkier_txn_xid_t txid[1];
    fd_funkier_rec_key_t tkey[1];

    do {

      int is_frozen = fd_funkier_last_publish_is_frozen( tst );

      FD_TEST( is_frozen==funk_is_frozen( ref ) );
      FD_TEST( xid_eq( fd_funkier_last_publish( tst ), ref->last_publish ) );

      ulong rpmap = 0UL;
      for( rec_t * rrec=ref->rec_head; rrec; rrec=rrec->next ) {
        FD_TEST( !fd_ulong_extract_bit( rpmap, (int)rrec->key ) );
        rpmap = fd_ulong_set_bit( rpmap, (int)rrec->key );
      }

      ulong tpmap = 0UL;
      for( fd_funkier_rec_t const * trec=fd_funkier_txn_first_rec( tst, NULL );
           trec;
           trec=fd_funkier_txn_next_rec( tst, trec ) ) {
        ulong _tkey = fd_funkier_rec_key( trec )->ul[0]; FD_TEST( _tkey<64UL );
        FD_TEST( !fd_ulong_extract_bit( tpmap, (int)_tkey ) );
        tpmap = fd_ulong_set_bit( tpmap, (int)_tkey );
      }

      ulong rkey = (ulong)(fd_rng_uint( rng ) & 63U);
      key_set( tkey, rkey );

      fd_funkier_rec_query_t rec_query[1];
#ifdef FD_FUNKIER_HANDHOLDING
      FD_TEST( !fd_funkier_rec_query_try         ( NULL, NULL, NULL, NULL ) );
      FD_TEST( !fd_funkier_rec_query_try         ( NULL, NULL, tkey, rec_query ) );
      FD_TEST( !fd_funkier_rec_query_try         ( tst,  NULL, NULL, rec_query ) );
      FD_TEST( !fd_funkier_rec_query_try         ( tst,  NULL, tkey, NULL ) );

      FD_TEST( !fd_funkier_rec_query_try_global      ( NULL, NULL, NULL, NULL, NULL ) );
      FD_TEST( !fd_funkier_rec_query_try_global      ( NULL, NULL, tkey, NULL, rec_query ) );
      FD_TEST( !fd_funkier_rec_query_try_global      ( tst,  NULL, NULL, NULL, rec_query ) );
      FD_TEST( !fd_funkier_rec_query_try_global      ( tst,  NULL, tkey, NULL, NULL ) );
#endif

      rec_t *               rrec = rec_query_global( ref, NULL, rkey );
      fd_funkier_rec_t const * trec = fd_funkier_rec_query_try_global( tst, NULL, tkey, NULL, rec_query );
      if( !rrec || rrec->erase ) FD_TEST( !trec );
      else                       FD_TEST( trec && xid_eq( fd_funkier_rec_xid( trec ), rrec->txn ? rrec->txn->xid : 0UL ) );
      FD_TEST( !fd_funkier_rec_query_test( rec_query ) );

#ifdef FD_FUNKIER_HANDHOLDING
      FD_TEST( fd_funkier_rec_remove( NULL, NULL, NULL, NULL, 0UL )==FD_FUNKIER_ERR_INVAL );
      FD_TEST( fd_funkier_rec_remove( NULL, NULL, tkey, NULL, 0UL )==FD_FUNKIER_ERR_INVAL );
      FD_TEST( fd_funkier_rec_remove( tst, NULL, NULL, NULL, 0UL )==FD_FUNKIER_ERR_INVAL );
#endif

      if( trec ) {
        if( is_frozen ) {
          FD_TEST( fd_funkier_rec_remove( tst, NULL, tkey, NULL, 0UL )==FD_FUNKIER_ERR_FROZEN );
        }
      }

      fd_funkier_rec_prepare_t rec_prepare[1];
      int err;
#ifdef FD_FUNKIER_HANDHOLDING
      FD_TEST( !fd_funkier_rec_prepare( NULL, NULL, NULL, NULL, NULL ) );
      FD_TEST( !fd_funkier_rec_prepare( NULL, NULL, NULL, NULL, &err ) ); FD_TEST( err==FD_FUNKIER_ERR_INVAL );
#endif

      if( is_frozen ) {
        FD_TEST( !fd_funkier_rec_prepare( tst, NULL, tkey, rec_prepare, NULL ) );
        FD_TEST( !fd_funkier_rec_prepare( tst, NULL, tkey, rec_prepare, &err ) ); FD_TEST( err==FD_FUNKIER_ERR_FROZEN );
      } else if( fd_funkier_rec_is_full( tst ) ) {
        FD_TEST( !fd_funkier_rec_prepare( tst, NULL, tkey, rec_prepare, NULL ) );
        FD_TEST( !fd_funkier_rec_prepare( tst, NULL, tkey, rec_prepare, &err ) ); FD_TEST( err==FD_FUNKIER_ERR_REC );
      }

    } while(0);

    ulong cnt = 0UL;

    txn_t * rtxn = ref->txn_map_head;
    while( rtxn ) {

      fd_funkier_txn_t * ttxn = fd_funkier_txn_query( xid_set( txid, rtxn->xid ), &txn_map );
      FD_TEST( ttxn && xid_eq( fd_funkier_txn_xid( ttxn ), rtxn->xid ) );

#     define TEST_RELATIVE(rel) do {                                    \
        txn_t *         r##rel = rtxn->rel;                             \
        fd_funkier_txn_t * t##rel = fd_funkier_txn_##rel( ttxn, &txn_pool ); \
        if( !r##rel ) FD_TEST( !t##rel );                               \
        else          FD_TEST( t##rel && xid_eq( fd_funkier_txn_xid( t##rel ), r##rel->xid ) ); \
      } while(0)
      TEST_RELATIVE( parent       );
      TEST_RELATIVE( child_head   );
      TEST_RELATIVE( child_tail   );
      TEST_RELATIVE( sibling_prev );
      TEST_RELATIVE( sibling_next );
#     undef TEST_RELATIVE

      int ttxn_is_frozen = fd_funkier_txn_is_frozen( ttxn );

      FD_TEST( txn_is_frozen    ( rtxn )==ttxn_is_frozen                    );
      FD_TEST( txn_is_only_child( rtxn )==fd_funkier_txn_is_only_child( ttxn ) );

      txn_t *         rancestor = txn_ancestor( rtxn );
      fd_funkier_txn_t * tancestor = fd_funkier_txn_ancestor( ttxn, &txn_pool );
      if( rancestor ) FD_TEST( tancestor && xid_eq( fd_funkier_txn_xid( tancestor ), rancestor->xid ) );
      else            FD_TEST( !tancestor );

      txn_t *         rdescendant = txn_descendant( rtxn );
      fd_funkier_txn_t * tdescendant = fd_funkier_txn_descendant( ttxn, &txn_pool );
      if( rdescendant ) FD_TEST( tdescendant && xid_eq( fd_funkier_txn_xid( tdescendant ), rdescendant->xid ) );
      else              FD_TEST( !tdescendant );

      ulong rkey = (ulong)(fd_rng_uint( rng ) & 63U);
      key_set( tkey, rkey );

      fd_funkier_rec_query_t rec_query[1];
#ifdef FD_FUNKIER_HANDHOLDING
      FD_TEST( !fd_funkier_rec_query_try         ( NULL, ttxn, NULL, NULL ) );
      FD_TEST( !fd_funkier_rec_query_try         ( NULL, ttxn, tkey, rec_query ) );
      FD_TEST( !fd_funkier_rec_query_try         ( tst,  ttxn, NULL, rec_query ) );
      FD_TEST( !fd_funkier_rec_query_try         ( tst,  ttxn, tkey, NULL ) );

      FD_TEST( !fd_funkier_rec_query_try_global      ( NULL, ttxn, NULL, NULL, NULL ) );
      FD_TEST( !fd_funkier_rec_query_try_global      ( NULL, ttxn, tkey, NULL, rec_query ) );
      FD_TEST( !fd_funkier_rec_query_try_global      ( tst,  ttxn, NULL, NULL, rec_query ) );
      FD_TEST( !fd_funkier_rec_query_try_global      ( tst,  ttxn, tkey, NULL, NULL ) );
#endif

      rec_t *               rrec = rec_query_global( ref, rtxn, rkey );
      fd_funkier_rec_t const * trec = fd_funkier_rec_query_try_global( tst, ttxn, tkey, NULL, rec_query );
      if( !rrec || rrec->erase ) FD_TEST( !trec );
      else {
        FD_TEST( trec && xid_eq( fd_funkier_rec_xid( trec ), rrec->txn ? rrec->txn->xid : 0UL ) );
      }
      FD_TEST( !fd_funkier_rec_query_test( rec_query ) );

#ifdef FD_FUNKIER_HANDHOLDING
      FD_TEST( fd_funkier_rec_remove( NULL, ttxn, NULL, NULL, 0UL )==FD_FUNKIER_ERR_INVAL );
      FD_TEST( fd_funkier_rec_remove( NULL, ttxn, tkey, NULL, 0UL )==FD_FUNKIER_ERR_INVAL );
      FD_TEST( fd_funkier_rec_remove( tst, ttxn, NULL, NULL, 0UL )==FD_FUNKIER_ERR_INVAL );
#endif

      if( trec && ttxn_is_frozen ) {
        FD_TEST( fd_funkier_rec_remove( tst, ttxn, tkey, NULL, 0UL )==FD_FUNKIER_ERR_FROZEN );
      }

      fd_funkier_rec_prepare_t rec_prepare[1];
      int err;
#ifdef FD_FUNKIER_HANDHOLDING
      FD_TEST( !fd_funkier_rec_prepare( NULL, ttxn, NULL, NULL, NULL ) );
      FD_TEST( !fd_funkier_rec_prepare( NULL, ttxn, NULL, NULL, &err ) ); FD_TEST( err==FD_FUNKIER_ERR_INVAL );
#endif

      if( ttxn_is_frozen ) {
        FD_TEST( !fd_funkier_rec_prepare( tst, ttxn, tkey, rec_prepare, NULL ) );
        FD_TEST( !fd_funkier_rec_prepare( tst, ttxn, tkey, rec_prepare, &err ) ); FD_TEST( err==FD_FUNKIER_ERR_FROZEN );
      } else if( fd_funkier_rec_is_full( tst ) ) {
        FD_TEST( !fd_funkier_rec_prepare( tst, ttxn, tkey, rec_prepare, NULL ) );
        FD_TEST( !fd_funkier_rec_prepare( tst, ttxn, tkey, rec_prepare, &err ) ); FD_TEST( err==FD_FUNKIER_ERR_REC );
      }

      ulong rpmap = 0UL;
      for( rec_t * rrec=rtxn->rec_head; rrec; rrec=rrec->next ) {
        FD_TEST( !fd_ulong_extract_bit( rpmap, (int)rrec->key ) );
        rpmap = fd_ulong_set_bit( rpmap, (int)rrec->key );
      }

      ulong tpmap = 0UL;
      for( fd_funkier_rec_t const * trec=fd_funkier_txn_first_rec( tst, ttxn );
           trec;
           trec=fd_funkier_txn_next_rec( tst, trec ) ) {
        ulong _tkey = fd_funkier_rec_key( trec )->ul[0]; FD_TEST( _tkey<64UL );
        FD_TEST( !fd_ulong_extract_bit( tpmap, (int)_tkey ) );
        tpmap = fd_ulong_set_bit( tpmap, (int)_tkey );
      }

      FD_TEST( rpmap==tpmap );

      cnt++;
      rtxn = rtxn->map_next;
    }

    FD_TEST( cnt==ref->txn_cnt );

    cnt = 0UL;

    rec_t * rrec = ref->rec_map_head;
    while( rrec ) {

      ulong rxid = rrec->txn ? rrec->txn->xid : 0UL;
      ulong rkey = rrec->key;

      xid_set( txid, rxid );
      key_set( tkey, rkey );

      fd_funkier_txn_t const * ttxn = rxid ? fd_funkier_txn_query( txid, &txn_map ) : NULL;
      fd_funkier_rec_query_t rec_query[1];
      fd_funkier_rec_t const * trec = fd_funkier_rec_query_try( tst, ttxn, tkey, rec_query );
      FD_TEST( trec && xid_eq( fd_funkier_rec_xid( trec ), rxid ) && key_eq( fd_funkier_rec_key( trec ), rkey ) );
      FD_TEST( !fd_funkier_rec_query_test( rec_query ) );

#     define TEST_RELATIVE(rel) do {                                             \
        rec_t *               r##rel = rrec->rel;                                \
        fd_funkier_rec_t const * t##rel = fd_funkier_txn_##rel##_rec( tst, trec ); \
        if( !r##rel ) FD_TEST( !t##rel );                                        \
        else {                                                                   \
          ulong r##rel##xid = r##rel->txn ? r##rel->txn->xid : 0UL;              \
          FD_TEST( t##rel && xid_eq( fd_funkier_rec_xid( t##rel ), r##rel##xid ) && \
                             key_eq( fd_funkier_rec_key( t##rel ), r##rel->key ) ); \
        }                                                                        \
      } while(0)
      TEST_RELATIVE( prev );
      TEST_RELATIVE( next );
#     undef TEST_RELATIVE

      cnt++;
      rrec = rrec->map_next;
    }

    FD_TEST( cnt==ref->rec_cnt );

    uint r = fd_rng_uint( rng );

    uint op = fd_rng_uint_roll( rng, 1U+1U+16U+128U+128U );
    if( op>=146U ) { /* Insert 8x prepare rate */

      if( FD_UNLIKELY( fd_funkier_rec_is_full( tst ) ) ) continue;

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
        rxid = 0UL;
      }

      ulong rkey = (ulong)(r & 63U); r >>= 6;
      if( rec_query( ref, rtxn, rkey ) ) continue;
      rec_insert( ref, rtxn, rkey );

      int err;
      fd_funkier_txn_t * ttxn = fd_funkier_txn_query( xid_set( txid, rxid ), &txn_map );
      fd_funkier_rec_prepare_t prepare[1];
      fd_funkier_rec_t const * trec = fd_funkier_rec_prepare( tst, ttxn, key_set( tkey, rkey ), prepare, &err );
      FD_TEST( trec );
      FD_TEST( !err );
      fd_funkier_rec_publish( prepare );

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
        rxid = 0UL;
      }
      ulong rkey = rrec->key;

      rec_remove( ref, rrec );

      fd_funkier_txn_t * ttxn = rxid ? fd_funkier_txn_query( xid_set( txid, rxid ), &txn_map ) : NULL;
      fd_funkier_rec_query_t query[1];
      fd_funkier_rec_t const * trec = fd_funkier_rec_query_try( tst, ttxn, key_set( tkey, rkey ), query );
      FD_TEST( trec );
      FD_TEST( !fd_funkier_rec_query_test( query ) );

      fd_funkier_rec_t * trec2;
      FD_TEST( !fd_funkier_rec_remove( tst, ttxn, key_set( tkey, rkey ), &trec2, 0UL ) );
      FD_TEST( trec == trec2 );

    } else if( op>=2 ) { /* Prepare 8x as publish and cancel combined */

      if( FD_UNLIKELY( fd_funkier_txn_is_full( tst ) ) ) continue;

      txn_t *         rparent;
      fd_funkier_txn_t * tparent;

      ulong idx = fd_rng_ulong_roll( rng, ref->txn_cnt+1UL );
      if( idx<ref->txn_cnt ) { /* Branch off in-prep */
        rparent = ref->txn_map_head; for( ulong rem=idx; rem; rem-- ) rparent = rparent->map_next;
        tparent = fd_funkier_txn_query( xid_set( txid, rparent->xid ), &txn_map );
      } else { /* Branch off last published */
        rparent = NULL;
        tparent = NULL;
      }

      ulong rxid = xid_unique();
      txn_prepare( ref, rparent, rxid );
      FD_TEST( fd_funkier_txn_prepare( tst, tparent, xid_set( txid, rxid ), verbose ) );

    } else if( op>=1UL ) {

      if( FD_UNLIKELY( !ref->txn_cnt ) ) continue;

      ulong idx = fd_rng_ulong_roll( rng, ref->txn_cnt );

      txn_t *         rtxn = ref->txn_map_head; for( ulong rem=idx; rem; rem-- ) rtxn = rtxn->map_next;
      fd_funkier_txn_t * ttxn = fd_funkier_txn_query( xid_set( txid, rtxn->xid ), &txn_map );

      ulong cnt = ref->txn_cnt; txn_cancel( ref, rtxn ); cnt -= ref->txn_cnt;
      FD_TEST( fd_funkier_txn_cancel( tst, ttxn, verbose )==cnt );

    } else {

      if( FD_UNLIKELY( !ref->txn_cnt ) ) continue;

      ulong idx = fd_rng_ulong_roll( rng, ref->txn_cnt );
      txn_t *         rtxn = ref->txn_map_head; for( ulong rem=idx; rem; rem-- ) rtxn = rtxn->map_next;
      fd_funkier_txn_t * ttxn = fd_funkier_txn_query( xid_set( txid, rtxn->xid ), &txn_map );

      ulong cnt = txn_publish( ref, rtxn, 0UL );
      FD_TEST( fd_funkier_txn_publish( tst, ttxn, verbose )==cnt );
    }

  }

  funk_delete( ref );

  fd_wksp_free_laddr( fd_funkier_delete( fd_funkier_leave( tst ) ) );
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
