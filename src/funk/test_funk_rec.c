#include "fd_funk.h"

#if FD_HAS_HOSTED

FD_STATIC_ASSERT( FD_FUNK_REC_ALIGN    == 32UL, unit_test );

FD_STATIC_ASSERT( FD_FUNK_REC_FLAG_ERASE==1UL, unit_test );

FD_STATIC_ASSERT( FD_FUNK_REC_IDX_NULL==ULONG_MAX, unit_test );

#include "test_funk_common.h"

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

  fd_funk_t * tst = fd_funk_join( fd_funk_new( fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(), wksp_tag ),
                                               wksp_tag, seed, txn_max, rec_max ) );
  if( FD_UNLIKELY( !tst ) ) FD_LOG_ERR(( "Unable to create tst" ));

  fd_funk_txn_t * txn_map = fd_funk_txn_map( tst, wksp );
  fd_funk_rec_t * rec_map = fd_funk_rec_map( tst, wksp );

  FD_TEST(  fd_funk_rec_idx_is_null( FD_FUNK_REC_IDX_NULL ) );
  FD_TEST( !fd_funk_rec_idx_is_null( 0UL                  ) );

  FD_TEST( !fd_funk_rec_cnt    ( rec_map ) );
  FD_TEST( !fd_funk_rec_is_full( rec_map ) );

  funk_t * ref = funk_new();

  for( ulong iter=0UL; iter<iter_max; iter++ ) {
    if( !(iter & 16383UL) ) FD_LOG_NOTICE(( "Iter %7lu (txn_cnt %3lu rec_cnt %3lu)", iter, ref->txn_cnt, ref->rec_cnt ));

  //if( !ref->txn_cnt ) {
  //  FD_LOG_NOTICE(( "***************************************************************" ));
  //  for( rec_t * rrec=ref->rec_head; rrec; rrec=rrec->next ) FD_LOG_NOTICE(( "has %lu", rrec->key ));
  //}

    FD_TEST( !fd_funk_verify( tst ) );

    fd_funk_txn_xid_t txid[1];
    fd_funk_rec_key_t tkey[1];

    do {

      int is_frozen = fd_funk_last_publish_is_frozen( tst );

      FD_TEST( is_frozen==funk_is_frozen( ref ) );
      FD_TEST( xid_eq( fd_funk_last_publish( tst ), ref->last_publish ) );

      txn_t *         rdescendant = funk_descendant( ref );
      fd_funk_txn_t * tdescendant = fd_funk_last_publish_descendant( tst, txn_map );
      if( rdescendant ) FD_TEST( tdescendant && xid_eq( fd_funk_txn_xid( tdescendant ), rdescendant->xid ) );
      else              FD_TEST( !tdescendant );

      ulong rpmap = 0UL;
      for( rec_t * rrec=ref->rec_head; rrec; rrec=rrec->next ) {
        FD_TEST( !fd_ulong_extract_bit( rpmap, (int)rrec->key ) );
        rpmap = fd_ulong_set_bit( rpmap, (int)rrec->key );
      }

      ulong tpmap = 0UL;
      for( fd_funk_rec_t const * trec=fd_funk_last_publish_rec_head( tst, rec_map );
           trec;
           trec=fd_funk_rec_next( trec, rec_map ) ) {
        ulong _tkey = fd_funk_rec_key( trec )->ul[0]; FD_TEST( _tkey<64UL );
        FD_TEST( !fd_ulong_extract_bit( tpmap, (int)_tkey ) );
        tpmap = fd_ulong_set_bit( tpmap, (int)_tkey );
      }

      ulong rkey = (ulong)(fd_rng_uint( rng ) & 63U);
      key_set( tkey, rkey );

      FD_TEST( !fd_funk_rec_query             ( NULL, NULL, NULL ) );
      FD_TEST( !fd_funk_rec_query             ( NULL, NULL, tkey ) );
      FD_TEST( !fd_funk_rec_query             ( tst,  NULL, NULL ) );

      FD_TEST( !fd_funk_rec_query_const       ( NULL, NULL, NULL ) );
      FD_TEST( !fd_funk_rec_query_const       ( NULL, NULL, tkey ) );
      FD_TEST( !fd_funk_rec_query_const       ( tst,  NULL, NULL ) );

      FD_TEST( !fd_funk_rec_query_global      ( NULL, NULL, NULL ) );
      FD_TEST( !fd_funk_rec_query_global      ( NULL, NULL, tkey ) );
      FD_TEST( !fd_funk_rec_query_global      ( tst,  NULL, NULL ) );

      FD_TEST( !fd_funk_rec_query_global_const( NULL, NULL, NULL ) );
      FD_TEST( !fd_funk_rec_query_global_const( NULL, NULL, tkey ) );
      FD_TEST( !fd_funk_rec_query_global_const( tst,  NULL, NULL ) );

      rec_t *               rrec = rec_query_global( ref, NULL, rkey );
      fd_funk_rec_t const * trec = fd_funk_rec_query_global( tst, NULL, tkey );
      if( !rrec ) FD_TEST( !trec );
      else        FD_TEST( trec && xid_eq( fd_funk_rec_xid( trec ), rrec->txn ? rrec->txn->xid : 0UL ) );

      fd_funk_rec_t const * _trec = fd_funk_rec_query_global_const( tst, NULL, tkey );
      FD_TEST( trec==_trec );

      FD_TEST( fd_funk_rec_test( NULL, NULL                 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_test( NULL, trec                 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_test( tst,  NULL                 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_test( tst,  rec_map+rec_max      )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_test( tst,  (fd_funk_rec_t *)1UL )==FD_FUNK_ERR_INVAL );

      FD_TEST( !fd_funk_rec_modify( NULL, NULL                 ) );
      FD_TEST( !fd_funk_rec_modify( NULL, trec                 ) );
      FD_TEST( !fd_funk_rec_modify( tst,  NULL                 ) );
      FD_TEST( !fd_funk_rec_modify( tst,  rec_map+rec_max      ) );
      FD_TEST( !fd_funk_rec_modify( tst,  (fd_funk_rec_t *)1UL ) );

      FD_TEST( fd_funk_rec_remove( NULL, NULL,                  0 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_remove( NULL, (fd_funk_rec_t *)trec, 0 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_remove( tst,  NULL,                  0 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_remove( tst,  rec_map+rec_max,       0 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_remove( tst,  (fd_funk_rec_t *)1UL,  0 )==FD_FUNK_ERR_INVAL );

      FD_TEST( fd_funk_rec_remove( NULL, NULL,                  1 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_remove( NULL, (fd_funk_rec_t *)trec, 1 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_remove( tst,  NULL,                  1 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_remove( tst,  rec_map+rec_max,       1 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_remove( tst,  (fd_funk_rec_t *)1UL,  1 )==FD_FUNK_ERR_INVAL );

      if( trec ) {
        if( is_frozen ) {
          FD_TEST( fd_funk_rec_remove( tst, (fd_funk_rec_t *)trec, 0 )==FD_FUNK_ERR_FROZEN );
          FD_TEST( fd_funk_rec_remove( tst, (fd_funk_rec_t *)trec, 1 )==FD_FUNK_ERR_FROZEN );
        } else {
          FD_TEST( fd_funk_rec_remove( tst, (fd_funk_rec_t *)trec, 0 )==FD_FUNK_ERR_XID );
        }
      }

      int err = fd_funk_rec_test( tst, &rec_map[0] );

      fd_funk_rec_t * mrec = fd_funk_rec_modify( tst, &rec_map[0] );

      if( fd_funk_rec_map_query( rec_map, fd_funk_rec_pair( &rec_map[0] ), NULL )!=&rec_map[0] ) {
        FD_TEST( err==FD_FUNK_ERR_KEY );
        FD_TEST( !mrec );
      } else {
        fd_funk_txn_t const * mtxn = fd_funk_rec_txn( &rec_map[0], txn_map );
        int is_frozen = mtxn ? fd_funk_txn_is_frozen( mtxn ) : fd_funk_last_publish_is_frozen( tst );
        FD_TEST( err ==(is_frozen ? FD_FUNK_ERR_FROZEN : FD_FUNK_SUCCESS) );
        FD_TEST( mrec==(is_frozen ? NULL               : &rec_map[0]    ) );
      }

      FD_TEST( !fd_funk_rec_insert( NULL, NULL, NULL, NULL ) );
      FD_TEST( !fd_funk_rec_insert( NULL, NULL, NULL, &err ) ); FD_TEST( err==FD_FUNK_ERR_INVAL );

      FD_TEST( !fd_funk_rec_insert( NULL, NULL, NULL, NULL ) );
      FD_TEST( !fd_funk_rec_insert( NULL, NULL, NULL, &err ) ); FD_TEST( err==FD_FUNK_ERR_INVAL );

      if( fd_funk_rec_is_full( rec_map ) ) {
        FD_TEST( !fd_funk_rec_insert( tst, NULL, tkey, NULL ) );
        FD_TEST( !fd_funk_rec_insert( tst, NULL, tkey, &err ) ); FD_TEST( err==FD_FUNK_ERR_REC );
      } else if( is_frozen ) {
        FD_TEST( !fd_funk_rec_insert( tst, NULL, tkey, NULL ) );
        FD_TEST( !fd_funk_rec_insert( tst, NULL, tkey, &err ) ); FD_TEST( err==FD_FUNK_ERR_FROZEN );
      } else {
        fd_funk_rec_t const * orec = fd_funk_rec_query( tst, NULL, tkey );
        if( orec && !(orec->flags & FD_FUNK_REC_FLAG_ERASE) ) {
          FD_TEST( !fd_funk_rec_insert( tst, NULL, tkey, NULL ) );
          FD_TEST( !fd_funk_rec_insert( tst, NULL, tkey, &err ) ); FD_TEST( err==FD_FUNK_ERR_KEY );
        }
      }

    } while(0);

    FD_TEST( ref->txn_cnt==fd_funk_txn_cnt( txn_map ) );
    FD_TEST( fd_funk_txn_is_full( txn_map )==(fd_funk_txn_cnt( txn_map )==txn_max) );

    ulong cnt = 0UL;

    txn_t * rtxn = ref->txn_map_head;
    while( rtxn ) {

      fd_funk_txn_t * ttxn = fd_funk_txn_query( xid_set( txid, rtxn->xid ), txn_map );
      FD_TEST( ttxn && xid_eq( fd_funk_txn_xid( ttxn ), rtxn->xid ) );

#     define TEST_RELATIVE(rel) do {                                                         \
        txn_t *         r##rel = rtxn->rel;                                                  \
        fd_funk_txn_t * t##rel = fd_funk_txn_##rel( ttxn, txn_map );                         \
        if( !r##rel ) FD_TEST( !t##rel );                                                    \
        else          FD_TEST( t##rel && xid_eq( fd_funk_txn_xid( t##rel ), r##rel->xid ) ); \
      } while(0)
      TEST_RELATIVE( parent       );
      TEST_RELATIVE( child_head   );
      TEST_RELATIVE( child_tail   );
      TEST_RELATIVE( sibling_prev );
      TEST_RELATIVE( sibling_next );
#     undef TEST_RELATIVE

      int ttxn_is_frozen = fd_funk_txn_is_frozen( ttxn );

      FD_TEST( txn_is_frozen    ( rtxn )==ttxn_is_frozen                    );
      FD_TEST( txn_is_only_child( rtxn )==fd_funk_txn_is_only_child( ttxn ) );

      txn_t *         rancestor = txn_ancestor( rtxn );
      fd_funk_txn_t * tancestor = fd_funk_txn_ancestor( ttxn, txn_map );
      if( rancestor ) FD_TEST( tancestor && xid_eq( fd_funk_txn_xid( tancestor ), rancestor->xid ) );
      else            FD_TEST( !tancestor );

      txn_t *         rdescendant = txn_descendant( rtxn );
      fd_funk_txn_t * tdescendant = fd_funk_txn_descendant( ttxn, txn_map );
      if( rdescendant ) FD_TEST( tdescendant && xid_eq( fd_funk_txn_xid( tdescendant ), rdescendant->xid ) );
      else              FD_TEST( !tdescendant );

      ulong rkey = (ulong)(fd_rng_uint( rng ) & 63U);
      key_set( tkey, rkey );

      FD_TEST( !fd_funk_rec_query             ( NULL, ttxn, NULL ) );
      FD_TEST( !fd_funk_rec_query             ( NULL, ttxn, tkey ) );
      FD_TEST( !fd_funk_rec_query             ( tst,  ttxn, NULL ) );

      FD_TEST( !fd_funk_rec_query_const       ( NULL, ttxn, NULL ) );
      FD_TEST( !fd_funk_rec_query_const       ( NULL, ttxn, tkey ) );
      FD_TEST( !fd_funk_rec_query_const       ( tst,  ttxn, NULL ) );

      FD_TEST( !fd_funk_rec_query_global      ( NULL, ttxn, NULL ) );
      FD_TEST( !fd_funk_rec_query_global      ( NULL, ttxn, tkey ) );
      FD_TEST( !fd_funk_rec_query_global      ( tst,  ttxn, NULL ) );

      FD_TEST( !fd_funk_rec_query_global_const( NULL, ttxn, NULL ) );
      FD_TEST( !fd_funk_rec_query_global_const( NULL, ttxn, tkey ) );
      FD_TEST( !fd_funk_rec_query_global_const( tst,  ttxn, NULL ) );

      rec_t *               rrec = rec_query_global( ref, rtxn, rkey );
      fd_funk_rec_t const * trec = fd_funk_rec_query_global( tst, ttxn, tkey );
      if( !rrec ) FD_TEST( !trec );
      else {
        FD_TEST( trec && xid_eq( fd_funk_rec_xid( trec ), rrec->txn ? rrec->txn->xid : 0UL ) );
        int is_frozen = (rrec->txn ? txn_is_frozen( rrec->txn ) : funk_is_frozen( ref ));
        FD_TEST( fd_funk_rec_test  ( tst, trec )==(is_frozen ? FD_FUNK_ERR_FROZEN : FD_FUNK_SUCCESS      ) );
        FD_TEST( fd_funk_rec_modify( tst, trec )==(is_frozen ? NULL               : (fd_funk_rec_t *)trec) );
      }

      fd_funk_rec_t const * _trec = fd_funk_rec_query_global_const( tst, ttxn, tkey );
      FD_TEST( trec==_trec );

      FD_TEST( fd_funk_rec_test( NULL, NULL                 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_test( NULL, trec                 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_test( tst,  NULL                 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_test( tst,  rec_map+rec_max      )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_test( tst,  (fd_funk_rec_t *)1UL )==FD_FUNK_ERR_INVAL );

      FD_TEST( !fd_funk_rec_modify( NULL, NULL                 ) );
      FD_TEST( !fd_funk_rec_modify( NULL, trec                 ) );
      FD_TEST( !fd_funk_rec_modify( tst,  NULL                 ) );
      FD_TEST( !fd_funk_rec_modify( tst,  rec_map+rec_max      ) );
      FD_TEST( !fd_funk_rec_modify( tst,  (fd_funk_rec_t *)1UL ) );

      FD_TEST( fd_funk_rec_remove( NULL, NULL,                  0 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_remove( NULL, (fd_funk_rec_t *)trec, 0 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_remove( tst,  NULL,                  0 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_remove( tst,  rec_map+rec_max,       0 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_remove( tst,  (fd_funk_rec_t *)1UL,  0 )==FD_FUNK_ERR_INVAL );

      FD_TEST( fd_funk_rec_remove( NULL, NULL,                  1 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_remove( NULL, (fd_funk_rec_t *)trec, 1 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_remove( tst,  NULL,                  1 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_remove( tst,  rec_map+rec_max,       1 )==FD_FUNK_ERR_INVAL );
      FD_TEST( fd_funk_rec_remove( tst,  (fd_funk_rec_t *)1UL,  1 )==FD_FUNK_ERR_INVAL );

      if( trec && ttxn_is_frozen ) {
        FD_TEST( fd_funk_rec_remove( tst, (fd_funk_rec_t *)trec, 0 )==FD_FUNK_ERR_FROZEN );
        FD_TEST( fd_funk_rec_remove( tst, (fd_funk_rec_t *)trec, 1 )==FD_FUNK_ERR_FROZEN );
      }

      int err;

      FD_TEST( !fd_funk_rec_insert( NULL, ttxn, NULL, NULL ) );
      FD_TEST( !fd_funk_rec_insert( NULL, ttxn, NULL, &err ) ); FD_TEST( err==FD_FUNK_ERR_INVAL );

      FD_TEST( !fd_funk_rec_insert( NULL, ttxn, NULL, NULL ) );
      FD_TEST( !fd_funk_rec_insert( NULL, ttxn, NULL, &err ) ); FD_TEST( err==FD_FUNK_ERR_INVAL );

      if( fd_funk_rec_is_full( rec_map ) ) {
        FD_TEST( !fd_funk_rec_insert( tst, ttxn, tkey, NULL ) );
        FD_TEST( !fd_funk_rec_insert( tst, ttxn, tkey, &err ) ); FD_TEST( err==FD_FUNK_ERR_REC );
      } else if( ttxn_is_frozen ) {
        FD_TEST( !fd_funk_rec_insert( tst, ttxn, tkey, NULL ) );
        FD_TEST( !fd_funk_rec_insert( tst, ttxn, tkey, &err ) ); FD_TEST( err==FD_FUNK_ERR_FROZEN );
      } else {
        fd_funk_rec_t const * orec = fd_funk_rec_query( tst, ttxn, tkey );
        if( orec && !(orec->flags & FD_FUNK_REC_FLAG_ERASE) ) {
          FD_TEST( !fd_funk_rec_insert( tst, ttxn, tkey, NULL ) );
          FD_TEST( !fd_funk_rec_insert( tst, ttxn, tkey, &err ) ); FD_TEST( err==FD_FUNK_ERR_KEY );
        }
      }

      ulong rpmap = 0UL;
      for( rec_t * rrec=rtxn->rec_head; rrec; rrec=rrec->next ) {
        FD_TEST( !fd_ulong_extract_bit( rpmap, (int)rrec->key ) );
        rpmap = fd_ulong_set_bit( rpmap, (int)rrec->key );
      }

      ulong tpmap = 0UL;
      for( fd_funk_rec_t const * trec=fd_funk_txn_rec_head( ttxn, rec_map ); trec; trec=fd_funk_rec_next( trec, rec_map ) ) {
        ulong _tkey = fd_funk_rec_key( trec )->ul[0]; FD_TEST( _tkey<64UL );
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

      fd_funk_txn_t const * ttxn = rxid ? fd_funk_txn_query( txid, txn_map ) : NULL;
      fd_funk_rec_t const * trec = fd_funk_rec_query( tst, ttxn, tkey );
      FD_TEST( trec && fd_funk_rec_txn( trec, txn_map )==ttxn &&
               xid_eq( fd_funk_rec_xid( trec ), rxid ) && key_eq( fd_funk_rec_key( trec ), rkey ) );

      fd_funk_rec_t const * trec_head;
      fd_funk_rec_t const * trec_tail;
      if( !rrec->txn ) {
        FD_TEST( !ttxn );
        trec_head = fd_funk_last_publish_rec_head( tst, rec_map );
        trec_tail = fd_funk_last_publish_rec_tail( tst, rec_map );
      } else {
        FD_TEST( ttxn && xid_eq( fd_funk_txn_xid( ttxn ), rxid ) );
        trec_head = fd_funk_txn_rec_head( ttxn, rec_map );
        trec_tail = fd_funk_txn_rec_tail( ttxn, rec_map );
      }
      FD_TEST( trec_head && xid_eq( fd_funk_rec_xid( trec_head ), rxid ) );
      FD_TEST( trec_tail && xid_eq( fd_funk_rec_xid( trec_tail ), rxid ) );

#     define TEST_RELATIVE(rel) do {                                             \
        rec_t *               r##rel = rrec->rel;                                \
        fd_funk_rec_t const * t##rel = fd_funk_rec_##rel( trec, rec_map );       \
        if( !r##rel ) FD_TEST( !t##rel );                                        \
        else {                                                                   \
          ulong r##rel##xid = r##rel->txn ? r##rel->txn->xid : 0UL;              \
          FD_TEST( t##rel && xid_eq( fd_funk_rec_xid( t##rel ), r##rel##xid ) && \
                             key_eq( fd_funk_rec_key( t##rel ), r##rel->key ) ); \
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

      if( FD_UNLIKELY( fd_funk_rec_is_full( rec_map ) ) ) continue;

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
      fd_funk_rec_t const * trec =
        fd_funk_rec_insert( tst, fd_funk_txn_query( xid_set( txid, rxid ), txn_map ), key_set( tkey, rkey ), &err );
      FD_TEST( trec );
      FD_TEST( !err );

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

      int erase = (!rxid) | (int)(r & 1U); r >>= 1;

      rec_remove( ref, rrec, erase );

      fd_funk_txn_t const * ttxn = rxid ? fd_funk_txn_query( xid_set( txid, rxid ), txn_map ) : NULL;
      fd_funk_rec_t const * trec = fd_funk_rec_query( tst, ttxn, key_set( tkey, rkey ) );
      FD_TEST( trec && fd_funk_rec_txn( trec, txn_map )==ttxn );

      fd_funk_rec_t * _trec = fd_funk_rec_modify( tst, trec );
      FD_TEST( trec==(fd_funk_rec_t const *)_trec );
      FD_TEST( !fd_funk_rec_remove( tst, _trec, erase ) );

    } else if( op>=2 ) { /* Prepare 8x as publish and cancel combined */

      if( FD_UNLIKELY( fd_funk_txn_is_full( txn_map ) ) ) continue;

      txn_t *         rparent;
      fd_funk_txn_t * tparent;

      ulong idx = fd_rng_ulong_roll( rng, ref->txn_cnt+1UL );
      if( idx<ref->txn_cnt ) { /* Branch off in-prep */
        rparent = ref->txn_map_head; for( ulong rem=idx; rem; rem-- ) rparent = rparent->map_next;
        tparent = fd_funk_txn_query( xid_set( txid, rparent->xid ), txn_map );
      } else { /* Branch off last published */
        rparent = NULL;
        tparent = NULL;
      }

      ulong rxid = xid_unique();
      txn_prepare( ref, rparent, rxid );
      FD_TEST( fd_funk_txn_prepare( tst, tparent, xid_set( txid, rxid ), verbose ) );

    } else if( op>=2UL ) { /* Cancel (same rate as publish and merge) */

      if( FD_UNLIKELY( !ref->txn_cnt ) ) continue;

      ulong idx = fd_rng_ulong_roll( rng, ref->txn_cnt );

      txn_t *         rtxn = ref->txn_map_head; for( ulong rem=idx; rem; rem-- ) rtxn = rtxn->map_next;
      fd_funk_txn_t * ttxn = fd_funk_txn_query( xid_set( txid, rtxn->xid ), txn_map );

      ulong cnt = ref->txn_cnt; txn_cancel( ref, rtxn ); cnt -= ref->txn_cnt;
      FD_TEST( fd_funk_txn_cancel( tst, ttxn, verbose )==cnt );

    } else if( op>=1UL ) { /* Merge (same rate as cancel and publish) */

      if( FD_UNLIKELY( !ref->txn_cnt ) ) continue;

      ulong idx = fd_rng_ulong_roll( rng, ref->txn_cnt );

      txn_t *         rtxn = ref->txn_map_head; for( ulong rem=idx; rem; rem-- ) rtxn = rtxn->map_next;
      if( !rtxn->parent || !txn_is_only_child( rtxn ) || txn_is_frozen( rtxn ) ) continue;
      
      fd_funk_txn_t * ttxn = fd_funk_txn_query( xid_set( txid, rtxn->parent->xid ), txn_map );
      FD_TEST( !fd_funk_txn_merge_all_children( tst, ttxn, verbose ) );

      txn_merge( ref, rtxn );

    } else { /* Publish (same rate as merge and cancel) */

      if( FD_UNLIKELY( !ref->txn_cnt ) ) continue;

      ulong idx = fd_rng_ulong_roll( rng, ref->txn_cnt );
      txn_t *         rtxn = ref->txn_map_head; for( ulong rem=idx; rem; rem-- ) rtxn = rtxn->map_next;
      fd_funk_txn_t * ttxn = fd_funk_txn_query( xid_set( txid, rtxn->xid ), txn_map );

      ulong cnt = txn_publish( ref, rtxn, 0UL );
      FD_TEST( fd_funk_txn_publish( tst, ttxn, verbose )==cnt );
    }

  }

  funk_delete( ref );

  fd_wksp_free_laddr( fd_funk_delete( fd_funk_leave( tst ) ) );
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
