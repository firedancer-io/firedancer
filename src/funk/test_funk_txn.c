#include "fd_funk.h"

/* TODO: more extensive testing of fd_funk_txn_cancel_siblings,
   fd_funk_txn_cancel_children (implicitly tested under the hood but the
   user wrappers aren't), coverage of fd_funk_txn_merge. */

#if FD_HAS_HOSTED

FD_STATIC_ASSERT( FD_FUNK_TXN_ALIGN    ==32UL, unit_test );
FD_STATIC_ASSERT( FD_FUNK_TXN_FOOTPRINT==96UL, unit_test );

FD_STATIC_ASSERT( FD_FUNK_TXN_ALIGN    ==alignof(fd_funk_txn_t), unit_test );
FD_STATIC_ASSERT( FD_FUNK_TXN_FOOTPRINT==sizeof (fd_funk_txn_t), unit_test );

FD_STATIC_ASSERT( FD_FUNK_TXN_IDX_NULL==(ulong)UINT_MAX, unit_test );

static fd_funk_txn_xid_t *
fd_funk_txn_xid_set_unique( fd_funk_txn_xid_t * xid ) {
  static FD_TL ulong tag = 0UL;
  xid->ul[0] = fd_log_app_id();
  xid->ul[1] = fd_log_thread_id();
  xid->ul[2] = ++tag;
# if FD_HAS_X86
  xid->ul[3] = (ulong)fd_tickcount();
# else
  xid->ul[3] = 0UL;
# endif
  return xid;
}

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
  ulong        rec_max  = fd_env_strip_cmdline_ulong( &argc, &argv, "--rec-max",   NULL,            32UL );
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

  fd_funk_t * funk = fd_funk_join( fd_funk_new( fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(), wksp_tag ),
                                                wksp_tag, seed, txn_max, rec_max ) );
  if( FD_UNLIKELY( !funk ) ) FD_LOG_ERR(( "Unable to create funk" ));

  fd_funk_start_write( funk );

  fd_funk_txn_t * map = fd_funk_txn_map( funk, wksp );

  for( ulong rem=1000000UL; rem; rem-- ) {
    ulong idx = (ulong)fd_rng_uint( rng );
    FD_TEST( fd_funk_txn_idx( fd_funk_txn_cidx( idx ) )==idx );
  }

  FD_TEST(  fd_funk_txn_idx_is_null( FD_FUNK_TXN_IDX_NULL ) );
  FD_TEST( !fd_funk_txn_idx_is_null( 0UL                  ) );

  fd_funk_txn_xid_t const * last_publish = fd_funk_last_publish( funk );

  FD_TEST( !fd_funk_txn_cnt    ( map ) );
  FD_TEST( !fd_funk_txn_is_full( map ) );

  fd_funk_txn_xid_t recent_xid[ 64 ]; for( ulong idx=0UL; idx<64UL; idx++ ) fd_funk_txn_xid_set_unique( &recent_xid[ idx ] );
  ulong recent_cursor = 0UL;

  for( ulong iter=0UL; iter<iter_max; iter++ ) {

    ulong live_pmap = 0UL;
    for( ulong idx=0UL; idx<64UL; idx++ ) if( fd_funk_txn_query( &recent_xid[ idx ], map ) ) live_pmap |= (1UL<<idx);

#   define RANDOM_SET_BIT_IDX(pmap) do {                                                       \
      idx = (r&63U);                                                                           \
      idx = (((uint)fd_ulong_find_lsb( fd_ulong_rotate_left( pmap, (int)idx ) )) - idx) & 63U; \
      r >>= 6;                                                                                 \
    } while(0)

    uint r = fd_rng_uint( rng );
    int op = (int)(r & 15U); r >>= 4;
    switch( op ) {

    case 0: { /* look up a live xid (always succeed) */
      if( FD_UNLIKELY( !live_pmap ) ) break;
      uint idx; RANDOM_SET_BIT_IDX( live_pmap );
      fd_funk_txn_t * txn = fd_funk_txn_query( &recent_xid[idx], map );
      FD_TEST( txn && fd_funk_txn_xid_eq( fd_funk_txn_xid( txn ), &recent_xid[idx] ) );
      break;
    }

    case 1: { /* look up a dead xid (always fail) */
      if( FD_UNLIKELY( !~live_pmap ) ) break;
      uint idx; RANDOM_SET_BIT_IDX( ~live_pmap );
      fd_funk_txn_t * txn = fd_funk_txn_query( &recent_xid[idx], map );
      FD_TEST( !txn );
      break;
    }

    case 2: { /* look up never seen xid (always fail) */
      fd_funk_txn_xid_t xid[1]; fd_funk_txn_xid_set_unique( xid );
      fd_funk_txn_t * txn = fd_funk_txn_query( xid, map );
      FD_TEST( !txn );
      break;
    }

    case 3: { /* prepare from most recent published with an live xid (always fail) */
      if( FD_UNLIKELY( !live_pmap ) ) break;
      uint idx; RANDOM_SET_BIT_IDX( live_pmap );
      FD_TEST( !fd_funk_txn_prepare( funk, NULL, &recent_xid[idx], verbose ) );
      break;
    }

    case 4: { /* prepare from most recent published with a dead xid (succeed if not full) */
      if( FD_UNLIKELY( !~live_pmap ) ) break;
      uint idx; RANDOM_SET_BIT_IDX( ~live_pmap );
      int is_full = fd_funk_txn_is_full( map );
      if( FD_UNLIKELY( fd_funk_txn_xid_eq( &recent_xid[idx], last_publish ) ) ) break;
      fd_funk_txn_t * txn = fd_funk_txn_prepare( funk, NULL, &recent_xid[idx], verbose );
      if( is_full ) FD_TEST( !txn );
      else          FD_TEST( txn && fd_funk_txn_xid_eq( fd_funk_txn_xid( txn ), &recent_xid[idx] ) );
      break;
    }

    case 5: { /* prepare from most recent published never seen xid (succeed if not full) */
      fd_funk_txn_xid_t const * xid = fd_funk_txn_xid_set_unique( &recent_xid[ recent_cursor ] );
      recent_cursor = (recent_cursor+1UL) & 63UL;
      int is_full = fd_funk_txn_is_full( map );
      fd_funk_txn_t * txn = fd_funk_txn_prepare( funk, NULL, xid, verbose );
      if( is_full ) FD_TEST( !txn );
      else          FD_TEST( txn && fd_funk_txn_xid_eq( fd_funk_txn_xid( txn ), xid ) );
      break;
    }

    case 6: { /* prepare from live xid with a live xid (always fail) */
      if( FD_UNLIKELY( !live_pmap ) ) break;
      uint idx; uint idx1; RANDOM_SET_BIT_IDX( live_pmap ); idx1 = idx; RANDOM_SET_BIT_IDX( live_pmap );
      fd_funk_txn_t * parent = fd_funk_txn_query( &recent_xid[idx], map );
      FD_TEST( parent && fd_funk_txn_xid_eq( fd_funk_txn_xid( parent ), &recent_xid[idx] ) );
      FD_TEST( !fd_funk_txn_prepare( funk, parent, &recent_xid[idx1], verbose ) );
      break;
    }

    case 7: { /* prepare from live xid with a dead xid (succeed if not full) */
      if( FD_UNLIKELY( !live_pmap || !~live_pmap ) ) break;
      uint idx; uint idx1; RANDOM_SET_BIT_IDX( ~live_pmap ); idx1 = idx; RANDOM_SET_BIT_IDX( live_pmap );
      if( FD_UNLIKELY( fd_funk_txn_xid_eq( &recent_xid[idx1], last_publish ) ) ) break;
      fd_funk_txn_t * parent = fd_funk_txn_query( &recent_xid[idx], map );
      FD_TEST( parent && fd_funk_txn_xid_eq( fd_funk_txn_xid( parent ), &recent_xid[idx] ) );
      int is_full = fd_funk_txn_is_full( map );
      fd_funk_txn_t * txn = fd_funk_txn_prepare( funk, parent, &recent_xid[idx1], verbose );
      if( is_full ) FD_TEST( !txn );
      else          FD_TEST( txn && fd_funk_txn_xid_eq( fd_funk_txn_xid( txn ), &recent_xid[idx1] ) );
      break;
    }

    case 8: { /* prepare from live xid with a never seen xid (succeed if not full) */
      if( FD_UNLIKELY( !live_pmap ) ) break;
      uint idx; RANDOM_SET_BIT_IDX( live_pmap );
      fd_funk_txn_t * parent = fd_funk_txn_query( &recent_xid[idx], map );
      FD_TEST( parent && fd_funk_txn_xid_eq( fd_funk_txn_xid( parent ), &recent_xid[idx] ) );
      fd_funk_txn_xid_t const * xid = fd_funk_txn_xid_set_unique( &recent_xid[ recent_cursor ] );
      recent_cursor = (recent_cursor+1UL) & 63UL;
      int is_full = fd_funk_txn_is_full( map );
      fd_funk_txn_t * txn = fd_funk_txn_prepare( funk, parent, xid, verbose );
      if( is_full ) FD_TEST( !txn );
      else          FD_TEST( txn && fd_funk_txn_xid_eq( fd_funk_txn_xid( txn ), xid ) );
      break;
    }

    case 9: { /* cancel a live xid (should always be at least 1) */
      if( FD_UNLIKELY( !live_pmap ) ) break;
      uint idx; RANDOM_SET_BIT_IDX( live_pmap );
      fd_funk_txn_t * txn = fd_funk_txn_query( &recent_xid[idx], map );
      FD_TEST( txn && fd_funk_txn_xid_eq( fd_funk_txn_xid( txn ), &recent_xid[idx] ) );
      FD_TEST( fd_funk_txn_cancel( funk, txn, verbose )>0UL );
      break;
    }

    case 10: { /* cancel a dead xid (should always be 0) */
      if( FD_UNLIKELY( !~live_pmap ) ) break;
      uint idx; RANDOM_SET_BIT_IDX( ~live_pmap );
      fd_funk_txn_t * txn = fd_funk_txn_query( &recent_xid[idx], map );
      FD_TEST( !txn );
      FD_TEST( fd_funk_txn_cancel( funk, txn, verbose )==0UL );
      break;
    }

    case 11: { /* cancel a never seen xid (should always be 0) */
      fd_funk_txn_xid_t xid[1]; fd_funk_txn_xid_set_unique( xid );
      fd_funk_txn_t * txn = fd_funk_txn_query( xid, map );
      FD_TEST( !txn );
      FD_TEST( fd_funk_txn_cancel( funk, txn, verbose )==0UL );
      break;
    }

    case 12: { /* publish a live xid (should always be at least 1) */
      if( FD_UNLIKELY( !live_pmap ) ) break;
      uint idx; RANDOM_SET_BIT_IDX( live_pmap );
      fd_funk_txn_t * txn = fd_funk_txn_query( &recent_xid[idx], map );
      FD_TEST( txn && fd_funk_txn_xid_eq( fd_funk_txn_xid( txn ), &recent_xid[idx] ) );
      FD_TEST( fd_funk_txn_publish( funk, txn, verbose )>0UL );
      FD_TEST( fd_funk_txn_xid_eq( last_publish, &recent_xid[idx] ) );
      break;
    }

    case 13: { /* publish a dead xid (should always be 0) */
      if( FD_UNLIKELY( !~live_pmap ) ) break;
      uint idx; RANDOM_SET_BIT_IDX( ~live_pmap );
      fd_funk_txn_t * txn = fd_funk_txn_query( &recent_xid[idx], map );
      FD_TEST( !txn );
      FD_TEST( fd_funk_txn_publish( funk, txn, verbose )==0UL );
      break;
    }

    case 14: { /* publish a never seen xid (should always be 0) */
      fd_funk_txn_xid_t xid[1]; fd_funk_txn_xid_set_unique( xid );
      fd_funk_txn_t * txn = fd_funk_txn_query( xid, map );
      FD_TEST( !txn );
      FD_TEST( fd_funk_txn_publish( funk, txn, verbose )==0UL );
      break;
    }

    default: { /* various sanity checks */
      uint idx = r & 63U; r >>= 6;
      fd_funk_txn_t * txn = fd_funk_txn_query( &recent_xid[idx], map );
      fd_funk_txn_xid_t xid[1]; fd_funk_txn_xid_set_unique( xid );

      fd_funk_txn_t * dead = NULL;
      if( txn_max && !fd_funk_txn_query( fd_funk_txn_xid( &map[0] ), map ) ) dead = &map[0];

      fd_funk_txn_t bad[1]; fd_funk_txn_xid_copy( &bad->xid, xid );

      /* Too many in-prep already tested */
      /* Live xid cases already tested */

      FD_TEST( !fd_funk_txn_prepare( NULL, txn, xid,             verbose ) ); /* NULL funk */
      FD_TEST( !fd_funk_txn_prepare( funk, txn, NULL,            verbose ) ); /* NULL xid */
      FD_TEST( !fd_funk_txn_prepare( funk, txn, last_publish,    verbose ) ); /* last published xid */
      FD_TEST( !fd_funk_txn_prepare( funk, bad, xid,             verbose ) ); /* Parent not in map */
      if( dead ) FD_TEST( !fd_funk_txn_prepare( funk, dead, xid, verbose ) ); /* Parent not in prep */

      FD_TEST( !fd_funk_txn_cancel( NULL, txn,  verbose ) );                  /* NULL funk (and maybe NULL txn) */
      FD_TEST( !fd_funk_txn_cancel( funk, NULL, verbose ) );                  /* NULL txn */
      FD_TEST( !fd_funk_txn_cancel( funk, bad,  verbose ) );                  /* tx not in map */
      if( dead ) FD_TEST( !fd_funk_txn_cancel( funk, dead, verbose ) );       /* tx not in prep */

      FD_TEST( !fd_funk_txn_publish( NULL, txn,  verbose ) );                 /* NULL funk (and maybe NULL txn) */
      FD_TEST( !fd_funk_txn_publish( funk, NULL, verbose ) );                 /* NULL txn */
      FD_TEST( !fd_funk_txn_publish( funk, bad,  verbose ) );                 /* tx not in map */
      if( dead ) FD_TEST( !fd_funk_txn_publish( funk, dead, verbose ) );      /* tx not in prep */

      if( txn ) {
        FD_TEST( fd_funk_txn_xid_eq( fd_funk_txn_xid( txn ), &recent_xid[idx] ) );

        fd_funk_txn_t * parent      = fd_funk_txn_parent      ( txn, map );
        fd_funk_txn_t * first_born  = fd_funk_txn_child_head  ( txn, map );
        fd_funk_txn_t * last_born   = fd_funk_txn_child_tail  ( txn, map );
        fd_funk_txn_t * older_sib   = fd_funk_txn_sibling_prev( txn, map );
        fd_funk_txn_t * younger_sib = fd_funk_txn_sibling_next( txn, map );

        /* Make sure transaction suitable marked as frozen */

        if( !first_born ) FD_TEST( !last_born  );
        if( !last_born  ) FD_TEST( !first_born );

        FD_TEST( fd_funk_txn_is_frozen( txn )==!!first_born );

        FD_TEST( fd_funk_txn_is_only_child( txn )==((!older_sib) & (!younger_sib)) );

        fd_funk_txn_t * cur;

        /* Make sure txn's children know that txn is the parent (in both
           directions) */

        for( cur = first_born; cur; cur = fd_funk_txn_sibling_next( cur, map ) ) FD_TEST( fd_funk_txn_parent( cur, map )==txn );
        for( cur = last_born;  cur; cur = fd_funk_txn_sibling_prev( cur, map ) ) FD_TEST( fd_funk_txn_parent( cur, map )==txn );

        /* Make sure txn's parent knows this txn is a child (in both
           directions) */

        if( !parent ) cur = fd_funk_last_publish_child_head( funk, map );
        else          cur = fd_funk_txn_child_head( parent, map );
        for( ; cur; cur = fd_funk_txn_sibling_next( cur, map ) ) if( cur==txn ) break;
        FD_TEST( cur );

        if( !parent ) cur = fd_funk_last_publish_child_tail( funk, map );
        else          cur = fd_funk_txn_child_tail( parent, map );
        for( ; cur; cur = fd_funk_txn_sibling_prev( cur, map ) ) if( cur==txn ) break;
        FD_TEST( cur );
      }

      break;
    }
    }

    FD_TEST( !fd_funk_verify( funk ) );
  }

  fd_funk_end_write( funk );

  fd_wksp_free_laddr( fd_funk_delete( fd_funk_leave( funk ) ) );
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
