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

  fd_funk_start_write( tst );

  fd_funk_txn_t * txn_map = fd_funk_txn_map( tst, wksp );
  fd_funk_rec_t * rec_map = fd_funk_rec_map( tst, wksp );
  fd_alloc_t *    alloc   = fd_funk_alloc  ( tst, wksp );

  funk_t * ref = funk_new();

  for( ulong iter=0UL; iter<iter_max; iter++ ) {
    if( !(iter & 16383UL) ) FD_LOG_NOTICE(( "Iter %7lu (txn_cnt %3lu rec_cnt %3lu)", iter, ref->txn_cnt, ref->rec_cnt ));

  //if( !ref->txn_cnt ) {
  //  FD_LOG_NOTICE(( "***************************************************************" ));
  //  for( rec_t * rrec=ref->rec_head; rrec; rrec=rrec->next ) FD_LOG_NOTICE(( "has %lu", rrec->key ));
  //}

#   define TEST_TAIL_PADDING(start) do {                              \
      uchar const * buf = (uchar const *)fd_funk_val_const( mrec, wksp ); \
      ulong         end = fd_funk_val_max( mrec );                        \
      uchar         tmp = (uchar)0;                                       \
      for( ulong off=start; off<end; off++ ) tmp |= buf[off];             \
      FD_TEST( !tmp );                                                    \
    } while(0)

    FD_TEST( !fd_funk_verify( tst ) );

    fd_funk_txn_xid_t txid[1];
    fd_funk_rec_key_t tkey[1];

    rec_t * rrec = ref->rec_map_head;
    while( rrec ) {

      ulong rxid = rrec->txn ? rrec->txn->xid : 0UL;
      ulong rkey = rrec->key;

      int is_frozen = rrec->txn ? txn_is_frozen( rrec->txn ) : funk_is_frozen( ref );

      xid_set( txid, rxid );
      key_set( tkey, rkey );

      fd_funk_txn_t const * ttxn = rxid ? fd_funk_txn_query( txid, txn_map ) : NULL;
      fd_funk_rec_t const * trec = fd_funk_rec_query(  tst, ttxn, tkey );
      fd_funk_rec_t *       mrec = fd_funk_rec_modify( tst, trec );

      void const * _val = (void const *)fd_funk_val_read( trec, 0UL, sizeof(uint), wksp );

      if( rrec->erase ) {

        FD_TEST( !_val );

        FD_TEST( !fd_funk_val_sz   ( trec ) );
        FD_TEST( !fd_funk_val_max  ( trec ) );
        FD_TEST( !fd_funk_val_const( trec, wksp ) );

        if( !is_frozen ) FD_TEST( !fd_funk_val( mrec, wksp ) );

      } else {

        FD_TEST( _val && FD_LOAD( uint, _val )==rrec->val );

        FD_TEST( fd_funk_val_sz   ( trec       )==sizeof(uint)       );
        FD_TEST( fd_funk_val_max  ( trec       )>=sizeof(uint)       );
        FD_TEST( fd_funk_val_const( trec, wksp )==(void const *)_val );

        if( !is_frozen ) FD_TEST( fd_funk_val( mrec, wksp )==(void *)_val );

        /* Various offsets */
        FD_TEST( ((ulong)fd_funk_val_read( trec, 0UL, 1UL, wksp ))==(((ulong)_val) + 0UL) );
        FD_TEST( ((ulong)fd_funk_val_read( trec, 1UL, 1UL, wksp ))==(((ulong)_val) + 1UL) );
        FD_TEST( ((ulong)fd_funk_val_read( trec, 2UL, 1UL, wksp ))==(((ulong)_val) + 2UL) );
        FD_TEST( ((ulong)fd_funk_val_read( trec, 3UL, 1UL, wksp ))==(((ulong)_val) + 3UL) );
        FD_TEST( ((ulong)fd_funk_val_read( trec, 0UL, 1UL, wksp ))==(((ulong)_val) + 0UL) );
        FD_TEST( ((ulong)fd_funk_val_read( trec, 0UL, 2UL, wksp ))==(((ulong)_val) + 0UL) );
        FD_TEST( ((ulong)fd_funk_val_read( trec, 0UL, 3UL, wksp ))==(((ulong)_val) + 0UL) );
        FD_TEST( ((ulong)fd_funk_val_read( trec, 1UL, 3UL, wksp ))==(((ulong)_val) + 1UL) );
        FD_TEST( ((ulong)fd_funk_val_read( trec, 2UL, 2UL, wksp ))==(((ulong)_val) + 2UL) );
        FD_TEST( ((ulong)fd_funk_val_read( trec, 3UL, 1UL, wksp ))==(((ulong)_val) + 3UL) );

      }

      FD_TEST( !fd_funk_val_read( NULL, 0UL,       4UL,       wksp ) ); /* NULL rec */
      FD_TEST( !fd_funk_val_read( trec, 0UL,       0UL,       wksp ) ); /* sz 0 */
      FD_TEST( !fd_funk_val_read( trec, 3UL,       ULONG_MAX, wksp ) ); /* off+sz wrapped */
      FD_TEST( !fd_funk_val_read( trec, ULONG_MAX, 3UL,       wksp ) ); /* off+sz wrapped */
      FD_TEST( !fd_funk_val_read( trec, 0UL,       4UL,       NULL ) ); /* NULL wksp */
      FD_TEST( !fd_funk_val_read( trec, 4UL,       1UL,       wksp ) ); /* read past end */

      uint val = (fd_rng_uint( rng )<<2) | 2U;

      if( !is_frozen ) {
        if( rrec->erase ) {

          FD_TEST( !fd_funk_val_write( mrec, 0UL, sizeof(uint), &val, wksp ) );

          FD_TEST( !fd_funk_val_copy    ( mrec, &val, sizeof(uint), 0UL, alloc, wksp, NULL ) );
          FD_TEST( !fd_funk_val_append  ( mrec, &val, sizeof(uint),      alloc, wksp, NULL ) );
          FD_TEST( !fd_funk_val_truncate( mrec, 0UL,                     alloc, wksp, NULL ) );

          int err;
          err = 1; FD_TEST( !fd_funk_val_copy    ( mrec, &val, sizeof(uint), 0UL, alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL );
          err = 1; FD_TEST( !fd_funk_val_append  ( mrec, &val, sizeof(uint),      alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL );
          err = 1; FD_TEST( !fd_funk_val_truncate( mrec, 0UL,                     alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL );

        } else {
          rrec->val = val;
          FD_TEST( fd_funk_val_write( mrec, 0UL, sizeof(uint), &val, wksp )==mrec );

          uchar const * _val;
          ulong         bigval = fd_rng_ulong( rng );
          int           err;

          FD_TEST( fd_funk_val_append( mrec, &bigval, sizeof(ulong), alloc, wksp, NULL )==mrec );

          _val = (uchar const *)fd_funk_val_const( mrec, wksp );
          FD_TEST( FD_LOAD( uint,  _val    )==val    );
          FD_TEST( FD_LOAD( ulong, _val+ 4 )==bigval );
          TEST_TAIL_PADDING( 12UL );

          bigval = ~bigval;
          err = 1; FD_TEST( fd_funk_val_append( mrec, &bigval, sizeof(ulong), alloc, wksp, &err )==mrec && !err );
          bigval = ~bigval;

          _val = (uchar const *)fd_funk_val_const( mrec, wksp );
          FD_TEST( FD_LOAD( uint,  _val    )== val    );
          FD_TEST( FD_LOAD( ulong, _val+ 4 )== bigval );
          FD_TEST( FD_LOAD( ulong, _val+12 )==~bigval );
          TEST_TAIL_PADDING( 20UL );

          FD_TEST( fd_funk_val_truncate( mrec, 4UL, alloc, wksp, NULL )==mrec );
        }
      }

      FD_TEST( fd_funk_val_write( (void *)1UL, 0UL, 0UL, NULL, NULL )==(void *)1UL ); /* sz 0 */

      FD_TEST( !fd_funk_val_write( NULL, 0UL,       4UL,       &val,              wksp ) ); /* NULL rec */
      FD_TEST( !fd_funk_val_write( mrec, 3UL,       ULONG_MAX, &val,              wksp ) ); /* off+sz wrapped */
      FD_TEST( !fd_funk_val_write( mrec, ULONG_MAX, 3UL,       &val,              wksp ) ); /* off+sz wrapped */
      FD_TEST( !fd_funk_val_write( mrec, 0UL,       4UL,       NULL,              wksp ) ); /* NULL data with sz!=0 */
      FD_TEST( !fd_funk_val_write( mrec, 0UL,       4UL,       (void *)ULONG_MAX, wksp ) ); /* data wrapped */
      FD_TEST( !fd_funk_val_write( mrec, 0UL,       4UL,       &val,              NULL ) ); /* NULL wksp */
      FD_TEST( !fd_funk_val_write( mrec, 4UL,       1UL,       &val,              NULL ) ); /* write past end */

      int err;

      void const * wrap    = (void const *)ULONG_MAX;
      ulong        too_big = FD_FUNK_REC_VAL_MAX + 1UL - (mrec ? fd_funk_val_sz( mrec ) : 0UL);
      ulong        vmax    = (mrec ? fd_funk_val_max( mrec ) : 0UL);

      FD_TEST( fd_funk_val_append( (void *)1UL, 0UL, 0UL, NULL, NULL, NULL )==(void *)1UL ); /* sz 0 */

      FD_TEST( !fd_funk_val_append( NULL, &val,     4UL,      alloc, wksp, NULL ) ); /* NULL rec */
      FD_TEST( !fd_funk_val_append( mrec, NULL,     4UL,      alloc, wksp, NULL ) ); /* NULL data with sz!=0 */
      FD_TEST( !fd_funk_val_append( mrec, wrap,     4UL,      alloc, wksp, NULL ) ); /* data wraps */
      FD_TEST( !fd_funk_val_append( NULL, &val,     too_big,  alloc, wksp, NULL ) ); /* sz too big */
      FD_TEST( !fd_funk_val_append( mrec, &val,     4UL,      NULL,  wksp, NULL ) ); /* NULL alloc */
      FD_TEST( !fd_funk_val_append( mrec, &val,     4UL,      alloc, NULL, NULL ) ); /* NULL wksp */

      err = 1; FD_TEST( fd_funk_val_append( (void *)1UL, 0UL, 0UL, NULL, NULL, &err )==(void *)1UL && !err ); /* sz 0 */

      err = 1; FD_TEST( !fd_funk_val_append( NULL, &val,     4UL,      alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* NULL rec */
      err = 1; FD_TEST( !fd_funk_val_append( mrec, NULL,     4UL,      alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* NULL data with sz!=0 */
      err = 1; FD_TEST( !fd_funk_val_append( mrec, wrap,     4UL,      alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* data wraps */
      err = 1; FD_TEST( !fd_funk_val_append( NULL, &val,     too_big,  alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* sz too big */
      err = 1; FD_TEST( !fd_funk_val_append( mrec, &val,     4UL,      NULL,  wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* NULL alloc */
      err = 1; FD_TEST( !fd_funk_val_append( mrec, &val,     4UL,      alloc, NULL, &err ) && err==FD_FUNK_ERR_INVAL ); /* NULL wksp */

      if( vmax ) {
        uchar const * olap = (uchar const *)fd_funk_val_const( mrec, wksp );
        FD_TEST( !fd_funk_val_append( mrec, olap,     vmax,     alloc, wksp, NULL ) ); /* exact overlap */
        FD_TEST( !fd_funk_val_append( mrec, olap-1UL, vmax,     alloc, wksp, NULL ) ); /* partial overlap start */
        FD_TEST( !fd_funk_val_append( mrec, olap+1UL, vmax,     alloc, wksp, NULL ) ); /* partial overlap end */
        FD_TEST( !fd_funk_val_append( mrec, olap+1UL, vmax-2UL, alloc, wksp, NULL ) ); /* val overlaps data */
        FD_TEST( !fd_funk_val_append( mrec, olap-1UL, vmax+2UL, alloc, wksp, NULL ) ); /* data overlaps val */

        err = 1; FD_TEST( !fd_funk_val_append( mrec, olap,     vmax,     alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* exact overlap */
        err = 1; FD_TEST( !fd_funk_val_append( mrec, olap-1UL, vmax,     alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* partial overlap start */
        err = 1; FD_TEST( !fd_funk_val_append( mrec, olap+1UL, vmax,     alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* partial overlap end */
        err = 1; FD_TEST( !fd_funk_val_append( mrec, olap+1UL, vmax-2UL, alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* val overlaps data */
        err = 1; FD_TEST( !fd_funk_val_append( mrec, olap-1UL, vmax+2UL, alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* data overlaps val */
      }

      rrec = rrec->map_next;
    }

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

      rec_t * rrec = rec_insert( ref, rtxn, rkey );

      int err = 1;
      fd_funk_rec_t const * trec =
        fd_funk_rec_insert( tst, fd_funk_txn_query( xid_set( txid, rxid ), txn_map ), key_set( tkey, rkey ), &err );
      FD_TEST( trec && !err );

      uint val = (fd_rng_uint( rng )<<2) | 1U;
      rrec->val = val;

      ulong bigval = fd_rng_ulong( rng );

      /* initial state should be empty */

      fd_funk_rec_t * mrec = fd_funk_rec_modify( tst, trec );
      FD_TEST( !fd_funk_val_sz ( mrec )         );
      FD_TEST( !fd_funk_val_max( mrec )         );
      FD_TEST( !fd_funk_val_const( mrec, wksp ) );
      FD_TEST( !fd_funk_val      ( mrec, wksp ) );
      TEST_TAIL_PADDING( 0UL );

      /* Do copy and truncate ops without error details ***************/

      /* basic copy */
      FD_TEST( fd_funk_val_copy( mrec, &val, sizeof(uint), 0UL, alloc, wksp, NULL )==mrec );
      FD_TEST( fd_funk_val_sz ( mrec )                         ==sizeof(uint) );
      FD_TEST( fd_funk_val_max( mrec )                         >=sizeof(uint) );
      FD_TEST( FD_LOAD( uint, fd_funk_val_const( mrec, wksp ) )==val          );
      FD_TEST( FD_LOAD( uint, fd_funk_val      ( mrec, wksp ) )==val          );
      TEST_TAIL_PADDING( 4UL );

      /* make it same */
      FD_TEST( fd_funk_val_truncate( mrec, 4UL, alloc, wksp, NULL )==mrec );
      FD_TEST( fd_funk_val_sz ( mrec )==4UL                           );
      FD_TEST( fd_funk_val_max( mrec )>=4UL                           );
      FD_TEST( FD_LOAD( uint,  fd_funk_val_const( mrec, wksp ) )==val );
      FD_TEST( FD_LOAD( uint,  fd_funk_val      ( mrec, wksp ) )==val );
      TEST_TAIL_PADDING( 4UL );

      /* make larger */
      FD_TEST( fd_funk_val_truncate( mrec, 8UL, alloc, wksp, NULL )==mrec );
      FD_TEST( fd_funk_val_sz ( mrec )==8UL                           );
      FD_TEST( fd_funk_val_max( mrec )>=8UL                           );
      FD_TEST( FD_LOAD( uint,  fd_funk_val_const( mrec, wksp ) )==val );
      FD_TEST( FD_LOAD( uint,  fd_funk_val      ( mrec, wksp ) )==val );
      TEST_TAIL_PADDING( 4UL );

      /* make smaller */
      FD_TEST( fd_funk_val_truncate( mrec, 4UL, alloc, wksp, NULL )==mrec );
      FD_TEST( fd_funk_val_sz ( mrec )==4UL                           );
      FD_TEST( fd_funk_val_max( mrec )>=4UL                           );
      FD_TEST( FD_LOAD( uint,  fd_funk_val_const( mrec, wksp ) )==val );
      FD_TEST( FD_LOAD( uint,  fd_funk_val      ( mrec, wksp ) )==val );
      TEST_TAIL_PADDING( 4UL );

      /* flush via copy */
      FD_TEST( fd_funk_val_copy( mrec, NULL, 0UL, 0UL, alloc, wksp, NULL )==mrec );
      FD_TEST( !fd_funk_val_sz ( mrec )         );
      FD_TEST( !fd_funk_val_max( mrec )         );
      FD_TEST( !fd_funk_val_const( mrec, wksp ) );
      FD_TEST( !fd_funk_val      ( mrec, wksp ) );
      TEST_TAIL_PADDING( 0UL );

      /* copy with preallocation */
      FD_TEST( fd_funk_val_copy( mrec, &val, sizeof(uint), sizeof(ulong), alloc, wksp, NULL )==mrec );
      FD_TEST( fd_funk_val_sz ( mrec )                         ==sizeof(uint)  );
      FD_TEST( fd_funk_val_max( mrec )                         >=sizeof(ulong) );
      FD_TEST( FD_LOAD( uint, fd_funk_val_const( mrec, wksp ) )==val           );
      FD_TEST( FD_LOAD( uint, fd_funk_val      ( mrec, wksp ) )==val           );
      TEST_TAIL_PADDING( 4UL );

      /* flush with preallocate */
      FD_TEST( fd_funk_val_copy( mrec, NULL, 0UL, 9UL, alloc, wksp, NULL )==mrec );
      FD_TEST( !fd_funk_val_sz( mrec )           );
      FD_TEST( fd_funk_val_max( mrec )>=9UL      );
      FD_TEST( !!fd_funk_val_const( mrec, wksp ) );
      FD_TEST( fd_funk_val( mrec, wksp )==(void *)fd_funk_val_const( mrec, wksp ) );
      TEST_TAIL_PADDING( 0UL );

      /* basic copy */
      FD_TEST( fd_funk_val_copy( mrec, &val, sizeof(uint), 0UL, alloc, wksp, NULL )==mrec );
      FD_TEST( fd_funk_val_sz ( mrec )                         ==sizeof(uint) );
      FD_TEST( fd_funk_val_max( mrec )                         >=sizeof(uint) );
      FD_TEST( FD_LOAD( uint, fd_funk_val_const( mrec, wksp ) )==val          );
      FD_TEST( FD_LOAD( uint, fd_funk_val      ( mrec, wksp ) )==val          );
      TEST_TAIL_PADDING( 4UL );

      /* copy bigger value over smaller value */
      FD_TEST( fd_funk_val_copy( mrec, &bigval, sizeof(ulong), 0UL, alloc, wksp, NULL )==mrec );
      FD_TEST( fd_funk_val_sz ( mrec )                          ==sizeof(ulong) );
      FD_TEST( fd_funk_val_max( mrec )                          >=sizeof(ulong) );
      FD_TEST( FD_LOAD( ulong, fd_funk_val_const( mrec, wksp ) )==bigval        );
      FD_TEST( FD_LOAD( ulong, fd_funk_val      ( mrec, wksp ) )==bigval        );
      TEST_TAIL_PADDING( 8UL );

      /* copy smaller value over bigger value and prep for later iter */
      FD_TEST( fd_funk_val_copy( mrec, &val, sizeof(uint), 0UL, alloc, wksp, NULL )==mrec );
      FD_TEST( fd_funk_val_sz ( mrec )                         ==sizeof(uint) );
      FD_TEST( fd_funk_val_max( mrec )                         >=sizeof(uint) );
      FD_TEST( FD_LOAD( uint, fd_funk_val_const( mrec, wksp ) )==val          );
      FD_TEST( FD_LOAD( uint, fd_funk_val      ( mrec, wksp ) )==val          );
      TEST_TAIL_PADDING( 4UL );

      /* flush via truncate */
      FD_TEST( fd_funk_val_truncate( mrec, 0UL, alloc, wksp, NULL )==mrec );
      FD_TEST( !fd_funk_val_sz ( mrec )         );
      FD_TEST( !fd_funk_val_max( mrec )         );
      FD_TEST( !fd_funk_val_const( mrec, wksp ) );
      FD_TEST( !fd_funk_val      ( mrec, wksp ) );
      TEST_TAIL_PADDING( 0UL );

      /* Do it again with err details *********************************/

      /* basic copy */
      err = 1; FD_TEST( fd_funk_val_copy( mrec, &val, sizeof(uint), 0UL, alloc, wksp, &err )==mrec && !err );
      FD_TEST( fd_funk_val_sz ( mrec )                         ==sizeof(uint) );
      FD_TEST( fd_funk_val_max( mrec )                         >=sizeof(uint) );
      FD_TEST( FD_LOAD( uint, fd_funk_val_const( mrec, wksp ) )==val          );
      FD_TEST( FD_LOAD( uint, fd_funk_val      ( mrec, wksp ) )==val          );
      TEST_TAIL_PADDING( 4UL );

      /* make it same */
      err = 1; FD_TEST( fd_funk_val_truncate( mrec, 4UL, alloc, wksp, &err )==mrec && !err );
      FD_TEST( fd_funk_val_sz ( mrec )==4UL                           );
      FD_TEST( fd_funk_val_max( mrec )>=4UL                           );
      FD_TEST( FD_LOAD( uint,  fd_funk_val_const( mrec, wksp ) )==val );
      FD_TEST( FD_LOAD( uint,  fd_funk_val      ( mrec, wksp ) )==val );
      TEST_TAIL_PADDING( 4UL );

      /* make larger */
      err = 1; FD_TEST( fd_funk_val_truncate( mrec, 8UL, alloc, wksp, &err )==mrec && !err );
      FD_TEST( fd_funk_val_sz ( mrec )==8UL                           );
      FD_TEST( fd_funk_val_max( mrec )>=8UL                           );
      FD_TEST( FD_LOAD( uint,  fd_funk_val_const( mrec, wksp ) )==val );
      FD_TEST( FD_LOAD( uint,  fd_funk_val      ( mrec, wksp ) )==val );
      TEST_TAIL_PADDING( 4UL );

      /* make smaller */
      err = 1; FD_TEST( fd_funk_val_truncate( mrec, 4UL, alloc, wksp, &err )==mrec && !err );
      FD_TEST( fd_funk_val_sz ( mrec )==4UL                           );
      FD_TEST( fd_funk_val_max( mrec )>=4UL                           );
      FD_TEST( FD_LOAD( uint,  fd_funk_val_const( mrec, wksp ) )==val );
      FD_TEST( FD_LOAD( uint,  fd_funk_val      ( mrec, wksp ) )==val );
      TEST_TAIL_PADDING( 4UL );

      /* flush via copy */
      err = 1; FD_TEST( fd_funk_val_copy( mrec, NULL, 0UL, 0UL, alloc, wksp, &err )==mrec && !err );
      FD_TEST( !fd_funk_val_sz ( mrec )         );
      FD_TEST( !fd_funk_val_max( mrec )         );
      FD_TEST( !fd_funk_val_const( mrec, wksp ) );
      FD_TEST( !fd_funk_val      ( mrec, wksp ) );
      TEST_TAIL_PADDING( 0UL );

      /* copy with preallocation */
      err = 1; FD_TEST( fd_funk_val_copy( mrec, &val, sizeof(uint), sizeof(ulong), alloc, wksp, &err )==mrec && !err );
      FD_TEST( fd_funk_val_sz ( mrec )                         ==sizeof(uint)  );
      FD_TEST( fd_funk_val_max( mrec )                         >=sizeof(ulong) );
      FD_TEST( FD_LOAD( uint, fd_funk_val_const( mrec, wksp ) )==val           );
      FD_TEST( FD_LOAD( uint, fd_funk_val      ( mrec, wksp ) )==val           );
      TEST_TAIL_PADDING( 4UL );

      /* flush with preallocate */
      err = 1; FD_TEST( fd_funk_val_copy( mrec, NULL, 0UL, 9UL, alloc, wksp, &err )==mrec && !err );
      FD_TEST( !fd_funk_val_sz( mrec )           );
      FD_TEST( fd_funk_val_max( mrec )>=9UL      );
      FD_TEST( !!fd_funk_val_const( mrec, wksp ) );
      FD_TEST( fd_funk_val( mrec, wksp )==(void *)fd_funk_val_const( mrec, wksp ) );
      TEST_TAIL_PADDING( 0UL );

      /* basic copy */
      err = 1; FD_TEST( fd_funk_val_copy( mrec, &val, sizeof(uint), 0UL, alloc, wksp, &err )==mrec && !err );
      FD_TEST( fd_funk_val_sz ( mrec )                         ==sizeof(uint) );
      FD_TEST( fd_funk_val_max( mrec )                         >=sizeof(uint) );
      FD_TEST( FD_LOAD( uint, fd_funk_val_const( mrec, wksp ) )==val          );
      FD_TEST( FD_LOAD( uint, fd_funk_val      ( mrec, wksp ) )==val          );
      TEST_TAIL_PADDING( 4UL );

      /* copy bigger value over smaller value */
      err = 1; FD_TEST( fd_funk_val_copy( mrec, &bigval, sizeof(ulong), 0UL, alloc, wksp, &err )==mrec && !err );
      FD_TEST( fd_funk_val_sz ( mrec )                          ==sizeof(ulong) );
      FD_TEST( fd_funk_val_max( mrec )                          >=sizeof(ulong) );
      FD_TEST( FD_LOAD( ulong, fd_funk_val_const( mrec, wksp ) )==bigval        );
      FD_TEST( FD_LOAD( ulong, fd_funk_val      ( mrec, wksp ) )==bigval        );
      TEST_TAIL_PADDING( 8UL );

      /* copy smaller value over bigger value and prep for later iter */
      err = 1; FD_TEST( fd_funk_val_copy( mrec, &val, sizeof(uint), 0UL, alloc, wksp, &err )==mrec && !err );
      FD_TEST( fd_funk_val_sz ( mrec )                         ==sizeof(uint) );
      FD_TEST( fd_funk_val_max( mrec )                         >=sizeof(uint) );
      FD_TEST( FD_LOAD( uint, fd_funk_val_const( mrec, wksp ) )==val          );
      FD_TEST( FD_LOAD( uint, fd_funk_val      ( mrec, wksp ) )==val          );
      TEST_TAIL_PADDING( 4UL );

      /* flush via truncate */
      err = 1; FD_TEST( fd_funk_val_truncate( mrec, 0UL, alloc, wksp, &err )==mrec && !err );
      FD_TEST( !fd_funk_val_sz ( mrec )         );
      FD_TEST( !fd_funk_val_max( mrec )         );
      FD_TEST( !fd_funk_val_const( mrec, wksp ) );
      FD_TEST( !fd_funk_val      ( mrec, wksp ) );
      TEST_TAIL_PADDING( 0UL );

      /* Prep for later iter ******************************************/

      FD_TEST( fd_funk_val_copy( mrec, &val, sizeof(uint), 0UL, alloc, wksp, NULL )==mrec );
      FD_TEST( fd_funk_val_sz ( mrec )                         ==sizeof(uint) );
      FD_TEST( fd_funk_val_max( mrec )                         >=sizeof(uint) );
      FD_TEST( FD_LOAD( uint, fd_funk_val_const( mrec, wksp ) )==val          );
      FD_TEST( FD_LOAD( uint, fd_funk_val      ( mrec, wksp ) )==val          );
      TEST_TAIL_PADDING( 4UL );

      void const *  wrap    = (void const *)ULONG_MAX;
      ulong         too_big = FD_FUNK_REC_VAL_MAX+1UL;
      uchar const * olap    = (uchar const *)fd_funk_val_const( mrec, wksp );

      /* Test a bunch of error cases */

      FD_TEST( !fd_funk_val_copy( NULL, &val,     sizeof(uint), 0UL,     alloc, wksp, NULL ) ); /* NULL rec */
      FD_TEST( !fd_funk_val_copy( mrec, NULL,     sizeof(uint), 0UL,     alloc, wksp, NULL ) ); /* NULL data w sz!=0 */
      FD_TEST( !fd_funk_val_copy( mrec, &val,     sizeof(uint), 0UL,     NULL,  wksp, NULL ) ); /* NULL alloc */
      FD_TEST( !fd_funk_val_copy( mrec, &val,     sizeof(uint), 0UL,     alloc, NULL, NULL ) ); /* NULL wksp */
      FD_TEST( !fd_funk_val_copy( mrec, wrap,     sizeof(uint), 0UL,     alloc, NULL, NULL ) ); /* data wraps */
      FD_TEST( !fd_funk_val_copy( mrec, &val,     too_big,      0UL,     alloc, NULL, NULL ) ); /* sz too big */
      FD_TEST( !fd_funk_val_copy( mrec, &val,     sizeof(uint), 1UL,     alloc, NULL, NULL ) ); /* sz_est<sz */
      FD_TEST( !fd_funk_val_copy( mrec, &val,     sizeof(uint), too_big, alloc, NULL, NULL ) ); /* sz_est too big */
      FD_TEST( !fd_funk_val_copy( mrec, olap,     sizeof(uint), 0UL,     alloc, wksp, NULL ) ); /* exact overlap */
      FD_TEST( !fd_funk_val_copy( mrec, olap-1UL, 2UL,          0UL,     alloc, wksp, NULL ) ); /* partial overlap start */
      FD_TEST( !fd_funk_val_copy( mrec, olap+3UL, 2UL,          0UL,     alloc, wksp, NULL ) ); /* partial overlap end */
      FD_TEST( !fd_funk_val_copy( mrec, olap+1UL, 1UL,          0UL,     alloc, wksp, NULL ) ); /* val overlaps data */
      FD_TEST( !fd_funk_val_copy( mrec, olap-1UL, 6UL,          0UL,     alloc, wksp, NULL ) ); /* data overlaps val */

      err = 1; FD_TEST( !fd_funk_val_copy( NULL, &val,     sizeof(uint), 0UL,     alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* NULL rec */
      err = 1; FD_TEST( !fd_funk_val_copy( mrec, NULL,     sizeof(uint), 0UL,     alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* NULL data w sz!=0 */
      err = 1; FD_TEST( !fd_funk_val_copy( mrec, &val,     sizeof(uint), 0UL,     NULL,  wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* NULL alloc */
      err = 1; FD_TEST( !fd_funk_val_copy( mrec, &val,     sizeof(uint), 0UL,     alloc, NULL, &err ) && err==FD_FUNK_ERR_INVAL ); /* NULL wksp */
      err = 1; FD_TEST( !fd_funk_val_copy( mrec, wrap,     sizeof(uint), 0UL,     alloc, NULL, &err ) && err==FD_FUNK_ERR_INVAL ); /* data wraps */
      err = 1; FD_TEST( !fd_funk_val_copy( mrec, &val,     too_big,      0UL,     alloc, NULL, &err ) && err==FD_FUNK_ERR_INVAL ); /* sz too big */
      err = 1; FD_TEST( !fd_funk_val_copy( mrec, &val,     sizeof(uint), 1UL,     alloc, NULL, &err ) && err==FD_FUNK_ERR_INVAL ); /* sz_est<sz */
      err = 1; FD_TEST( !fd_funk_val_copy( mrec, &val,     sizeof(uint), too_big, alloc, NULL, &err ) && err==FD_FUNK_ERR_INVAL ); /* sz_est too big */
      err = 1; FD_TEST( !fd_funk_val_copy( mrec, olap,     sizeof(uint), 0UL,     alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* exact overlap */
      err = 1; FD_TEST( !fd_funk_val_copy( mrec, olap-1UL, 2UL,          0UL,     alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* partial overlap start */
      err = 1; FD_TEST( !fd_funk_val_copy( mrec, olap+3UL, 2UL,          0UL,     alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* partial overlap end */
      err = 1; FD_TEST( !fd_funk_val_copy( mrec, olap+1UL, 1UL,          0UL,     alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* val overlaps data */
      err = 1; FD_TEST( !fd_funk_val_copy( mrec, olap-1UL, 6UL,          0UL,     alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* data overlaps val */

      FD_TEST( !fd_funk_val_truncate( NULL, 0UL,     alloc, wksp, NULL ) ); /* NULL rec */
      FD_TEST( !fd_funk_val_truncate( mrec, too_big, alloc, wksp, NULL ) ); /* too big val sz */
      FD_TEST( !fd_funk_val_truncate( mrec, 0UL,     NULL,  wksp, NULL ) ); /* NULL alloc */
      FD_TEST( !fd_funk_val_truncate( mrec, 0UL,     alloc, NULL, NULL ) ); /* NULL wksp */

      err = 1; FD_TEST( !fd_funk_val_truncate( NULL, 0UL,     alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* NULL rec */
      err = 1; FD_TEST( !fd_funk_val_truncate( mrec, too_big, alloc, wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* too big val sz */
      err = 1; FD_TEST( !fd_funk_val_truncate( mrec, 0UL,     NULL,  wksp, &err ) && err==FD_FUNK_ERR_INVAL ); /* NULL alloc */
      err = 1; FD_TEST( !fd_funk_val_truncate( mrec, 0UL,     alloc, NULL, &err ) && err==FD_FUNK_ERR_INVAL ); /* NULL wksp */

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

      fd_funk_rec_t * _trec = fd_funk_rec_modify( tst, trec );
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

    } else if( op>=1UL ) { /* Cancel (same rate as publish) */

      if( FD_UNLIKELY( !ref->txn_cnt ) ) continue;

      ulong idx = fd_rng_ulong_roll( rng, ref->txn_cnt );

      txn_t *         rtxn = ref->txn_map_head; for( ulong rem=idx; rem; rem-- ) rtxn = rtxn->map_next;
      fd_funk_txn_t * ttxn = fd_funk_txn_query( xid_set( txid, rtxn->xid ), txn_map );

      ulong cnt = ref->txn_cnt; txn_cancel( ref, rtxn ); cnt -= ref->txn_cnt;
      FD_TEST( fd_funk_txn_cancel( tst, ttxn, verbose )==cnt );

    } else { /* Publish (same rate as cancel) */

      if( FD_UNLIKELY( !ref->txn_cnt ) ) continue;

      ulong idx = fd_rng_ulong_roll( rng, ref->txn_cnt );

      txn_t *         rtxn = ref->txn_map_head; for( ulong rem=idx; rem; rem-- ) rtxn = rtxn->map_next;
      fd_funk_txn_t * ttxn = fd_funk_txn_query( xid_set( txid, rtxn->xid ), txn_map );

      ulong cnt = txn_publish( ref, rtxn, 0UL );
      FD_TEST( fd_funk_txn_publish( tst, ttxn, verbose )==cnt );

    }
  }

  fd_funk_end_write( tst );

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
