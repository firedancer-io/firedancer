#include "../fd_util.h"

uchar mem[ 16384 ];

FD_STATIC_ASSERT( FD_POD_SUCCESS    == 0, unit_test );
FD_STATIC_ASSERT( FD_POD_ERR_INVAL  ==-1, unit_test );
FD_STATIC_ASSERT( FD_POD_ERR_TYPE   ==-2, unit_test );
FD_STATIC_ASSERT( FD_POD_ERR_RESOLVE==-3, unit_test );
FD_STATIC_ASSERT( FD_POD_ERR_FULL   ==-4, unit_test );

FD_STATIC_ASSERT( FD_POD_VAL_TYPE_SUBPOD == 0, unit_test );
FD_STATIC_ASSERT( FD_POD_VAL_TYPE_BUF    == 1, unit_test );
FD_STATIC_ASSERT( FD_POD_VAL_TYPE_CSTR   == 2, unit_test );
FD_STATIC_ASSERT( FD_POD_VAL_TYPE_CHAR   == 3, unit_test );
FD_STATIC_ASSERT( FD_POD_VAL_TYPE_SCHAR  == 4, unit_test );
FD_STATIC_ASSERT( FD_POD_VAL_TYPE_SHORT  == 5, unit_test );
FD_STATIC_ASSERT( FD_POD_VAL_TYPE_INT    == 6, unit_test );
FD_STATIC_ASSERT( FD_POD_VAL_TYPE_LONG   == 7, unit_test );
FD_STATIC_ASSERT( FD_POD_VAL_TYPE_INT128 == 8, unit_test );
FD_STATIC_ASSERT( FD_POD_VAL_TYPE_UCHAR  == 9, unit_test );
FD_STATIC_ASSERT( FD_POD_VAL_TYPE_USHORT ==10, unit_test );
FD_STATIC_ASSERT( FD_POD_VAL_TYPE_UINT   ==11, unit_test );
FD_STATIC_ASSERT( FD_POD_VAL_TYPE_ULONG  ==12, unit_test );
FD_STATIC_ASSERT( FD_POD_VAL_TYPE_UINT128==13, unit_test );
FD_STATIC_ASSERT( FD_POD_VAL_TYPE_FLOAT  ==14, unit_test );
FD_STATIC_ASSERT( FD_POD_VAL_TYPE_DOUBLE ==15, unit_test );

FD_STATIC_ASSERT( FD_POD_FOOTPRINT_MIN==3UL, unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# define TEST(c) do if( !(c) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  ulong max = fd_env_strip_cmdline_ulong( &argc, &argv, "--max", NULL, 16384UL );
  if( FD_UNLIKELY( !((FD_POD_FOOTPRINT_MIN<=max) & (max<=16384UL)) ) ) {
    FD_LOG_WARNING(( "SKIP: invalid --max %lu for current unit test", max ));
    return 0;
  }

  FD_LOG_NOTICE(( "Testing with --max %lu", max ));

  ulong   align     = fd_pod_align();          TEST( align    ==1UL           );
  ulong   footprint = fd_pod_footprint( max ); TEST( footprint==max           );
  void *  shpod     = fd_pod_new ( mem, max ); TEST( shpod    ==(void *)mem   );
  uchar * pod       = fd_pod_join( mem      ); TEST( pod      ==(void *)shpod );

  FD_LOG_NOTICE(( "Testing SUCCESS strerror (%i-%s)", FD_POD_SUCCESS,     fd_pod_strerror( FD_POD_SUCCESS     ) ));
  FD_LOG_NOTICE(( "Testing INVAL   strerror (%i-%s)", FD_POD_ERR_INVAL,   fd_pod_strerror( FD_POD_ERR_INVAL   ) ));
  FD_LOG_NOTICE(( "Testing TYPE    strerror (%i-%s)", FD_POD_ERR_TYPE,    fd_pod_strerror( FD_POD_ERR_TYPE    ) ));
  FD_LOG_NOTICE(( "Testing RESOLVE strerror (%i-%s)", FD_POD_ERR_RESOLVE, fd_pod_strerror( FD_POD_ERR_RESOLVE ) ));
  FD_LOG_NOTICE(( "Testing FULL    strerror (%i-%s)", FD_POD_ERR_FULL,    fd_pod_strerror( FD_POD_ERR_FULL    ) ));
  FD_LOG_NOTICE(( "Testing UNKNOWN strerror (%i-%s)", 1,                  fd_pod_strerror( 1                  ) ));

  for( ulong iter=0UL; iter<1000; iter++ ) {
    ulong hdr_sz = 3UL*fd_ulong_svw_enc_sz( max );
    TEST( fd_pod_max  ( pod )==max        );
    TEST( fd_pod_used ( pod )==hdr_sz     );
    TEST( fd_pod_cnt  ( pod )==0UL        );
    TEST( fd_pod_avail( pod )==max-hdr_sz );

    for(;;) {
      uint  r       = fd_rng_uint( rng );
      int   type    = (int)(r & 15U);         r >>= 4;
      ulong path_sz = 1UL + (ulong)(r & 63U); r >>= 6;
      int   remove  = (int)(r & 1U);          r >>= 1;
      int   compact = !(r & 15U);             r >>= 4;
      int   full    = (int)(r & 1U);          r >>= 1;

      if( compact ) {
        ulong orig_max = fd_pod_max( pod );
        ulong orig_cnt = fd_pod_cnt( pod );

        ulong compact_max = fd_pod_compact( pod, full );
        TEST( fd_pod_max( pod )==compact_max );

        if( !full ) TEST( fd_pod_max( pod )==orig_max );
        TEST( fd_pod_cnt( pod )==orig_cnt );

        TEST( fd_pod_resize( pod, max )==max );

        TEST( fd_pod_max( pod )==max      );
        TEST( fd_pod_cnt( pod )==orig_cnt );
      }

      ulong cnt = fd_pod_cnt( pod );
      if( cnt<=64UL ) {
        fd_pod_info_t list[64]; TEST( fd_pod_list( pod, list )==list );
        for( ulong idx=0UL; idx<cnt; idx++ ) {
          fd_pod_info_t query[1]; TEST( !fd_pod_query( pod, list[idx].key, query ) );
          TEST( list[idx].key_sz  ==query->key_sz   );
          TEST( list[idx].key     ==query->key      );
          TEST( list[idx].val_type==query->val_type );
          TEST( list[idx].val_sz  ==query->val_sz   );
          TEST( list[idx].val     ==query->val      );
          TEST( list[idx].parent  ==query->parent   );
        }
      }

      ulong cnt2 = fd_pod_cnt_recursive( pod );
      if( cnt2<=64UL ) {
        fd_pod_info_t list[64]; TEST( fd_pod_list_recursive( pod, list )==list );
        for( ulong idx=0UL; idx<cnt2; idx++ ) {
          if( list[idx].parent!=NULL ) continue;
          fd_pod_info_t query[1]; TEST( !fd_pod_query( pod, list[idx].key, query ) );
          TEST( list[idx].key_sz  ==query->key_sz   );
          TEST( list[idx].key     ==query->key      );
          TEST( list[idx].val_type==query->val_type );
          TEST( list[idx].val_sz  ==query->val_sz   );
          TEST( list[idx].val     ==query->val      );
          TEST( list[idx].parent  ==query->parent   );
        }
      }

      char path[65];
      for( ulong b=0UL; b<path_sz-1UL; b++ ) {
        char c = (char)( (uint)'a' + (fd_rng_uint( rng ) & 3U) );
        if( c=='d' ) c = '.';
        path[b] = c;
      }
      path[path_sz-1UL] = '\0';

      fd_pod_info_t info[1];
      int err  = fd_pod_query( pod, path, info ); TEST( (!err) | (err==FD_POD_ERR_TYPE) | (err==FD_POD_ERR_RESOLVE) );
      int coll = 0;
      if(      err==FD_POD_ERR_RESOLVE ) TEST( fd_pod_remove( pod, path )==FD_POD_ERR_RESOLVE );
      else if( err==FD_POD_ERR_TYPE    ) TEST( fd_pod_remove( pod, path )==FD_POD_ERR_TYPE    );
      else if( remove )                  TEST( fd_pod_remove( pod, path )==FD_POD_SUCCESS     );
      else                               coll = 1;

      switch( type ) {
      case FD_POD_VAL_TYPE_SUBPOD: break;

      case FD_POD_VAL_TYPE_BUF: {
        void const * buf = fd_pod_query_buf( pod, path, NULL );
        if( !coll || info->val_type!=FD_POD_VAL_TYPE_BUF ) TEST( !buf  );
        else                                               TEST( buf==info->val );

        uchar _buf[63];
        ulong _buf_sz = ((ulong)fd_rng_uint( rng )) & 63UL;
        for( ulong b=0UL; b<_buf_sz; b++ ) _buf[b] = fd_rng_uchar( rng );

        ulong off = fd_pod_insert_buf( pod, path, _buf, _buf_sz );

        if( coll || err==FD_POD_ERR_TYPE ) TEST( !off );
        else if( !off ) goto full;
        else {
          TEST( !memcmp( pod+off, _buf, _buf_sz ) );
          ulong buf_sz;
          TEST( fd_pod_query_buf( pod, path, &buf_sz )==(void const *)(pod+off) );
          TEST( buf_sz==_buf_sz );
        }
      } break;

      case FD_POD_VAL_TYPE_CSTR: {
        char const * def  = "default";
        char const * cstr = fd_pod_query_cstr( pod, path, def );
        if( !coll || info->val_type!=FD_POD_VAL_TYPE_CSTR ) TEST( cstr==def  );
        else if( !info->val_sz )                            TEST( cstr==NULL );
        else                                                TEST( cstr==(char const *)info->val );

        char _cstr[63];
        ulong _cstr_sz = ((ulong)fd_rng_uint( rng )) & 63UL;
        for( ulong b=0UL; b<_cstr_sz; b++ ) _cstr[b] = (char)(fd_rng_uint( rng ) | 1U);
        if( _cstr_sz ) _cstr[_cstr_sz-1UL] = '\0';

        ulong off = fd_pod_insert_cstr( pod, path, _cstr_sz ? _cstr : NULL );
        if( coll || err==FD_POD_ERR_TYPE ) TEST( !off );
        else if( !off ) goto full;
        else {
          TEST( !memcmp( pod+off, _cstr, _cstr_sz ) );
          TEST( fd_pod_query_cstr( pod, path, def )==(_cstr_sz ? (char const *)(pod+off) : NULL) );
        }
      } break;

#     define CASE(type,TYPE)                                                    \
      case FD_POD_VAL_TYPE_##TYPE: {                                            \
        type  def = (type)fd_rng_ulong( rng );                                  \
        type  val = fd_pod_query_##type( pod, path, def );                      \
        if( !coll || info->val_type!=FD_POD_VAL_TYPE_##TYPE ) TEST( val==def ); \
        val = (type)fd_rng_ulong( rng );                                        \
        ulong off = fd_pod_insert_##type( pod, path, val );                     \
        if( coll || err==FD_POD_ERR_TYPE ) TEST( !off );                        \
        else if( !off ) goto full;                                              \
        else TEST( fd_pod_query_##type( pod, path, def )==val );                \
      } break

      CASE(char,   CHAR   );
      CASE(schar,  SCHAR  );
      CASE(short,  SHORT  );
      CASE(int,    INT    );
      CASE(long,   LONG   );
#     if FD_HAS_INT128
      CASE(int128, INT128 ); /* FIXME: USE WIDER GEN */
#     endif
      CASE(uchar,  UCHAR  );
      CASE(ushort, USHORT );
      CASE(uint,   UINT   );
      CASE(ulong,  ULONG  );
#     if FD_HAS_INT128
      CASE(uint128,UINT128); /* FIXME: USE WIDER GEN */
#     endif
      CASE(float,  FLOAT  );
#     if FD_HAS_DOUBLE
      CASE(double, DOUBLE );
#     endif

      default: break;
      }
    }

  full:
    TEST( fd_pod_reset( pod )==pod );
  }

  TEST( fd_pod_leave ( pod   )==shpod       );
  TEST( fd_pod_delete( shpod )==(void *)mem );

# undef TEST

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

