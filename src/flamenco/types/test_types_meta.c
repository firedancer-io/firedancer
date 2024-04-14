#include "fd_types_meta.h"
#include "../../util/fd_util.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_NULL    )==1 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_BOOL    )==1 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_UCHAR   )==1 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_SCHAR   )==1 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_USHORT  )==1 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_SSHORT  )==1 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_UINT    )==1 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_SINT    )==1 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_ULONG   )==1 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_SLONG   )==1 );
# if FD_HAS_INT128
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_UINT128 )==1 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_SINT128 )==1 );
# endif
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_FLOAT   )==1 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_DOUBLE  )==1 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_HASH256 )==1 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_SIG512  )==1 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_CSTR    )==1 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_ARR     )==0 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_ARR_END )==0 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_MAP     )==0 );
  FD_TEST( fd_flamenco_type_is_primitive( FD_FLAMENCO_TYPE_MAP_END )==0 );

  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_NULL    )==0 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_BOOL    )==0 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_UCHAR   )==0 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_SCHAR   )==0 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_USHORT  )==0 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_SSHORT  )==0 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_UINT    )==0 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_SINT    )==0 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_ULONG   )==0 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_SLONG   )==0 );
# if FD_HAS_INT128
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_UINT128 )==0 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_SINT128 )==0 );
# endif
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_FLOAT   )==0 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_DOUBLE  )==0 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_HASH256 )==0 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_SIG512  )==0 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_CSTR    )==0 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_ARR     )==1 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_ARR_END )==1 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_MAP     )==1 );
  FD_TEST( fd_flamenco_type_is_collection( FD_FLAMENCO_TYPE_MAP_END )==1 );

  FD_TEST( fd_flamenco_type_is_collection_begin( FD_FLAMENCO_TYPE_ARR     )==1 );
  FD_TEST( fd_flamenco_type_is_collection_begin( FD_FLAMENCO_TYPE_ARR_END )==0 );
  FD_TEST( fd_flamenco_type_is_collection_begin( FD_FLAMENCO_TYPE_MAP     )==1 );
  FD_TEST( fd_flamenco_type_is_collection_begin( FD_FLAMENCO_TYPE_MAP_END )==0 );

  FD_TEST( fd_flamenco_type_is_collection_end( FD_FLAMENCO_TYPE_ARR     )==0 );
  FD_TEST( fd_flamenco_type_is_collection_end( FD_FLAMENCO_TYPE_ARR_END )==1 );
  FD_TEST( fd_flamenco_type_is_collection_end( FD_FLAMENCO_TYPE_MAP     )==0 );
  FD_TEST( fd_flamenco_type_is_collection_end( FD_FLAMENCO_TYPE_MAP_END )==1 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}
