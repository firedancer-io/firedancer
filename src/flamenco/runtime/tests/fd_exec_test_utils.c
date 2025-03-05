#include "fd_exec_test_utils.h"

int
fd_exec_test_restore_feature_flags( fd_features_t * features,
                                    fd_exec_test_feature_set_t const * feature_set ) {
  fd_features_disable_all( features );
  for( ulong j=0UL; j < feature_set->features_count; j++ ) {
    ulong                   prefix = feature_set->features[j];
    fd_feature_id_t const * id     = fd_feature_id_query( prefix );
    if( FD_UNLIKELY( !id ) ) {
      FD_LOG_WARNING(( "unsupported feature ID 0x%016lx", prefix ));
      return 0;
    }
    /* Enabled since genesis */
    fd_features_set( features, id, 0UL );
  }
  return 1;
}
