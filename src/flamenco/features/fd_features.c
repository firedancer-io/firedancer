#include "fd_features.h"

void
fd_features_enable_all( fd_features_t * f ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
       !fd_feature_iter_done( id );
       id = fd_feature_iter_next( id ) ) {
    fd_features_set( f, id, 0UL );
  }
}

void
fd_features_disable_all( fd_features_t * f ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
       !fd_feature_iter_done( id );
       id = fd_feature_iter_next( id ) ) {
    fd_features_set( f, id, FD_FEATURE_DISABLED );
  }
}

void
fd_features_enable_hardcoded( fd_features_t * f ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
       !fd_feature_iter_done( id );
       id = fd_feature_iter_next( id ) ) {
    if( id->hardcoded ) {
      fd_features_set( f, id, 0UL );
    }
  }
}
