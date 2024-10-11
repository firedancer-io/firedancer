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
fd_features_enable_cleaned_up( fd_features_t * f, uint cluster_version[3] ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
       !fd_feature_iter_done( id );
       id = fd_feature_iter_next( id ) ) {
    if( ( id->cleaned_up[0]<cluster_version[0] ) ||
        ( id->cleaned_up[0]==cluster_version[0] && id->cleaned_up[1]<cluster_version[1] ) ||
        ( id->cleaned_up[0]==cluster_version[0] && id->cleaned_up[1]==cluster_version[1] && id->cleaned_up[2]<=cluster_version[2] ) ) {
      fd_features_set( f, id, 0UL );
    } else {
      fd_features_set( f, id, FD_FEATURE_DISABLED );
    }
  }
}

void
fd_features_enable_one_offs( fd_features_t * f, char const * * one_offs, uint one_offs_cnt, ulong slot ) {
  uchar pubkey[32];
  for( uint i=0U; i<one_offs_cnt; i++ ) {
    fd_base58_decode_32( one_offs[i], pubkey );
    for( fd_feature_id_t const * id = fd_feature_iter_init();
         !fd_feature_iter_done( id );
         id = fd_feature_iter_next( id ) ) {
      if( !memcmp( &id->id, pubkey, sizeof(fd_pubkey_t) ) ) {
        fd_features_set( f, id, slot );
        break;
      }
    }
  }
}
