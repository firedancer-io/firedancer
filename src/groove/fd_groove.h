#ifndef HEADER_fd_src_groove_fd_groove_h
#define HEADER_fd_src_groove_fd_groove_h

/* Note: will still function without FD_HAS_ATOMIC but will not be safe
   to use concurrently. */

//#include "fd_groove_base.h"   /* includes ../util/fd_util.h */
#include "fd_groove_meta.h"   /* includes fd_groove_base.h */
//#include "fd_groove_volume.h" /* includes fd_groove_base.h */
#include "fd_groove_data.h"     /* includes fd_groove_meta.h, fd_groove_volume.h */

struct fd_groove {
   /* The metadata store */
   fd_groove_meta_map_t * meta_map;

   /* The data store */
   fd_groove_data_t * data;
};
typedef struct fd_groove fd_groove_t;

/* Look up to see if the account is in the metadata store */
int
fd_groove_account_exists( fd_groove_t const * groove,
                          fd_pubkey_t const * pubkey ) {

//   fd_groove_key_t * key = fd_type_pub(pubkey);
//   fd_groove_meta_map_query_t query[1];
//   int rc = fd_groove_meta_map_prepare( groove->meta_map, key, NULL, query, FD_MAP_FLAG_BLOCKING );
//   if( FD_UNLIKELY( rc != FD_MAP_SUCCESS )) {
//    return rc;
//   }

//   fd_groove_meta_t *ele = fd_groove_meta_map_query_ele( query );
//   int res = fd_groove_meta_bits_used( ele );
//   fd_groove_meta_map_query_cancel(query);

}

#endif /* HEADER_fd_src_groove_fd_groove_h */
