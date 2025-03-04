#include "fd_director.h"
#include "../../groove/fd_groove.h"
#include "fd_acc_mgr.h"
#include "../types/fd_types.h"

#define FD_DIRECTOR_HOT_STORE_SIZE (100000000000UL);

struct fd_director {
  /* Local join to the hot store (Funk) */
  fd_funk_t * funk;

  /* Local join to the cold store (Groove volume) */
  fd_groove_t * groove;
};

int
fd_director_account_in_hot_store( fd_director_t const * director,
                                  fd_funk_txn_t const * txn,
                                  fd_pubkey_t const   * pubkey ) {
  fd_funk_rec_key_t id      = fd_acc_funk_key( pubkey );
  fd_funk_rec_t const * rec = fd_funk_rec_query_global( director->funk, txn, &id, NULL );
  return rec != NULL;               
}

int
fd_director_find_record_to_evict( fd_director_t      *  director,
                                  fd_funk_txn_t      ** out_txn,
                                  fd_pubkey_t        ** out_pubkey ) {

  /* Locate the root transaction */

}

/* Loads the given account from the cold store into the hot store, if it is not already in the hot store. */
int
fd_director_load_account_into_funk( fd_director_t      * director,
                                    fd_funk_txn_t const * txn,
                                    fd_pubkey_t   const * pubkey ) {

  /* If the account is already present in Funk we don't need to do anything */
  if( FD_LIKELY(( fd_director_account_in_hot_store( director, txn, pubkey ) )) ) {
    return FD_DIRECTOR_ACCOUNT_SUCCESS;
  }

  /* Check to see if the account is present in the cold store */
  fd_groove_key_t const * key = fd_type_pun_const( pubkey );
  fd_groove_meta_map_query_t query[1];
  int rc = fd_groove_meta_map_prepare( director->groove->meta_map, key, NULL, query, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( rc != FD_MAP_SUCCESS )) {
   return rc;
  }
  fd_groove_meta_t * ele = fd_groove_meta_map_query_ele( query );
  int present            = ele && fd_groove_meta_bits_used( ele->bits ) && fd_groove_meta_bits_cold( ele->bits );

  /* If the account does not exist in the cold store, then we return an error */
  if( FD_UNLIKELY(( !present )) ) {
    fd_groove_meta_map_cancel( query );
    return FD_DIRECTOR_ACCOUNT_MISSING;
  }

  /* If the account is in cold storage, swap the oldest accessed account in Funk  */
  /* Oldest account:
     - Find the root transaction
     - Find the oldest record in the root transaction
  */
  fd_funk_rec_t fd_funk_txn_rec_

  return 0;
}