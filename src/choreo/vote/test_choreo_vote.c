#include <sys/random.h>
#include "../../util/fd_util.h"
#include "../../choreo/fd_choreo.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/txn/fd_txn_generate.h"
#include "../../flamenco/runtime/fd_system_ids.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

#define TEST_VOTE_TXN_MAGIC (0x7e58UL)

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  /* keys */
  fd_sha512_t sha[2];
  fd_pubkey_t vote_acct_pubkey, validator_pubkey;
  uchar vote_acct_privkey[32], validator_privkey[32];

  FD_TEST( 32UL == getrandom( vote_acct_privkey, 32UL, 0 ) );
  FD_TEST( 32UL == getrandom( validator_privkey, 32UL, 0 ) );
  FD_TEST( fd_ed25519_public_from_private( vote_acct_pubkey.key, vote_acct_privkey, &sha[0] ) );
  FD_TEST( fd_ed25519_public_from_private( validator_pubkey.key, validator_privkey, &sha[1] ) );

  /* workspace */
  ulong page_cnt = 1;
  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* alloc */
  void * alloc_shmem =
      fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), TEST_VOTE_TXN_MAGIC );
  void *       alloc_shalloc = fd_alloc_new( alloc_shmem, TEST_VOTE_TXN_MAGIC );
  fd_alloc_t * alloc         = fd_alloc_join( alloc_shalloc, 0UL );
  fd_valloc_t  valloc        = fd_alloc_virtual( alloc );

  /* create compact_vote_state_update with dummy values */
  fd_compact_vote_state_update_t compact_vote_update;
  memset( &compact_vote_update, 0, sizeof(fd_compact_vote_state_update_t) );
  compact_vote_update.root = 100;
  compact_vote_update.lockouts_len = 0;
  static ulong now = 1715701506716580798UL;
  compact_vote_update.timestamp = &now;
  FD_TEST( 32UL == getrandom( compact_vote_update.hash.key, 32UL, 0 ) );

  /* create the vote transaction */
  uchar txn_meta_buf[ FD_TXN_MAX_SZ ];
  uchar txn_buf [ FD_TXN_MTU ];
  uchar *recent_blockhash = NULL;
  ulong txn_size = fd_vote_txn_generate( &compact_vote_update, &validator_pubkey, &vote_acct_pubkey, validator_privkey, vote_acct_privkey, recent_blockhash, txn_meta_buf, txn_buf);
  FD_LOG_NOTICE(("fd_vote_txn_generate: vote txn has %lu bytes", txn_size));

  /* parse the transaction back */
  fd_compact_vote_state_update_t parsed_vote_update;
  FD_TEST( FD_VOTE_TXN_PARSE_OK == fd_vote_txn_parse(txn_buf, txn_size, valloc, &parsed_vote_update) );
  FD_LOG_NOTICE((".root: %ld == %ld", compact_vote_update.root, parsed_vote_update.root));
  FD_LOG_NOTICE((".timestamp: %lu == %lu", *compact_vote_update.timestamp, *parsed_vote_update.timestamp));
  FD_LOG_NOTICE((".hash: %32J == %32J", compact_vote_update.hash.key, parsed_vote_update.hash.key));
}
