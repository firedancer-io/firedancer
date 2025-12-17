#include "fd_stake_ci.h"
#include "../../ballet/base58/fd_base58.h"

uchar _stake_ci[ 32UL*1024UL*1024UL ] __attribute__((aligned(128UL)));
uchar _stake_ci_broadcast[ 32UL*1024UL*1024UL ] __attribute__((aligned(128UL)));

uchar _stake_msg_mem[ FD_STAKE_CI_STAKE_MSG_SZ ];

/* Cluster data from deterministic Rust test */
static const struct {
  const char * pubkey_base58;
  ulong stake;
} CLUSTER_NODES[20] = {
  { "HyepegvEV1ZwAMnuunwLoBT81GzgD8Uud6pJwK537cpT", 100 }, /* Leader */
  { "jwV7SyvqCSrVcKibYvurCCWr7DUmT7yRYPmY9QwvrGo", 600 },
  { "25TXLvcMJNvRY4vb95G9Kpvf9A3LJCdWLswD47xvXsaX", 0 },
  { "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM", 100 },
  { "QRSsyMWN1yHT9ir42bgNZUNZ4PdEhcSWCrL2AryKpy5", 400 },
  { "oqtkwi1j2wZuJSh74CMk7wk77nFUQDt1Qhf3Liweew9", 700 },
  { "g35TxFqwMx95vCk63fTxGTHb6ei4W24qg5t2x6xD3cT", 600 },
  { "wei3wABWhvzigge84jFXySCd8untJRhB9KS3jLw6GFq", 0 },
  { "skJQSS6csSHJzZfcZToe3gyN8M2BMKnbH1YYY2wNTbV", 700 },
  { "UKrXU5bFrTzrqqpZXs8GVDbp4xPweiM65ADXNAy3ddR", 400 },
  { "21Z7hRtGQYRi8NocdZzhRuBRt9UZbFXbm1dKYvevp4vB", 0 },
  { "29MvzRLSCDR8wm3ZeaXbDkftQAc719jQvkF6ZKGvFgEs", 0 },
  { "LX3EUdRUBUa3TbsYXLEUdj9J3prXkWXvLYSWyYyc2Jj", 300 },
  { "YEGAxog9gxiGXxo538aAQxq55XAebpFfwU72ZUxmSHm", 500 },
  { "GcdayuLaLyrdmUu324nahyv33G5poQdLUEZ1nEytDeP", 300 },
  { "2DGLdv4X63urMTAYA5o37gR7fBAsi6qKWcYz4WauyUuD", 0 },
  { "CiDwVBFgWV9E5MvXWoLgnEgn2hK7rJikbvfWavzAQz3", 200 },
  { "c8fpTXm3XTRgE5maYQ24Li4L65wMYvAFomzXknxVEx7", 500 },
  { "2HAkHQnbytQZm9HWfb4V1cALvBjeR3wE6UrsZhtuhHZZ", 0 },
  { "8opHzTAnfzRpPEx21XtnrVTX28YQuCpAjcn1PczScKh", 200 },
};

/* Expected leader schedule from Rust */
static const struct {
  const char * pubkey_base58;
  ulong slot;
} EXPECTED_LEADERS[9] = {
  { "LX3EUdRUBUa3TbsYXLEUdj9J3prXkWXvLYSWyYyc2Jj", 8 },
  { "LX3EUdRUBUa3TbsYXLEUdj9J3prXkWXvLYSWyYyc2Jj", 10 },
  { "YEGAxog9gxiGXxo538aAQxq55XAebpFfwU72ZUxmSHm", 12 },
  { "skJQSS6csSHJzZfcZToe3gyN8M2BMKnbH1YYY2wNTbV", 16 },
  { "QRSsyMWN1yHT9ir42bgNZUNZ4PdEhcSWCrL2AryKpy5", 20 },
  { "c8fpTXm3XTRgE5maYQ24Li4L65wMYvAFomzXknxVEx7", 24 },
  { "c8fpTXm3XTRgE5maYQ24Li4L65wMYvAFomzXknxVEx7", 32 },
  { "skJQSS6csSHJzZfcZToe3gyN8M2BMKnbH1YYY2wNTbV", 40 },
  { "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM", 164 },
};

/* Typedefs for expected data structures */
typedef struct {
  ulong slot;
  uint shred_index;
  int is_data;
  const char * expected_broadcast_pubkey;
} expected_broadcast_t;

typedef struct {
  const char * pubkey_base58;
  ulong num_children;
} expected_first_layer_t;

typedef struct {
  ulong parent_idx;
  const char * child_pubkey_base58;
} expected_second_layer_t;

/* Expected broadcast node from Rust (slot 28, index 31, Data shred, CHACHA20) */
/* Slot 28 is where first node (HyepegvEV1ZwAMnuunwLoBT81GzgD8Uud6pJwK537cpT) is the leader */
/* Root/broadcast node (first recipient from leader) is LX3EUdRUBUa3TbsYXLEUdj9J3prXkWXvLYSWyYyc2Jj */
static const expected_broadcast_t EXPECTED_BROADCAST_CHACHA20 = {
  28, 31, 1, "LX3EUdRUBUa3TbsYXLEUdj9J3prXkWXvLYSWyYyc2Jj"
};

/* Expected first layer of turbine tree (CHACHA20) */
/* These are the children of the broadcast peer (root node) */
static const expected_first_layer_t EXPECTED_FIRST_LAYER_CHACHA20[10] = {
  { "oqtkwi1j2wZuJSh74CMk7wk77nFUQDt1Qhf3Liweew9", 1 },
  { "c8fpTXm3XTRgE5maYQ24Li4L65wMYvAFomzXknxVEx7", 1 },
  { "8opHzTAnfzRpPEx21XtnrVTX28YQuCpAjcn1PczScKh", 1 },
  { "jwV7SyvqCSrVcKibYvurCCWr7DUmT7yRYPmY9QwvrGo", 1 },
  { "QRSsyMWN1yHT9ir42bgNZUNZ4PdEhcSWCrL2AryKpy5", 1 },
  { "skJQSS6csSHJzZfcZToe3gyN8M2BMKnbH1YYY2wNTbV", 1 },
  { "GcdayuLaLyrdmUu324nahyv33G5poQdLUEZ1nEytDeP", 1 },
  { "YEGAxog9gxiGXxo538aAQxq55XAebpFfwU72ZUxmSHm", 1 },
  { "UKrXU5bFrTzrqqpZXs8GVDbp4xPweiM65ADXNAy3ddR", 0 },
  { "g35TxFqwMx95vCk63fTxGTHb6ei4W24qg5t2x6xD3cT", 0 },
};

/* Expected second layer of turbine tree (CHACHA20) */
/* Each first-layer node may have their own children */
static const expected_second_layer_t EXPECTED_SECOND_LAYER_CHACHA20[8] = {
  { 0, "CiDwVBFgWV9E5MvXWoLgnEgn2hK7rJikbvfWavzAQz3" },
  { 1, "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM" },
  { 2, "21Z7hRtGQYRi8NocdZzhRuBRt9UZbFXbm1dKYvevp4vB" },
  { 3, "2HAkHQnbytQZm9HWfb4V1cALvBjeR3wE6UrsZhtuhHZZ" },
  { 4, "25TXLvcMJNvRY4vb95G9Kpvf9A3LJCdWLswD47xvXsaX" },
  { 5, "wei3wABWhvzigge84jFXySCd8untJRhB9KS3jLw6GFq" },
  { 6, "2DGLdv4X63urMTAYA5o37gR7fBAsi6qKWcYz4WauyUuD" },
  { 7, "29MvzRLSCDR8wm3ZeaXbDkftQAc719jQvkF6ZKGvFgEs" },
};

/* Expected broadcast node from Rust (slot 28, index 31, Data shred, CHACHA8) */
/* Slot 28 is where first node (HyepegvEV1ZwAMnuunwLoBT81GzgD8Uud6pJwK537cpT) is the leader */
/* Root/broadcast node (first recipient from leader) is GcdayuLaLyrdmUu324nahyv33G5poQdLUEZ1nEytDeP */
static const expected_broadcast_t EXPECTED_BROADCAST_CHACHA8 = {
  28, 31, 1, "GcdayuLaLyrdmUu324nahyv33G5poQdLUEZ1nEytDeP"
};

/* Expected first layer of turbine tree (CHACHA8) */
/* These are the children of the broadcast peer (root node) */
static const expected_first_layer_t EXPECTED_FIRST_LAYER_CHACHA8[10] = {
  { "oqtkwi1j2wZuJSh74CMk7wk77nFUQDt1Qhf3Liweew9", 1 },
  { "QRSsyMWN1yHT9ir42bgNZUNZ4PdEhcSWCrL2AryKpy5", 1 },
  { "UKrXU5bFrTzrqqpZXs8GVDbp4xPweiM65ADXNAy3ddR", 1 },
  { "c8fpTXm3XTRgE5maYQ24Li4L65wMYvAFomzXknxVEx7", 1 },
  { "CiDwVBFgWV9E5MvXWoLgnEgn2hK7rJikbvfWavzAQz3", 1 },
  { "g35TxFqwMx95vCk63fTxGTHb6ei4W24qg5t2x6xD3cT", 1 },
  { "YEGAxog9gxiGXxo538aAQxq55XAebpFfwU72ZUxmSHm", 1 },
  { "LX3EUdRUBUa3TbsYXLEUdj9J3prXkWXvLYSWyYyc2Jj", 1 },
  { "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM", 0 },
  { "jwV7SyvqCSrVcKibYvurCCWr7DUmT7yRYPmY9QwvrGo", 0 },
};

/* Expected second layer of turbine tree (CHACHA8) */
/* Each first-layer node may have their own children */
static const expected_second_layer_t EXPECTED_SECOND_LAYER_CHACHA8[8] = {
  { 0, "skJQSS6csSHJzZfcZToe3gyN8M2BMKnbH1YYY2wNTbV" },
  { 1, "8opHzTAnfzRpPEx21XtnrVTX28YQuCpAjcn1PczScKh" },
  { 2, "29MvzRLSCDR8wm3ZeaXbDkftQAc719jQvkF6ZKGvFgEs" },
  { 3, "2HAkHQnbytQZm9HWfb4V1cALvBjeR3wE6UrsZhtuhHZZ" },
  { 4, "25TXLvcMJNvRY4vb95G9Kpvf9A3LJCdWLswD47xvXsaX" },
  { 5, "21Z7hRtGQYRi8NocdZzhRuBRt9UZbFXbm1dKYvevp4vB" },
  { 6, "wei3wABWhvzigge84jFXySCd8untJRhB9KS3jLw6GFq" },
  { 7, "2DGLdv4X63urMTAYA5o37gR7fBAsi6qKWcYz4WauyUuD" },
};

static void
test_shred_dest_conformance(
  int use_chacha8,
  expected_broadcast_t const * expected_broadcast,
  expected_first_layer_t const * expected_first_layer,
  ulong expected_first_layer_cnt,
  expected_second_layer_t const * expected_second_layer,
  ulong expected_second_layer_cnt
) {
  const char * rng_name = use_chacha8 ? "ChaCha8" : "ChaCha20";
  (void)expected_second_layer_cnt;  /* Suppress unused warning - count is implicit in loop */
  FD_LOG_NOTICE(( "=== Testing Shred Dest Conformance (%s) ===", rng_name ));

  /* Decode all pubkeys from base58 to binary */
  fd_pubkey_t pubkeys[20];
  for( ulong i=0UL; i<20UL; i++ ) {
    uchar * result = fd_base58_decode_32( CLUSTER_NODES[i].pubkey_base58, pubkeys[i].uc );
    FD_TEST( result != NULL );
  }

  /* Create fd_stake_ci with the leader node as identity */
  fd_pubkey_t const * identity_key = &pubkeys[0];
  fd_stake_ci_t * stake_ci = fd_stake_ci_join( fd_stake_ci_new( _stake_ci, identity_key ) );
  FD_TEST( stake_ci );

  /* Initialize stake message for epoch 123 */
  fd_stake_weight_msg_t * stake_msg = (fd_stake_weight_msg_t *)_stake_msg_mem;
  stake_msg->epoch = 123UL;
  stake_msg->start_slot = 0UL;
  stake_msg->slot_cnt = 432000UL;
  stake_msg->excluded_stake = 0UL;
  stake_msg->vote_keyed_lsched = 0UL;  /* Use identity-keyed leader schedule */

  /* Count staked nodes and build stake weights */
  ulong staked_cnt = 0UL;
  for( ulong i=0UL; i<20UL; i++ ) {
    if( CLUSTER_NODES[i].stake > 0UL ) {
      memcpy( stake_msg->weights[staked_cnt].id_key.uc, pubkeys[i].uc, 32UL );
      memcpy( stake_msg->weights[staked_cnt].vote_key.uc, pubkeys[i].uc, 32UL );
      stake_msg->weights[staked_cnt].stake = CLUSTER_NODES[i].stake;
      staked_cnt++;
    }
  }
  stake_msg->staked_cnt = staked_cnt;

  FD_LOG_NOTICE(( "Staked nodes: %lu / 20", staked_cnt ));

  /* Process stake message */
  fd_stake_ci_stake_msg_init( stake_ci, stake_msg );
  fd_stake_ci_stake_msg_fini( stake_ci );

  /* Add destination contact info for all nodes */
  fd_shred_dest_weighted_t * dest_info = fd_stake_ci_dest_add_init( stake_ci );
  for( ulong i=0UL; i<20UL; i++ ) {
    memcpy( dest_info[i].pubkey.uc, pubkeys[i].uc, 32UL );
    dest_info[i].stake_lamports = CLUSTER_NODES[i].stake;
    dest_info[i].ip4 = (uint)(i+1);  /* Dummy IP */
    dest_info[i].port = (ushort)(8000 + i);  /* Dummy port */
  }
  fd_stake_ci_dest_add_fini( stake_ci, 20UL );

  /* Get leader schedule for testing */
  fd_epoch_leaders_t * lsched = fd_stake_ci_get_lsched_for_slot( stake_ci, EXPECTED_LEADERS[0].slot );
  FD_TEST( lsched );

  /* Test: Leader schedule */
  FD_LOG_NOTICE(( "\n=== Testing Leader Schedule ===" ));
  ulong leader_passed = 0UL;
  ulong leader_failed = 0UL;

  for( ulong i=0UL; i<9UL; i++ ) {
    fd_pubkey_t const * slot_leader = fd_epoch_leaders_get( lsched, EXPECTED_LEADERS[i].slot );

    uchar expected_pubkey[32];
    uchar * decode_result = fd_base58_decode_32( EXPECTED_LEADERS[i].pubkey_base58, expected_pubkey );
    FD_TEST( decode_result != NULL );

    if( !memcmp( slot_leader->uc, expected_pubkey, 32UL ) ) {
      leader_passed++;
      FD_LOG_NOTICE(( "  PASS: slot=%lu -> leader=%s",
        EXPECTED_LEADERS[i].slot, EXPECTED_LEADERS[i].pubkey_base58 ));
    } else {
      leader_failed++;
      char leader_str[FD_BASE58_ENCODED_32_SZ];
      fd_base58_encode_32( slot_leader->uc, NULL, leader_str );
      FD_LOG_WARNING(( "  FAIL: slot=%lu, expected leader=%s, got leader=%s",
        EXPECTED_LEADERS[i].slot, EXPECTED_LEADERS[i].pubkey_base58, leader_str ));
    }
  }

  FD_LOG_NOTICE(( "\nLeader schedule: %lu passed, %lu failed out of 9 tests",
    leader_passed, leader_failed ));

  /* Test 2: Broadcast node */
  FD_LOG_NOTICE(( "\n=== Testing Broadcast Node ===" ));

  /* Get the leader for the test slot */
  fd_pubkey_t const * test_slot_leader = fd_epoch_leaders_get( lsched, expected_broadcast->slot );
  FD_TEST( test_slot_leader );

  char test_slot_leader_str[FD_BASE58_ENCODED_32_SZ];
  fd_base58_encode_32( test_slot_leader->uc, NULL, test_slot_leader_str );
  FD_LOG_NOTICE(( "Leader for slot %lu: %s", expected_broadcast->slot, test_slot_leader_str ));

  /* Get shred dest for the test slot */
  fd_shred_dest_t * sdest = fd_stake_ci_get_sdest_for_slot( stake_ci, expected_broadcast->slot );
  FD_TEST( sdest );

  /* Create test shred */
  fd_shred_t shred[1];
  shred->slot = expected_broadcast->slot;
  shred->variant = fd_shred_variant(
    expected_broadcast->is_data ? FD_SHRED_TYPE_MERKLE_DATA : FD_SHRED_TYPE_MERKLE_CODE, 2 );
  shred->idx = expected_broadcast->shred_index;

  fd_shred_t const * shred_ptr[1] = { shred };

  /* Compute broadcast peer */
  fd_shred_dest_idx_t result[1];
  FD_TEST( fd_shred_dest_compute_first( sdest, shred_ptr, 1UL, result, use_chacha8 ) );
  fd_shred_dest_weighted_t const * broadcast_peer = fd_shred_dest_idx_to_dest( sdest, *result );

  if( !broadcast_peer->ip4 ) broadcast_peer = fd_shred_dest_idx_to_dest( sdest, FD_SHRED_DEST_NO_DEST );

  /* Encode result pubkey to base58 */
  char result_pubkey_base58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( broadcast_peer->pubkey.uc, NULL, result_pubkey_base58 );

  /* Decode expected pubkey */
  uchar expected_broadcast_pubkey[32];
  uchar * decode_result = fd_base58_decode_32( expected_broadcast->expected_broadcast_pubkey, expected_broadcast_pubkey );
  FD_TEST( decode_result != NULL );

  /* Compare */
  ulong broadcast_passed = 0UL;
  ulong broadcast_failed = 0UL;

  if( !memcmp( broadcast_peer->pubkey.uc, expected_broadcast_pubkey, 32UL ) ) {
    broadcast_passed++;
    FD_LOG_NOTICE(( "  PASS: slot=%lu, shred_idx=%u -> broadcast=%s",
      expected_broadcast->slot, expected_broadcast->shred_index, result_pubkey_base58 ));
  } else {
    broadcast_failed++;
    FD_LOG_WARNING(( "  FAIL: slot=%lu, shred_idx=%u, expected broadcast=%s, got broadcast=%s",
      expected_broadcast->slot, expected_broadcast->shred_index,
      expected_broadcast->expected_broadcast_pubkey, result_pubkey_base58 ));
  }

  FD_LOG_NOTICE(( "\nBroadcast node: %lu passed, %lu failed out of 1 test",
    broadcast_passed, broadcast_failed ));

  /* Test 3: Turbine tree children */
  FD_LOG_NOTICE(( "\n=== Testing Turbine Tree Children ===" ));

  /* To compute children from broadcast peer's perspective, we need to recreate stake_ci
     with the broadcast peer as the identity */
  fd_stake_ci_t * stake_ci_broadcast = fd_stake_ci_join( fd_stake_ci_new( _stake_ci_broadcast, &broadcast_peer->pubkey ) );
  FD_TEST( stake_ci_broadcast );

  /* Process stake message */
  fd_stake_ci_stake_msg_init( stake_ci_broadcast, stake_msg );
  fd_stake_ci_stake_msg_fini( stake_ci_broadcast );

  /* Add destination contact info for all nodes */
  fd_shred_dest_weighted_t * dest_info_broadcast = fd_stake_ci_dest_add_init( stake_ci_broadcast );
  for( ulong i=0UL; i<20UL; i++ ) {
    memcpy( dest_info_broadcast[i].pubkey.uc, pubkeys[i].uc, 32UL );
    dest_info_broadcast[i].stake_lamports = CLUSTER_NODES[i].stake;
    dest_info_broadcast[i].ip4 = (uint)(i+1);  /* Dummy IP */
    dest_info_broadcast[i].port = (ushort)(8000 + i);  /* Dummy port */
  }
  fd_stake_ci_dest_add_fini( stake_ci_broadcast, 20UL );

  /* Get shred dest for the test slot from broadcast peer's perspective */
  fd_shred_dest_t * sdest_broadcast = fd_stake_ci_get_sdest_for_slot( stake_ci_broadcast, expected_broadcast->slot );
  FD_TEST( sdest_broadcast );

  ulong fanout = 10UL;
  fd_shred_dest_idx_t children_result[10];
  ulong max_dest_cnt = 0UL;

  /* Compute children for the test shred from the broadcast peer's perspective
     For single shred, use out_stride=1 so results are at children_result[0..9] */
  fd_shred_dest_idx_t * children_ptr = fd_shred_dest_compute_children(
    sdest_broadcast, shred_ptr, 1UL, children_result, /*out_stride=*/1UL, fanout, fanout, &max_dest_cnt, use_chacha8 );
  FD_TEST( children_ptr );

  FD_LOG_NOTICE(( "Computed %lu children (max_dest_cnt=%lu)", fanout, max_dest_cnt ));

  ulong children_passed = 0UL;
  ulong children_failed = 0UL;

  for( ulong i=0UL; i<expected_first_layer_cnt; i++ ) {
    fd_shred_dest_weighted_t const * child = fd_shred_dest_idx_to_dest( sdest_broadcast, children_result[i] );

    /* Check if this is a valid destination */
    if( children_result[i] == FD_SHRED_DEST_NO_DEST || !child->ip4 ) {
      FD_LOG_WARNING(( "  SKIP: child[%lu] is NO_DEST or has no IP", i ));
      children_failed++;
      continue;
    }

    char child_pubkey_base58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( child->pubkey.uc, NULL, child_pubkey_base58 );

    /* Decode expected child pubkey */
    uchar expected_child_pubkey[32];
    uchar * child_decode_result = fd_base58_decode_32( expected_first_layer[i].pubkey_base58, expected_child_pubkey );
    FD_TEST( child_decode_result != NULL );

    if( !memcmp( child->pubkey.uc, expected_child_pubkey, 32UL ) ) {
      children_passed++;
      if( i < 3UL ) {  /* Print first few */
        FD_LOG_NOTICE(( "  PASS: child[%lu] -> %s", i, child_pubkey_base58 ));
      }
    } else {
      children_failed++;
      FD_LOG_WARNING(( "  FAIL: child[%lu], expected=%s, got=%s",
        i, expected_first_layer[i].pubkey_base58, child_pubkey_base58 ));
    }
  }

  FD_LOG_NOTICE(( "\nTurbine tree children: %lu passed, %lu failed out of 10 tests",
    children_passed, children_failed ));

  /* Clean up broadcast stake_ci */
  fd_stake_ci_delete( fd_stake_ci_leave( stake_ci_broadcast ) );

  /* Test 4: Second layer of turbine tree */
  FD_LOG_NOTICE(( "\n=== Testing Turbine Tree Second Layer ===" ));

  ulong second_layer_passed = 0UL;
  ulong second_layer_failed = 0UL;
  ulong second_layer_child_idx = 0UL;

  /* For each first-layer child, compute their children */
  for( ulong parent_idx=0UL; parent_idx<10UL; parent_idx++ ) {
    /* children_result was computed using sdest_broadcast, so decode using sdest_broadcast */
    fd_shred_dest_weighted_t const * parent = fd_shred_dest_idx_to_dest( sdest_broadcast, children_result[parent_idx] );

    /* Expected number of children for this parent */
    ulong expected_num_children = expected_first_layer[parent_idx].num_children;

    if( expected_num_children == 0UL ) {
      /* No children expected, skip */
      continue;
    }

    /* Create stake_ci for this parent */
    fd_stake_ci_t * parent_stake_ci = fd_stake_ci_join( fd_stake_ci_new( _stake_ci_broadcast, &parent->pubkey ) );
    FD_TEST( parent_stake_ci );

    /* Process stake message */
    fd_stake_ci_stake_msg_init( parent_stake_ci, stake_msg );
    fd_stake_ci_stake_msg_fini( parent_stake_ci );

    /* Add destination contact info for all nodes */
    fd_shred_dest_weighted_t * parent_dest_info = fd_stake_ci_dest_add_init( parent_stake_ci );
    for( ulong i=0UL; i<20UL; i++ ) {
      memcpy( parent_dest_info[i].pubkey.uc, pubkeys[i].uc, 32UL );
      parent_dest_info[i].stake_lamports = CLUSTER_NODES[i].stake;
      parent_dest_info[i].ip4 = (uint)(i+1);  /* Dummy IP */
      parent_dest_info[i].port = (ushort)(8000 + i);  /* Dummy port */
    }
    fd_stake_ci_dest_add_fini( parent_stake_ci, 20UL );

    /* Get shred dest for the test slot from parent's perspective */
    fd_shred_dest_t * parent_sdest = fd_stake_ci_get_sdest_for_slot( parent_stake_ci, expected_broadcast->slot );
    FD_TEST( parent_sdest );

    /* Compute children for this parent */
    fd_shred_dest_idx_t parent_children_result[10];
    ulong parent_max_dest_cnt = 0UL;
    fd_shred_dest_idx_t * parent_children_ptr = fd_shred_dest_compute_children(
      parent_sdest, shred_ptr, 1UL, parent_children_result, /*out_stride=*/1UL, fanout, fanout, &parent_max_dest_cnt, use_chacha8 );
    FD_TEST( parent_children_ptr );

    /* Verify children */
    for( ulong child_idx=0UL; child_idx<expected_num_children; child_idx++ ) {
      fd_shred_dest_weighted_t const * child = fd_shred_dest_idx_to_dest( parent_sdest, parent_children_result[child_idx] );

      if( parent_children_result[child_idx] == FD_SHRED_DEST_NO_DEST || !child->ip4 ) {
        second_layer_failed++;
        continue;
      }

      /* Decode expected child pubkey */
      uchar expected_child_pubkey[32];
      uchar * decode_result = fd_base58_decode_32( expected_second_layer[second_layer_child_idx].child_pubkey_base58, expected_child_pubkey );
      FD_TEST( decode_result != NULL );

      if( !memcmp( child->pubkey.uc, expected_child_pubkey, 32UL ) ) {
        second_layer_passed++;
        if( parent_idx < 3UL ) {  /* Print first few */
          char child_str[ FD_BASE58_ENCODED_32_SZ ];
          fd_base58_encode_32( child->pubkey.uc, NULL, child_str );
          FD_LOG_NOTICE(( "  PASS: parent[%lu] child[%lu] -> %s", parent_idx, child_idx, child_str ));
        }
      } else {
        second_layer_failed++;
        char child_str[ FD_BASE58_ENCODED_32_SZ ];
        fd_base58_encode_32( child->pubkey.uc, NULL, child_str );
        FD_LOG_WARNING(( "  FAIL: parent[%lu] child[%lu], expected=%s, got=%s",
          parent_idx, child_idx, expected_second_layer[second_layer_child_idx].child_pubkey_base58, child_str ));
      }

      second_layer_child_idx++;
    }

    /* Clean up parent stake_ci */
    fd_stake_ci_delete( fd_stake_ci_leave( parent_stake_ci ) );
  }

  FD_LOG_NOTICE(( "\nTurbine tree second layer: %lu passed, %lu failed out of 8 tests",
    second_layer_passed, second_layer_failed ));

  /* Clean up stake_ci (this also cleans up lsched and sdest) */
  fd_stake_ci_delete( fd_stake_ci_leave( stake_ci ) );

  /* Print summary */
  FD_LOG_NOTICE(( "\n=== Summary ===" ));
  FD_LOG_NOTICE(( "Leader schedule: %lu/%lu passed", leader_passed, 9UL ));
  FD_LOG_NOTICE(( "Broadcast node: %lu/%lu passed", broadcast_passed, 1UL ));
  FD_LOG_NOTICE(( "Turbine tree children (layer 1): %lu/%lu passed", children_passed, 10UL ));
  FD_LOG_NOTICE(( "Turbine tree children (layer 2): %lu/%lu passed", second_layer_passed, 8UL ));

  if( leader_failed > 0UL || broadcast_failed > 0UL || children_failed > 0UL || second_layer_failed > 0UL ) {
    FD_LOG_WARNING(( "Some tests do not match Rust implementation!" ));
  } else {
    FD_LOG_NOTICE(( "SUCCESS: All tests match Rust implementation!" ));
  }
  FD_TEST(!( leader_failed > 0UL || broadcast_failed > 0UL || children_failed > 0UL || second_layer_failed > 0UL ));

  FD_LOG_NOTICE(( "\n=== Test Complete ===" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  /* Test with ChaCha20 */
  test_shred_dest_conformance(
    0 /* use_chacha8 */,
    &EXPECTED_BROADCAST_CHACHA20,
    EXPECTED_FIRST_LAYER_CHACHA20,
    10,
    EXPECTED_SECOND_LAYER_CHACHA20,
    8
  );

  /* Test with ChaCha8 */
  test_shred_dest_conformance(
    1 /* use_chacha8 */,
    &EXPECTED_BROADCAST_CHACHA8,
    EXPECTED_FIRST_LAYER_CHACHA8,
    10,
    EXPECTED_SECOND_LAYER_CHACHA8,
    8
  );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

/* ============================================================================
   RUST REFERENCE IMPLEMENTATION

   This is the Rust code that generates the expected test data above.

   USAGE:
   - Add this code to agave/turbine/src/cluster_nodes.rs inside the #[cfg(test)] mod tests block
   - Run with: cd agave/turbine && cargo test test_deterministic_cluster_conformance -- --nocapture
   - Copy the output between === START C CODE === and === END C CODE === markers

   ============================================================================ */

/*
    // Inside #[cfg(test)] mod tests { ... }

    // Conformance tests to generate deterministic test data for C
    mod conformance_tests {
        use solana_ledger::leader_schedule::IdentityKeyedLeaderSchedule;
        use super::*;
        use solana_gossip::crds_value::CrdsValue;
        use solana_gossip::crds_data::CrdsData;
        use solana_gossip::crds::GossipRoute;
        use solana_hash::Hash as SolanaHash;
        use solana_ledger::shred::{ProcessShredsStats, ReedSolomonCache, Shredder};
        use rand::{SeedableRng, rngs::StdRng};
        use test_case::test_case;

        pub fn make_deterministic_test_cluster(
            num_nodes: usize,
        ) -> (
            Vec<GossipContactInfo>,
            HashMap<Pubkey, u64>, // stakes
            ClusterInfo,
        ) {
            let mut nodes: Vec<_> = (0..num_nodes)
                .map(|i| {
                    let mut seed = [0u8; 32];
                    seed[0] = i as u8;
                    let pubkey = Pubkey::new_from_array(seed);
                    GossipContactInfo::new_localhost(&pubkey, timestamp())
                })
                .collect();

            // Create a deterministic keypair for node[0] using a seeded RNG
            let mut rng_seed = [0u8; 32];
            rng_seed[0] = 42; // Fixed seed for determinism
            let mut rng = StdRng::from_seed(rng_seed);
            use rand::RngCore;
            let mut keypair_seed = [0u8; 32];
            rng.fill_bytes(&mut keypair_seed);
            let keypair = Arc::new(Keypair::new_from_array(keypair_seed));

            // Update node[0] to use this keypair's pubkey
            nodes[0] = GossipContactInfo::new_localhost(&keypair.pubkey(), timestamp());
            let this_node = nodes[0].clone();

            let stakes: HashMap<Pubkey, u64> = nodes
                .iter()
                .enumerate()
                .map(|(i, node)| {
                    // 70% staked nodes, 30% unstaked
                    if i < (num_nodes * 7 / 10) {
                        (*node.pubkey(), 100*(i/2 + 1) as u64) // Assign increasing stakes
                    } else {
                        (*node.pubkey(), 0) // Unstaked
                    }
                })
                .collect();

            let cluster_info = ClusterInfo::new(this_node, keypair, SocketAddrSpace::Unspecified);
            {
                let now = timestamp();
                let gossip_keypair = Keypair::new();
                let mut gossip_crds = cluster_info.gossip.crds.write().unwrap();
                // First node is pushed to crds table by ClusterInfo constructor.
                for node in nodes.iter().skip(1) {
                    let node = CrdsData::from(node);
                    let node = CrdsValue::new(node, &gossip_keypair);
                    let _ = gossip_crds.insert(node, now, GossipRoute::LocalMessage);
                }
            }
            nodes[1..].shuffle(&mut rng);
            (nodes, stakes, cluster_info)
        }

        #[test_case(true)]   // chacha8
        #[test_case(false)]  // chacha20
        fn test_deterministic_cluster_conformance(use_chacha8: bool) {
            let num_nodes = 20;
            let (nodes, stakes, cluster_info) = make_deterministic_test_cluster(num_nodes);
            let slot_leader = cluster_info.id();

            let rng_name = if use_chacha8 { "CHACHA8" } else { "CHACHA20" };

            // Output common data only once (for ChaCha20 test)
            if !use_chacha8 {
                // Output cluster nodes, leader schedule...
            }

            // Generate leader schedule for epoch 123
            let epoch = 123u64;
            let slot_cnt = 432000u64;
            let leader_schedule = IdentityKeyedLeaderSchedule::new(&stakes, epoch, slot_cnt, 4);

            // Find a slot where slot_leader (the first node) is actually the leader
            let mut broadcast_test_slot = 0u64;
            for slot in 0..slot_cnt {
                let leader = &leader_schedule[slot];
                if leader == &slot_leader {
                    broadcast_test_slot = slot;
                    break;
                }
            }

            // Create cluster nodes for broadcast
            let cluster_nodes = new_cluster_nodes::<BroadcastStage>(
                    &cluster_info,
                    ClusterType::Development,
                    &stakes,
                    use_chacha8,
                );

            // Create a test shred
            let shred = Shredder::new(broadcast_test_slot, 1, 0, 0)
                    .unwrap()
                    .entries_to_merkle_shreds_for_tests(
                        &Keypair::new(),
                        &[],
                        true,
                        SolanaHash::default(),
                        0,
                        0,
                        &ReedSolomonCache::default(),
                        &mut ProcessShredsStats::default(),
                    )
                    .0
                    .pop()
                    .unwrap();

            // Compute turbine tree starting from the leader
            let fanout = 10usize;
            let mut weighted_shuffle = cluster_nodes.weighted_shuffle.clone();
            let mut chacha_rng = TurbineRng::new_seeded(&slot_leader, &shred.id(), use_chacha8);
            let shuffled_nodes: Vec<&Node> = weighted_shuffle
                .shuffle(&mut chacha_rng)
                .map(|i| &cluster_nodes.nodes[i])
                .collect();

            // The root node is shuffled_nodes[0] - this is who the leader sends to first
            let root_pubkey = *shuffled_nodes[0].pubkey();

            // Get first layer: root's children
            let (_, root_children) = get_retransmit_peers(
                fanout,
                |n: &Node| n.pubkey() == &root_pubkey,
                shuffled_nodes.clone(),
            );
            let root_children_vec: Vec<Pubkey> = root_children.take(fanout).map(|n| *n.pubkey()).collect();

            // Second layer: compute children for each first-layer child
            let mut second_layer_data: Vec<(usize, Pubkey, Vec<Pubkey>)> = Vec::new();
            for (idx, child_pk) in root_children_vec.iter().enumerate() {
                // Use the SAME shuffle as everyone else (seeded with slot_leader)
                // All nodes in the turbine tree use the same deterministic shuffle
                let (_, child_children) = get_retransmit_peers(
                    fanout,
                    |n: &Node| n.pubkey() == child_pk,
                    shuffled_nodes.clone(),
                );
                let child_children_vec: Vec<Pubkey> = child_children.take(fanout).map(|n| *n.pubkey()).collect();
                second_layer_data.push((idx, *child_pk, child_children_vec));
            }

            // Verify complete coverage (all nodes covered exactly once)
            let mut covered = std::collections::HashSet::new();
            covered.insert(slot_leader);        // Leader has the shred
            covered.insert(root_pubkey);        // Root node (broadcast peer)
            for child_pk in &root_children_vec {
                covered.insert(*child_pk);      // First layer
            }
            for (_idx, _parent_pk, children) in &second_layer_data {
                for child_pk in children {
                    covered.insert(*child_pk);  // Second layer
                }
            }
            assert_eq!(covered.len(), nodes.len(), "All nodes should be covered exactly once");
        }
    }  // mod conformance_tests

   ============================================================================ */
