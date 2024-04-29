#include "./test_consensus.h"

#define TEST_CONSENSUS_MAGIC ( 0x7e57UL ) /* test */

/* FIXME: remove these static variables */
/* variables should be either on stack or use wksp_alloc_laddr */
static int gossip_sockfd = -1;
static fd_keyguard_client_t keyguard_client;
static fd_tvu_gossip_deliver_arg_t gossip_deliver_arg;

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  /* wksp */
  ulong  page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 128UL );
  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  FD_LOG_NOTICE( ( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)",
                   page_cnt,
                   _page_sz,
                   numa_idx ) );
  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* restore */
  const char * restore = fd_env_strip_cmdline_cstr( &argc, &argv, "--restore", NULL, NULL );
  if (restore) {
    ulong funk_hashseed;
    char  funk_hostname[64];
    gethostname( funk_hostname, sizeof(funk_hostname) );
    funk_hashseed = fd_hash( 0, funk_hostname, strnlen( funk_hostname, sizeof( funk_hostname ) ) );
    FD_LOG_NOTICE( ( "fd_wksp_restore %s", restore ) );
    int err = fd_wksp_restore( wksp, restore, (uint)funk_hashseed );
    if( err ) FD_LOG_ERR( ( "fd_wksp_restore failed: error %d", err ) );
  }

  /* funk */
  fd_funk_t * funk = NULL;
  fd_wksp_tag_query_info_t funk_info;
  ulong                    funk_tag = FD_FUNK_MAGIC;
  if( fd_wksp_tag_query( wksp, &funk_tag, 1, &funk_info, 1 ) > 0 ) {
    void * shmem = fd_wksp_laddr_fast( wksp, funk_info.gaddr_lo );
    funk         = fd_funk_join( shmem );
  }
  if( funk == NULL ) FD_LOG_ERR( ( "failed to join a funky" ) );

  /* allocator */
  void * alloc_shmem =
      fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), TEST_CONSENSUS_MAGIC );
  void *       alloc_shalloc = fd_alloc_new( alloc_shmem, TEST_CONSENSUS_MAGIC );
  fd_alloc_t * alloc         = fd_alloc_join( alloc_shalloc, 0UL );
  fd_valloc_t  valloc        = fd_alloc_virtual( alloc );

  /* do replay+shredcap or archive+live_data */
  const char * shredcap = fd_env_strip_cmdline_cstr( &argc, &argv, "--shredcap", NULL, NULL );
  if( shredcap )
    goto replay_offline;
  else
    goto archive_online;

 archive_online:
  FD_LOG_NOTICE( ("test_consensus running in archive mode") );

  /* gossip */
  //FIXME, initialize bft and repair
  //gossip_deliver_arg->bft = bft;
  //gossip_deliver_arg->repair = repair;
  const char * gossip_addr = "139.178.68.207:8001"; /* temporary */
  gossip_deliver_arg.valloc = valloc;

  void *        gossip_shmem = fd_wksp_alloc_laddr( wksp, fd_gossip_align(), fd_gossip_footprint(), TEST_CONSENSUS_MAGIC );
  fd_gossip_t * gossip       = fd_gossip_join( fd_gossip_new( gossip_shmem, TEST_CONSENSUS_MAGIC, valloc ) );
  fd_gossip_config_t gossip_config;
  gossip_config.shred_version = 0;
  gossip_config.deliver_fun   = gossip_deliver_fun;
  gossip_config.deliver_arg   = &gossip_deliver_arg;
  gossip_config.send_fun      = gossip_send_packet;
  gossip_config.send_arg      = NULL;
  gossip_config.sign_fun      = signer_fun;
  gossip_config.sign_arg      = &keyguard_client;
  FD_TEST ( fd_gossip_set_config( gossip, &gossip_config ) );

  fd_gossip_peer_addr_t gossip_peer_addr;
  FD_TEST ( resolve_hostport( gossip_addr, &gossip_peer_addr ) );

  if( fd_gossip_add_active_peer(
            gossip, resolve_hostport( gossip_addr, &gossip_peer_addr ) ) )
      FD_LOG_ERR( ( "error adding gossip active peer" ) );
  
  FD_LOG_ERR( ( "online_archive_init not ready yet" ) );
  goto END;

 replay_offline:
  FD_LOG_NOTICE( ("test_consensus running in replay mode") );

  /* blockstore */
  fd_wksp_tag_query_info_t blockstore_info;
  ulong                    blockstore_tag = FD_BLOCKSTORE_MAGIC;
  if( fd_wksp_tag_query( wksp, &blockstore_tag, 1, &blockstore_info, 1 ) == 0 ) {
    FD_LOG_ERR( ( "failed to find a blockstore" ) );
  }
  void *            shblockstore = fd_wksp_laddr_fast( wksp, blockstore_info.gaddr_lo );
  fd_blockstore_t * blockstore   = fd_blockstore_join( shblockstore );
  FD_TEST( blockstore );
  fd_blockstore_clear( blockstore );

  /* scratch */

  ulong smax   = 1UL << 21;
  ulong sdepth = 128;
  FD_LOG_NOTICE( ( "smem footprint %lu", fd_scratch_smem_footprint( smax ) ) );
  FD_TEST( fd_scratch_smem_footprint( smax ) > 765312 );
  void * smem =
      fd_wksp_alloc_laddr( wksp, fd_scratch_smem_align(), fd_scratch_smem_footprint( smax ), 1UL );
  void * fmem = fd_wksp_alloc_laddr(
      wksp, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( sdepth ), 1UL );
  FD_TEST( ( !!smem ) & ( !!fmem ) );
  fd_scratch_attach( smem, fmem, smax, sdepth );

  /* acc mgr */

  fd_acc_mgr_t acc_mgr[1];
  fd_acc_mgr_new( acc_mgr, funk );

  /* epoch_ctx */

  uchar * epoch_ctx_mem =
      fd_wksp_alloc_laddr( wksp, fd_exec_epoch_ctx_align(), fd_exec_epoch_ctx_footprint(), 1UL );
  fd_exec_epoch_ctx_t * epoch_ctx =
      fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem ) );
  FD_TEST( epoch_ctx );

  /* forks */

  ulong  forks_max = fd_ulong_pow2_up( FD_DEFAULT_SLOTS_PER_EPOCH );
  void * forks_mem =
      fd_wksp_alloc_laddr( wksp, fd_forks_align(), fd_forks_footprint( forks_max ), 1UL );
  fd_forks_t * forks = fd_forks_join( fd_forks_new( forks_mem, forks_max, 42UL ) );
  FD_TEST( forks );

  /* ghost */

  ulong  ghost_node_max = forks_max;
  ulong  ghost_vote_max = 1UL << 16;
  void * ghost_mem      = fd_wksp_alloc_laddr(
      wksp, fd_ghost_align(), fd_ghost_footprint( ghost_node_max, ghost_vote_max ), 1UL );
  fd_ghost_t * ghost =
      fd_ghost_join( fd_ghost_new( ghost_mem, ghost_node_max, ghost_vote_max, 1UL ) );
  FD_TEST( ghost );

  /* latest votes */

//   void * latest_votes_mem = fd_wksp_alloc_laddr(
//       wksp, fd_latest_vote_deque_align(), fd_latest_vote_deque_footprint(), 42UL );
//   fd_latest_vote_t * latest_votes =
//       fd_latest_vote_deque_join( fd_latest_vote_deque_new( latest_votes_mem ) );
//   FD_TEST( latest_votes );

  /* bft */

  void *     bft_mem = fd_wksp_alloc_laddr( wksp, fd_bft_align(), fd_bft_footprint(), 1UL );
  fd_bft_t * bft     = fd_bft_join( fd_bft_new( bft_mem ) );
  bft->acc_mgr       = acc_mgr;
  bft->blockstore    = blockstore;
  bft->commitment    = NULL;
  bft->forks         = forks;
  bft->ghost         = ghost;
  bft->valloc        = valloc;
  // TODO can this change within an epoch?
  fd_bft_epoch_stake_update( bft, epoch_ctx );

  /* replay */

  void * replay_mem    = fd_wksp_alloc_laddr( wksp, fd_replay_align(), fd_replay_footprint(), 1UL );
  fd_replay_t * replay = fd_replay_join( fd_replay_new( replay_mem ) );
  FD_TEST( replay );
  replay->acc_mgr     = acc_mgr;
  replay->blockstore  = blockstore;
  replay->epoch_ctx   = epoch_ctx;
  replay->forks       = forks;
  replay->funk        = funk;
  replay->gossip      = NULL;
  replay->max_workers = 1;
  replay->tpool       = NULL;
  replay->valloc      = valloc;

  /* snapshot init */

  fd_fork_t *          snapshot_fork = fd_fork_pool_ele_acquire( forks->pool );
  fd_exec_slot_ctx_t * snapshot_slot_ctx =
      fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &snapshot_fork->slot_ctx, valloc ) );
  FD_TEST( snapshot_slot_ctx );

  snapshot_slot_ctx->epoch_ctx  = epoch_ctx;
  snapshot_slot_ctx->acc_mgr    = acc_mgr;
  snapshot_slot_ctx->blockstore = blockstore;
  snapshot_slot_ctx->valloc     = valloc;

  fd_runtime_recover_banks( snapshot_slot_ctx, 0 );
  FD_TEST( snapshot_slot_ctx->funk_txn );

  ulong snapshot_slot = snapshot_slot_ctx->slot_bank.slot;
  FD_LOG_NOTICE( ( "snapshot_slot: %lu", snapshot_slot ) );

  snapshot_slot_ctx->slot_bank.collected_fees = 0;
  snapshot_slot_ctx->slot_bank.collected_rent = 0;
  FD_TEST( !fd_runtime_sysvar_cache_load( snapshot_slot_ctx ) );
  fd_features_restore( snapshot_slot_ctx );
  fd_runtime_update_leaders( snapshot_slot_ctx, snapshot_slot_ctx->slot_bank.slot );
  fd_calculate_epoch_accounts_hash_values( snapshot_slot_ctx );
  fd_bpf_scan_and_create_bpf_program_cache_entry( snapshot_slot_ctx, snapshot_slot_ctx->funk_txn );
  snapshot_slot_ctx->leader =
      fd_epoch_leaders_get( fd_exec_epoch_ctx_leaders( replay->epoch_ctx ), snapshot_slot );

  /* snapshot init: blockstore */

  fd_blockstore_snapshot_insert( blockstore, &snapshot_slot_ctx->slot_bank );

  /* snapshot init: replay */

  replay->smr = snapshot_slot;

  /* snapshot init: forks */

  snapshot_fork->slot = snapshot_slot;
  fd_fork_frontier_ele_insert( replay->forks->frontier, snapshot_fork, replay->forks->pool );

  /* snapshot init: ghost */

  fd_slot_hash_t key = { .slot = snapshot_fork->slot,
                         .hash = snapshot_fork->slot_ctx.slot_bank.banks_hash };
  fd_ghost_leaf_insert( ghost, &key, NULL );
  FD_TEST( fd_ghost_node_map_ele_query( ghost->node_map, &key, NULL, ghost->node_pool ) );

  /* snapshot init: bft */

  bft->snapshot_slot = snapshot_slot;

  fd_shred_cap_replay( shredcap, replay );

 END:
  fd_halt();
  return 0;
}

static void
gossip_deliver_fun( fd_crds_data_t * data, void * arg ) {
  fd_tvu_gossip_deliver_arg_t * arg_ = (fd_tvu_gossip_deliver_arg_t *)arg;
  if( data->discriminant == fd_crds_data_enum_contact_info_v1 ) {
    fd_repair_peer_addr_t repair_peer_addr = { 0 };
    fd_gossip_from_soladdr( &repair_peer_addr, &data->inner.contact_info_v1.serve_repair );
    if( repair_peer_addr.port == 0 ) return;
    if( FD_UNLIKELY( fd_repair_add_active_peer(
            arg_->repair, &repair_peer_addr, &data->inner.contact_info_v1.id ) ) ) {
      FD_LOG_DEBUG( ( "error adding peer" ) ); /* Probably filled up the table */
    };
  }
}

static int
gossip_to_sockaddr( uchar * dst, fd_gossip_peer_addr_t const * src ) {
  fd_memset( dst, 0, sizeof( struct sockaddr_in ) );
  struct sockaddr_in * t = (struct sockaddr_in *)dst;
  t->sin_family          = AF_INET;
  t->sin_addr.s_addr     = src->addr;
  t->sin_port            = src->port;
  return sizeof( struct sockaddr_in );
}

static void
gossip_send_packet( uchar const *                 data,
                    size_t                        sz,
                    fd_gossip_peer_addr_t const * addr,
                    void *                        arg ) {
  (void)arg;
  uchar saddr[sizeof( struct sockaddr_in )];
  int   saddrlen = gossip_to_sockaddr( saddr, addr );
  char  s[1000]  = { 0 };
  fd_gossip_addr_str( s, sizeof( s ), addr );
  if( sendto( gossip_sockfd,
              data,
              sz,
              MSG_DONTWAIT,
              (const struct sockaddr *)saddr,
              (socklen_t)saddrlen ) < 0 ) {
    FD_LOG_WARNING( ( "sendto failed: %s", strerror( errno ) ) );
  }
}

static void
signer_fun( void *    arg,
            uchar         signature[ static 64 ],
            uchar const * buffer,
            ulong         len ) {
  fd_keyguard_client_t * keyguard_client = (fd_keyguard_client_t *)arg;
  fd_keyguard_client_sign( keyguard_client, signature, buffer, len );
}

/* Convert a host:port string to a repair network address. If host is
 * missing, it assumes the local hostname. */
static fd_repair_peer_addr_t *
resolve_hostport( const char * str /* host:port */, fd_repair_peer_addr_t * res ) {
  fd_memset( res, 0, sizeof( fd_repair_peer_addr_t ) );

  /* Find the : and copy out the host */
  char buf[128];
  uint i;
  for( i = 0;; ++i ) {
    if( str[i] == '\0' || i > sizeof( buf ) - 1U ) {
      FD_LOG_ERR( ( "missing colon" ) );
      return NULL;
    }
    if( str[i] == ':' ) {
      buf[i] = '\0';
      break;
    }
    buf[i] = str[i];
  }
  if( i == 0 || strcmp( buf, "localhost" ) == 0 ||
      strcmp( buf, "127.0.0.1" ) == 0 ) /* :port means $HOST:port */
    gethostname( buf, sizeof( buf ) );

  struct hostent * host = gethostbyname( buf );
  if( host == NULL ) {
    FD_LOG_WARNING( ( "unable to resolve host %s", buf ) );
    return NULL;
  }
  /* Convert result to repair address */
  res->l    = 0;
  //res->addr = ( (struct in_addr *)host->h_addr )->s_addr;
  // FIXME why the above does not work?
  res->addr = ( (struct in_addr *)host->h_addr_list[0] )->s_addr;
  int port  = atoi( str + i + 1 );
  if( ( port > 0 && port < 1024 ) || port > (int)USHORT_MAX ) {
    FD_LOG_ERR( ( "invalid port number" ) );
    return NULL;
  }
  res->port = htons( (ushort)port );

  return res;
}

