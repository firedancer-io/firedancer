#include "../../util/fd_util.h"

#include "fd_crds.h"
#include "fd_active_set.h"
#include "fd_gossip_wsample.h"
#include "fd_gossip_purged.h"
#include "fd_gossip_out.h"
#include "../stakes/fd_stake_weight.h"

#include <stdlib.h>
#include <string.h>

#define ELE_MAX (1024UL)

static const long STAKED_EXPIRE_DURATION_NANOS   = 432000L*400L*1000L*1000L;
static const long UNSTAKED_EXPIRE_DURATION_NANOS = 15L*1000L*1000L*1000L;

/* The test avoids CONTACT_INFO crds which triggers stem/publish codepaths. */
static fd_stem_context_t stem[ 1 ] = {0};
static fd_gossip_out_ctx_t gossip_out[ 1 ] = {0};

static void
noop_activity_update( void *                           ctx,
                      fd_pubkey_t const *              identity,
                      fd_gossip_contact_info_t const * ci,
                      int                              change_type ) {
  (void)ctx; (void)identity; (void)ci; (void)change_type;
}

typedef struct {
  fd_crds_t * crds;
  void *      purged_mem;
  void *      wsample_mem;
  void *      crds_mem;
  void *      as_mem;
} test_crds_env_t;

static fd_crds_t *
make_crds( fd_rng_t * rng,
           test_crds_env_t * env ) {
  void * purged_mem = aligned_alloc( fd_gossip_purged_align(), fd_gossip_purged_footprint( ELE_MAX ) );
  FD_TEST( purged_mem );
  fd_gossip_purged_t * purged = fd_gossip_purged_join( fd_gossip_purged_new( purged_mem, rng, ELE_MAX ) );
  FD_TEST( purged );

  void * wsample_mem = aligned_alloc( fd_gossip_wsample_align(), fd_gossip_wsample_footprint( FD_CONTACT_INFO_TABLE_SIZE ) );
  FD_TEST( wsample_mem );
  fd_gossip_wsample_t * wsample = fd_gossip_wsample_join( fd_gossip_wsample_new( wsample_mem, rng, FD_CONTACT_INFO_TABLE_SIZE ) );
  FD_TEST( wsample );

  void * crds_mem = aligned_alloc( fd_crds_align(),       fd_crds_footprint( ELE_MAX ) );
  FD_TEST( crds_mem );
  void * as_mem   = aligned_alloc( fd_active_set_align(), fd_active_set_footprint()    );
  FD_TEST( as_mem );

  uchar identity[ 32UL ] = {0};

  fd_crds_t * crds = fd_crds_join( fd_crds_new( crds_mem, NULL, 0UL, wsample, (fd_active_set_t *)as_mem, rng, ELE_MAX, purged, noop_activity_update, NULL, gossip_out ) );
  FD_TEST( crds );

  FD_TEST( fd_active_set_join( fd_active_set_new( as_mem, wsample, crds, rng, identity, 0UL, NULL, NULL ) ) );

  env->crds        = crds;
  env->purged_mem  = purged_mem;
  env->wsample_mem = wsample_mem;
  env->crds_mem    = crds_mem;
  env->as_mem      = as_mem;

  return crds;
}

static void
teardown_crds( test_crds_env_t * env ) {
  free( env->purged_mem );
  free( env->wsample_mem );
  free( env->crds_mem );
  free( env->as_mem );
}

static void
insert_node_instance( fd_crds_t * crds,
                      uchar       origin_byte,
                      ulong       token,
                      ulong       origin_stake,
                      long        now ) {
  fd_gossip_value_t value[ 1 ];
  memset( value, 0, sizeof(fd_gossip_value_t) );
  value->tag       = FD_GOSSIP_VALUE_NODE_INSTANCE;
  value->wallclock = 100UL;
  memset( value->origin, origin_byte, 32UL );
  value->node_instance->token = token;

  uchar value_bytes[ 128UL ];
  memset( value_bytes, 0, sizeof(value_bytes) );
  value_bytes[ 0 ] = origin_byte;
  memcpy( value_bytes+1UL, &token, sizeof(ulong) );

  FD_TEST( fd_crds_insert( crds, value, value_bytes, sizeof(value_bytes), origin_stake, 0, 0, now, stem )==0L );
}

static fd_stake_weight_t
mk_stake( uchar byte,
          ulong stake ) {
  fd_stake_weight_t sw;
  memset( &sw, 0, sizeof(sw) );
  memset( sw.key.uc, byte, 32UL );
  sw.stake = stake;
  return sw;
}

/* Before stakes are loaded, unstaked entries use the long expiry
   duration, so they are not flushed at 15s. */

static void
test_unstaked_no_expire_before_stakes( fd_rng_t * rng ) {
  test_crds_env_t env[ 1 ] = { 0 };
  fd_crds_t * crds = make_crds( rng, env );

  long t0 = 1000L*1000L*1000L;
  insert_node_instance( crds, 0x44, 1UL, 0UL, t0 );
  FD_TEST( fd_crds_len( crds )==1UL );

  fd_crds_advance( crds, t0+UNSTAKED_EXPIRE_DURATION_NANOS+1000L*1000L*1000L, stem, NULL );
  FD_TEST( fd_crds_len( crds )==1UL );

  teardown_crds( env );
}

/* Loading stakes reclassifies entries: newly-staked entries move to the
   long-lived staked list, still-unstaked ones expire at 15s. */

static void
test_reclassify( fd_rng_t * rng ) {
  test_crds_env_t env[ 1 ] = { 0 };
  fd_crds_t * crds = make_crds( rng, env );

  long t0 = 1000L*1000L*1000L;
  insert_node_instance( crds, 0x11, 1UL, 0UL, t0 );
  insert_node_instance( crds, 0x22, 2UL, 0UL, t0 );
  insert_node_instance( crds, 0x33, 3UL, 0UL, t0 );
  FD_TEST( fd_crds_len( crds )==3UL );

  fd_stake_weight_t stakes[ 1 ] = { mk_stake( 0x22, 500UL ) };
  fd_stake_weight_key_sort_inplace( stakes, 1UL );
  fd_crds_refresh_stakes( crds, stakes, 1UL );
  FD_TEST( fd_crds_len( crds )==3UL );

  int charge_busy = 0;
  fd_crds_advance( crds, t0+UNSTAKED_EXPIRE_DURATION_NANOS+1000L*1000L*1000L, stem, &charge_busy );
  FD_TEST( fd_crds_len( crds )==1UL );
  FD_TEST( charge_busy==1 );

  fd_crds_advance( crds, t0+STAKED_EXPIRE_DURATION_NANOS-1L, stem, NULL );
  FD_TEST( fd_crds_len( crds )==1UL );

  fd_crds_advance( crds, t0+STAKED_EXPIRE_DURATION_NANOS+1L, stem, NULL );
  FD_TEST( fd_crds_len( crds )==0UL );

  teardown_crds( env );
}

/* refresh_stakes re-sorts the expiry lists, so the oldest entry must
   still expire first afterwards. */

static void
test_ordering_preserved( fd_rng_t * rng ) {
  test_crds_env_t env[ 1 ] = { 0 };
  fd_crds_t * crds = make_crds( rng, env );

  long t_bb = 1000L*1000L*1000L;
  long t_aa = t_bb + 5L*1000L*1000L*1000L;
  insert_node_instance( crds, 0xBB, 1UL, 0UL, t_bb );
  insert_node_instance( crds, 0xAA, 2UL, 0UL, t_aa );

  fd_crds_refresh_stakes( crds, NULL, 0UL );
  FD_TEST( fd_crds_len( crds )==2UL );

  long t1 = t_bb + UNSTAKED_EXPIRE_DURATION_NANOS + 1000L*1000L*1000L;
  FD_TEST( t1 < t_aa+UNSTAKED_EXPIRE_DURATION_NANOS );
  fd_crds_advance( crds, t1, stem, NULL );
  FD_TEST( fd_crds_len( crds )==1UL );

  fd_crds_advance( crds, t_aa+UNSTAKED_EXPIRE_DURATION_NANOS+1000L*1000L*1000L, stem, NULL );
  FD_TEST( fd_crds_len( crds )==0UL );

  teardown_crds( env );
}

static void
test_empty_refresh( fd_rng_t * rng ) {
  test_crds_env_t env[ 1 ] = { 0 };
  fd_crds_t * crds = make_crds( rng, env );
  fd_crds_refresh_stakes( crds, NULL, 0UL );
  FD_TEST( fd_crds_len( crds )==0UL );
  teardown_crds( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_empty_refresh( rng );
  test_unstaked_no_expire_before_stakes( rng );
  test_reclassify( rng );
  test_ordering_preserved( rng );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
