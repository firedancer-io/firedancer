#include "crds/fd_crds.h"

#include <stdlib.h>

/* Mock gossip out context for testing */
static fd_gossip_out_ctx_t test_gossip_out_ctx = {0};

void
stub_ci_change( void *              ctx,
                ulong               crds_pool_idx,
                ulong               stake,
                int                 change_type,
                fd_stem_context_t * ctx_unused,
                long                now ) {
  (void)ctx; (void)crds_pool_idx; (void)stake; (void)change_type; (void)ctx_unused; (void)now;
}

fd_crds_t *
create_test_crds_with_ci( fd_rng_t * rng, ulong num_peers ) {
  ulong ele_max = 1024UL;
  ulong purged_max = 512UL;

  void * crds_mem = aligned_alloc( fd_crds_align(), fd_crds_footprint( ele_max, purged_max ) );
  FD_TEST( crds_mem );

  fd_crds_t * crds = fd_crds_join( fd_crds_new( crds_mem, rng, ele_max, purged_max, &test_gossip_out_ctx, stub_ci_change, NULL ) );
  FD_TEST( crds );

  /* Insert test contact info entries */
  for( ulong i=0UL; i<num_peers; i++ ) {
    /* Create a minimal contact info payload */
    uchar payload[ FD_GOSSIP_CRDS_MAX_SZ ];
    fd_memset( payload, 0, sizeof(payload) );

    /* Generate random pubkey */
    for( ulong j=0UL; j<32UL; j++ ) {
      payload[j] = fd_rng_uchar( rng );
    }

    /* Create a minimal gossip view for contact info */
    fd_gossip_view_crds_value_t view = {0};
    view.tag = FD_GOSSIP_VALUE_CONTACT_INFO;
    view.pubkey_off = 0;
    view.value_off = 0;
    view.length = 200; /* Minimal size */
    view.wallclock_nanos = fd_log_wallclock();

    /* Create minimal contact info view */
    view.ci_view->contact_info->instance_creation_wallclock_nanos = view.wallclock_nanos;

    /* Generate random stake */
    ulong stake = fd_rng_ulong_roll( rng, 1000000UL ) + 1UL;

    /* Insert into CRDS, mark entries as active */
    fd_crds_insert( crds, &view, payload, stake, 0, view.wallclock_nanos, NULL );
    fd_crds_peer_active( crds, payload );
  }

  return crds;
}

void
free_test_crds( fd_crds_t * crds ) {
  free( (void *)crds );
}
