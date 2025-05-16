#include "crds/fd_crds.h"

fd_crds_t *
create_test_crds_with_ci( fd_rng_t * rng, ulong num_peers ) {
  ulong ele_max = 1024UL;
  ulong purged_max = 512UL;

  void * crds_mem = aligned_alloc( fd_crds_align(), fd_crds_footprint( ele_max, purged_max ) );
  FD_TEST( crds_mem );

  fd_crds_t * crds = fd_crds_join( fd_crds_new( crds_mem, rng, ele_max, purged_max, NULL, NULL ) );
  FD_TEST( crds );

  /* Insert test contact info entries */
  for( ulong i=0UL; i<num_peers; i++ ) {
    /* Create a minimal contact info payload */
    uchar payload[1232];
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
    fd_gossip_view_contact_info_t contact_info = {0};
    contact_info.instance_creation_wallclock_nanos = view.wallclock_nanos;
    view.contact_info[0] = contact_info;

    /* Generate random stake */
    ulong stake = fd_rng_ulong_roll( rng, 1000000UL ) + 1UL;

    /* Insert into CRDS, mark entries as active */
    fd_crds_insert( crds, &view, payload, stake, FD_CRDS_UPSERT_CHECK_UPSERTS, 0, view.wallclock_nanos, NULL );
    fd_crds_peer_active( crds, payload,  view.wallclock_nanos );
  }

  return crds;
}
