#include "fd_qos.h"

void
add_key_value( fd_qos_t *     qos,
               fd_qos_map_t * map,
               fd_qos_key_t   key,
               float          val ) {
  fd_qos_entry_t * entry = fd_qos_query( map, key );
  if( !entry ) {
    entry = fd_qos_insert( map, key );
    FD_LOG_NOTICE(( "inserting @ %u", (uint)key ));
    FD_TEST( entry );
    entry->value.state = FD_QOS_STATE_ASSIGNED;
  }
  FD_TEST( entry );

  entry->value.stats.txn_success += val;

  /* enqueue */
  fd_qos_enqueue_delta( qos, entry );
}

float
fetch_value( fd_qos_map_t * map, fd_qos_key_t key ) {
  float cur_value = 0.0f;
  fd_qos_entry_t * entry = fd_qos_query( map, key );
  if( entry ) cur_value = entry->value.stats.txn_success;
  FD_LOG_NOTICE(( "value @ %u = %f",
    (uint)key,
    (double)cur_value ));
  return cur_value;
}

#define check_value( map, key, value ) \
  FD_TEST( value == fetch_value( map, key ) )

uint
fetch_state( fd_qos_map_t * map, fd_qos_key_t key ) {
  uint cur_state = 0.0f;
  fd_qos_entry_t * entry = fd_qos_query( map, key );
  if( entry ) cur_state = entry->value.state;
  return cur_state;
}

#define check_state( map, key, state ) \
  FD_TEST( state == fetch_state( map, key ) )

#define LG_ENTRIES 10

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"                   );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 1UL                          );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",  NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  uchar * shmem = (uchar*)fd_wksp_alloc_laddr(
                     wksp,
                     fd_qos_align(),
                     fd_qos_footprint( 1<<LG_ENTRIES ),
                     1UL );

  FD_TEST( shmem );

  ulong  qos_sz  = fd_qos_footprint( 1<<LG_ENTRIES );
  void * qos_mem = fd_qos_new( shmem, 1<<LG_ENTRIES );

  FD_TEST( qos_mem );

  fd_qos_t * qos = fd_qos_join( qos_mem );

  FD_TEST( qos );

  /* create qos_local, mimicking another tile */
  ulong  qos_local_sz  = fd_qos_local_footprint( 1<<LG_ENTRIES );
  (void)qos_local_sz;
  void * qos_local_mem = fd_qos_local_new( shmem + qos_sz, 1<<LG_ENTRIES );

  FD_TEST( qos_local_mem );

  fd_qos_local_t * qos_local = fd_qos_local_join( qos_local_mem );

  FD_TEST( qos_local );

  fd_qos_map_t * local_map = fd_qos_local_get_map( qos_local );

  FD_TEST( local_map );

  ulong N = 100;
  FD_TEST( (1UL<<LG_ENTRIES) > N );
  for( ulong j = 1; j <= N; ++j ) {
    fd_qos_entry_t * entry = fd_qos_insert( local_map, (uint)j );
    FD_TEST( entry );

    entry->value.state = 42;
  }

  for( ulong j = 1; j <= N; ++j ) {
    fd_qos_entry_t * entry = fd_qos_query( local_map, (uint)j );
    FD_TEST( entry );

    FD_TEST( entry->value.state == 42 );
  }

  fd_qos_map_t * global_map = fd_qos_global_get_map( qos );

  /* insert some zero entries into global map */
  add_key_value( qos, global_map, 1000,  2000.0f );
  add_key_value( qos, global_map, 1100,  3000.0f );
  /* not inserting 1200 and 1300, so they should be
   * marked for removal (unnassigning) */

  /* add value to entry, inserting if necessary, and queue */
  add_key_value( qos, local_map, 1000,  100.0f );
  add_key_value( qos, local_map, 1100,  110.0f );
  add_key_value( qos, local_map, 1200,  120.0f );
  add_key_value( qos, local_map, 1300,  130.0f );
  add_key_value( qos, local_map, 1300, 1000.0f );

  check_value( local_map, 1000,  100.0f );
  check_value( local_map, 1100,  110.0f );
  check_value( local_map, 1200,  120.0f );
  check_value( local_map, 1300, 1130.0f );

  check_state( local_map, 1000, FD_QOS_STATE_QUEUED );
  check_state( local_map, 1100, FD_QOS_STATE_QUEUED );
  check_state( local_map, 1200, FD_QOS_STATE_QUEUED );
  check_state( local_map, 1300, FD_QOS_STATE_QUEUED );

  check_value( global_map, 1000, 2000.0f );
  check_value( global_map, 1100, 3000.0f );
  check_value( global_map, 1200,    0.0f );
  check_value( global_map, 1300,    0.0f );

  /* run process */
  fd_qos_process_deltas( qos );

  /* local map entries should be zero */
  check_value( local_map, 1000, 0.0f );
  check_value( local_map, 1100, 0.0f );
  check_value( local_map, 1200, 0.0f );
  check_value( local_map, 1300, 0.0f );

  /* because keys 1200 and 1300 are not in the global map,
   * the state is changed to UNASSIGNED to inform the owner
   * of the local updates to remove the key */
  check_state( local_map, 1000, FD_QOS_STATE_ASSIGNED );
  check_state( local_map, 1100, FD_QOS_STATE_ASSIGNED );
  check_state( local_map, 1200, FD_QOS_STATE_UNASSIGNED );
  check_state( local_map, 1300, FD_QOS_STATE_UNASSIGNED );

  /* these global map entries should hold total */
  check_value( global_map, 1000, 2100.0f );
  check_value( global_map, 1100, 3110.0f );

  /* theswe global map entries should be void */
  check_value( global_map, 1200,   0.0f );
  check_value( global_map, 1300,   0.0f );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();

  return 0;
}
