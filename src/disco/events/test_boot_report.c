/* test_boot_report runs the boot report collector against the build
   host and the encoder against a small synthetic topology, checking
   the collector degrades cleanly without privileges and the encoded
   event fits its bound. */

#include "fd_event_client.c" /* struct visibility; only id_reserve is exercised */

#include "fd_boot_report.h"
#include "../../ballet/pb/fd_pb_tokenize.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* the boot encoder is written by hand against 1-based schema
   positions; decode the published event against the generated proto so
   a renumbered or mistyped field fails here rather than in the fleet
   dataset */

FD_IMPORT_CSTR( events_proto, "src/disco/events/schema/events.proto" );

struct pb_field {
  uint id;
  uint wire;
  uint rep;
  char msg[ 32 ]; /* set when the field is a nested message */
};

static ulong
proto_msg_fields( char const *      name,
                  struct pb_field * out,
                  ulong             max ) {
  char hdr[ 64 ];
  FD_TEST( fd_cstr_printf_check( hdr, sizeof(hdr), NULL, "message %s {", name ) );
  char const * p = strstr( events_proto, hdr );
  FD_TEST( p );
  char const * end = strstr( p, "\n}" );
  FD_TEST( end );
  ulong cnt = 0UL;
  for( char const * line=strchr( p, '\n' ); line && line<end; line=strchr( line+1, '\n' ) ) {
    char const * l = line+1;
    while( *l==' ' ) l++;
    if( l[ 0 ]=='/' ) continue;
    char kind[ 33 ], fname[ 65 ]; uint id;
    uint rep = !strncmp( l, "repeated ", 9UL );
    if( rep ) l += 9UL;
    if( sscanf( l, "%32s %64s = %u;", kind, fname, &id )!=3 ) continue;
    FD_TEST( cnt<max );
    struct pb_field * f = &out[ cnt++ ];
    f->id       = id;
    f->rep      = rep;
    f->msg[ 0 ] = '\0';
    if( !strcmp( kind, "bytes" ) || !strcmp( kind, "string" ) ) f->wire = FD_PB_WIRE_TYPE_LEN;
    else if( !strcmp( kind, "bool" ) || !strcmp( kind, "uint32" ) || !strcmp( kind, "uint64" ) || !strcmp( kind, "int64" ) ) f->wire = FD_PB_WIRE_TYPE_VARINT;
    else {
      char sub[ 64 ];
      FD_TEST( fd_cstr_printf_check( sub, sizeof(sub), NULL, "message %s {", kind ) );
      if( strstr( events_proto, sub ) ) {
        f->wire = FD_PB_WIRE_TYPE_LEN;
        FD_TEST( fd_cstr_printf_check( f->msg, sizeof(f->msg), NULL, "%s", kind ) );
      } else {
        FD_TEST( fd_cstr_printf_check( sub, sizeof(sub), NULL, "enum %s {", kind ) );
        FD_TEST( strstr( events_proto, sub ) );
        f->wire = FD_PB_WIRE_TYPE_VARINT;
      }
    }
  }
  FD_TEST( cnt );
  return cnt;
}

static void
check_msg( uchar const *            data,
           ulong                    sz,
           char const *             name,
           fd_boot_report_t const * report ) {
  struct pb_field fields[ 96 ];
  ulong field_cnt = proto_msg_fields( name, fields, sizeof(fields)/sizeof(fields[0]) );
  int boot = !strcmp( name, "Boot" );
  fd_pb_inbuf_t buf[1];
  fd_pb_inbuf_init( buf, data, sz );
  uint prev_id = 0U;
  while( fd_pb_inbuf_sz( buf ) ) {
    fd_pb_tlv_t tlv[1];
    FD_TEST( fd_pb_read_tlv( buf, tlv ) );
    struct pb_field const * f = NULL;
    for( ulong i=0UL; i<field_cnt; i++ ) if( fields[ i ].id==tlv->field_id ) f = &fields[ i ];
    if( FD_UNLIKELY( !f ) ) FD_LOG_ERR(( "field %u is not in message %s", tlv->field_id, name ));
    FD_TEST( tlv->wire_type==f->wire );
    /* the encoder emits in schema order; only repeated fields recur */
    FD_TEST( tlv->field_id>prev_id || ( f->rep && tlv->field_id==prev_id ) );
    prev_id = tlv->field_id;
    if( tlv->wire_type==FD_PB_WIRE_TYPE_LEN ) {
      FD_TEST( tlv->len<=fd_pb_inbuf_sz( buf ) );
      if( f->msg[ 0 ] ) check_msg( buf->cur, tlv->len, f->msg, report );
      if( boot && tlv->field_id==1U ) FD_TEST( tlv->len==strlen( report->kernel_release ) && !memcmp( buf->cur, report->kernel_release, tlv->len ) );
      fd_pb_inbuf_skip( buf, tlv->len );
    } else if( boot ) {
      switch( tlv->field_id ) {
        case 69U: FD_TEST( tlv->varint==report->tile_count               ); break;
        case 70U: FD_TEST( tlv->varint==report->memory_total             ); break;
        case 74U: FD_TEST( tlv->varint==report->process_start_time_nanos ); break;
        case 75U: FD_TEST( tlv->varint==report->feature_set_id           ); break;
      }
    }
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static fd_topo_t topo[1];
  strcpy( topo->resolved_config_json, "{\"test\":true}" );
  topo->resolved_config_json_len = strlen( topo->resolved_config_json );
  strcpy( topo->user_config_json, "{\"user\":true}" );
  topo->user_config_json_len = strlen( topo->user_config_json );

  static fd_topo_tile_t event_tile[1];
  strcpy( event_tile->event.accounts_path,  "/tmp" );
  strcpy( event_tile->event.snapshots_path, "/tmp" );
  strcpy( event_tile->event.log_path,       "/tmp" );

  static fd_boot_report_t report[1];
  fd_boot_report_collect( report, topo, event_tile );

  FD_TEST( !report->float_pool ); /* no floaters, no pool */
  FD_TEST( report->kernel_release[ 0 ] );
  FD_TEST( report->cpu_logical_count );
  FD_TEST( report->host_memory_bytes );
  FD_TEST( report->libc_kind==1 || report->libc_kind==2 );
  FD_TEST( report->libc_version[ 0 ] );
  FD_TEST( report->resolved_config_json_len==13UL );
  FD_TEST( report->user_config_json_len==13UL );
  FD_TEST( report->filesystems_cnt>=1UL );
  FD_TEST( report->accounts_fs_idx==report->snapshots_fs_idx );
  FD_TEST( report->shredb_fs_idx==255 );
  /* l3 map is all or nothing, covers the numa map, and numbers domains densely from 0 */
  FD_TEST( !report->l3_cpu_to_domain_cnt || report->l3_cpu_to_domain_cnt<=report->numa_cpu_to_node_cnt );
  for( ulong i=0UL, top=0UL; i<report->l3_cpu_to_domain_cnt; i++ ) {
    if( report->l3_cpu_to_domain[ i ]==USHORT_MAX ) continue; /* offline */
    FD_TEST( report->l3_cpu_to_domain[ i ]<=top );
    if( report->l3_cpu_to_domain[ i ]==top ) top++;
  }

  FD_LOG_NOTICE(( "kernel_release %s",  report->kernel_release ));
  FD_LOG_NOTICE(( "distro %s %s",       report->distro_id, report->distro_version_id ));
  FD_LOG_NOTICE(( "mitigations %lu",    report->mitigations_cnt ));
  FD_LOG_NOTICE(( "cpu %s (%u cores %u threads %u sockets)", report->cpu_model_name,
                  report->cpu_physical_core_count, report->cpu_logical_count, report->cpu_socket_count ));
  ulong l3_domains = 0UL;
  for( ulong i=0UL; i<report->l3_cpu_to_domain_cnt; i++ ) if( report->l3_cpu_to_domain[ i ]!=USHORT_MAX ) l3_domains = fd_ulong_max( l3_domains, report->l3_cpu_to_domain[ i ]+1UL );
  FD_LOG_NOTICE(( "l3 domains %lu over %lu cpus", l3_domains, report->l3_cpu_to_domain_cnt ));
  FD_TEST( report->cpu_features_cnt>=2UL ); /* every supported x86 CPU has sse and avx */
  /* core map covers the numa map; distinct online values match the physical core count */
  FD_TEST( report->cpu_to_core_cnt==report->numa_cpu_to_node_cnt );
  ulong cores = 0UL, offline = 0UL;
  for( ulong i=0UL; i<report->cpu_to_core_cnt; i++ ) {
    if( report->cpu_to_core[ i ]==USHORT_MAX ) { offline++; continue; }
    FD_TEST( report->cpu_to_core[ i ]<=cores );
    if( report->cpu_to_core[ i ]==cores ) cores++;
  }
  FD_TEST( cores==report->cpu_physical_core_count );
  FD_LOG_NOTICE(( "cpu_to_core %lu cores %lu offline over %lu cpus", cores, offline, report->cpu_to_core_cnt ));
  FD_TEST( report->accounts_fs_idx!=255 );
  FD_LOG_NOTICE(( "root fs device_idx %u", report->filesystems[ report->accounts_fs_idx ].device_idx ));
  FD_LOG_NOTICE(( "dimms %lu nics %lu blocks %lu nvme %lu md %lu fs %lu",
                  report->dmi_dimms_cnt, report->nic_devices_cnt, report->block_devices_cnt,
                  report->nvme_devices_cnt, report->mdraid_arrays_cnt, report->filesystems_cnt ));
  FD_LOG_NOTICE(( "hypervisor %d container %d chassis %d",
                  report->hypervisor_vendor, report->container_type, report->dmi_chassis_type ));
  FD_TEST( report->cpuset_partition>=1 && report->cpuset_partition<=6 );
  FD_TEST( report->cpuset_partition!=1 || !report->cpuset_partition_cpus_cnt );
  FD_LOG_NOTICE(( "cpuset partition %d over %lu cpus", report->cpuset_partition, report->cpuset_partition_cpus_cnt ));

  ulong  cap = 16UL<<20;
  void * mem = aligned_alloc( FD_CIRCQ_ALIGN, fd_ulong_align_up( fd_circq_footprint( cap ), FD_CIRCQ_ALIGN ) );
  FD_TEST( mem );
  fd_circq_t * circq = fd_circq_join( fd_circq_new( mem, cap ) );
  FD_TEST( circq );

  static fd_event_client_t client[1];

  /* Rendering checks below use a fixed core map: cpus 2c and 2c+1 are
     siblings of core c, independent of the host */
  report->cpu_to_core_cnt = 8UL;
  for( ulong i=0UL; i<8UL; i++ ) report->cpu_to_core[ i ] = (ushort)(i/2UL);

  topo->tile_cnt = 2UL;
  strcpy( topo->tiles[ 0 ].name, "net" );
  topo->tiles[ 0 ].cpu_idx = 1UL;
  topo->tiles[ 0 ].floats  = 1;
  topo->tiles[ 0 ].out_cnt = 1UL;
  topo->tiles[ 0 ].out_link_id[ 0 ] = 0UL;
  strcpy( topo->tiles[ 1 ].name, "shred" );
  topo->tiles[ 1 ].cpu_idx = ULONG_MAX;
  topo->tiles[ 1 ].in_cnt = 1UL;
  topo->tiles[ 1 ].in_link_id[ 0 ] = 0UL;
  topo->tiles[ 1 ].event_link_id = ULONG_MAX;
  topo->tiles[ 0 ].event_link_id = ULONG_MAX;
  /* loopback sock copies a pinned net's CPU, and a startup-only
     genesi reuses execle's CPU: neither is a shared core; replay on
     cpu 2's sibling with dedup is.  The launchers found no float pool,
     so floating net:0 runs pinned on cpu 1, sharing net:1's core */
  topo->tile_cnt = 8UL;
  report->float_pool = 0;
  strcpy( topo->tiles[ 2 ].name, "net" );
  topo->tiles[ 2 ].kind_id = 1UL;
  topo->tiles[ 2 ].cpu_idx = 0UL;
  strcpy( topo->tiles[ 3 ].name, "sock" );
  topo->tiles[ 3 ].cpu_idx = 0UL;
  topo->tiles[ 3 ].sock.only_recv_lo = 1;
  topo->tiles[ 3 ].sock.net_tile_id  = 2UL;
  strcpy( topo->tiles[ 4 ].name, "genesi" );
  topo->tiles[ 4 ].cpu_idx        = 4UL;
  topo->tiles[ 4 ].allow_shutdown = 1;
  strcpy( topo->tiles[ 5 ].name, "execle" );
  topo->tiles[ 5 ].cpu_idx = 4UL;
  strcpy( topo->tiles[ 6 ].name, "replay" );
  topo->tiles[ 6 ].cpu_idx = 3UL;
  strcpy( topo->tiles[ 7 ].name, "dedup" );
  topo->tiles[ 7 ].cpu_idx = 2UL;
  for( ulong i=0UL; i<8UL; i++ ) topo->tiles[ i ].id = i;
  for( ulong i=2UL; i<8UL; i++ ) topo->tiles[ i ].event_link_id = ULONG_MAX;
  topo->link_cnt = 1UL;
  strcpy( topo->links[ 0 ].name, "net_shred" );
  topo->links[ 0 ].depth = 128UL;
  topo->links[ 0 ].mtu   = 2048UL;
  topo->wksp_cnt = 1UL;
  strcpy( topo->workspaces[ 0 ].name, "net_shred" );
  topo->workspaces[ 0 ].page_sz  = 1UL<<21;
  topo->workspaces[ 0 ].page_cnt = 2UL;

  fd_boot_report_publish( report, topo, circq, client );

  FD_TEST( report->topology_json_len );
  FD_LOG_NOTICE(( "topology_json %s", report->topology_json ));
  FD_TEST( strstr( report->topology_json, "\"cpu_idx\":1,\"floats\":true,\"core_shared\":true,\"sibling_cpu\":0," ) );
  FD_TEST( strstr( report->topology_json, "\"kind\":\"net\",\"kind_id\":1,\"cpu_idx\":0,\"floats\":false,\"core_shared\":true," ) );
  FD_TEST( strstr( report->topology_json, "\"cpu_idx\":-1,\"floats\":false,\"core_shared\":false,\"sibling_cpu\":-1" ) );
  FD_TEST( strstr( report->topology_json, "\"kind\":\"genesi\",\"kind_id\":0,\"cpu_idx\":4,\"floats\":false,\"core_shared\":false,\"sibling_cpu\":5," ) );
  FD_TEST( strstr( report->topology_json, "\"kind\":\"execle\",\"kind_id\":0,\"cpu_idx\":4,\"floats\":false,\"core_shared\":false," ) );
  FD_TEST( strstr( report->topology_json, "\"kind\":\"replay\",\"kind_id\":0,\"cpu_idx\":3,\"floats\":false,\"core_shared\":true,\"sibling_cpu\":2," ) );
  FD_TEST( strstr( report->topology_json, "\"kind\":\"dedup\",\"kind_id\":0,\"cpu_idx\":2,\"floats\":false,\"core_shared\":true," ) );
  FD_TEST( strstr( report->topology_json, "\"kind\":\"sock\",\"kind_id\":0,\"cpu_idx\":0,\"floats\":false,\"core_shared\":true," ) ); /* via net:0 */

  ulong sz = 0UL;
  uchar const * msg = fd_circq_cursor_advance( circq, &sz );
  FD_TEST( msg );
  FD_TEST( sz && sz<=FD_EVENT_BOOT_BUF_MAX );
  FD_LOG_NOTICE(( "boot event encoded %lu bytes (bound %lu)", sz, FD_EVENT_BOOT_BUF_MAX ));

  /* StreamEventsRequest envelope: nonce, event_id, link_seq,
     timestamp_nanos, then the Event submessage filling the rest */
  fd_pb_inbuf_t buf[1];
  fd_pb_inbuf_init( buf, msg, sz );
  fd_pb_tlv_t tlv[1];
  for( uint id=1U; id<=4U; id++ ) FD_TEST( fd_pb_read_tlv( buf, tlv ) && tlv->field_id==id && tlv->wire_type==FD_PB_WIRE_TYPE_VARINT );
  FD_TEST( fd_pb_read_tlv( buf, tlv ) && tlv->field_id==5U && tlv->wire_type==FD_PB_WIRE_TYPE_LEN );
  FD_TEST( tlv->len==fd_pb_inbuf_sz( buf ) );
  check_msg( buf->cur, tlv->len, "Event", report );
  FD_LOG_NOTICE(( "decode cross-check against events.proto passed" ));

  /* With a float pool floaters float and never share: net:1 and its
     loopback sock are alone again */
  static fd_boot_report_t pooled[1];
  *pooled = *report;
  pooled->float_pool = 1;
  fd_boot_report_publish( pooled, topo, circq, client );
  FD_TEST( fd_circq_cursor_advance( circq, &sz ) );
  FD_TEST( strstr( pooled->topology_json, "\"cpu_idx\":1,\"floats\":true,\"core_shared\":false,\"sibling_cpu\":0," ) );
  FD_TEST( strstr( pooled->topology_json, "\"kind\":\"net\",\"kind_id\":1,\"cpu_idx\":0,\"floats\":false,\"core_shared\":false," ) );
  FD_TEST( strstr( pooled->topology_json, "\"kind\":\"sock\",\"kind_id\":0,\"cpu_idx\":0,\"floats\":false,\"core_shared\":false," ) );

  /* Two floaters fall back to pinned without a pool: snapdc and snapin
     on cpu 1 share it (the startup/post-start pair with execle on its
     sibling stays exempt) */
  static fd_topo_t two[1];
  memset( two, 0, sizeof(two) );
  two->tile_cnt = 3UL;
  char const * two_name[ 3 ] = { "snapdc", "snapin", "execle" };
  ulong        two_cpu [ 3 ] = { 1UL, 1UL, 0UL };
  pooled->float_pool = 0;
  for( ulong i=0UL; i<3UL; i++ ) {
    strcpy( two->tiles[ i ].name, two_name[ i ] );
    two->tiles[ i ].id            = i;
    two->tiles[ i ].cpu_idx       = two_cpu[ i ];
    two->tiles[ i ].floats        = i<2UL;
    two->tiles[ i ].event_link_id = ULONG_MAX;
  }
  fd_boot_report_publish( pooled, two, circq, client );
  FD_TEST( fd_circq_cursor_advance( circq, &sz ) );
  FD_TEST( strstr( pooled->topology_json, "\"kind\":\"snapdc\",\"kind_id\":0,\"cpu_idx\":1,\"floats\":true,\"core_shared\":true," ) );
  FD_TEST( strstr( pooled->topology_json, "\"kind\":\"snapin\",\"kind_id\":0,\"cpu_idx\":1,\"floats\":true,\"core_shared\":true," ) );
  FD_TEST( strstr( pooled->topology_json, "\"kind\":\"execle\",\"kind_id\":0,\"cpu_idx\":0,\"floats\":false,\"core_shared\":false," ) );

  /* worst case validates the buffer bound deterministically: every
     string at max_len, every array full, every numeric at max varint
     width; topology_json is re-rendered small by publish so its
     remaining headroom is added back below */
  static fd_boot_report_t maxed[1];
  memset( maxed, 0xFF, sizeof(*maxed) );
#define PAD( f ) do { memset( (f), 'a', sizeof(f)-1UL ); (f)[ sizeof(f)-1UL ] = '\0'; } while(0)
  PAD( maxed->kernel_release ); PAD( maxed->kernel_version ); PAD( maxed->distro_id ); PAD( maxed->distro_version_id );
  PAD( maxed->distro_id_like ); PAD( maxed->libc_version ); PAD( maxed->build_extras ); PAD( maxed->compiler_version );
  PAD( maxed->cpu_model_name ); PAD( maxed->cpu_max_enabled_cstate ); PAD( maxed->dmi_sys_vendor ); PAD( maxed->dmi_product_name );
  PAD( maxed->dmi_bios_version ); PAD( maxed->dmi_bios_date ); PAD( maxed->dmi_board_vendor ); PAD( maxed->dmi_board_name );
  for( ulong i=0UL; i<32UL; i++ ) PAD( maxed->mitigations[ i ] );
  for( ulong i=0UL; i<16UL; i++ ) PAD( maxed->build_features[ i ] );
  for( ulong i=0UL; i<16UL; i++ ) PAD( maxed->cpu_features[ i ] );
  for( ulong i=0UL; i<16UL; i++ ) PAD( maxed->nic_bond_slaves[ i ] );
  for( ulong i=0UL; i<64UL; i++ ) {
    fd_boot_report_dimm_t * d = &maxed->dmi_dimms[ i ];
    PAD( d->mem_type ); PAD( d->manufacturer ); PAD( d->part_number );
  }
  for( ulong i=0UL; i<16UL; i++ ) {
    fd_boot_report_nic_t * n = &maxed->nic_devices[ i ];
    PAD( n->name ); PAD( n->driver ); PAD( n->driver_version ); PAD( n->firmware_version );
    PAD( n->pcie_current_link_speed ); PAD( n->pcie_max_link_speed ); PAD( n->bus_info ); PAD( n->rss_hash_func );
    for( ulong j=0UL; j<64UL; j++ ) PAD( n->offloads[ j ] );
    n->offloads_cnt = 64UL;
  }
  for( ulong i=0UL; i<24UL; i++ ) {
    fd_boot_report_block_device_t * d = &maxed->block_devices[ i ];
    PAD( d->name ); PAD( d->model ); PAD( d->transport ); PAD( d->scheduler );
  }
  for( ulong i=0UL; i<16UL; i++ ) PAD( maxed->nvme_devices[ i ].firmware_rev );
  for( ulong i=0UL; i<16UL; i++ ) { PAD( maxed->mdraid_arrays[ i ].name ); PAD( maxed->mdraid_arrays[ i ].level ); }
  for( ulong i=0UL; i<8UL;  i++ ) { PAD( maxed->filesystems[ i ].fs_type ); PAD( maxed->filesystems[ i ].mount_options ); }
#undef PAD
  maxed->mitigations_cnt      = 32UL;
  maxed->build_features_cnt   = 16UL;
  maxed->cpu_features_cnt     = 16UL;
  maxed->numa_cpu_to_node_cnt = 1024UL;
  maxed->isolated_cpus_cnt    = 1024UL;
  maxed->l3_cpu_to_domain_cnt = 1024UL;
  maxed->cpu_to_core_cnt      = 1024UL;
  maxed->launch_cpus_cnt      = 1024UL;
  maxed->cpuset_partition     = 6;
  maxed->cpuset_partition_cpus_cnt = 1024UL;
  maxed->dmi_dimms_cnt        = 64UL;
  maxed->nic_devices_cnt      = 16UL;
  maxed->nic_bond_slaves_cnt  = 16UL;
  maxed->block_devices_cnt    = 24UL;
  maxed->nvme_devices_cnt     = 16UL;
  maxed->mdraid_arrays_cnt    = 16UL;
  maxed->filesystems_cnt      = 8UL;
  memset( maxed->resolved_config_json, 'a', sizeof(maxed->resolved_config_json) );
  memset( maxed->user_config_json,     'a', sizeof(maxed->user_config_json) );
  maxed->resolved_config_json_len = FD_BOOT_REPORT_JSON_MAX;
  maxed->user_config_json_len     = FD_BOOT_REPORT_USER_JSON_MAX;

  fd_boot_report_publish( maxed, topo, circq, client );
  ulong max_sz = 0UL;
  FD_TEST( fd_circq_cursor_advance( circq, &max_sz ) );
  ulong worst = max_sz + ( FD_BOOT_REPORT_JSON_MAX-maxed->topology_json_len );
  FD_TEST( worst<=FD_EVENT_BOOT_BUF_MAX );
  FD_LOG_NOTICE(( "worst-case encode %lu (bound %lu, headroom %lu)", worst, FD_EVENT_BOOT_BUF_MAX, FD_EVENT_BOOT_BUF_MAX-worst ));

  free( fd_circq_delete( fd_circq_leave( circq ) ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
