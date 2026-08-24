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

  FD_TEST( report->kernel_release[ 0 ] );
  FD_TEST( report->cpu_logical_count );
  FD_TEST( report->host_memory_bytes );
  FD_TEST( report->resolved_config_json_len==13UL );
  FD_TEST( report->user_config_json_len==13UL );
  FD_TEST( report->filesystems_cnt>=1UL );
  FD_TEST( report->accounts_fs_idx==report->snapshots_fs_idx );
  FD_TEST( report->shredb_fs_idx==255 );

  FD_LOG_NOTICE(( "kernel_release %s",  report->kernel_release ));
  FD_LOG_NOTICE(( "distro %s %s",       report->distro_id, report->distro_version_id ));
  FD_LOG_NOTICE(( "mitigations %lu",    report->mitigations_cnt ));
  FD_LOG_NOTICE(( "cpu %s (%u cores %u threads %u sockets)", report->cpu_model_name,
                  report->cpu_physical_core_count, report->cpu_logical_count, report->cpu_socket_count ));
  FD_TEST( report->accounts_fs_idx!=255 );
  FD_LOG_NOTICE(( "root fs device_idx %u", report->filesystems[ report->accounts_fs_idx ].device_idx ));
  FD_LOG_NOTICE(( "dimms %lu nics %lu blocks %lu nvme %lu md %lu fs %lu",
                  report->dmi_dimms_cnt, report->nic_devices_cnt, report->block_devices_cnt,
                  report->nvme_devices_cnt, report->mdraid_arrays_cnt, report->filesystems_cnt ));
  FD_LOG_NOTICE(( "hypervisor %d container %d chassis %d",
                  report->hypervisor_vendor, report->container_type, report->dmi_chassis_type ));

  ulong  cap = 16UL<<20;
  void * mem = aligned_alloc( FD_CIRCQ_ALIGN, fd_ulong_align_up( fd_circq_footprint( cap ), FD_CIRCQ_ALIGN ) );
  FD_TEST( mem );
  fd_circq_t * circq = fd_circq_join( fd_circq_new( mem, cap ) );
  FD_TEST( circq );

  static fd_event_client_t client[1];

  topo->tile_cnt = 2UL;
  strcpy( topo->tiles[ 0 ].name, "net" );
  topo->tiles[ 0 ].cpu_idx = 1UL;
  topo->tiles[ 0 ].out_cnt = 1UL;
  topo->tiles[ 0 ].out_link_id[ 0 ] = 0UL;
  strcpy( topo->tiles[ 1 ].name, "shred" );
  topo->tiles[ 1 ].cpu_idx = ULONG_MAX;
  topo->tiles[ 1 ].in_cnt = 1UL;
  topo->tiles[ 1 ].in_link_id[ 0 ] = 0UL;
  topo->tiles[ 1 ].event_link_id = ULONG_MAX;
  topo->tiles[ 0 ].event_link_id = ULONG_MAX;
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
  maxed->numa_cpu_to_node_cnt = 1024UL;
  maxed->isolated_cpus_cnt    = 1024UL;
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
