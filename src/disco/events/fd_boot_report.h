#ifndef HEADER_fd_src_disco_events_fd_boot_report_h
#define HEADER_fd_src_disco_events_fd_boot_report_h

/* fd_boot_report collects and publishes the boot telemetry event
   (schema id 10, schema/boot.json).  The event is a wide fingerprint
   of the host taken once at process start: collection runs in the
   event tile's privileged_init (root, pre-sandbox, full /proc, /sys
   and device access), and the encoded event is pushed into the event
   queue in unprivileged_init, to be delivered whenever the client
   connects.

   The schema is variable-length so the generator emits no C struct or
   serializer for it; the struct below, the collector, and the
   protobuf encoder are maintained by hand against schema/boot.json.
   Field numbers in the encoder are the 1-based positions of fields in
   the schema file; enum values are the 1-based positions of variants.

   Facts only knowable to the boot process travel on the topology:
   config-derived paths and the bound interface are tile config fields,
   and the rendered config documents are filled into fd_topo_t by the
   app during topology construction. */

#include "fd_circq.h"
#include "fd_event_client.h"
#include "../topo/fd_topo.h"

#define FD_BOOT_REPORT_JSON_MAX      (262144UL)
#define FD_BOOT_REPORT_USER_JSON_MAX (131072UL)

FD_STATIC_ASSERT( sizeof(((fd_topo_t *)0)->resolved_config_json)==FD_BOOT_REPORT_JSON_MAX,      boot_report_resolved_json_sz );
FD_STATIC_ASSERT( sizeof(((fd_topo_t *)0)->user_config_json)    ==FD_BOOT_REPORT_USER_JSON_MAX, boot_report_user_json_sz );

/* Conservative bound on the encoded size of a boot event (all strings
   at max_len, all arrays full).  Dominated by the two JSON dumps. */

#define FD_EVENT_BOOT_BUF_MAX (2UL*FD_BOOT_REPORT_JSON_MAX+FD_BOOT_REPORT_USER_JSON_MAX+131072UL)

struct fd_boot_report_dimm {
  ulong size_bytes;
  char  mem_type[ 9 ];
  ulong speed_mts;
  ulong rated_speed_mts;
  char  manufacturer[ 33 ];
  char  part_number[ 33 ];
};
typedef struct fd_boot_report_dimm fd_boot_report_dimm_t;

struct fd_boot_report_nic {
  char   name[ 17 ];
  char   driver[ 33 ];
  char   driver_version[ 65 ];
  char   firmware_version[ 65 ];
  uchar  pcie_current_link_width;
  uchar  pcie_max_link_width;
  char   pcie_current_link_speed[ 17 ];
  char   pcie_max_link_speed[ 17 ];
  char   bus_info[ 33 ];
  ushort pci_device_id;
  ushort pci_vendor_id;
  ushort pci_subsystem_vendor_id;
  ushort pci_subsystem_device_id;
  ulong  numa_node;
  ulong  mtu;
  ulong  link_speed_mbps;
  int    carrier;
  int    promiscuous;
  ushort channels_current;
  ushort channels_max;
  ulong  rx_ring_size;
  ulong  tx_ring_size;
  ulong  rx_ring_max;
  ulong  tx_ring_max;
  char   offloads[ 64 ][ 36 ];
  ulong  offloads_cnt;
  int    rss_flow_hash_udp4;
  ulong  coalesce_rx_usecs;
  int    coalesce_adaptive_rx;
  char   rss_hash_func[ 17 ];
  ulong  ntuple_rule_count;
  int    is_bond_master;
};
typedef struct fd_boot_report_nic fd_boot_report_nic_t;

struct fd_boot_report_block_device {
  char  name[ 65 ];
  char  model[ 49 ];
  ulong capacity_bytes;
  int   rotational;
  char  transport[ 17 ];
  char  scheduler[ 17 ];
};
typedef struct fd_boot_report_block_device fd_boot_report_block_device_t;

struct fd_boot_report_nvme {
  uchar device_idx;
  char  firmware_rev[ 33 ];
  uchar critical_warning;
  uchar available_spare_pct;
  uchar percentage_used;
  ulong media_errors;
  uchar numa_node;
  ulong namespace_size_bytes;
};
typedef struct fd_boot_report_nvme fd_boot_report_nvme_t;

struct fd_boot_report_mdraid {
  char  name[ 33 ];
  char  level[ 17 ];
  uchar device_count;
  int   degraded;
};
typedef struct fd_boot_report_mdraid fd_boot_report_mdraid_t;

struct fd_boot_report_fs {
  uchar device_idx; /* index into block_devices, 255 if not a local block device */
  char  fs_type[ 17 ];
  char  mount_options[ 257 ];
  ulong capacity_bytes;
  ulong free_bytes;
};
typedef struct fd_boot_report_fs fd_boot_report_fs_t;

struct fd_boot_report {
  char  kernel_release[ 66 ];
  char  kernel_version[ 130 ];
  char  mitigations[ 32 ][ 33 ];
  ulong mitigations_cnt;
  char  distro_id[ 65 ];
  char  distro_version_id[ 65 ];
  char  distro_id_like[ 129 ];
  int   libc_kind;
  char  libc_version[ 33 ];
  int   build_machine_target;
  char  build_extras[ 129 ];
  int   build_git_dirty;
  int   compiler;
  char  compiler_version[ 129 ];
  ulong build_timestamp_nanos;
  char  build_features[ 16 ][ 8 ];
  ulong build_features_cnt;

  int    cpu_arch;
  int    cpu_vendor;
  char   cpu_model_name[ 97 ];
  ushort cpu_family;
  ushort cpu_model_id;
  uchar  cpu_stepping;
  ulong  cpu_microcode_version;
  ushort cpu_logical_count;
  ushort cpu_physical_core_count;
  uchar  cpu_socket_count;
  int    smt_active;
  int    cpufreq_governor;
  int    cpufreq_driver;
  int    cpu_energy_perf_preference;
  int    cpu_idle_driver;
  char   cpu_max_enabled_cstate[ 17 ];

  ulong host_memory_bytes;
  ulong host_memory_available_bytes;
  uchar  numa_cpu_to_node[ 1024 ];
  ulong  numa_cpu_to_node_cnt;
  ushort isolated_cpus[ 1024 ];
  ulong  isolated_cpus_cnt;

  fd_boot_report_dimm_t dmi_dimms[ 64 ];
  ulong                 dmi_dimms_cnt;

  fd_boot_report_nic_t nic_devices[ 16 ];
  ulong                nic_devices_cnt;
  char                 nic_bond_slaves[ 16 ][ 17 ];
  ulong                nic_bond_slaves_cnt;
  int                  bond_mode;
  uchar                bound_nic_idx;
  uchar                net_bpf_jit_enable;

  char  dmi_sys_vendor[ 65 ];
  char  dmi_product_name[ 65 ];
  char  dmi_bios_version[ 65 ];
  char  dmi_bios_date[ 17 ];
  char  dmi_board_vendor[ 65 ];
  char  dmi_board_name[ 65 ];
  int   dmi_chassis_type;
  int   iommu_mode;
  int   hypervisor_vendor;

  int   container_type;
  int   kubernetes_pod;
  ulong cgroup_memory_limit_bytes;
  ulong cgroup_memory_high_bytes;
  ulong cgroup_swap_limit_bytes;
  uint  cgroup_cpu_quota_millicores;

  fd_boot_report_block_device_t block_devices[ 24 ];
  ulong                         block_devices_cnt;
  fd_boot_report_nvme_t         nvme_devices[ 16 ];
  ulong                         nvme_devices_cnt;
  fd_boot_report_mdraid_t       mdraid_arrays[ 16 ];
  ulong                         mdraid_arrays_cnt;
  fd_boot_report_fs_t           filesystems[ 8 ];
  ulong                         filesystems_cnt;
  uchar                         accounts_fs_idx;
  uchar                         snapshots_fs_idx;
  uchar                         log_fs_idx;
  uchar                         shredb_fs_idx;
  uchar                         guidb_fs_idx;

  char   resolved_config_json[ FD_BOOT_REPORT_JSON_MAX ];
  ulong  resolved_config_json_len;
  char   user_config_json[ FD_BOOT_REPORT_USER_JSON_MAX ];
  ulong  user_config_json_len;
  char   topology_json[ FD_BOOT_REPORT_JSON_MAX ];
  ulong  topology_json_len;
  ushort tile_count;
  ulong  memory_total;
  ulong  memory_gigantic_pages;
  ulong  memory_huge_pages;
  ulong  memory_normal_pages;
  ulong  process_start_time_nanos;
  uint   feature_set_id;
};
typedef struct fd_boot_report fd_boot_report_t;

FD_PROTOTYPES_BEGIN

/* fd_boot_report_collect fills report from the local machine and the
   boot facts on tile->event.  Must run with full privileges (reads
   /sys/firmware/dmi entries, NVMe admin ioctls) and before sandboxing.
   Unreadable machine sources leave zero/unknown values; unset config
   documents on the tile abort. */

void
fd_boot_report_collect( fd_boot_report_t *     report,
                        fd_topo_t const *      topo,
                        fd_topo_tile_t const * tile );

/* fd_boot_report_publish renders topology_json from topo, encodes the
   event, and pushes it into the event queue with a freshly reserved
   event id. */

void
fd_boot_report_publish( fd_boot_report_t *  report,
                        fd_topo_t const *   topo,
                        fd_circq_t *        circq,
                        fd_event_client_t * client );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_events_fd_boot_report_h */
