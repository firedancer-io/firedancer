#include "fd_iavf.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include <linux/vfio.h>
#include <linux/pci_regs.h>

#define FD_IAVF_PCI_SYSFS "/sys/bus/pci/devices"

/* Intel IAVF register window required for queue tails and the Admin Queue. */
#define FD_IAVF_HW_BAR0_MAP_SZ (0x9000UL)

/* Intel IAVF_VFGEN_RSTAT register and virtchnl_vfr_states values. */
#define FD_IAVF_HW_VFGEN_RSTAT           (0x8800UL)
#define FD_IAVF_HW_VFGEN_RSTAT_STATE     (0x3U)
#define FD_IAVF_HW_VFR_STATE_COMPLETED   (1U)
#define FD_IAVF_HW_VFR_STATE_ACTIVE      (2U)

/* Intel IAVF Admin Queue registers. */
#define FD_IAVF_HW_VF_ARQBAH  (0x6000UL)
#define FD_IAVF_HW_VF_ARQBAL  (0x6c00UL)
#define FD_IAVF_HW_VF_ARQH    (0x7400UL)
#define FD_IAVF_HW_VF_ARQLEN  (0x8000UL)
#define FD_IAVF_HW_VF_ARQT    (0x7000UL)
#define FD_IAVF_HW_VF_ATQBAH  (0x7800UL)
#define FD_IAVF_HW_VF_ATQBAL  (0x7c00UL)
#define FD_IAVF_HW_VF_ATQH    (0x6400UL)
#define FD_IAVF_HW_VF_ATQLEN  (0x6800UL)
#define FD_IAVF_HW_VF_ATQT    (0x8400UL)
#define FD_IAVF_HW_AQ_ENABLE  (1U<<31)
#define FD_IAVF_HW_AQ_HEAD    (0x3ffU)

#define FD_IAVF_HW_TX_TAIL(queue_id) (0x0000UL + 4UL*(queue_id))
#define FD_IAVF_HW_RX_TAIL(queue_id) (0x2000UL + 4UL*(queue_id))

#define FD_IAVF_HW_TX_DESC_DONE          (0xfUL)
#define FD_IAVF_HW_TX_DESC_CMD_SHIFT     (4)
#define FD_IAVF_HW_TX_DESC_CMD_EOP       (1UL)
#define FD_IAVF_HW_TX_DESC_CMD_REPORT_STATUS (2UL) /* IAVF_TX_DESC_CMD_RS */
#define FD_IAVF_HW_TX_DESC_BUFFER_SHIFT  (34)
#define FD_IAVF_HW_TX_DESC_BUFFER_MAX    (0x3fffUL)

#define FD_IAVF_HW_RX_DESC_DONE          (1UL<<0)
#define FD_IAVF_HW_RX_DESC_END_OF_PACKET (1UL<<1)
#define FD_IAVF_HW_RX_DESC_ERROR_SHIFT   (19)
#define FD_IAVF_HW_RX_DESC_ERROR_MASK    (0xffUL)
#define FD_IAVF_HW_RX_DESC_LENGTH_SHIFT  (38)
#define FD_IAVF_HW_RX_DESC_LENGTH_MASK   (0x3fffUL)

#define FD_IAVF_HW_ADMINQ_DEPTH       (32UL)
#define FD_IAVF_HW_ADMINQ_BUF_SZ      (4096UL)
#define FD_IAVF_HW_ADMINQ_DESC_OFF    (0UL)
#define FD_IAVF_HW_ADMINQ_RECV_OFF    (4096UL)
#define FD_IAVF_HW_ADMINQ_SEND_BUF_OFF (8192UL)
#define FD_IAVF_HW_ADMINQ_RECV_BUF_OFF (FD_IAVF_HW_ADMINQ_SEND_BUF_OFF + FD_IAVF_HW_ADMINQ_DEPTH*FD_IAVF_HW_ADMINQ_BUF_SZ)
#define FD_IAVF_HW_ADMINQ_FOOTPRINT    (FD_IAVF_HW_ADMINQ_RECV_BUF_OFF + FD_IAVF_HW_ADMINQ_DEPTH*FD_IAVF_HW_ADMINQ_BUF_SZ)

/* Intel libie_aq_desc hardware format. */
struct fd_iavf_hw_aq_desc {
  ushort flags;
  ushort opcode;
  ushort datalen;
  ushort retval;
  uint   cookie_high;
  uint   cookie_low;
  uint   param0;
  uint   param1;
  uint   addr_high;
  uint   addr_low;
};

typedef struct fd_iavf_hw_aq_desc fd_iavf_hw_aq_desc_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_aq_desc_t)==32UL, iavf_aq_desc_sz );

/* Intel LIBIE_AQ_FLAG_* descriptor flags. */
#define FD_IAVF_HW_AQ_FLAG_ERR (1U<<2)
#define FD_IAVF_HW_AQ_FLAG_LB  (1U<<9)
#define FD_IAVF_HW_AQ_FLAG_RD  (1U<<10)
#define FD_IAVF_HW_AQ_FLAG_BUF (1U<<12)
#define FD_IAVF_HW_AQ_FLAG_SI  (1U<<13)

/* Intel Admin Queue virtualization opcodes and virtchnl operations. */
#define FD_IAVF_HW_AQ_SEND_MSG_TO_PF (0x0801U)
#define FD_IAVF_HW_AQ_SEND_MSG_TO_VF (0x0802U)
#define FD_IAVF_HW_VIRTCHNL_VERSION          (1U)
#define FD_IAVF_HW_VIRTCHNL_GET_VF_RESOURCES (3U)
#define FD_IAVF_HW_VIRTCHNL_CONFIG_QUEUES    (6U)
#define FD_IAVF_HW_VIRTCHNL_CONFIG_IRQ_MAP   (7U)
#define FD_IAVF_HW_VIRTCHNL_ENABLE_QUEUES    (8U)
#define FD_IAVF_HW_VIRTCHNL_GET_STATS        (15U)
#define FD_IAVF_HW_VIRTCHNL_EVENT            (17U)
#define FD_IAVF_HW_VIRTCHNL_ADD_FDIR_FILTER  (47U)

#define FD_IAVF_HW_VIRTCHNL_CAP_L2             (1U<<0)
#define FD_IAVF_HW_VIRTCHNL_CAP_ADV_LINK_SPEED (1U<<7)
#define FD_IAVF_HW_VIRTCHNL_CAP_FDIR_PF        (1U<<28)
#define FD_IAVF_HW_VIRTCHNL_VSI_SRIOV          (6)

#define FD_IAVF_HW_VIRTCHNL_PROTO_ETH  (1)
#define FD_IAVF_HW_VIRTCHNL_PROTO_IPV4 (4)
#define FD_IAVF_HW_VIRTCHNL_PROTO_UDP  (7)
#define FD_IAVF_HW_VIRTCHNL_PROTO_GRE  (24)

#define FD_IAVF_HW_VIRTCHNL_IPV4_FIELD_DST      (1U<<1)
#define FD_IAVF_HW_VIRTCHNL_IPV4_FIELD_PROTOCOL (1U<<4)
#define FD_IAVF_HW_VIRTCHNL_UDP_FIELD_DST_PORT  (1U<<1)

#define FD_IAVF_HW_VIRTCHNL_ACTION_QUEUE (3)

#define FD_IAVF_HW_IPV4_PROTOCOL_OFF (9UL)
#define FD_IAVF_HW_IPV4_DST_OFF      (16UL)
#define FD_IAVF_HW_UDP_DST_PORT_OFF  (2UL)
#define FD_IAVF_HW_IP_PROTOCOL_UDP   (17U)
#define FD_IAVF_HW_IP_PROTOCOL_GRE   (47U)

#define FD_IAVF_HW_VIRTCHNL_FDIR_SUCCESS          (0)
#define FD_IAVF_HW_VIRTCHNL_FDIR_NORESOURCE       (1)
#define FD_IAVF_HW_VIRTCHNL_FDIR_RULE_EXIST       (2)
#define FD_IAVF_HW_VIRTCHNL_FDIR_RULE_CONFLICT    (3)
#define FD_IAVF_HW_VIRTCHNL_FDIR_RULE_NONEXIST    (4)
#define FD_IAVF_HW_VIRTCHNL_FDIR_RULE_INVALID     (5)
#define FD_IAVF_HW_VIRTCHNL_FDIR_RULE_TIMEOUT     (6)
#define FD_IAVF_HW_VIRTCHNL_FDIR_QUERY_INVALID    (7)

struct fd_iavf_hw_virtchnl_version {
  uint major;
  uint minor;
};

typedef struct fd_iavf_hw_virtchnl_version fd_iavf_hw_virtchnl_version_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_virtchnl_version_t)==8UL, iavf_virtchnl_version_sz );

/* Intel virtchnl_vf_resource header. */
struct fd_iavf_hw_virtchnl_vf_resource {
  ushort num_vsis;
  ushort num_queue_pairs;
  ushort max_vectors;
  ushort max_mtu;
  uint   capability_flags;
  uint   rss_key_sz;
  uint   rss_lut_sz;
};

typedef struct fd_iavf_hw_virtchnl_vf_resource fd_iavf_hw_virtchnl_vf_resource_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_virtchnl_vf_resource_t)==20UL, iavf_virtchnl_vf_resource_sz );

/* Intel virtchnl_vsi_resource hardware format. */
struct fd_iavf_hw_virtchnl_vsi_resource {
  ushort vsi_id;
  ushort num_queue_pairs;
  int    vsi_type;
  ushort qset_handle;
  uchar  default_mac_addr[ 6 ];
};

typedef struct fd_iavf_hw_virtchnl_vsi_resource fd_iavf_hw_virtchnl_vsi_resource_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_virtchnl_vsi_resource_t)==16UL, iavf_virtchnl_vsi_resource_sz );

/* Intel virtchnl_pf_event hardware format. */
struct fd_iavf_hw_virtchnl_event {
  int   event;
  uint  link_speed;
  uchar link_up;
  uchar pad[ 3 ];
  int   severity;
};

typedef struct fd_iavf_hw_virtchnl_event fd_iavf_hw_virtchnl_event_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_virtchnl_event_t)==16UL, iavf_virtchnl_event_sz );

/* Intel virtchnl_txq_info hardware format. */
struct fd_iavf_hw_virtchnl_txq_info {
  ushort vsi_id;
  ushort queue_id;
  ushort ring_len;
  ushort head_writeback_enabled;
  ulong  ring_iova;
  ulong  head_writeback_iova;
};

typedef struct fd_iavf_hw_virtchnl_txq_info fd_iavf_hw_virtchnl_txq_info_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_virtchnl_txq_info_t)==24UL, iavf_virtchnl_txq_info_sz );

/* Intel virtchnl_rxq_info hardware format. */
struct fd_iavf_hw_virtchnl_rxq_info {
  ushort vsi_id;
  ushort queue_id;
  uint   ring_len;
  ushort header_buffer_sz;
  ushort split_header_enabled;
  uint   data_buffer_sz;
  uint   max_frame_sz;
  uchar  crc_disable;
  uchar  descriptor_id;
  uchar  flags;
  uchar  pad1;
  ulong  ring_iova;
  int    split_position;
  uint   pad2;
};

typedef struct fd_iavf_hw_virtchnl_rxq_info fd_iavf_hw_virtchnl_rxq_info_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_virtchnl_rxq_info_t)==40UL, iavf_virtchnl_rxq_info_sz );

struct fd_iavf_hw_virtchnl_queue_config {
  ushort vsi_id;
  ushort queue_pair_cnt;
  uint   pad;
  fd_iavf_hw_virtchnl_txq_info_t tx;
  fd_iavf_hw_virtchnl_rxq_info_t rx;
  /* Linux virtchnl legacy sizing includes one extra zero queue pair. */
  uchar legacy_padding[ 64 ];
};

typedef struct fd_iavf_hw_virtchnl_queue_config fd_iavf_hw_virtchnl_queue_config_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_virtchnl_queue_config_t)==136UL, iavf_virtchnl_queue_config_sz );

struct fd_iavf_hw_virtchnl_irq_map {
  ushort vector_cnt;
  ushort vsi_id;
  ushort vector_id;
  ushort rx_queue_map;
  ushort tx_queue_map;
  ushort rx_itr_idx;
  ushort tx_itr_idx;
  /* Linux virtchnl legacy sizing includes one extra zero vector map. */
  uchar legacy_padding[ 12 ];
};

typedef struct fd_iavf_hw_virtchnl_irq_map fd_iavf_hw_virtchnl_irq_map_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_virtchnl_irq_map_t)==26UL, iavf_virtchnl_irq_map_sz );

struct fd_iavf_hw_virtchnl_queue_select {
  ushort vsi_id;
  ushort pad;
  uint   rx_queue_map;
  uint   tx_queue_map;
};

typedef struct fd_iavf_hw_virtchnl_queue_select fd_iavf_hw_virtchnl_queue_select_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_virtchnl_queue_select_t)==12UL, iavf_virtchnl_queue_select_sz );

/* Intel virtchnl_proto_hdr ABI format. */
struct fd_iavf_hw_virtchnl_proto_hdr {
  int   type;
  uint  field_selector;
  uchar buffer[ 64 ];
};

typedef struct fd_iavf_hw_virtchnl_proto_hdr fd_iavf_hw_virtchnl_proto_hdr_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_virtchnl_proto_hdr_t)==72UL, iavf_virtchnl_proto_hdr_sz );

/* Intel virtchnl_proto_hdrs ABI format. */
struct fd_iavf_hw_virtchnl_proto_hdrs {
  uchar tunnel_level;
  uchar pad[ 3 ];
  uint  count;
  fd_iavf_hw_virtchnl_proto_hdr_t headers[ 32 ];
};

typedef struct fd_iavf_hw_virtchnl_proto_hdrs fd_iavf_hw_virtchnl_proto_hdrs_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_virtchnl_proto_hdrs_t)==2312UL, iavf_virtchnl_proto_hdrs_sz );

/* Intel virtchnl_filter_action ABI format. */
struct fd_iavf_hw_virtchnl_filter_action {
  int type;
  union {
    struct {
      ushort index;
      uchar  region;
    } queue;
    uchar reserved[ 32 ];
  } config;
};

typedef struct fd_iavf_hw_virtchnl_filter_action fd_iavf_hw_virtchnl_filter_action_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_virtchnl_filter_action_t)==36UL, iavf_virtchnl_filter_action_sz );

/* Intel virtchnl_filter_action_set ABI format. */
struct fd_iavf_hw_virtchnl_filter_action_set {
  uint count;
  fd_iavf_hw_virtchnl_filter_action_t actions[ 8 ];
};

typedef struct fd_iavf_hw_virtchnl_filter_action_set fd_iavf_hw_virtchnl_filter_action_set_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_virtchnl_filter_action_set_t)==292UL, iavf_virtchnl_filter_action_set_sz );

/* Intel virtchnl_fdir_rule ABI format. */
struct fd_iavf_hw_virtchnl_fdir_rule {
  fd_iavf_hw_virtchnl_proto_hdrs_t        protocol_headers;
  fd_iavf_hw_virtchnl_filter_action_set_t action_set;
};

typedef struct fd_iavf_hw_virtchnl_fdir_rule fd_iavf_hw_virtchnl_fdir_rule_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_virtchnl_fdir_rule_t)==2604UL, iavf_virtchnl_fdir_rule_sz );

/* Intel virtchnl_fdir_add ABI format. */
struct fd_iavf_hw_virtchnl_fdir_add {
  ushort vsi_id;
  ushort validate_only;
  uint   flow_id;
  fd_iavf_hw_virtchnl_fdir_rule_t rule;
  int status;
};

typedef struct fd_iavf_hw_virtchnl_fdir_add fd_iavf_hw_virtchnl_fdir_add_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_virtchnl_fdir_add_t)==2616UL, iavf_virtchnl_fdir_add_sz );

/* Intel iavf_tx_desc hardware format. */
struct fd_iavf_hw_tx_desc {
  ulong buffer_iova;
  ulong cmd_type_offset_buffer_sz;
};

typedef struct fd_iavf_hw_tx_desc fd_iavf_hw_tx_desc_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_tx_desc_t)==16UL, iavf_tx_desc_sz );

/* Intel 32-byte receive descriptor hardware format. */
struct fd_iavf_hw_rx_desc {
  ulong qword[ 4 ];
};

typedef struct fd_iavf_hw_rx_desc fd_iavf_hw_rx_desc_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_rx_desc_t)==32UL, iavf_rx_desc_sz );
FD_STATIC_ASSERT( sizeof(fd_iavf_hw_stats_t)==96UL, iavf_stats_sz );

/* Intel Ethernet Adaptive Virtual Function PCI IDs supported by Linux iavf. */
static int
fd_iavf_hw_device_supported( ushort device_id ) {
  return device_id==0x154cU ||
         device_id==0x1571U ||
         device_id==0x1889U ||
         device_id==0x37cdU;
}

static int
fd_iavf_pci_addr_normalize( char       normalized[ FD_IAVF_PCI_ADDR_SZ ],
                            char const * pci_addr ) {
  if( FD_UNLIKELY( !pci_addr || strnlen( pci_addr, FD_IAVF_PCI_ADDR_SZ )!=FD_IAVF_PCI_ADDR_SZ-1UL ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( pci_addr[4]!=':' || pci_addr[7]!=':' || pci_addr[10]!='.' ) ) {
    errno = EINVAL;
    return -1;
  }

  for( ulong i=0UL; i<FD_IAVF_PCI_ADDR_SZ-1UL; i++ ) {
    if( i==4UL || i==7UL || i==10UL ) {
      normalized[i] = pci_addr[i];
      continue;
    }
    uchar c = (uchar)pci_addr[i];
    if( FD_UNLIKELY( !isxdigit( c ) ) ) {
      errno = EINVAL;
      return -1;
    }
    normalized[i] = (char)tolower( c );
  }
  normalized[ FD_IAVF_PCI_ADDR_SZ-1UL ] = '\0';

  char * end;
  ulong slot = strtoul( normalized+8, &end, 16 );
  if( FD_UNLIKELY( end!=normalized+10 || slot>31UL ) ) {
    errno = EINVAL;
    return -1;
  }
  ulong function = strtoul( normalized+11, &end, 16 );
  if( FD_UNLIKELY( end!=normalized+12 || function>7UL ) ) {
    errno = EINVAL;
    return -1;
  }
  return 0;
}

static int
fd_iavf_path_join( char         path[ PATH_MAX ],
                   char const * parent,
                   char const * name ) {
  int path_sz = snprintf( path, PATH_MAX, "%s/%s", parent, name );
  if( FD_UNLIKELY( path_sz<0 || path_sz>=PATH_MAX ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}

static int
fd_iavf_read_ulong( char const * path,
                    int          base,
                    ulong *      value ) {
  int fd = open( path, O_RDONLY|O_CLOEXEC );
  if( FD_UNLIKELY( fd<0 ) ) return -1;

  char buf[ 64 ];
  ssize_t read_sz = read( fd, buf, sizeof(buf)-1UL );
  int err = 0;
  if( FD_UNLIKELY( read_sz<0 ) )                          err = errno;
  else if( FD_UNLIKELY( (ulong)read_sz==sizeof(buf)-1UL ) ) err = EOVERFLOW;
  if( FD_UNLIKELY( close( fd ) && !err ) )                err = errno;
  if( FD_UNLIKELY( err ) ) {
    errno = err;
    return -1;
  }

  while( read_sz && isspace( (uchar)buf[ read_sz-1L ] ) ) read_sz--;
  if( FD_UNLIKELY( !read_sz ) ) {
    errno = EPROTO;
    return -1;
  }
  buf[ read_sz ] = '\0';

  errno = 0;
  char * end;
  ulong parsed = strtoul( buf, &end, base );
  if( FD_UNLIKELY( errno || *end ) ) {
    if( !errno ) errno = EPROTO;
    return -1;
  }
  *value = parsed;
  return 0;
}

static int
fd_iavf_read_link_name( char *       name,
                        ulong        name_max,
                        char const * path,
                        int          optional ) {
  char target[ PATH_MAX ];
  ssize_t target_sz = readlink( path, target, sizeof(target)-1UL );
  if( FD_UNLIKELY( target_sz<0 ) ) {
    if( optional && errno==ENOENT ) {
      name[0] = '\0';
      return 0;
    }
    return -1;
  }
  if( FD_UNLIKELY( (ulong)target_sz==sizeof(target)-1UL ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  target[ target_sz ] = '\0';

  char const * base = strrchr( target, '/' );
  base = base ? base+1 : target;
  ulong base_sz = strlen( base );
  if( FD_UNLIKELY( !base_sz || base_sz>=name_max ) ) {
    errno = EPROTO;
    return -1;
  }
  fd_memcpy( name, base, base_sz+1UL );
  return 0;
}

static int
fd_iavf_iommu_group_check( char const * pci_addr,
                           uint         iommu_group ) {
  char devices_path[ PATH_MAX ];
  int path_sz = snprintf( devices_path, sizeof(devices_path),
                          "/sys/kernel/iommu_groups/%u/devices", iommu_group );
  if( FD_UNLIKELY( path_sz<0 || (ulong)path_sz>=sizeof(devices_path) ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }

  DIR * devices = opendir( devices_path );
  if( FD_UNLIKELY( !devices ) ) return -1;

  ulong device_cnt = 0UL;
  ulong match_cnt  = 0UL;
  int err = 0;
  for(;;) {
    errno = 0;
    struct dirent * entry = readdir( devices );
    if( !entry ) {
      err = errno;
      break;
    }
    if( entry->d_name[0]=='.' ) continue;
    device_cnt++;
    match_cnt += (ulong)!strcmp( entry->d_name, pci_addr );
  }
  if( FD_UNLIKELY( closedir( devices ) && !err ) ) err = errno;
  if( FD_UNLIKELY( err ) ) {
    errno = err;
    return -1;
  }
  if( FD_UNLIKELY( device_cnt!=1UL || match_cnt!=1UL ) ) {
    errno = EBUSY;
    return -1;
  }
  return 0;
}

int
fd_iavf_hw_pci_probe( fd_iavf_hw_pci_info_t * info,
                      char const *            pci_addr ) {
  if( FD_UNLIKELY( !info ) ) {
    errno = EINVAL;
    return -1;
  }
  fd_memset( info, 0, sizeof(*info) );

  fd_iavf_hw_pci_info_t probed[1];
  fd_memset( probed, 0, sizeof(probed) );
  if( FD_UNLIKELY( fd_iavf_pci_addr_normalize( probed->pci_addr, pci_addr ) ) ) return -1;

  char device_path[ PATH_MAX ];
  if( FD_UNLIKELY( fd_iavf_path_join( device_path, FD_IAVF_PCI_SYSFS, probed->pci_addr ) ) ) return -1;

  struct stat device_stat;
  if( FD_UNLIKELY( stat( device_path, &device_stat ) ) ) return -1;
  if( FD_UNLIKELY( !S_ISDIR( device_stat.st_mode ) ) ) {
    errno = ENODEV;
    return -1;
  }

  char path[ PATH_MAX ];
  ulong value;
  if( FD_UNLIKELY( fd_iavf_path_join( path, device_path, "vendor" ) ||
                   fd_iavf_read_ulong( path, 0, &value ) ) ) return -1;
  if( FD_UNLIKELY( value!=0x8086UL ) ) {
    errno = ENODEV;
    return -1;
  }

  if( FD_UNLIKELY( fd_iavf_path_join( path, device_path, "class" ) ||
                   fd_iavf_read_ulong( path, 0, &value ) ) ) return -1;
  if( FD_UNLIKELY( value!=0x020000UL ) ) {
    errno = ENODEV;
    return -1;
  }

  if( FD_UNLIKELY( fd_iavf_path_join( path, device_path, "device" ) ||
                   fd_iavf_read_ulong( path, 0, &value ) ) ) return -1;
  if( FD_UNLIKELY( value>USHRT_MAX ) ) {
    errno = EPROTO;
    return -1;
  }
  probed->device_id = (ushort)value;
  if( FD_UNLIKELY( !fd_iavf_hw_device_supported( probed->device_id ) ) ) {
    errno = ENODEV;
    return -1;
  }

  char pf_addr[ FD_IAVF_PCI_ADDR_SZ ];
  if( FD_UNLIKELY( fd_iavf_path_join( path, device_path, "physfn" ) ||
                   fd_iavf_read_link_name( pf_addr, sizeof(pf_addr), path, 0 ) ||
                   fd_iavf_pci_addr_normalize( probed->pf_pci_addr, pf_addr ) ) ) {
    if( errno==ENOENT ) errno = ENODEV;
    return -1;
  }

  char iommu_group_name[ 32 ];
  if( FD_UNLIKELY( fd_iavf_path_join( path, device_path, "iommu_group" ) ||
                   fd_iavf_read_link_name( iommu_group_name, sizeof(iommu_group_name), path, 0 ) ) ) return -1;
  errno = 0;
  char * end;
  ulong iommu_group = strtoul( iommu_group_name, &end, 10 );
  if( FD_UNLIKELY( errno || *end || iommu_group>UINT_MAX ) ) {
    if( !errno ) errno = EPROTO;
    return -1;
  }
  probed->iommu_group = (uint)iommu_group;
  if( FD_UNLIKELY( fd_iavf_iommu_group_check( probed->pci_addr, probed->iommu_group ) ) ) return -1;

  if( FD_UNLIKELY( fd_iavf_path_join( path, device_path, "driver" ) ||
                   fd_iavf_read_link_name( probed->driver, sizeof(probed->driver), path, 1 ) ) ) return -1;

  *info = *probed;
  return 0;
}

static void
fd_iavf_hw_vfio_cleanup( fd_iavf_hw_vfio_t * vfio,
                         int                  container_set ) {
  if( vfio->bar0 ) munmap( (void *)vfio->bar0, FD_IAVF_HW_BAR0_MAP_SZ );
  if( vfio->device_fd>=0 ) close( vfio->device_fd );
  if( container_set && vfio->group_fd>=0 ) ioctl( vfio->group_fd, VFIO_GROUP_UNSET_CONTAINER );
  if( vfio->group_fd>=0 )     close( vfio->group_fd );
  if( vfio->container_fd>=0 ) close( vfio->container_fd );
  vfio->bar0         = NULL;
  vfio->device_fd    = -1;
  vfio->group_fd     = -1;
  vfio->container_fd = -1;
}

static int
fd_iavf_hw_wait_reset( fd_iavf_hw_vfio_t * vfio ) {
  volatile uint const * reset_reg = (volatile uint const *)(vfio->bar0 + FD_IAVF_HW_VFGEN_RSTAT);
  struct timespec delay = { .tv_sec=0L, .tv_nsec=1000000L };
  for( ulong retry=0UL; retry<10000UL; retry++ ) {
    uint reset_state = *reset_reg & FD_IAVF_HW_VFGEN_RSTAT_STATE;
    if( reset_state==FD_IAVF_HW_VFR_STATE_COMPLETED ||
        reset_state==FD_IAVF_HW_VFR_STATE_ACTIVE ) {
      vfio->reset_state = reset_state;
      return 0;
    }
    if( FD_UNLIKELY( nanosleep( &delay, NULL ) && errno!=EINTR ) ) return -1;
  }
  errno = ETIMEDOUT;
  return -1;
}

static int
fd_iavf_hw_enable_pci( fd_iavf_hw_vfio_t * vfio ) {
  struct vfio_region_info config = {
    .argsz = sizeof(config),
    .index = VFIO_PCI_CONFIG_REGION_INDEX
  };
  if( FD_UNLIKELY( ioctl( vfio->device_fd, VFIO_DEVICE_GET_REGION_INFO, &config ) ) ) return -1;
  if( FD_UNLIKELY( config.size<PCI_COMMAND+sizeof(ushort) || config.offset>(ulong)LLONG_MAX-PCI_COMMAND ) ) {
    errno = EPROTO;
    return -1;
  }

  off_t command_off = (off_t)(config.offset+PCI_COMMAND);
  ushort command;
  errno = 0;
  if( FD_UNLIKELY( pread( vfio->device_fd, &command, sizeof(command), command_off )!=(ssize_t)sizeof(command) ) ) {
    if( !errno ) errno = EIO;
    return -1;
  }
  command = (ushort)(command | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
  errno = 0;
  if( FD_UNLIKELY( pwrite( vfio->device_fd, &command, sizeof(command), command_off )!=(ssize_t)sizeof(command) ) ) {
    if( !errno ) errno = EIO;
    return -1;
  }
  ushort enabled;
  errno = 0;
  if( FD_UNLIKELY( pread( vfio->device_fd, &enabled, sizeof(enabled), command_off )!=(ssize_t)sizeof(enabled) ) ) {
    if( !errno ) errno = EIO;
    return -1;
  }
  if( FD_UNLIKELY( (enabled & (PCI_COMMAND_MEMORY|PCI_COMMAND_MASTER))!=(PCI_COMMAND_MEMORY|PCI_COMMAND_MASTER) ) ) {
    errno = EIO;
    return -1;
  }
  return 0;
}

int
fd_iavf_hw_init_vfio( fd_iavf_hw_vfio_t *          vfio,
                      fd_iavf_hw_pci_info_t const * info ) {
  if( FD_UNLIKELY( !vfio || !info || strcmp( info->driver, "vfio-pci" ) ) ) {
    errno = EINVAL;
    return -1;
  }

  *vfio = (fd_iavf_hw_vfio_t) {
    .container_fd = -1,
    .group_fd     = -1,
    .device_fd    = -1
  };
  int container_set = 0;

  vfio->container_fd = open( "/dev/vfio/vfio", O_RDWR|O_CLOEXEC );
  if( FD_UNLIKELY( vfio->container_fd<0 ) ) goto fail;
  int api_version = ioctl( vfio->container_fd, VFIO_GET_API_VERSION );
  if( FD_UNLIKELY( api_version<0 ) ) goto fail;
  if( FD_UNLIKELY( api_version!=VFIO_API_VERSION ) ) {
    errno = EPROTONOSUPPORT;
    goto fail;
  }
  int type1v2_supported = ioctl( vfio->container_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1v2_IOMMU );
  if( FD_UNLIKELY( type1v2_supported<0 ) ) goto fail;
  if( FD_UNLIKELY( !type1v2_supported ) ) {
    errno = EPROTONOSUPPORT;
    goto fail;
  }

  char group_path[ 64 ];
  int group_path_sz = snprintf( group_path, sizeof(group_path), "/dev/vfio/%u", info->iommu_group );
  if( FD_UNLIKELY( group_path_sz<0 || (ulong)group_path_sz>=sizeof(group_path) ) ) {
    errno = ENAMETOOLONG;
    goto fail;
  }
  vfio->group_fd = open( group_path, O_RDWR|O_CLOEXEC );
  if( FD_UNLIKELY( vfio->group_fd<0 ) ) goto fail;

  struct vfio_group_status group_status = { .argsz=sizeof(group_status) };
  if( FD_UNLIKELY( ioctl( vfio->group_fd, VFIO_GROUP_GET_STATUS, &group_status ) ) ) goto fail;
  if( FD_UNLIKELY( !(group_status.flags & VFIO_GROUP_FLAGS_VIABLE) ) ) {
    errno = EBUSY;
    goto fail;
  }
  if( FD_UNLIKELY( group_status.flags & VFIO_GROUP_FLAGS_CONTAINER_SET ) ) {
    errno = EBUSY;
    goto fail;
  }
  if( FD_UNLIKELY( ioctl( vfio->group_fd, VFIO_GROUP_SET_CONTAINER, &vfio->container_fd ) ) ) goto fail;
  container_set = 1;
  if( FD_UNLIKELY( ioctl( vfio->container_fd, VFIO_SET_IOMMU, VFIO_TYPE1v2_IOMMU ) ) ) goto fail;

  struct vfio_iommu_type1_info iommu_info = { .argsz=sizeof(iommu_info) };
  if( FD_UNLIKELY( ioctl( vfio->container_fd, VFIO_IOMMU_GET_INFO, &iommu_info ) ) ) goto fail;
  if( FD_UNLIKELY( !(iommu_info.flags & VFIO_IOMMU_INFO_PGSIZES) || !iommu_info.iova_pgsizes ) ) {
    errno = EPROTO;
    goto fail;
  }
  vfio->iova_pgsizes = (ulong)iommu_info.iova_pgsizes;

  vfio->device_fd = ioctl( vfio->group_fd, VFIO_GROUP_GET_DEVICE_FD, info->pci_addr );
  if( FD_UNLIKELY( vfio->device_fd<0 ) ) goto fail;

  struct vfio_device_info device_info = { .argsz=sizeof(device_info) };
  if( FD_UNLIKELY( ioctl( vfio->device_fd, VFIO_DEVICE_GET_INFO, &device_info ) ) ) goto fail;
  if( FD_UNLIKELY( !(device_info.flags & VFIO_DEVICE_FLAGS_PCI) ||
                    !(device_info.flags & VFIO_DEVICE_FLAGS_RESET) ) ) {
    errno = EOPNOTSUPP;
    goto fail;
  }
  if( FD_UNLIKELY( device_info.num_regions<=VFIO_PCI_BAR0_REGION_INDEX ) ) {
    errno = EPROTO;
    goto fail;
  }

  struct vfio_region_info bar0 = {
    .argsz = sizeof(bar0),
    .index = VFIO_PCI_BAR0_REGION_INDEX
  };
  if( FD_UNLIKELY( ioctl( vfio->device_fd, VFIO_DEVICE_GET_REGION_INFO, &bar0 ) ) ) goto fail;
  if( FD_UNLIKELY( bar0.size<FD_IAVF_HW_BAR0_MAP_SZ ||
                    !(bar0.flags & VFIO_REGION_INFO_FLAG_READ) ||
                    !(bar0.flags & VFIO_REGION_INFO_FLAG_WRITE) ||
                    !(bar0.flags & VFIO_REGION_INFO_FLAG_MMAP) ) ) {
    errno = EOPNOTSUPP;
    goto fail;
  }

  void * bar0_map = mmap( NULL, FD_IAVF_HW_BAR0_MAP_SZ, PROT_READ|PROT_WRITE,
                          MAP_SHARED, vfio->device_fd, (off_t)bar0.offset );
  if( FD_UNLIKELY( bar0_map==MAP_FAILED ) ) goto fail;
  vfio->bar0    = (volatile uchar *)bar0_map;
  vfio->bar0_sz = (ulong)bar0.size;

  if( FD_UNLIKELY( ioctl( vfio->device_fd, VFIO_DEVICE_RESET ) ) ) goto fail;
  if( FD_UNLIKELY( fd_iavf_hw_wait_reset( vfio ) ) ) goto fail;
  if( FD_UNLIKELY( fd_iavf_hw_enable_pci( vfio ) ) ) goto fail;
  return 0;

fail:
  {
    int err = errno;
    fd_iavf_hw_vfio_cleanup( vfio, container_set );
    errno = err;
    return -1;
  }
}

int
fd_iavf_hw_dma_map( fd_iavf_hw_vfio_t * vfio,
                    void *               memory,
                    ulong                memory_sz,
                    ulong                iova ) {
  if( FD_UNLIKELY( !vfio || vfio->container_fd<0 || !memory || !memory_sz || !vfio->iova_pgsizes ) ) {
    errno = EINVAL;
    return -1;
  }

  ulong page_sz = vfio->iova_pgsizes & -vfio->iova_pgsizes;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)memory, page_sz ) ||
                   !fd_ulong_is_aligned( memory_sz,     page_sz ) ||
                   !fd_ulong_is_aligned( iova,          page_sz ) ||
                   (ulong)memory>ULONG_MAX-memory_sz ||
                   memory_sz>ULONG_MAX-iova ) ) {
    errno = EINVAL;
    return -1;
  }

  struct vfio_iommu_type1_dma_map dma_map = {
    .argsz = sizeof(dma_map),
    .flags = VFIO_DMA_MAP_FLAG_READ|VFIO_DMA_MAP_FLAG_WRITE,
    .vaddr = (ulong)memory,
    .iova  = iova,
    .size  = memory_sz
  };
  return ioctl( vfio->container_fd, VFIO_IOMMU_MAP_DMA, &dma_map );
}

static inline uint
fd_iavf_hw_mmio_read( fd_iavf_hw_vfio_t const * vfio,
                      ulong                      reg ) {
  volatile uint const * ptr = (volatile uint const *)(vfio->bar0 + reg);
  uint value = *ptr;
  FD_COMPILER_MFENCE();
  return value;
}

static inline void
fd_iavf_hw_mmio_write( fd_iavf_hw_vfio_t * vfio,
                       ulong                reg,
                       uint                 value ) {
  FD_COMPILER_MFENCE();
  volatile uint * ptr = (volatile uint *)(vfio->bar0 + reg);
  *ptr = value;
  FD_COMPILER_MFENCE();
}

static inline void
fd_iavf_hw_dma_to_device( void ) {
#if FD_HAS_X86
  FD_COMPILER_MFENCE();
#elif FD_HAS_ARM
  __asm__ __volatile__( "dmb oshst" ::: "memory" );
#else
  FD_HW_MFENCE_ST();
#endif
}

static inline void
fd_iavf_hw_dma_from_device( void ) {
#if FD_HAS_X86
  __asm__ __volatile__( "lfence" ::: "memory" );
#elif FD_HAS_ARM
  __asm__ __volatile__( "dmb oshld" ::: "memory" );
#else
  FD_HW_MFENCE();
#endif
}

void
fd_iavf_hw_adminq_regs( fd_iavf_hw_vfio_t const * vfio,
                        fd_iavf_hw_adminq_regs_t * regs ) {
  regs->atq_head = fd_iavf_hw_mmio_read( vfio, FD_IAVF_HW_VF_ATQH   );
  regs->atq_tail = fd_iavf_hw_mmio_read( vfio, FD_IAVF_HW_VF_ATQT   );
  regs->atq_len  = fd_iavf_hw_mmio_read( vfio, FD_IAVF_HW_VF_ATQLEN );
  regs->arq_head = fd_iavf_hw_mmio_read( vfio, FD_IAVF_HW_VF_ARQH   );
  regs->arq_tail = fd_iavf_hw_mmio_read( vfio, FD_IAVF_HW_VF_ARQT   );
  regs->arq_len  = fd_iavf_hw_mmio_read( vfio, FD_IAVF_HW_VF_ARQLEN );
}

static inline fd_iavf_hw_aq_desc_t *
fd_iavf_hw_atq_desc( fd_iavf_hw_adminq_t * adminq,
                     uint                    idx ) {
  return (fd_iavf_hw_aq_desc_t *)((uchar *)adminq->dma_memory + FD_IAVF_HW_ADMINQ_DESC_OFF) + idx;
}

static inline fd_iavf_hw_aq_desc_t *
fd_iavf_hw_arq_desc( fd_iavf_hw_adminq_t * adminq,
                     uint                    idx ) {
  return (fd_iavf_hw_aq_desc_t *)((uchar *)adminq->dma_memory + FD_IAVF_HW_ADMINQ_RECV_OFF) + idx;
}

static inline uchar *
fd_iavf_hw_atq_buf( fd_iavf_hw_adminq_t * adminq,
                    uint                    idx ) {
  return (uchar *)adminq->dma_memory + FD_IAVF_HW_ADMINQ_SEND_BUF_OFF + (ulong)idx*FD_IAVF_HW_ADMINQ_BUF_SZ;
}

static inline uchar *
fd_iavf_hw_arq_buf( fd_iavf_hw_adminq_t * adminq,
                    uint                    idx ) {
  return (uchar *)adminq->dma_memory + FD_IAVF_HW_ADMINQ_RECV_BUF_OFF + (ulong)idx*FD_IAVF_HW_ADMINQ_BUF_SZ;
}

static inline ulong
fd_iavf_hw_atq_buf_iova( fd_iavf_hw_adminq_t const * adminq,
                         uint                         idx ) {
  return adminq->dma_iova + FD_IAVF_HW_ADMINQ_SEND_BUF_OFF + (ulong)idx*FD_IAVF_HW_ADMINQ_BUF_SZ;
}

static inline ulong
fd_iavf_hw_arq_buf_iova( fd_iavf_hw_adminq_t const * adminq,
                         uint                         idx ) {
  return adminq->dma_iova + FD_IAVF_HW_ADMINQ_RECV_BUF_OFF + (ulong)idx*FD_IAVF_HW_ADMINQ_BUF_SZ;
}

static inline void
fd_iavf_hw_aq_desc_set_addr( fd_iavf_hw_aq_desc_t * desc,
                             ulong                    iova ) {
  desc->addr_high = (uint)(iova>>32);
  desc->addr_low  = (uint)iova;
}

static void
fd_iavf_hw_arq_post( fd_iavf_hw_adminq_t * adminq,
                     uint                    idx ) {
  fd_iavf_hw_aq_desc_t * desc = fd_iavf_hw_arq_desc( adminq, idx );
  fd_memset( desc, 0, sizeof(*desc) );
  desc->flags   = FD_IAVF_HW_AQ_FLAG_BUF|FD_IAVF_HW_AQ_FLAG_LB;
  desc->datalen = FD_IAVF_HW_ADMINQ_BUF_SZ;
  fd_iavf_hw_aq_desc_set_addr( desc, fd_iavf_hw_arq_buf_iova( adminq, idx ) );
}

ulong
fd_iavf_hw_adminq_footprint( void ) {
  return FD_IAVF_HW_ADMINQ_FOOTPRINT;
}

int
fd_iavf_hw_init_adminq( fd_iavf_hw_vfio_t *  vfio,
                        fd_iavf_hw_adminq_t * adminq,
                        void *                dma_memory,
                        ulong                 dma_memory_sz,
                        ulong                 dma_iova ) {
  if( FD_UNLIKELY( !vfio || !vfio->bar0 || !adminq || !dma_memory ||
                   dma_memory_sz<FD_IAVF_HW_ADMINQ_FOOTPRINT ||
                   !fd_ulong_is_aligned( (ulong)dma_memory, 4096UL ) ||
                   !fd_ulong_is_aligned( dma_iova,          4096UL ) ||
                   !(vfio->iova_pgsizes & 4096UL) ) ) {
    errno = EINVAL;
    return -1;
  }

  fd_memset( dma_memory, 0, FD_IAVF_HW_ADMINQ_FOOTPRINT );
  if( FD_UNLIKELY( fd_iavf_hw_dma_map( vfio, dma_memory, FD_IAVF_HW_ADMINQ_FOOTPRINT, dma_iova ) ) ) return -1;

  *adminq = (fd_iavf_hw_adminq_t) {
    .dma_memory    = dma_memory,
    .dma_memory_sz = FD_IAVF_HW_ADMINQ_FOOTPRINT,
    .dma_iova      = dma_iova
  };
  for( uint idx=0U; idx<(uint)FD_IAVF_HW_ADMINQ_DEPTH; idx++ ) fd_iavf_hw_arq_post( adminq, idx );
  fd_iavf_hw_dma_to_device();

  ulong atq_iova = dma_iova + FD_IAVF_HW_ADMINQ_DESC_OFF;
  fd_iavf_hw_mmio_write( vfio, FD_IAVF_HW_VF_ATQH,   0U );
  fd_iavf_hw_mmio_write( vfio, FD_IAVF_HW_VF_ATQT,   0U );
  fd_iavf_hw_mmio_write( vfio, FD_IAVF_HW_VF_ATQLEN, (uint)FD_IAVF_HW_ADMINQ_DEPTH|FD_IAVF_HW_AQ_ENABLE );
  fd_iavf_hw_mmio_write( vfio, FD_IAVF_HW_VF_ATQBAL, (uint)atq_iova );
  fd_iavf_hw_mmio_write( vfio, FD_IAVF_HW_VF_ATQBAH, (uint)(atq_iova>>32) );

  ulong arq_iova = dma_iova + FD_IAVF_HW_ADMINQ_RECV_OFF;
  fd_iavf_hw_mmio_write( vfio, FD_IAVF_HW_VF_ARQH,   0U );
  fd_iavf_hw_mmio_write( vfio, FD_IAVF_HW_VF_ARQT,   0U );
  fd_iavf_hw_mmio_write( vfio, FD_IAVF_HW_VF_ARQLEN, (uint)FD_IAVF_HW_ADMINQ_DEPTH|FD_IAVF_HW_AQ_ENABLE );
  fd_iavf_hw_mmio_write( vfio, FD_IAVF_HW_VF_ARQBAL, (uint)arq_iova );
  fd_iavf_hw_mmio_write( vfio, FD_IAVF_HW_VF_ARQBAH, (uint)(arq_iova>>32) );
  fd_iavf_hw_mmio_write( vfio, FD_IAVF_HW_VF_ARQT,   (uint)FD_IAVF_HW_ADMINQ_DEPTH-1U );

  if( FD_UNLIKELY( fd_iavf_hw_mmio_read( vfio, FD_IAVF_HW_VF_ATQBAL )!=(uint)atq_iova ||
                   fd_iavf_hw_mmio_read( vfio, FD_IAVF_HW_VF_ATQBAH )!=(uint)(atq_iova>>32) ||
                   fd_iavf_hw_mmio_read( vfio, FD_IAVF_HW_VF_ARQBAL )!=(uint)arq_iova ||
                   fd_iavf_hw_mmio_read( vfio, FD_IAVF_HW_VF_ARQBAH )!=(uint)(arq_iova>>32) ||
                   fd_iavf_hw_mmio_read( vfio, FD_IAVF_HW_VF_ATQLEN )!=((uint)FD_IAVF_HW_ADMINQ_DEPTH|FD_IAVF_HW_AQ_ENABLE) ||
                   fd_iavf_hw_mmio_read( vfio, FD_IAVF_HW_VF_ARQLEN )!=((uint)FD_IAVF_HW_ADMINQ_DEPTH|FD_IAVF_HW_AQ_ENABLE) ) ) {
    errno = EIO;
    return -1;
  }
  return 0;
}

static int
fd_iavf_hw_atq_send( fd_iavf_hw_vfio_t *  vfio,
                     fd_iavf_hw_adminq_t * adminq,
                     uint                    virtchnl_op,
                     void const *            message,
                     ulong                   message_sz ) {
  if( FD_UNLIKELY( (!message && message_sz) || message_sz>FD_IAVF_HW_ADMINQ_BUF_SZ ) ) {
    errno = EINVAL;
    return -1;
  }

  uint idx  = adminq->atq_prod;
  uint next = (idx+1U) & ((uint)FD_IAVF_HW_ADMINQ_DEPTH-1U);
  fd_iavf_hw_aq_desc_t * desc = fd_iavf_hw_atq_desc( adminq, idx );
  fd_memset( desc, 0, sizeof(*desc) );
  desc->flags       = FD_IAVF_HW_AQ_FLAG_SI;
  desc->opcode      = FD_IAVF_HW_AQ_SEND_MSG_TO_PF;
  desc->cookie_high = virtchnl_op;
  if( message_sz ) {
    fd_memcpy( fd_iavf_hw_atq_buf( adminq, idx ), message, message_sz );
    desc->flags   |= FD_IAVF_HW_AQ_FLAG_BUF|FD_IAVF_HW_AQ_FLAG_RD;
    desc->datalen  = (ushort)message_sz;
    fd_iavf_hw_aq_desc_set_addr( desc, fd_iavf_hw_atq_buf_iova( adminq, idx ) );
  }
  fd_iavf_hw_dma_to_device();
  adminq->atq_prod = next;
  fd_iavf_hw_mmio_write( vfio, FD_IAVF_HW_VF_ATQT, next );

  struct timespec delay = { .tv_sec=0L, .tv_nsec=1000000L };
  for( ulong retry=0UL; retry<2000UL; retry++ ) {
    if( (fd_iavf_hw_mmio_read( vfio, FD_IAVF_HW_VF_ATQH ) & FD_IAVF_HW_AQ_HEAD)==next ) {
      fd_iavf_hw_dma_from_device();
      if( FD_UNLIKELY( (desc->flags & FD_IAVF_HW_AQ_FLAG_ERR) || desc->retval ) ) {
        errno = EIO;
        return -1;
      }
      return 0;
    }
    if( FD_UNLIKELY( nanosleep( &delay, NULL ) && errno!=EINTR ) ) return -1;
  }
  errno = ETIMEDOUT;
  return -1;
}

static int
fd_iavf_hw_arq_recv( fd_iavf_hw_vfio_t *  vfio,
                     fd_iavf_hw_adminq_t * adminq,
                     uint *                  virtchnl_op,
                     int *                   virtchnl_status,
                     void *                  message,
                     ulong *                 message_sz ) {
  uint head = fd_iavf_hw_mmio_read( vfio, FD_IAVF_HW_VF_ARQH ) & FD_IAVF_HW_AQ_HEAD;
  uint idx  = adminq->arq_cons;
  if( head==idx ) return 0;

  fd_iavf_hw_dma_from_device();
  fd_iavf_hw_aq_desc_t * desc = fd_iavf_hw_arq_desc( adminq, idx );
  fd_iavf_hw_aq_desc_t completed = *desc;
  ulong completed_sz = completed.datalen;
  int err = 0;
  if( FD_UNLIKELY( completed.opcode!=FD_IAVF_HW_AQ_SEND_MSG_TO_VF ||
                   (completed.flags & FD_IAVF_HW_AQ_FLAG_ERR) || completed.retval ) ) err = EIO;
  else if( FD_UNLIKELY( completed_sz>*message_sz || completed_sz>FD_IAVF_HW_ADMINQ_BUF_SZ ) ) err = EMSGSIZE;
  else if( completed_sz ) fd_memcpy( message, fd_iavf_hw_arq_buf( adminq, idx ), completed_sz );

  fd_iavf_hw_arq_post( adminq, idx );
  fd_iavf_hw_dma_to_device();
  fd_iavf_hw_mmio_write( vfio, FD_IAVF_HW_VF_ARQT, idx );
  adminq->arq_cons = (idx+1U) & ((uint)FD_IAVF_HW_ADMINQ_DEPTH-1U);

  if( FD_UNLIKELY( err ) ) {
    errno = err;
    return -1;
  }
  *virtchnl_op     = completed.cookie_high;
  *virtchnl_status = (int)completed.cookie_low;
  *message_sz      = completed_sz;
  return 1;
}

static int
fd_iavf_hw_virtchnl_request( fd_iavf_hw_vfio_t *  vfio,
                             fd_iavf_hw_adminq_t * adminq,
                             uint                    virtchnl_op,
                             void const *            request,
                             ulong                   request_sz,
                             void *                  response,
                             ulong *                 response_sz ) {
  if( FD_UNLIKELY( !response_sz || (!response && *response_sz) ) ) {
    errno = EINVAL;
    return -1;
  }
  ulong response_capacity = *response_sz;
  *response_sz = 0UL;
  if( FD_UNLIKELY( fd_iavf_hw_atq_send( vfio, adminq, virtchnl_op, request, request_sz ) ) ) return -1;

  struct timespec delay = { .tv_sec=0L, .tv_nsec=1000000L };
  for( ulong retry=0UL; retry<2000UL; retry++ ) {
    uchar message[ FD_IAVF_HW_ADMINQ_BUF_SZ ];
    ulong message_sz = sizeof(message);
    uint received_op;
    int received_status;
    int received = fd_iavf_hw_arq_recv( vfio, adminq, &received_op, &received_status,
                                        message, &message_sz );
    if( FD_UNLIKELY( received<0 ) ) return -1;
    if( !received ) {
      if( FD_UNLIKELY( nanosleep( &delay, NULL ) && errno!=EINTR ) ) return -1;
      continue;
    }
    adminq->last_operation = received_op;
    adminq->last_status    = received_status;
    if( received_op==FD_IAVF_HW_VIRTCHNL_EVENT ) {
      if( FD_UNLIKELY( message_sz!=sizeof(adminq->pending_event) ) ) {
        errno = EPROTO;
        return -1;
      }
      fd_memcpy( adminq->pending_event, message, message_sz );
      adminq->pending_event_sz = message_sz;
      continue;
    }
    if( FD_UNLIKELY( received_op!=virtchnl_op ) ) {
      errno = EPROTO;
      return -1;
    }
    if( FD_UNLIKELY( received_status ) ) {
      errno = EIO;
      return -1;
    }
    if( FD_UNLIKELY( message_sz>response_capacity ) ) {
      errno = EMSGSIZE;
      return -1;
    }
    if( message_sz ) fd_memcpy( response, message, message_sz );
    *response_sz = message_sz;
    return 0;
  }
  errno = ETIMEDOUT;
  return -1;
}

int
fd_iavf_hw_virtchnl_version( fd_iavf_hw_vfio_t *  vfio,
                            fd_iavf_hw_adminq_t * adminq ) {
  fd_iavf_hw_virtchnl_version_t requested = { .major=1U, .minor=1U };
  fd_iavf_hw_virtchnl_version_t response;
  ulong response_sz = sizeof(response);
  if( FD_UNLIKELY( fd_iavf_hw_virtchnl_request( vfio, adminq, FD_IAVF_HW_VIRTCHNL_VERSION,
                                                &requested, sizeof(requested),
                                                &response, &response_sz ) ) ) return -1;
  if( FD_UNLIKELY( response_sz!=sizeof(response) || response.major!=1U ) ) {
    errno = EPROTONOSUPPORT;
    return -1;
  }
  adminq->version_major = response.major;
  adminq->version_minor = response.minor;
  return 0;
}

static uint
fd_iavf_hw_link_speed_mbps( uint link_speed ) {
  switch( link_speed ) {
  case 1U<<0: return 2500U;
  case 1U<<1: return 100U;
  case 1U<<2: return 1000U;
  case 1U<<3: return 10000U;
  case 1U<<4: return 40000U;
  case 1U<<5: return 20000U;
  case 1U<<6: return 25000U;
  case 1U<<7: return 5000U;
  default:    return 0U;
  }
}

static int
fd_iavf_hw_apply_pending_event( fd_iavf_hw_adminq_t * adminq,
                                fd_iavf_hw_vf_info_t * info ) {
  if( !adminq->pending_event_sz ) return 0;
  if( FD_UNLIKELY( adminq->pending_event_sz!=sizeof(fd_iavf_hw_virtchnl_event_t) ) ) {
    errno = EPROTO;
    return -1;
  }
  fd_iavf_hw_virtchnl_event_t event;
  fd_memcpy( &event, adminq->pending_event, sizeof(event) );
  adminq->pending_event_sz = 0UL;
  if( event.event==1 ) {
    info->link_state_valid = 1;
    info->link_up          = !!event.link_up;
    info->link_speed_mbps  = (info->capability_flags & FD_IAVF_HW_VIRTCHNL_CAP_ADV_LINK_SPEED)
                             ? event.link_speed
                             : fd_iavf_hw_link_speed_mbps( event.link_speed );
    return 0;
  }
  if( FD_UNLIKELY( event.event==2 ) ) {
    errno = ECONNRESET;
    return -1;
  }
  if( FD_UNLIKELY( event.event==3 ) ) {
    errno = ESHUTDOWN;
    return -1;
  }
  return 0;
}

static int
fd_iavf_hw_wait_link_event( fd_iavf_hw_vfio_t *  vfio,
                            fd_iavf_hw_adminq_t * adminq,
                            fd_iavf_hw_vf_info_t * info ) {
  if( FD_UNLIKELY( fd_iavf_hw_apply_pending_event( adminq, info ) ) ) return -1;
  if( info->link_state_valid ) return 0;

  struct timespec delay = { .tv_sec=0L, .tv_nsec=1000000L };
  for( ulong retry=0UL; retry<100UL; retry++ ) {
    uchar message[ FD_IAVF_HW_ADMINQ_BUF_SZ ];
    ulong message_sz = sizeof(message);
    uint virtchnl_op;
    int virtchnl_status;
    int received = fd_iavf_hw_arq_recv( vfio, adminq, &virtchnl_op, &virtchnl_status,
                                        message, &message_sz );
    if( FD_UNLIKELY( received<0 ) ) return -1;
    if( !received ) {
      if( FD_UNLIKELY( nanosleep( &delay, NULL ) && errno!=EINTR ) ) return -1;
      continue;
    }
    if( FD_UNLIKELY( virtchnl_op!=FD_IAVF_HW_VIRTCHNL_EVENT || virtchnl_status ||
                     message_sz!=sizeof(adminq->pending_event) ) ) {
      errno = EPROTO;
      return -1;
    }
    fd_memcpy( adminq->pending_event, message, message_sz );
    adminq->pending_event_sz = message_sz;
    if( FD_UNLIKELY( fd_iavf_hw_apply_pending_event( adminq, info ) ) ) return -1;
    if( info->link_state_valid ) return 0;
  }
  return 0;
}

int
fd_iavf_hw_get_vf_resources( fd_iavf_hw_vfio_t *  vfio,
                             fd_iavf_hw_adminq_t * adminq,
                             fd_iavf_hw_vf_info_t * info ) {
  if( FD_UNLIKELY( !vfio || !adminq || !info || adminq->version_major!=1U ) ) {
    errno = EINVAL;
    return -1;
  }
  fd_memset( info, 0, sizeof(*info) );

  uint requested_caps = FD_IAVF_HW_VIRTCHNL_CAP_L2 |
                        FD_IAVF_HW_VIRTCHNL_CAP_ADV_LINK_SPEED |
                        FD_IAVF_HW_VIRTCHNL_CAP_FDIR_PF;
  uchar response[ FD_IAVF_HW_ADMINQ_BUF_SZ ];
  ulong response_sz = sizeof(response);
  if( FD_UNLIKELY( fd_iavf_hw_virtchnl_request( vfio, adminq, FD_IAVF_HW_VIRTCHNL_GET_VF_RESOURCES,
                                                &requested_caps, sizeof(requested_caps),
                                                response, &response_sz ) ) ) return -1;
  if( FD_UNLIKELY( response_sz<sizeof(fd_iavf_hw_virtchnl_vf_resource_t) ) ) {
    errno = EPROTO;
    return -1;
  }

  fd_iavf_hw_virtchnl_vf_resource_t resources;
  fd_memcpy( &resources, response, sizeof(resources) );
  ulong vsi_capacity = (sizeof(response)-sizeof(resources))/sizeof(fd_iavf_hw_virtchnl_vsi_resource_t);
  ulong expected_sz  = sizeof(resources) + (ulong)resources.num_vsis*sizeof(fd_iavf_hw_virtchnl_vsi_resource_t);
  if( FD_UNLIKELY( !resources.num_vsis || (ulong)resources.num_vsis>vsi_capacity ||
                   response_sz!=expected_sz || !resources.num_queue_pairs ||
                   !(resources.capability_flags & FD_IAVF_HW_VIRTCHNL_CAP_L2) ) ) {
    errno = EPROTO;
    return -1;
  }
  if( FD_UNLIKELY( !(resources.capability_flags & FD_IAVF_HW_VIRTCHNL_CAP_FDIR_PF) ) ) {
    errno = EPROTONOSUPPORT;
    return -1;
  }

  fd_iavf_hw_virtchnl_vsi_resource_t selected = {0};
  ulong selected_cnt = 0UL;
  for( ulong vsi_idx=0UL; vsi_idx<(ulong)resources.num_vsis; vsi_idx++ ) {
    fd_iavf_hw_virtchnl_vsi_resource_t vsi;
    fd_memcpy( &vsi, response+sizeof(resources)+vsi_idx*sizeof(vsi), sizeof(vsi) );
    if( vsi.vsi_type==FD_IAVF_HW_VIRTCHNL_VSI_SRIOV ) {
      selected = vsi;
      selected_cnt++;
    }
  }
  if( FD_UNLIKELY( selected_cnt!=1UL || !selected.num_queue_pairs ||
                   (selected.default_mac_addr[0] & 1U) ) ) {
    errno = EPROTO;
    return -1;
  }
  ulong mac_bits = 0UL;
  fd_memcpy( &mac_bits, selected.default_mac_addr, sizeof(selected.default_mac_addr) );
  if( FD_UNLIKELY( !(mac_bits & 0xffffffffffffUL) ) ) {
    errno = EPROTO;
    return -1;
  }

  info->vsi_id             = selected.vsi_id;
  info->queue_pair_cnt     = fd_ushort_min( resources.num_queue_pairs, selected.num_queue_pairs );
  info->vector_cnt         = resources.max_vectors;
  info->max_mtu            = resources.max_mtu;
  info->capability_flags   = resources.capability_flags;
  fd_memcpy( info->mac_addr, selected.default_mac_addr, sizeof(info->mac_addr) );
  return fd_iavf_hw_wait_link_event( vfio, adminq, info );
}

ulong
fd_iavf_hw_queue_footprint( uint tx_depth,
                            uint rx_depth ) {
  if( FD_UNLIKELY( tx_depth<64U || tx_depth>4096U || !fd_uint_is_pow2( tx_depth ) ||
                   rx_depth<64U || rx_depth>4096U || !fd_uint_is_pow2( rx_depth ) ) ) return 0UL;
  ulong tx_ring_sz = fd_ulong_align_up( (ulong)tx_depth*sizeof(fd_iavf_hw_tx_desc_t), 4096UL );
  ulong rx_ring_sz = fd_ulong_align_up( (ulong)rx_depth*sizeof(fd_iavf_hw_rx_desc_t), 4096UL );
  ulong tx_comp_sz = fd_ulong_align_up( (ulong)tx_depth*sizeof(ulong), 4096UL );
  return tx_ring_sz + rx_ring_sz + tx_comp_sz;
}

int
fd_iavf_hw_init_queue( fd_iavf_hw_vfio_t *          vfio,
                       fd_iavf_hw_adminq_t *         adminq,
                       fd_iavf_hw_vf_info_t const *  info,
                       fd_iavf_hw_queue_t *           queue,
                       void *                         dma_memory,
                       ulong                          dma_memory_sz,
                       ulong                          dma_iova,
                       uint                           tx_depth,
                       uint                           rx_depth,
                       uint                           rx_buffer_sz,
                       uint                           max_frame_sz ) {
  ulong footprint = fd_iavf_hw_queue_footprint( tx_depth, rx_depth );
  if( FD_UNLIKELY( !vfio || !adminq || !info || !queue || !dma_memory || !footprint ||
                   dma_memory_sz<footprint || !fd_ulong_is_aligned( (ulong)dma_memory, 4096UL ) ||
                   !fd_ulong_is_aligned( dma_iova, 4096UL ) || !info->queue_pair_cnt ||
                   info->vector_cnt<2U || !rx_buffer_sz || max_frame_sz>rx_buffer_sz ||
                   max_frame_sz>info->max_mtu ) ) {
    errno = EINVAL;
    return -1;
  }

  fd_memset( dma_memory, 0, footprint );
  if( FD_UNLIKELY( fd_iavf_hw_dma_map( vfio, dma_memory, footprint, dma_iova ) ) ) return -1;
  ulong tx_ring_sz = fd_ulong_align_up( (ulong)tx_depth*sizeof(fd_iavf_hw_tx_desc_t), 4096UL );
  ulong rx_ring_sz = fd_ulong_align_up( (ulong)rx_depth*sizeof(fd_iavf_hw_rx_desc_t), 4096UL );
  *queue = (fd_iavf_hw_queue_t) {
    .dma_memory   = dma_memory,
    .dma_memory_sz= footprint,
    .dma_iova     = dma_iova,
    .tx_ring      = dma_memory,
    .rx_ring      = (uchar *)dma_memory + tx_ring_sz,
    .tx_comp_ring = (ulong *)((uchar *)dma_memory + tx_ring_sz + rx_ring_sz),
    .tx_ring_iova = dma_iova,
    .rx_ring_iova = dma_iova + tx_ring_sz,
    .tx_depth     = tx_depth,
    .rx_depth     = rx_depth,
    .tx_tail      = (volatile uint *)(vfio->bar0 + FD_IAVF_HW_TX_TAIL( 0U )),
    .rx_tail      = (volatile uint *)(vfio->bar0 + FD_IAVF_HW_RX_TAIL( 0U ))
  };

  fd_iavf_hw_virtchnl_queue_config_t config = {
    .vsi_id         = info->vsi_id,
    .queue_pair_cnt = 1U,
    .tx = {
      .vsi_id    = info->vsi_id,
      .queue_id  = 0U,
      .ring_len  = (ushort)tx_depth,
      .ring_iova = queue->tx_ring_iova
    },
    .rx = {
      .vsi_id         = info->vsi_id,
      .queue_id       = 0U,
      .ring_len       = rx_depth,
      .data_buffer_sz = rx_buffer_sz,
      .max_frame_sz   = max_frame_sz,
      .ring_iova      = queue->rx_ring_iova
    }
  };
  ulong response_sz = 0UL;
  if( FD_UNLIKELY( fd_iavf_hw_virtchnl_request( vfio, adminq, FD_IAVF_HW_VIRTCHNL_CONFIG_QUEUES,
                                                &config, sizeof(config), NULL, &response_sz ) ) ) return -1;

  fd_iavf_hw_virtchnl_irq_map_t irq_map = {
    .vector_cnt   = 1U,
    .vsi_id       = info->vsi_id,
    .vector_id    = 1U,
    .rx_queue_map = 1U,
    .tx_queue_map = 1U,
    .rx_itr_idx   = 0U,
    .tx_itr_idx   = 0U
  };
  response_sz = 0UL;
  if( FD_UNLIKELY( fd_iavf_hw_virtchnl_request( vfio, adminq, FD_IAVF_HW_VIRTCHNL_CONFIG_IRQ_MAP,
                                                &irq_map, sizeof(irq_map), NULL, &response_sz ) ) ) return -1;
  return 0;
}

int
fd_iavf_hw_rx_post( fd_iavf_hw_queue_t * queue,
                    ulong                buffer_iova,
                    uint *               desc_idx ) {
  if( FD_UNLIKELY( !queue || !queue->rx_ring || !buffer_iova ||
                   !fd_ulong_is_aligned( buffer_iova, 128UL ) ||
                   queue->rx_prod-queue->rx_cons>=queue->rx_depth-1UL ) ) {
    errno = EINVAL;
    return -1;
  }
  uint idx = (uint)(queue->rx_prod & (queue->rx_depth-1U));
  fd_iavf_hw_rx_desc_t * desc = (fd_iavf_hw_rx_desc_t *)queue->rx_ring + idx;
  desc->qword[0] = buffer_iova;
  desc->qword[1] = 0UL;
  desc->qword[2] = 0UL;
  desc->qword[3] = 0UL;
  queue->rx_prod++;
  if( desc_idx ) *desc_idx = idx;
  return 0;
}

void
fd_iavf_hw_rx_flush( fd_iavf_hw_queue_t * queue ) {
  if( FD_UNLIKELY( queue->rx_posted==queue->rx_prod ) ) return;

  fd_iavf_hw_dma_to_device();
  *queue->rx_tail = (uint)(queue->rx_prod & (queue->rx_depth-1U));
  FD_COMPILER_MFENCE();
  queue->rx_posted = queue->rx_prod;
}

int
fd_iavf_hw_enable_queue( fd_iavf_hw_vfio_t *  vfio,
                         fd_iavf_hw_adminq_t * adminq,
                         fd_iavf_hw_vf_info_t * info,
                         fd_iavf_hw_queue_t *   queue ) {
  if( FD_UNLIKELY( !vfio || !adminq || !info || !queue || queue->enabled || !queue->rx_posted ||
                   queue->rx_posted!=queue->rx_prod ||
                   queue->rx_prod-queue->rx_cons>=queue->rx_depth ) ) {
    errno = EINVAL;
    return -1;
  }
  fd_iavf_hw_virtchnl_queue_select_t select = {
    .vsi_id       = info->vsi_id,
    .rx_queue_map = 1U,
    .tx_queue_map = 1U
  };
  ulong response_sz = 0UL;
  if( FD_UNLIKELY( fd_iavf_hw_virtchnl_request( vfio, adminq, FD_IAVF_HW_VIRTCHNL_ENABLE_QUEUES,
                                                &select, sizeof(select), NULL, &response_sz ) ) ) return -1;
  queue->enabled = 1;
  info->link_state_valid = 0;
  return fd_iavf_hw_wait_link_event( vfio, adminq, info );
}

static int
fd_iavf_hw_fdir_status_errno( int status ) {
  switch( status ) {
  case FD_IAVF_HW_VIRTCHNL_FDIR_NORESOURCE:    return ENOSPC;
  case FD_IAVF_HW_VIRTCHNL_FDIR_RULE_EXIST:    return EEXIST;
  case FD_IAVF_HW_VIRTCHNL_FDIR_RULE_CONFLICT: return EADDRINUSE;
  case FD_IAVF_HW_VIRTCHNL_FDIR_RULE_NONEXIST: return ENOENT;
  case FD_IAVF_HW_VIRTCHNL_FDIR_RULE_INVALID:  return EINVAL;
  case FD_IAVF_HW_VIRTCHNL_FDIR_RULE_TIMEOUT:  return ETIMEDOUT;
  case FD_IAVF_HW_VIRTCHNL_FDIR_QUERY_INVALID: return EINVAL;
  default:                                      return EIO;
  }
}

static int
fd_iavf_hw_add_udp_flow_impl( fd_iavf_hw_vfio_t *          vfio,
                              fd_iavf_hw_adminq_t *         adminq,
                              fd_iavf_hw_vf_info_t const *  info,
                              uint                          dst_ip,
                              ushort                        dst_port,
                              int                           gre ) {
  if( FD_UNLIKELY( !vfio || !adminq || !info || !dst_port ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( !(info->capability_flags & FD_IAVF_HW_VIRTCHNL_CAP_FDIR_PF) ) ) {
    errno = EPROTONOSUPPORT;
    return -1;
  }

  fd_iavf_hw_virtchnl_fdir_add_t request;
  fd_memset( &request, 0, sizeof(request) );
  request.vsi_id = info->vsi_id;

  fd_iavf_hw_virtchnl_proto_hdr_t * eth        = request.rule.protocol_headers.headers;
  fd_iavf_hw_virtchnl_proto_hdr_t * outer_ipv4 = eth+1;
  fd_iavf_hw_virtchnl_proto_hdr_t * ipv4       = gre ? eth+3 : outer_ipv4;
  fd_iavf_hw_virtchnl_proto_hdr_t * udp        = gre ? eth+4 : eth+2;
  request.rule.protocol_headers.count = gre ? 5U : 3U;
  eth->type        = FD_IAVF_HW_VIRTCHNL_PROTO_ETH;
  outer_ipv4->type = FD_IAVF_HW_VIRTCHNL_PROTO_IPV4;
  udp->type        = FD_IAVF_HW_VIRTCHNL_PROTO_UDP;
  if( gre ) {
    outer_ipv4->field_selector = FD_IAVF_HW_VIRTCHNL_IPV4_FIELD_PROTOCOL;
    outer_ipv4->buffer[ FD_IAVF_HW_IPV4_PROTOCOL_OFF ] = FD_IAVF_HW_IP_PROTOCOL_GRE;
    request.rule.protocol_headers.headers[2].type = FD_IAVF_HW_VIRTCHNL_PROTO_GRE;
    ipv4->type = FD_IAVF_HW_VIRTCHNL_PROTO_IPV4;
  }

  ipv4->field_selector = FD_IAVF_HW_VIRTCHNL_IPV4_FIELD_PROTOCOL;
  ipv4->buffer[ FD_IAVF_HW_IPV4_PROTOCOL_OFF ] = FD_IAVF_HW_IP_PROTOCOL_UDP;
  if( dst_ip ) {
    ipv4->field_selector |= FD_IAVF_HW_VIRTCHNL_IPV4_FIELD_DST;
    fd_memcpy( ipv4->buffer+FD_IAVF_HW_IPV4_DST_OFF, &dst_ip, sizeof(dst_ip) );
  }
  udp->field_selector = FD_IAVF_HW_VIRTCHNL_UDP_FIELD_DST_PORT;
  ushort const net_dst_port = fd_ushort_bswap( dst_port );
  fd_memcpy( udp->buffer+FD_IAVF_HW_UDP_DST_PORT_OFF, &net_dst_port, sizeof(net_dst_port) );

  request.rule.action_set.count = 1U;
  request.rule.action_set.actions[0].type = FD_IAVF_HW_VIRTCHNL_ACTION_QUEUE;
  request.rule.action_set.actions[0].config.queue.index = 0U;

  fd_iavf_hw_virtchnl_fdir_add_t response;
  ulong response_sz = sizeof(response);
  adminq->last_fdir_status = -1;
  if( FD_UNLIKELY( fd_iavf_hw_virtchnl_request( vfio, adminq, FD_IAVF_HW_VIRTCHNL_ADD_FDIR_FILTER,
                                                &request, sizeof(request),
                                                &response, &response_sz ) ) ) return -1;
  if( FD_UNLIKELY( response_sz!=sizeof(response) ) ) {
    errno = EPROTO;
    return -1;
  }
  adminq->last_fdir_status = response.status;
  if( FD_UNLIKELY( response.status!=FD_IAVF_HW_VIRTCHNL_FDIR_SUCCESS ) ) {
    errno = fd_iavf_hw_fdir_status_errno( response.status );
    return -1;
  }
  return 0;
}

int
fd_iavf_hw_add_udp_flow( fd_iavf_hw_vfio_t *          vfio,
                         fd_iavf_hw_adminq_t *         adminq,
                         fd_iavf_hw_vf_info_t const *  info,
                         uint                          dst_ip,
                         ushort                        dst_port ) {
  return fd_iavf_hw_add_udp_flow_impl( vfio, adminq, info, dst_ip, dst_port, 0 );
}

int
fd_iavf_hw_add_gre_udp_flow( fd_iavf_hw_vfio_t *          vfio,
                             fd_iavf_hw_adminq_t *         adminq,
                             fd_iavf_hw_vf_info_t const *  info,
                             uint                          inner_dst_ip,
                             ushort                        inner_dst_port ) {
  return fd_iavf_hw_add_udp_flow_impl( vfio, adminq, info, inner_dst_ip, inner_dst_port, 1 );
}

int
fd_iavf_hw_tx_submit( fd_iavf_hw_queue_t * queue,
                      ulong                frame_iova,
                      ulong                frame_sz ) {
  if( FD_UNLIKELY( !queue || !queue->enabled || !frame_iova || frame_sz<14UL ||
                   frame_sz>FD_IAVF_HW_TX_DESC_BUFFER_MAX ||
                   queue->tx_prod-queue->tx_cons>=queue->tx_depth-1UL ) ) {
    errno = EINVAL;
    return -1;
  }
  uint idx = (uint)(queue->tx_prod & (queue->tx_depth-1U));
  fd_iavf_hw_tx_desc_t * desc = (fd_iavf_hw_tx_desc_t *)queue->tx_ring + idx;
  desc->buffer_iova = frame_iova;
  desc->cmd_type_offset_buffer_sz =
      (FD_IAVF_HW_TX_DESC_CMD_EOP<<FD_IAVF_HW_TX_DESC_CMD_SHIFT) |
      (frame_sz<<FD_IAVF_HW_TX_DESC_BUFFER_SHIFT);
  queue->tx_prod++;
  return 0;
}

void
fd_iavf_hw_tx_flush( fd_iavf_hw_queue_t * queue ) {
  if( FD_UNLIKELY( queue->tx_posted==queue->tx_prod ) ) return;

  ulong const tx_end = queue->tx_prod;
  uint const desc_idx = (uint)((tx_end-1UL) & (queue->tx_depth-1U));
  fd_iavf_hw_tx_desc_t * desc = (fd_iavf_hw_tx_desc_t *)queue->tx_ring + desc_idx;
  desc->cmd_type_offset_buffer_sz |= FD_IAVF_HW_TX_DESC_CMD_REPORT_STATUS<<FD_IAVF_HW_TX_DESC_CMD_SHIFT;
  queue->tx_comp_ring[ queue->tx_comp_prod & (queue->tx_depth-1U) ] = tx_end;
  queue->tx_comp_prod++;

  fd_iavf_hw_dma_to_device();
  *queue->tx_tail = (uint)(tx_end & (queue->tx_depth-1U));
  FD_COMPILER_MFENCE();
  queue->tx_posted = tx_end;
}

ulong
fd_iavf_hw_tx_complete( fd_iavf_hw_queue_t * queue ) {
  ulong tx_cons   = queue->tx_cons;
  ulong comp_cons = queue->tx_comp_cons;
  while( comp_cons<queue->tx_comp_prod ) {
    ulong const tx_end = queue->tx_comp_ring[ comp_cons & (queue->tx_depth-1U) ];
    uint const desc_idx = (uint)((tx_end-1UL) & (queue->tx_depth-1U));
    fd_iavf_hw_tx_desc_t * desc = (fd_iavf_hw_tx_desc_t *)queue->tx_ring + desc_idx;
    ulong cmd = FD_VOLATILE_CONST( desc->cmd_type_offset_buffer_sz );
    if( (cmd & 0xfUL)!=FD_IAVF_HW_TX_DESC_DONE ) break;
    tx_cons = tx_end;
    comp_cons++;
  }
  ulong const complete_cnt = tx_cons-queue->tx_cons;
  if( complete_cnt ) {
    fd_iavf_hw_dma_from_device();
    queue->tx_cons      = tx_cons;
    queue->tx_comp_cons = comp_cons;
  }
  return complete_cnt;
}

int
fd_iavf_hw_rx_poll( fd_iavf_hw_queue_t * queue,
                    fd_iavf_hw_rx_comp_t * comp,
                    uint                   comp_capacity ) {
  if( FD_UNLIKELY( !queue || !queue->enabled || !comp || !comp_capacity ) ) {
    errno = EINVAL;
    return -1;
  }
  ulong rx_cons = queue->rx_cons;
  uint const comp_limit = fd_uint_min( comp_capacity, queue->rx_depth );
  uint comp_cnt = 0U;
  while( comp_cnt<comp_limit && rx_cons<queue->rx_posted ) {
    uint const desc_idx = (uint)(rx_cons & (queue->rx_depth-1U));
    fd_iavf_hw_rx_desc_t * desc = (fd_iavf_hw_rx_desc_t *)queue->rx_ring + desc_idx;
    ulong const status = FD_VOLATILE_CONST( desc->qword[1] );
    if( !(status & FD_IAVF_HW_RX_DESC_DONE) ) break;

    uint error_flags = (uint)((status>>FD_IAVF_HW_RX_DESC_ERROR_SHIFT) & FD_IAVF_HW_RX_DESC_ERROR_MASK);
    if( !(status & FD_IAVF_HW_RX_DESC_END_OF_PACKET) ) error_flags |= 1U<<31;
    comp[ comp_cnt++ ] = (fd_iavf_hw_rx_comp_t) {
      .desc_idx    = desc_idx,
      .error_flags = error_flags,
      .frame_sz    = (status>>FD_IAVF_HW_RX_DESC_LENGTH_SHIFT) & FD_IAVF_HW_RX_DESC_LENGTH_MASK
    };
    rx_cons++;
  }
  if( comp_cnt ) {
    fd_iavf_hw_dma_from_device();
    queue->rx_cons = rx_cons;
  }
  return (int)comp_cnt;
}

int
fd_iavf_hw_get_stats( fd_iavf_hw_vfio_t *          vfio,
                      fd_iavf_hw_adminq_t *         adminq,
                      fd_iavf_hw_vf_info_t const *  info,
                      fd_iavf_hw_stats_t *           stats ) {
  if( FD_UNLIKELY( !vfio || !adminq || !info || !stats ) ) {
    errno = EINVAL;
    return -1;
  }
  fd_iavf_hw_virtchnl_queue_select_t select = { .vsi_id=info->vsi_id };
  ulong response_sz = sizeof(*stats);
  if( FD_UNLIKELY( fd_iavf_hw_virtchnl_request( vfio, adminq, FD_IAVF_HW_VIRTCHNL_GET_STATS,
                                                &select, sizeof(select), stats, &response_sz ) ) ) return -1;
  if( FD_UNLIKELY( response_sz!=sizeof(*stats) ) ) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}

int
fd_iavf_hw_poll_link( fd_iavf_hw_vfio_t *  vfio,
                      fd_iavf_hw_adminq_t * adminq,
                      fd_iavf_hw_vf_info_t * info,
                      int *                  changed ) {
  if( FD_UNLIKELY( !vfio || !adminq || !info || !changed ) ) {
    errno = EINVAL;
    return -1;
  }

  int const old_valid = info->link_state_valid;
  int const old_up    = info->link_up;
  uint const old_speed = info->link_speed_mbps;
  if( FD_UNLIKELY( fd_iavf_hw_apply_pending_event( adminq, info ) ) ) return -1;

  for(;;) {
    uchar message[ FD_IAVF_HW_ADMINQ_BUF_SZ ];
    ulong message_sz = sizeof(message);
    uint virtchnl_op;
    int virtchnl_status;
    int const received = fd_iavf_hw_arq_recv( vfio, adminq, &virtchnl_op, &virtchnl_status,
                                              message, &message_sz );
    if( FD_UNLIKELY( received<0 ) ) return -1;
    if( !received ) break;
    if( FD_UNLIKELY( virtchnl_op!=FD_IAVF_HW_VIRTCHNL_EVENT || virtchnl_status ||
                     message_sz!=sizeof(adminq->pending_event) ) ) {
      errno = EPROTO;
      return -1;
    }
    fd_memcpy( adminq->pending_event, message, message_sz );
    adminq->pending_event_sz = message_sz;
    if( FD_UNLIKELY( fd_iavf_hw_apply_pending_event( adminq, info ) ) ) return -1;
  }

  *changed = old_valid!=info->link_state_valid ||
             old_up!=info->link_up ||
             old_speed!=info->link_speed_mbps;
  return 0;
}
