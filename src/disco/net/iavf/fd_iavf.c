#define _GNU_SOURCE /* strcasestr */
#include "fd_iavf_private.h"
#include "../../../util/fd_util.h"
#include "../../../util/net/fd_eth.h"
#include "../fd_linux_bond.h"

#if FD_HAS_X86
#include <cpuid.h>
#include <sys/utsname.h>
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <linux/vfio.h>
#include <linux/pci_regs.h>

#define FD_IAVF_PCI_SYSFS "/sys/bus/pci/devices"

#define FD_IAVF_PCI_RESOURCE_MEM      (0x00000200UL) /* IORESOURCE_MEM */
#define FD_IAVF_PCI_RESOURCE_UNUSABLE (0x30000000UL) /* IORESOURCE_UNSET | IORESOURCE_DISABLED */

/* A VF reset reinitializes the NIC state for one virtual PCI device.
   The PF reports here when the VF is ready for Admin Queue setup. */
#define FD_IAVF_VFGEN_RSTAT         (0x8800UL) /* IAVF_VFGEN_RSTAT */
#define FD_IAVF_VFGEN_RSTAT_STATE   (0x3U)     /* IAVF_VFGEN_RSTAT_VFR_STATE_MASK */
#define FD_IAVF_VFR_STATE_COMPLETED (1U)       /* VIRTCHNL_VFR_COMPLETED */
#define FD_IAVF_VFR_STATE_ACTIVE    (2U)       /* VIRTCHNL_VFR_VFACTIVE */

#define FD_IAVF_VFINT_DYN_CTL        (0x3800UL) /* IAVF_VFINT_DYN_CTLN1(0) */
#define FD_IAVF_VFINT_WB_ON_ITR      (1U<<30)   /* IAVF_VFINT_DYN_CTLN1_WB_ON_ITR_MASK */
#define FD_IAVF_VFINT_INTERVAL_SHIFT (5U)       /* IAVF_VFINT_DYN_CTLN1_INTERVAL_SHIFT */

/* The PF driver controls the VF's packet queues and receive filters.
   Admin Queues carry virtchnl requests to it through ATQ and replies or
   unsolicited events back through ARQ. */
#define FD_IAVF_VF_ARQBAH (0x6000UL) /* IAVF_VF_ARQBAH1 */
#define FD_IAVF_VF_ARQBAL (0x6c00UL) /* IAVF_VF_ARQBAL1 */
#define FD_IAVF_VF_ARQH   (0x7400UL) /* IAVF_VF_ARQH1 */
#define FD_IAVF_VF_ARQLEN (0x8000UL) /* IAVF_VF_ARQLEN1 */
#define FD_IAVF_VF_ARQT   (0x7000UL) /* IAVF_VF_ARQT1 */
#define FD_IAVF_VF_ATQBAH (0x7800UL) /* IAVF_VF_ATQBAH1 */
#define FD_IAVF_VF_ATQBAL (0x7c00UL) /* IAVF_VF_ATQBAL1 */
#define FD_IAVF_VF_ATQH   (0x6400UL) /* IAVF_VF_ATQH1 */
#define FD_IAVF_VF_ATQLEN (0x6800UL) /* IAVF_VF_ATQLEN1 */
#define FD_IAVF_VF_ATQT   (0x8400UL) /* IAVF_VF_ATQT1 */
#define FD_IAVF_ATQ_ENABLE (1U<<31) /* IAVF_VF_ATQLEN1_ATQENABLE_MASK */
#define FD_IAVF_ARQ_ENABLE (1U<<31) /* IAVF_VF_ARQLEN1_ARQENABLE_MASK */
#define FD_IAVF_ATQ_HEAD   (0x3ffU) /* IAVF_VF_ATQH1_ATQH_MASK */
#define FD_IAVF_ARQ_HEAD   (0x3ffU) /* IAVF_VF_ARQH1_ARQH_MASK */

#define FD_IAVF_POLL_INTERVAL_NS (1000000L)
#define FD_IAVF_RESET_RETRY_CNT  (10000UL)
#define FD_IAVF_ADMINQ_RETRY_CNT (2000UL)
#define FD_IAVF_LINK_RETRY_CNT   (100UL)

/* Keep both Admin Queue rings and their message buffers in one DMA mapping.
   Descriptors point to the buffers containing the virtchnl payloads. */
#define FD_IAVF_ADMINQ_DEPTH         (32UL)
#define FD_IAVF_ADMINQ_BUF_SZ        (4096UL)
#define FD_IAVF_AQ_LARGE_BUF         (512UL) /* IAVF_AQ_LARGE_BUF */
#define FD_IAVF_ADMINQ_SEND_DESC_OFF (0UL)
#define FD_IAVF_ADMINQ_RECV_DESC_OFF (4096UL)
#define FD_IAVF_ADMINQ_SEND_BUF_OFF  (8192UL)
#define FD_IAVF_ADMINQ_RECV_BUF_OFF  (FD_IAVF_ADMINQ_SEND_BUF_OFF + FD_IAVF_ADMINQ_DEPTH*FD_IAVF_ADMINQ_BUF_SZ)
#define FD_IAVF_ADMINQ_FOOTPRINT     (FD_IAVF_ADMINQ_RECV_BUF_OFF + FD_IAVF_ADMINQ_DEPTH*FD_IAVF_ADMINQ_BUF_SZ)

/* Linux PF validation requires one padding byte after the RSS key or LUT */
#define FD_IAVF_RSS_KEY_HEADER_SZ (4UL) /* sizeof(struct virtchnl_rss_key) */
#define FD_IAVF_RSS_KEY_LEGACY_SZ (6UL) /* virtchnl_rss_key_LEGACY_SIZEOF */
#define FD_IAVF_RSS_KEY_MAX_SZ    (FD_IAVF_ADMINQ_BUF_SZ-FD_IAVF_RSS_KEY_LEGACY_SZ)
#define FD_IAVF_RSS_LUT_HEADER_SZ (4UL) /* sizeof(struct virtchnl_rss_lut) */
#define FD_IAVF_RSS_LUT_LEGACY_SZ (6UL) /* virtchnl_rss_lut_LEGACY_SIZEOF */
#define FD_IAVF_RSS_LUT_MAX_SZ    (FD_IAVF_ADMINQ_BUF_SZ-FD_IAVF_RSS_LUT_LEGACY_SZ)

#define FD_IAVF_DEVICE_VF          (0x154cU) /* IAVF_DEV_ID_VF */
#define FD_IAVF_DEVICE_VF_HV       (0x1571U) /* IAVF_DEV_ID_VF_HV */
#define FD_IAVF_DEVICE_ADAPTIVE_VF (0x1889U) /* IAVF_DEV_ID_ADAPTIVE_VF */
#define FD_IAVF_DEVICE_X722_VF     (0x37cdU) /* IAVF_DEV_ID_X722_VF */

/* fd_iavf_aq_desc is the Linux libie_aq_desc hardware descriptor. */
struct fd_iavf_aq_desc {
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

typedef struct fd_iavf_aq_desc fd_iavf_aq_desc_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_aq_desc_t)==32UL, iavf_aq_desc_sz );

#define FD_IAVF_AQ_FLAG_ERR (1U<<2)  /* LIBIE_AQ_FLAG_ERR */
#define FD_IAVF_AQ_FLAG_LB  (1U<<9)  /* LIBIE_AQ_FLAG_LB */
#define FD_IAVF_AQ_FLAG_RD  (1U<<10) /* LIBIE_AQ_FLAG_RD */
#define FD_IAVF_AQ_FLAG_BUF (1U<<12) /* LIBIE_AQ_FLAG_BUF */
#define FD_IAVF_AQ_FLAG_SI  (1U<<13) /* LIBIE_AQ_FLAG_SI */

/* Admin Queue opcodes select message transport, cookie_high carries the
   virtchnl operation and cookie_low carries the PF reply status */
#define FD_IAVF_AQ_SEND_MSG_TO_PF         (0x0801U) /* iavf_aqc_opc_send_msg_to_pf */
#define FD_IAVF_AQ_SEND_MSG_TO_VF         (0x0802U) /* iavf_aqc_opc_send_msg_to_vf */
#define FD_IAVF_VIRTCHNL_VERSION          (1U)      /* VIRTCHNL_OP_VERSION */
#define FD_IAVF_VIRTCHNL_GET_VF_RESOURCES (3U)      /* VIRTCHNL_OP_GET_VF_RESOURCES */
#define FD_IAVF_VIRTCHNL_CONFIG_QUEUES    (6U)      /* VIRTCHNL_OP_CONFIG_VSI_QUEUES */
#define FD_IAVF_VIRTCHNL_CONFIG_IRQ_MAP   (7U)      /* VIRTCHNL_OP_CONFIG_IRQ_MAP */
#define FD_IAVF_VIRTCHNL_ENABLE_QUEUES    (8U)      /* VIRTCHNL_OP_ENABLE_QUEUES */
#define FD_IAVF_VIRTCHNL_ADD_ETH_ADDR     (10U)     /* VIRTCHNL_OP_ADD_ETH_ADDR */
#define FD_IAVF_VIRTCHNL_CONFIG_RSS_KEY   (23U)     /* VIRTCHNL_OP_CONFIG_RSS_KEY */
#define FD_IAVF_VIRTCHNL_CONFIG_RSS_LUT   (24U)     /* VIRTCHNL_OP_CONFIG_RSS_LUT */
#define FD_IAVF_VIRTCHNL_EVENT            (17U)     /* VIRTCHNL_OP_EVENT */

#define FD_IAVF_VIRTCHNL_CAP_L2        (1U<<0)  /* VIRTCHNL_VF_OFFLOAD_L2 */
#define FD_IAVF_VIRTCHNL_CAP_WB_ON_ITR (1U<<5)  /* VIRTCHNL_VF_OFFLOAD_WB_ON_ITR */
#define FD_IAVF_VIRTCHNL_CAP_RSS_PF    (1U<<19) /* VIRTCHNL_VF_OFFLOAD_RSS_PF */
#define FD_IAVF_VIRTCHNL_VSI_SRIOV   (6)      /* VIRTCHNL_VSI_SRIOV */
#define FD_IAVF_VIRTCHNL_MAC_PRIMARY (1U)     /* VIRTCHNL_ETHER_ADDR_PRIMARY */

#define FD_IAVF_EVENT_LINK_CHANGE     (1) /* VIRTCHNL_EVENT_LINK_CHANGE */
#define FD_IAVF_EVENT_RESET_IMPENDING (2) /* VIRTCHNL_EVENT_RESET_IMPENDING */
#define FD_IAVF_EVENT_PF_DRIVER_CLOSE (3) /* VIRTCHNL_EVENT_PF_DRIVER_CLOSE */

/* fd_iavf_virtchnl_version is the Linux virtchnl_version_info VF/PF message. */
struct fd_iavf_virtchnl_version {
  uint major;
  uint minor;
};

typedef struct fd_iavf_virtchnl_version fd_iavf_virtchnl_version_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_virtchnl_version_t)==8UL, iavf_virtchnl_version_sz );

/* fd_iavf_virtchnl_vf_resource is the fixed Linux virtchnl_vf_resource header. */
struct fd_iavf_virtchnl_vf_resource {
  ushort num_vsis;
  ushort num_queue_pairs;
  ushort max_vectors;
  ushort max_mtu;
  uint   capability_flags;
  uint   rss_key_sz;
  uint   rss_lut_sz;
};

typedef struct fd_iavf_virtchnl_vf_resource fd_iavf_virtchnl_vf_resource_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_virtchnl_vf_resource_t)==20UL, iavf_virtchnl_vf_resource_sz );

/* fd_iavf_virtchnl_vsi_resource is the Linux virtchnl_vsi_resource VF/PF message entry. */
struct fd_iavf_virtchnl_vsi_resource {
  ushort vsi_id;
  ushort num_queue_pairs;
  int    vsi_type;
  ushort qset_handle;
  uchar  default_mac_addr[ 6 ];
};

typedef struct fd_iavf_virtchnl_vsi_resource fd_iavf_virtchnl_vsi_resource_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_virtchnl_vsi_resource_t)==16UL, iavf_virtchnl_vsi_resource_sz );

/* fd_iavf_virtchnl_event is the Linux virtchnl_pf_event PF-to-VF message. */
struct fd_iavf_virtchnl_event {
  int   event;
  /* Unused, link_up has the same offset in both Linux event formats. */
  uint  link_speed;
  uchar link_up;
  uchar pad[ 3 ];
  int   severity;
};

typedef struct fd_iavf_virtchnl_event fd_iavf_virtchnl_event_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_virtchnl_event_t)==16UL, iavf_virtchnl_event_sz );

/* fd_iavf_virtchnl_txq_info is the Linux virtchnl_txq_info VF/PF message entry. */
struct fd_iavf_virtchnl_txq_info {
  ushort vsi_id;
  ushort queue_id;
  ushort ring_len;
  ushort head_writeback_enabled;
  ulong  ring_iova;
  ulong  head_writeback_iova;
};

typedef struct fd_iavf_virtchnl_txq_info fd_iavf_virtchnl_txq_info_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_virtchnl_txq_info_t)==24UL, iavf_virtchnl_txq_info_sz );

/* fd_iavf_virtchnl_rxq_info is the Linux virtchnl_rxq_info VF/PF message entry. */
struct fd_iavf_virtchnl_rxq_info {
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

typedef struct fd_iavf_virtchnl_rxq_info fd_iavf_virtchnl_rxq_info_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_virtchnl_rxq_info_t)==40UL, iavf_virtchnl_rxq_info_sz );

/* fd_iavf_virtchnl_queue_pair is the Linux virtchnl_queue_pair_info message entry. */
struct fd_iavf_virtchnl_queue_pair {
  fd_iavf_virtchnl_txq_info_t tx;
  fd_iavf_virtchnl_rxq_info_t rx;
};

typedef struct fd_iavf_virtchnl_queue_pair fd_iavf_virtchnl_queue_pair_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_virtchnl_queue_pair_t)==64UL, iavf_virtchnl_queue_pair_sz );

/* fd_iavf_virtchnl_queue_config holds Linux virtchnl_vsi_queue_config_info and its queue pairs. */
struct fd_iavf_virtchnl_queue_config {
  ushort vsi_id;
  ushort queue_pair_cnt;
  uint   pad;
  /* Linux PF message validation requires space for one extra queue pair. */
  fd_iavf_virtchnl_queue_pair_t pairs[ 2 ];
};

typedef struct fd_iavf_virtchnl_queue_config fd_iavf_virtchnl_queue_config_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_virtchnl_queue_config_t)==136UL, iavf_virtchnl_queue_config_sz );

/* fd_iavf_virtchnl_irq_map holds Linux virtchnl_irq_map_info and one virtchnl_vector_map. */
struct fd_iavf_virtchnl_irq_map {
  ushort vector_cnt;
  ushort vsi_id;
  ushort vector_id;
  ushort rx_queue_map;
  ushort tx_queue_map;
  ushort rx_itr_idx;
  ushort tx_itr_idx;
  /* Linux PF message validation requires space for one extra vector map. */
  uchar legacy_padding[ 12 ];
};

typedef struct fd_iavf_virtchnl_irq_map fd_iavf_virtchnl_irq_map_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_virtchnl_irq_map_t)==26UL, iavf_virtchnl_irq_map_sz );

/* fd_iavf_virtchnl_queue_select is the Linux virtchnl_queue_select VF/PF message. */
struct fd_iavf_virtchnl_queue_select {
  ushort vsi_id;
  ushort pad;
  uint   rx_queue_map;
  uint   tx_queue_map;
};

typedef struct fd_iavf_virtchnl_queue_select fd_iavf_virtchnl_queue_select_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_virtchnl_queue_select_t)==12UL, iavf_virtchnl_queue_select_sz );

static int
fd_iavf_device_supported( ushort device_id ) {
  return device_id==FD_IAVF_DEVICE_VF          ||
         device_id==FD_IAVF_DEVICE_VF_HV       ||
         device_id==FD_IAVF_DEVICE_ADAPTIVE_VF ||
         device_id==FD_IAVF_DEVICE_X722_VF;
}

static int
fd_iavf_pci_addr_normalize( char         normalized[ FD_IAVF_PCI_ADDR_SZ ],
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

  ulong slot = strtoul( normalized+8, NULL, 16 );
  if( FD_UNLIKELY( slot>31UL ) ) {
    errno = EINVAL;
    return -1;
  }
  ulong function = strtoul( normalized+11, NULL, 16 );
  if( FD_UNLIKELY( function>7UL ) ) {
    errno = EINVAL;
    return -1;
  }
  return 0;
}

static void
fd_iavf_path_join( char         path[ PATH_MAX ],
                   char const * parent,
                   char const * name ) {
  int path_sz = snprintf( path, PATH_MAX, "%s/%s", parent, name );
  FD_TEST( path_sz>=0 && path_sz<PATH_MAX );
}

static int
fd_iavf_read_ulong( char const * path,
                    int          base,
                    ulong *      value ) {
  int fd = open( path, O_RDONLY|O_CLOEXEC );
  if( FD_UNLIKELY( fd<0 ) ) return -1;

  char buf[ 64 ];
  ssize_t read_sz = read( fd, buf, sizeof(buf)-1UL );
  int     err     = 0;
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
  base              = base ? base+1 : target;
  ulong base_sz     = strlen( base );
  if( FD_UNLIKELY( !base_sz || base_sz>=name_max ) ) {
    errno = EPROTO;
    return -1;
  }
  fd_memcpy( name, base, base_sz+1UL );
  return 0;
}

int
fd_iavf_vfio_avail( void ) {
  struct stat st;
  return !stat( "/sys/bus/pci/drivers/vfio-pci", &st ) && S_ISDIR( st.st_mode );
}

int
fd_iavf_member_interfaces( char const * interface,
                           char         members[ FD_IAVF_MEMBER_MAX ][ IF_NAMESIZE ],
                           ulong *      member_cnt ) {
  if( !interface || !members || !member_cnt || !interface[0] || strlen(interface)>=IF_NAMESIZE ) {
    errno = EINVAL;
    return -1;
  }
  *member_cnt = 0UL;
  /* Find PF interfaces, expanding 802.3ad bonds into their members */
  if( fd_bonding_is_master( interface ) ) {
    if( !fd_bonding_is_lacp( interface ) ) {
      errno = EOPNOTSUPP;
      return -1;
    }
    fd_bonding_slave_iter_t iter[1];
    for( fd_bonding_slave_iter_init( iter, interface );
         !fd_bonding_slave_iter_done( iter );
         fd_bonding_slave_iter_next( iter ) ) {
      char const * name = fd_bonding_slave_iter_ele( iter );
      if( *member_cnt>=FD_IAVF_MEMBER_MAX || strlen(name)>=IF_NAMESIZE ) {
        errno = E2BIG;
        return -1;
      }
      fd_cstr_ncpy( members[ (*member_cnt)++ ], name, IF_NAMESIZE );
    }
  } else {
    fd_cstr_ncpy( members[0], interface, IF_NAMESIZE );
    *member_cnt = 1UL;
  }
  if( !*member_cnt ) {
    errno = ENODEV;
    return -1;
  }
  /* Require ice or i40e on every PF */
  for( ulong i=0UL; i<*member_cnt; i++ ) {
    char path  [ PATH_MAX ];
    char driver[ FD_IAVF_DRIVER_NAME_MAX ];
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/sys/class/net/%s/device/driver", members[i] ) );
    if( fd_iavf_read_link_name( driver, sizeof(driver), path, 0 ) ) return -1;
    if( strcmp(driver,"ice") && strcmp(driver,"i40e") ) {
      errno = EPROTONOSUPPORT;
      return -1;
    }
  }
  return 0;
}

#if FD_HAS_X86
static int
fd_iavf_cpu_vendor( char vendor[ 13 ] ) {
  uint eax, ebx, ecx, edx;
  if( !__get_cpuid( 0U, &eax, &ebx, &ecx, &edx ) ) return 0;

  /* CPUID returns the vendor string in EBX, EDX, ECX order. */
  fd_memcpy( vendor,   &ebx, 4UL );
  fd_memcpy( vendor+4, &edx, 4UL );
  fd_memcpy( vendor+8, &ecx, 4UL );
  vendor[ 12 ] = '\0';
  return 1;
}

/* fd_iavf_cmdline_next splits one boot argument in place using Linux
   lib/cmdline.c next_arg quoting rules. Quotes group whitespace and
   backslashes are literal. Returns the remaining command line, or
   NULL for unclosed quotes. param and value point into cmdline, with
   value set to NULL when the argument has no value. */
static char *
fd_iavf_cmdline_next( char *  cmdline,
                      char ** param,
                      char ** value ) {
  while( fd_isspace( (int)(uchar)*cmdline ) ) cmdline++;
  int quoted = *cmdline=='"';
  char * arg = cmdline+quoted;

  char * equals = NULL;
  char * end    = arg;
  int in_quote  = quoted;
  for( ; *end; end++ ) {
    if( fd_isspace( (int)(uchar)*end ) && !in_quote ) break;
    if( *end=='=' && !equals && end!=arg ) equals = end;
    if( *end=='"' ) in_quote = !in_quote;
  }
  if( in_quote ) return NULL;

  char * next = end;
  if( *next ) *next++ = '\0';
  *param = arg;
  *value = NULL;
  if( equals ) {
    *equals = '\0';
    *value  = equals+1;
    if( **value=='"' ) {
      (*value)++;
      if( end>*value && end[-1]=='"' ) end[-1] = '\0';
    }
  }
  if( quoted && end>arg && end[-1]=='"' ) end[-1] = '\0';
  return next;
}

static int
fd_iavf_intel_iommu_default_off( void ) {
  struct utsname kernel;
  if( uname( &kernel ) ) return 0;

  char config_path[ PATH_MAX ];
  if( !fd_cstr_printf_check( config_path, sizeof(config_path), NULL, "/boot/config-%s", kernel.release ) ) return 0;

  FILE * config_file = fopen( config_path, "r" );
  if( !config_file ) return 0;

  /* Long CONFIG_CMDLINE values can span reads, so only match at line starts. */
  char line[ 256 ];
  int line_start     = 1;
  int driver_enabled = 0;
  int default_off    = 0;
  while( fgets( line, sizeof(line), config_file ) ) {
    if( line_start ) {
      if( !strcmp( line, "CONFIG_INTEL_IOMMU=y\n" ) ) driver_enabled = 1;
      if( !strcmp( line, "# CONFIG_INTEL_IOMMU_DEFAULT_ON is not set\n" ) ) default_off = 1;
    }
    line_start = !!strchr( line, '\n' );
  }

  int read_err  = ferror( config_file );
  int close_err = fclose( config_file );
  return driver_enabled && default_off && !read_err && !close_err;
}
#endif

char const *
fd_iavf_sriov_bios_guide( void ) {
  char const * fallback = "Enable SR-IOV and IOMMU in the system BIOS.\n"
                          "  Set Virtualization Mode to SR-IOV in the NIC's BIOS settings";

#if FD_HAS_X86
  char vendor[ 13 ];
  if( !fd_iavf_cpu_vendor( vendor ) ) return fallback;
  int is_intel = !strcmp( vendor, "GenuineIntel" );
  int is_amd   = !strcmp( vendor, "AuthenticAMD" );
  /* The board vendor can identify Supermicro in systems sold under another brand. */
  char const * const paths[] = {
    "/sys/class/dmi/id/board_vendor",
    "/sys/class/dmi/id/sys_vendor"
  };
  for( ulong i=0UL; i<sizeof(paths)/sizeof(paths[0]); i++ ) {
    int fd = open( paths[i], O_RDONLY|O_CLOEXEC );
    if( fd<0 ) continue;

    char manufacturer[ 128 ];
    ulong manufacturer_sz;
    int read_err  = fd_io_read( fd, manufacturer, sizeof(manufacturer), sizeof(manufacturer), &manufacturer_sz );
    int close_err = close( fd );
    if( read_err>=0 || close_err || !manufacturer_sz ) continue;
    manufacturer[ manufacturer_sz ] = '\0';

    if( strcasestr( manufacturer, "Supermicro" ) || strcasestr( manufacturer, "Super Micro" ) ) {
      if( is_intel ) {
        return "Follow Supermicro's instructions at\n"
               "    https://www.supermicro.com/en/support/faqs/faq.php?faq=31936";
      }
      if( is_amd ) {
        return "Follow Supermicro's instructions at\n"
               "    https://www.supermicro.com/en/support/faqs/faq.php?faq=31883";
      }
    }
    if( strcasestr( manufacturer, "Dell" ) ) {
      if( is_intel ) {
        return "This PowerEdge guide uses a Mellanox card, but the system and NIC BIOS\n"
               "  changes are roughly the same for Intel NICs:\n"
               "    https://enterprise-support.nvidia.com/s/article/howto-set-dell-poweredge-r730-bios-parameters-to-support-sr-iov";
      }
      if( is_amd ) {
        return "This PowerEdge guide uses an Intel CPU and a Mellanox card, but the\n"
               "  system and NIC BIOS changes are roughly the same for Intel NICs:\n"
               "    https://enterprise-support.nvidia.com/s/article/howto-set-dell-poweredge-r730-bios-parameters-to-support-sr-iov";
      }
      return "Follow NVIDIA's PowerEdge SR-IOV configuration guide at\n"
             "    https://enterprise-support.nvidia.com/s/article/howto-set-dell-poweredge-r730-bios-parameters-to-support-sr-iov";
    }
  }
#endif
  return fallback;
}

static char const *
fd_iavf_iommu_diagnose( void ) {
  char const * fallback = fd_iavf_sriov_bios_guide();

#if FD_HAS_X86
  char vendor[ 13 ];
  if( !fd_iavf_cpu_vendor( vendor ) ) return fallback;
  int is_intel = !strcmp( vendor, "GenuineIntel" );
  int is_amd   = !strcmp( vendor, "AuthenticAMD" );

  int cmdline_fd = open( "/proc/cmdline", O_RDONLY|O_CLOEXEC );
  if( cmdline_fd<0 ) return fallback;

  /* Read through EOF so a truncated command line cannot hide a later override. */
  char cmdline[ 4096 ];
  ulong cmdline_sz;
  int read_err  = fd_io_read( cmdline_fd, cmdline, sizeof(cmdline), sizeof(cmdline), &cmdline_sz );
  int close_err = close( cmdline_fd );
  if( read_err>=0 || close_err || !cmdline_sz ) return fallback;
  cmdline[ cmdline_sz ] = '\0';

  /* Match Linux's intel_iommu_setup, iommu_setup and parse_amd_iommu_options,
     including prefix and substring matches. Intel's last on/off option wins. */
  int iommu_off  = 0;
  int intel_mode = -1;
  int amd_off    = 0;
  for( char * next=cmdline; *next; ) {
    char * param;
    char * value;
    next = fd_iavf_cmdline_next( next, &param, &value );
    if( !next ) return fallback;
    if( !value ) {
      if( !strcmp( param, "--" ) ) break;
      continue;
    }

    if( is_amd && !strcmp( param, "amd_iommu" ) && strstr( value, "off" ) ) amd_off = 1;
    char * save;
    for( char * opt=strtok_r( value, ",", &save ); opt; opt=strtok_r( NULL, ",", &save ) ) {
      if( !strcmp( param, "iommu" ) ) {
        if( !strncmp( opt, "off", 3UL ) ) iommu_off = 1;
        if( !strncmp( opt, "usedac", 6UL ) ) break;
      } else if( is_intel && !strcmp( param, "intel_iommu" ) ) {
        if(      !strncmp( opt, "on",  2UL ) ) intel_mode = 1;
        else if( !strncmp( opt, "off", 3UL ) ) intel_mode = 0;
      }
    }
  }

  if( iommu_off ) {
    return "The iommu=off kernel boot argument disables IOMMU support, so remove it "
           "from the boot arguments and reboot the machine";
  }

  if( is_intel && intel_mode==0 ) {
    return "The intel_iommu=off kernel boot argument disables Intel IOMMU support, "
           "so replace it with intel_iommu=on and reboot the machine";
  }

  if( is_amd && amd_off ) {
    return "The amd_iommu=off kernel boot argument disables AMD IOMMU support, "
           "so remove it from the boot arguments and reboot the machine";
  }

  if( is_intel && intel_mode<0 && fd_iavf_intel_iommu_default_off() ) {
    return "Add intel_iommu=on to the kernel boot arguments and reboot the machine "
           "to enable Intel IOMMU support";
  }
#endif
  return fallback;
}

int
fd_iavf_iommu_check( char const *  pf_if,
                     char const ** diagnostic ) {
  if( diagnostic ) *diagnostic = NULL;

  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/sys/class/net/%s/device/iommu_group", pf_if ) );
  char resolved[ PATH_MAX ];
  if( realpath( path, resolved ) ) return 0;

  int err = errno;
  if( diagnostic ) {
    *diagnostic = err==ENOENT ? fd_iavf_iommu_diagnose()
                             : "Check that the PF's iommu_group sysfs link is accessible "
                               "so its IOMMU status can be determined";
  }
  errno = err;
  return -1;
}

int
fd_iavf_numvfs_get( char const * pf_if,
                    uint *       numvfs ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/sys/class/net/%s/device/sriov_numvfs", pf_if ) );
  ulong value;
  if( FD_UNLIKELY( fd_iavf_read_ulong( path, 10, &value ) ) ) return -1;
  if( FD_UNLIKELY( value>UINT_MAX ) ) {
    errno = EOVERFLOW;
    return -1;
  }
  *numvfs = (uint)value;
  return 0;
}

int
fd_iavf_sriov_resources_check( char const * pf_if ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/sys/class/net/%s/device/resource", pf_if ) );
  FILE * file = fopen( path, "re" );
  if( FD_UNLIKELY( !file ) ) return -1;

  int err = 0;
  /* Linux lists VF BAR0 and BAR3 at resource indices 7 and 10 */
  for( ulong resource_idx=0UL; resource_idx<13UL; resource_idx++ ) {
    ulong start, end, flags;
    errno = 0;
    if( FD_UNLIKELY( fscanf( file, "%lx %lx %lx", &start, &end, &flags )!=3 ) ) {
      err = ferror( file ) ? (errno ? errno : EIO) : EPROTO;
      break;
    }
    if( resource_idx!=7UL && resource_idx!=10UL ) continue;
    if( FD_UNLIKELY( !start || end<start || !(flags & FD_IAVF_PCI_RESOURCE_MEM) ||
                     (flags & FD_IAVF_PCI_RESOURCE_UNUSABLE) ) ) {
      err = ENOMEM;
      break;
    }
  }
  if( FD_UNLIKELY( fclose( file ) && !err ) ) err = errno;
  if( FD_UNLIKELY( err ) ) {
    errno = err;
    return -1;
  }
  return 0;
}

int
fd_iavf_get_last_vf( char const * pf_if,
                     uint *       vf_idx,
                     char         vf_pci_addr[ FD_IAVF_PCI_ADDR_SZ ] ) {
  /* Find the highest enabled VF index */
  uint numvfs;
  if( FD_UNLIKELY( fd_iavf_numvfs_get( pf_if, &numvfs ) ) ) return -1;
  if( FD_UNLIKELY( !numvfs ) ) {
    errno = ENOENT;
    return -1;
  }
  uint const last_vf_idx = numvfs-1U;

  /* Read the PCI address from the PF's virtfn link */
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/sys/class/net/%s/device/virtfn%u", pf_if, last_vf_idx ) );
  char pci_addr[ FD_IAVF_PCI_ADDR_SZ ];
  if( FD_UNLIKELY( fd_iavf_read_link_name( pci_addr, sizeof(pci_addr), path, 0 ) ) ) return -1;
  if( FD_UNLIKELY( fd_iavf_pci_addr_normalize( vf_pci_addr, pci_addr ) ) ) return -1;
  if( vf_idx ) *vf_idx = last_vf_idx;
  return 0;
}

static int
fd_iavf_iommu_group_check( char const * pci_addr,
                           uint         iommu_group ) {
  char devices_path[ PATH_MAX ];
  int path_sz = snprintf( devices_path, sizeof(devices_path),
                          "/sys/kernel/iommu_groups/%u/devices", iommu_group );
  FD_TEST( path_sz>=0 && (ulong)path_sz<sizeof(devices_path) );

  DIR * devices = opendir( devices_path );
  if( FD_UNLIKELY( !devices ) ) return -1;

  ulong device_cnt = 0UL;
  ulong match_cnt  = 0UL;
  int   err        = 0;
  for(;;) {
    errno                 = 0;
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
    FD_LOG_WARNING(( "PCI %s is not alone in IOMMU group %u (%i-%s)", pci_addr, iommu_group, EBUSY, fd_io_strerror( EBUSY ) ));
    errno = EBUSY;
    return -1;
  }
  return 0;
}

int
fd_iavf_pci_probe( fd_iavf_pci_info_t * info,
                   char const *         pci_addr ) {
  if( FD_UNLIKELY( !info ) ) {
    errno = EINVAL;
    return -1;
  }
  fd_memset( info, 0, sizeof(*info) );

  fd_iavf_pci_info_t probed[1];
  fd_memset( probed, 0, sizeof(probed) );
  if( FD_UNLIKELY( fd_iavf_pci_addr_normalize( probed->pci_addr, pci_addr ) ) ) return -1;

  char device_path[ PATH_MAX ];
  fd_iavf_path_join( device_path, FD_IAVF_PCI_SYSFS, probed->pci_addr );

  /* Check Intel Ethernet VF identity */
  char  path[ PATH_MAX ];
  ulong value;
  fd_iavf_path_join( path, device_path, "vendor" );
  if( FD_UNLIKELY( fd_iavf_read_ulong( path, 0, &value ) ) ) return -1;
  if( FD_UNLIKELY( value!=0x8086UL ) ) {
    FD_LOG_WARNING(( "PCI %s vendor %#lx is not Intel (%i-%s)", pci_addr, value, ENODEV, fd_io_strerror( ENODEV ) ));
    errno = ENODEV;
    return -1;
  }

  fd_iavf_path_join( path, device_path, "class" );
  if( FD_UNLIKELY( fd_iavf_read_ulong( path, 0, &value ) ) ) return -1;
  if( FD_UNLIKELY( value!=0x020000UL ) ) {
    FD_LOG_WARNING(( "PCI %s class %#lx is not Ethernet (%i-%s)", pci_addr, value, ENODEV, fd_io_strerror( ENODEV ) ));
    errno = ENODEV;
    return -1;
  }

  fd_iavf_path_join( path, device_path, "device" );
  if( FD_UNLIKELY( fd_iavf_read_ulong( path, 0, &value ) ) ) return -1;
  if( FD_UNLIKELY( value>USHRT_MAX ) ) {
    FD_LOG_WARNING(( "PCI %s device ID %#lx exceeds 16 bits (%i-%s)", pci_addr, value, EPROTO, fd_io_strerror( EPROTO ) ));
    errno = EPROTO;
    return -1;
  }
  probed->device_id = (ushort)value;
  if( FD_UNLIKELY( !fd_iavf_device_supported( probed->device_id ) ) ) {
    FD_LOG_WARNING(( "unsupported Intel VF device %#x (%i-%s)", (uint)probed->device_id, ENODEV, fd_io_strerror( ENODEV ) ));
    errno = ENODEV;
    return -1;
  }

  /* Confirm the VF's parent PF and IOMMU isolation */
  char pf_addr[ FD_IAVF_PCI_ADDR_SZ ];
  fd_iavf_path_join( path, device_path, "physfn" );
  if( FD_UNLIKELY( fd_iavf_read_link_name( pf_addr, sizeof(pf_addr), path, 0 ) ||
                   fd_iavf_pci_addr_normalize( probed->pf_pci_addr, pf_addr ) ) ) {
    if( errno==ENOENT ) errno = ENODEV;
    return -1;
  }

  char iommu_group_name[ 32 ];
  fd_iavf_path_join( path, device_path, "iommu_group" );
  if( FD_UNLIKELY( fd_iavf_read_link_name( iommu_group_name, sizeof(iommu_group_name), path, 0 ) ) ) return -1;
  errno = 0;
  char * end;
  ulong iommu_group = strtoul( iommu_group_name, &end, 10 );
  if( FD_UNLIKELY( errno || *end || iommu_group>UINT_MAX ) ) {
    int err = errno ? errno : EPROTO;
    FD_LOG_WARNING(( "invalid IOMMU group for PCI %s (%i-%s)", pci_addr, err, fd_io_strerror( err ) ));
    errno = err;
    return -1;
  }
  probed->iommu_group = (uint)iommu_group;
  if( FD_UNLIKELY( fd_iavf_iommu_group_check( probed->pci_addr, probed->iommu_group ) ) ) return -1;

  fd_iavf_path_join( path, device_path, "driver" );
  if( FD_UNLIKELY( fd_iavf_read_link_name( probed->driver, sizeof(probed->driver), path, 1 ) ) ) return -1;

  *info = *probed;
  return 0;
}

static void
fd_iavf_vfio_cleanup( fd_iavf_vfio_t * vfio,
                      int              container_set ) {
  if( vfio->bar0 ) munmap( (void *)vfio->bar0, FD_IAVF_BAR0_MAP_SZ );
  if( vfio->device_fd>=0 ) close( vfio->device_fd );
  if( container_set ) ioctl( vfio->group_fd, VFIO_GROUP_UNSET_CONTAINER );
  if( vfio->group_fd>=0 )     close( vfio->group_fd );
  if( vfio->container_fd>=0 ) close( vfio->container_fd );
  vfio->bar0         = NULL;
  vfio->device_fd    = -1;
  vfio->group_fd     = -1;
  vfio->container_fd = -1;
}

static int
fd_iavf_vfio_wait_reset( fd_iavf_vfio_t * vfio ) {
  volatile uint const * reset_reg = (volatile uint const *)(vfio->bar0 + FD_IAVF_VFGEN_RSTAT);
  struct timespec       delay     = { .tv_sec=0L, .tv_nsec=FD_IAVF_POLL_INTERVAL_NS };
  for( ulong retry=0UL; retry<FD_IAVF_RESET_RETRY_CNT; retry++ ) {
    uint reset_state = *reset_reg & FD_IAVF_VFGEN_RSTAT_STATE;
    if( reset_state==FD_IAVF_VFR_STATE_COMPLETED ||
        reset_state==FD_IAVF_VFR_STATE_ACTIVE ) {
      return 0;
    }
    if( FD_UNLIKELY( nanosleep( &delay, NULL ) && errno!=EINTR ) ) return -1;
  }
  errno = ETIMEDOUT;
  return -1;
}

static int
fd_iavf_vfio_enable_pci( fd_iavf_vfio_t * vfio ) {
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
  errno   = 0;
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
fd_iavf_vfio_map_bar( fd_iavf_vfio_t * vfio ) {
  if( FD_UNLIKELY( !vfio || vfio->device_fd<0 ) ) {
    errno = EINVAL;
    return -1;
  }
  struct vfio_region_info bar0 = {
    .argsz = sizeof(bar0),
    .index = VFIO_PCI_BAR0_REGION_INDEX
  };
  if( FD_UNLIKELY( ioctl( vfio->device_fd, VFIO_DEVICE_GET_REGION_INFO, &bar0 ) ) ) return -1;
  if( FD_UNLIKELY( bar0.size<FD_IAVF_BAR0_MAP_SZ || bar0.offset>(ulong)LLONG_MAX ||
                    !(bar0.flags & VFIO_REGION_INFO_FLAG_READ) ||
                    !(bar0.flags & VFIO_REGION_INFO_FLAG_WRITE) ||
                    !(bar0.flags & VFIO_REGION_INFO_FLAG_MMAP) ) ) {
    errno = EOPNOTSUPP;
    return -1;
  }

  void * bar0_map = mmap( NULL, FD_IAVF_BAR0_MAP_SZ, PROT_READ|PROT_WRITE,
                          MAP_SHARED, vfio->device_fd, (off_t)bar0.offset );
  if( FD_UNLIKELY( bar0_map==MAP_FAILED ) ) return -1;
  vfio->bar0 = (volatile uchar *)bar0_map;

  return 0;
}

int
fd_iavf_vfio_unmap_bar( fd_iavf_vfio_t * vfio ) {
  if( FD_UNLIKELY( munmap( (void *)vfio->bar0, FD_IAVF_BAR0_MAP_SZ ) ) ) return -1;
  vfio->bar0 = NULL;
  return 0;
}

static int
fd_iavf_vfio_init( fd_iavf_vfio_t *           vfio,
                   fd_iavf_pci_info_t const * info ) {
  if( FD_UNLIKELY( strcmp( info->driver, "vfio-pci" ) ) ) {
    errno = EINVAL;
    return -1;
  }

  *vfio = (fd_iavf_vfio_t) {
    .container_fd = -1,
    .group_fd     = -1,
    .device_fd    = -1
  };
  int          container_set = 0;
  char const * operation     = "open(/dev/vfio/vfio)";

  /* Check VFIO API and IOMMU support */
  vfio->container_fd = open( "/dev/vfio/vfio", O_RDWR|O_CLOEXEC );
  if( FD_UNLIKELY( vfio->container_fd<0 ) ) goto fail;
  operation       = "VFIO_GET_API_VERSION";
  int api_version = ioctl( vfio->container_fd, VFIO_GET_API_VERSION );
  if( FD_UNLIKELY( api_version<0 ) ) goto fail;
  if( FD_UNLIKELY( api_version!=VFIO_API_VERSION ) ) {
    operation = "unsupported VFIO API version";
    errno     = EPROTONOSUPPORT;
    goto fail;
  }
  operation             = "VFIO_CHECK_EXTENSION(TYPE1v2)";
  int type1v2_supported = ioctl( vfio->container_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1v2_IOMMU );
  if( FD_UNLIKELY( type1v2_supported<0 ) ) goto fail;
  if( FD_UNLIKELY( !type1v2_supported ) ) {
    operation = "VFIO TYPE1v2 IOMMU unsupported";
    errno     = EPROTONOSUPPORT;
    goto fail;
  }

  /* Attach the VF's IOMMU group to this container */
  char group_path[ 64 ];
  int group_path_sz = snprintf( group_path, sizeof(group_path), "/dev/vfio/%u", info->iommu_group );
  FD_TEST( group_path_sz>=0 && (ulong)group_path_sz<sizeof(group_path) );
  operation      = "open VFIO group";
  vfio->group_fd = open( group_path, O_RDWR|O_CLOEXEC );
  if( FD_UNLIKELY( vfio->group_fd<0 ) ) goto fail;

  operation                             = "VFIO_GROUP_GET_STATUS";
  struct vfio_group_status group_status = { .argsz=sizeof(group_status) };
  if( FD_UNLIKELY( ioctl( vfio->group_fd, VFIO_GROUP_GET_STATUS, &group_status ) ) ) goto fail;
  if( FD_UNLIKELY( !(group_status.flags & VFIO_GROUP_FLAGS_VIABLE) ) ) {
    operation = "VFIO group not viable";
    errno     = EBUSY;
    goto fail;
  }
  if( FD_UNLIKELY( group_status.flags & VFIO_GROUP_FLAGS_CONTAINER_SET ) ) {
    operation = "VFIO group already has a container";
    errno     = EBUSY;
    goto fail;
  }
  operation = "VFIO_GROUP_SET_CONTAINER";
  if( FD_UNLIKELY( ioctl( vfio->group_fd, VFIO_GROUP_SET_CONTAINER, &vfio->container_fd ) ) ) goto fail;
  container_set = 1;
  operation     = "VFIO_SET_IOMMU";
  if( FD_UNLIKELY( ioctl( vfio->container_fd, VFIO_SET_IOMMU, VFIO_TYPE1v2_IOMMU ) ) ) goto fail;

  /* Query page sizes for DMA mappings */
  operation                               = "VFIO_IOMMU_GET_INFO";
  struct vfio_iommu_type1_info iommu_info = { .argsz=sizeof(iommu_info) };
  if( FD_UNLIKELY( ioctl( vfio->container_fd, VFIO_IOMMU_GET_INFO, &iommu_info ) ) ) goto fail;
  if( FD_UNLIKELY( !(iommu_info.flags & VFIO_IOMMU_INFO_PGSIZES) || !iommu_info.iova_pgsizes ) ) {
    operation = "VFIO IOMMU page sizes missing";
    errno     = EPROTO;
    goto fail;
  }
  vfio->iova_pgsizes = (ulong)iommu_info.iova_pgsizes;

  /* Open the VF and map its registers */
  operation       = "VFIO_GROUP_GET_DEVICE_FD";
  vfio->device_fd = ioctl( vfio->group_fd, VFIO_GROUP_GET_DEVICE_FD, info->pci_addr );
  if( FD_UNLIKELY( vfio->device_fd<0 ) ) goto fail;

  operation                           = "VFIO_DEVICE_GET_INFO";
  struct vfio_device_info device_info = { .argsz=sizeof(device_info) };
  if( FD_UNLIKELY( ioctl( vfio->device_fd, VFIO_DEVICE_GET_INFO, &device_info ) ) ) goto fail;
  if( FD_UNLIKELY( !(device_info.flags & VFIO_DEVICE_FLAGS_PCI) ||
                    !(device_info.flags & VFIO_DEVICE_FLAGS_RESET) ) ) {
    operation = "VFIO device lacks PCI or reset support";
    errno     = EOPNOTSUPP;
    goto fail;
  }
  if( FD_UNLIKELY( device_info.num_regions<=VFIO_PCI_BAR0_REGION_INDEX ) ) {
    operation = "VFIO BAR0 region missing";
    errno     = EPROTO;
    goto fail;
  }

  operation = "VFIO BAR0 mapping";
  if( FD_UNLIKELY( fd_iavf_vfio_map_bar( vfio ) ) ) goto fail;

  /* Reset the VF and wait for the PF to report it ready */
  operation = "VFIO_DEVICE_RESET";
  if( FD_UNLIKELY( ioctl( vfio->device_fd, VFIO_DEVICE_RESET ) ) ) goto fail;
  operation = "VF reset wait";
  if( FD_UNLIKELY( fd_iavf_vfio_wait_reset( vfio ) ) ) goto fail;
  operation = "PCI memory and bus mastering enable";
  if( FD_UNLIKELY( fd_iavf_vfio_enable_pci( vfio ) ) ) goto fail;
  return 0;

fail:
  {
    int err = errno;
    FD_LOG_WARNING(( "%s failed for PCI %s (%i-%s)", operation, info->pci_addr, err, fd_io_strerror( err ) ));
    fd_iavf_vfio_cleanup( vfio, container_set );
    errno = err;
    return -1;
  }
}

int
fd_iavf_vfio_dma_map( fd_iavf_vfio_t * vfio,
                      void *           memory,
                      ulong            memory_sz,
                      ulong            iova ) {
  if( FD_UNLIKELY( !vfio || vfio->container_fd<0 || !memory || !memory_sz || !vfio->iova_pgsizes ) ) {
    errno = EINVAL;
    return -1;
  }

  /* The smallest supported IOMMU page size sets mapping alignment */
  ulong page_sz = vfio->iova_pgsizes & -vfio->iova_pgsizes;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)memory, page_sz ) ||
                   !fd_ulong_is_aligned( memory_sz,     page_sz ) ||
                   !fd_ulong_is_aligned( iova,          page_sz ) ||
                   (ulong)memory>ULONG_MAX-memory_sz ||
                   memory_sz>ULONG_MAX-iova ) ) {
    FD_LOG_WARNING(( "invalid DMA mapping bounds or alignment, memory %p, size %lu, IOVA %#lx, required alignment %lu", memory, memory_sz, iova, page_sz ));
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
  if( FD_UNLIKELY( ioctl( vfio->container_fd, VFIO_IOMMU_MAP_DMA, &dma_map ) ) ) {
    int err = errno;
    FD_LOG_WARNING(( "VFIO_IOMMU_MAP_DMA failed, size %lu, IOVA %#lx (%i-%s)", memory_sz, iova, err, fd_io_strerror( err ) ));
    errno = err;
    return -1;
  }
  return 0;
}

static inline uint
fd_iavf_mmio_read( fd_iavf_vfio_t const * vfio,
                   ulong                  reg ) {
  volatile uint const * ptr   = (volatile uint const *)(vfio->bar0 + reg);
  uint                  value = *ptr;
  FD_COMPILER_MFENCE();
  return value;
}

static inline void
fd_iavf_mmio_write( fd_iavf_vfio_t * vfio,
                    ulong            reg,
                    uint             value ) {
  FD_COMPILER_MFENCE();
  volatile uint * ptr = (volatile uint *)(vfio->bar0 + reg);
  *ptr                = value;
  FD_COMPILER_MFENCE();
}

static int
fd_iavf_mmio_verify( fd_iavf_vfio_t const * vfio,
                     ulong                  reg,
                     uint                   expected ) {
  uint const actual = fd_iavf_mmio_read( vfio, reg );
  if( FD_UNLIKELY( actual!=expected ) ) {
    FD_LOG_WARNING(( "register %#lx read %#x, expected %#x (%i-%s)", reg, actual, expected, EIO, fd_io_strerror( EIO ) ));
    errno = EIO;
    return -1;
  }
  return 0;
}

static inline fd_iavf_aq_desc_t *
fd_iavf_adminq_atq_desc( fd_iavf_adminq_t * adminq,
                         uint               idx ) {
  return (fd_iavf_aq_desc_t *)((uchar *)adminq->dma_memory + FD_IAVF_ADMINQ_SEND_DESC_OFF) + idx;
}

static inline fd_iavf_aq_desc_t *
fd_iavf_adminq_arq_desc( fd_iavf_adminq_t * adminq,
                         uint               idx ) {
  return (fd_iavf_aq_desc_t *)((uchar *)adminq->dma_memory + FD_IAVF_ADMINQ_RECV_DESC_OFF) + idx;
}

static inline uchar *
fd_iavf_adminq_atq_buf( fd_iavf_adminq_t * adminq,
                        uint               idx ) {
  return (uchar *)adminq->dma_memory + FD_IAVF_ADMINQ_SEND_BUF_OFF + (ulong)idx*FD_IAVF_ADMINQ_BUF_SZ;
}

static inline uchar *
fd_iavf_adminq_arq_buf( fd_iavf_adminq_t * adminq,
                        uint               idx ) {
  return (uchar *)adminq->dma_memory + FD_IAVF_ADMINQ_RECV_BUF_OFF + (ulong)idx*FD_IAVF_ADMINQ_BUF_SZ;
}

static inline ulong
fd_iavf_adminq_atq_buf_iova( fd_iavf_adminq_t const * adminq,
                             uint                     idx ) {
  return adminq->dma_iova + FD_IAVF_ADMINQ_SEND_BUF_OFF + (ulong)idx*FD_IAVF_ADMINQ_BUF_SZ;
}

static inline ulong
fd_iavf_adminq_arq_buf_iova( fd_iavf_adminq_t const * adminq,
                             uint                     idx ) {
  return adminq->dma_iova + FD_IAVF_ADMINQ_RECV_BUF_OFF + (ulong)idx*FD_IAVF_ADMINQ_BUF_SZ;
}

static inline void
fd_iavf_adminq_desc_set_addr( fd_iavf_aq_desc_t * desc,
                              ulong               iova ) {
  desc->addr_high = (uint)(iova>>32);
  desc->addr_low  = (uint)iova;
}

static void
fd_iavf_adminq_arq_post( fd_iavf_adminq_t * adminq,
                         uint               idx ) {
  fd_iavf_aq_desc_t * desc = fd_iavf_adminq_arq_desc( adminq, idx );
  fd_memset( desc, 0, sizeof(*desc) );
  desc->flags   = FD_IAVF_AQ_FLAG_BUF|FD_IAVF_AQ_FLAG_LB;
  desc->datalen = FD_IAVF_ADMINQ_BUF_SZ;
  fd_iavf_adminq_desc_set_addr( desc, fd_iavf_adminq_arq_buf_iova( adminq, idx ) );
}

ulong
fd_iavf_adminq_footprint( void ) {
  return FD_IAVF_ADMINQ_FOOTPRINT;
}

static int
fd_iavf_adminq_init( fd_iavf_vfio_t *   vfio,
                     fd_iavf_adminq_t * adminq,
                     void *             dma_memory,
                     ulong              dma_iova ) {
  if( FD_UNLIKELY( !dma_memory ||
                   !fd_ulong_is_aligned( (ulong)dma_memory, FD_IAVF_PAGE_SZ ) ||
                   !fd_ulong_is_aligned( dma_iova,          FD_IAVF_PAGE_SZ ) ||
                   !(vfio->iova_pgsizes & FD_IAVF_PAGE_SZ) ) ) {
    errno = EINVAL;
    return -1;
  }

  /* Map Admin Queue rings and prepare receive buffers */
  fd_memset( dma_memory, 0, FD_IAVF_ADMINQ_FOOTPRINT );
  if( FD_UNLIKELY( fd_iavf_vfio_dma_map( vfio, dma_memory, FD_IAVF_ADMINQ_FOOTPRINT, dma_iova ) ) ) return -1;

  *adminq = (fd_iavf_adminq_t) {
    .dma_memory = dma_memory,
    .dma_iova   = dma_iova
  };
  for( uint idx=0U; idx<(uint)FD_IAVF_ADMINQ_DEPTH; idx++ ) fd_iavf_adminq_arq_post( adminq, idx );
  fd_iavf_hw_dma_to_device();

  /* Enable ATQ for outgoing PF requests */
  ulong atq_iova = dma_iova + FD_IAVF_ADMINQ_SEND_DESC_OFF;
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ATQH,   0U );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ATQT,   0U );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ATQLEN, (uint)FD_IAVF_ADMINQ_DEPTH|FD_IAVF_ATQ_ENABLE );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ATQBAL, (uint)atq_iova );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ATQBAH, (uint)(atq_iova>>32) );

  /* Enable ARQ and post buffers for PF replies and events */
  ulong arq_iova = dma_iova + FD_IAVF_ADMINQ_RECV_DESC_OFF;
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ARQH,   0U );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ARQT,   0U );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ARQLEN, (uint)FD_IAVF_ADMINQ_DEPTH|FD_IAVF_ARQ_ENABLE );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ARQBAL, (uint)arq_iova );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ARQBAH, (uint)(arq_iova>>32) );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ARQT,   (uint)FD_IAVF_ADMINQ_DEPTH-1U );

  if( FD_UNLIKELY( fd_iavf_mmio_verify( vfio, FD_IAVF_VF_ATQBAL, (uint)atq_iova ) ||
                   fd_iavf_mmio_verify( vfio, FD_IAVF_VF_ATQBAH, (uint)(atq_iova>>32) ) ||
                   fd_iavf_mmio_verify( vfio, FD_IAVF_VF_ARQBAL, (uint)arq_iova ) ||
                   fd_iavf_mmio_verify( vfio, FD_IAVF_VF_ARQBAH, (uint)(arq_iova>>32) ) ||
                   fd_iavf_mmio_verify( vfio, FD_IAVF_VF_ATQLEN, (uint)FD_IAVF_ADMINQ_DEPTH|FD_IAVF_ATQ_ENABLE ) ||
                   fd_iavf_mmio_verify( vfio, FD_IAVF_VF_ARQLEN, (uint)FD_IAVF_ADMINQ_DEPTH|FD_IAVF_ARQ_ENABLE ) ) ) return -1;
  return 0;
}

static char const *
fd_iavf_virtchnl_op_name( uint op ) {
  switch( op ) {
  case FD_IAVF_VIRTCHNL_VERSION:         return "version exchange";
  case FD_IAVF_VIRTCHNL_GET_VF_RESOURCES: return "VF resource discovery";
  case FD_IAVF_VIRTCHNL_CONFIG_QUEUES:    return "queue configuration";
  case FD_IAVF_VIRTCHNL_CONFIG_IRQ_MAP:   return "IRQ mapping";
  case FD_IAVF_VIRTCHNL_ENABLE_QUEUES:    return "queue enable";
  case FD_IAVF_VIRTCHNL_ADD_ETH_ADDR:     return "MAC registration";
  case FD_IAVF_VIRTCHNL_CONFIG_RSS_KEY:   return "RSS key configuration";
  case FD_IAVF_VIRTCHNL_CONFIG_RSS_LUT:   return "RSS table configuration";
  default:                              return "virtchnl request";
  }
}

static int
fd_iavf_adminq_send( fd_iavf_vfio_t *   vfio,
                     fd_iavf_adminq_t * adminq,
                     uint               virtchnl_op,
                     void const *       message,
                     ulong              message_sz ) {
  uint                idx  = adminq->atq_prod;
  uint                next = (idx+1U) & ((uint)FD_IAVF_ADMINQ_DEPTH-1U);
  fd_iavf_aq_desc_t * desc = fd_iavf_adminq_atq_desc( adminq, idx );
  fd_memset( desc, 0, sizeof(*desc) );
  desc->flags       = FD_IAVF_AQ_FLAG_SI;
  desc->opcode      = FD_IAVF_AQ_SEND_MSG_TO_PF;
  desc->cookie_high = virtchnl_op;
  if( message_sz ) {
    fd_memcpy( fd_iavf_adminq_atq_buf( adminq, idx ), message, message_sz );
    desc->flags   |= FD_IAVF_AQ_FLAG_BUF|FD_IAVF_AQ_FLAG_RD;
    /* Match Linux IAVF's descriptor flags for large requests. */
    if( message_sz>FD_IAVF_AQ_LARGE_BUF ) desc->flags |= FD_IAVF_AQ_FLAG_LB;
    desc->datalen = (ushort)message_sz;
    fd_iavf_adminq_desc_set_addr( desc, fd_iavf_adminq_atq_buf_iova( adminq, idx ) );
  }
  /* Publish the descriptor and payload before advancing ATQ tail */
  fd_iavf_hw_dma_to_device();
  adminq->atq_prod = next;
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ATQT, next );

  /* Wait for send completion, the PF's reply arrives separately on ARQ */
  struct timespec delay = { .tv_sec=0L, .tv_nsec=FD_IAVF_POLL_INTERVAL_NS };
  for( ulong retry=0UL; retry<FD_IAVF_ADMINQ_RETRY_CNT; retry++ ) {
    if( (fd_iavf_mmio_read( vfio, FD_IAVF_VF_ATQH ) & FD_IAVF_ATQ_HEAD)==next ) {
      fd_iavf_hw_dma_from_device();
      if( FD_UNLIKELY( (desc->flags & FD_IAVF_AQ_FLAG_ERR) || desc->retval ) ) {
        FD_LOG_WARNING(( "%s Admin Queue send failed, status %hu (%i-%s)", fd_iavf_virtchnl_op_name( virtchnl_op ), desc->retval, EIO, fd_io_strerror( EIO ) ));
        errno = EIO;
        return -1;
      }
      return 0;
    }
    if( FD_UNLIKELY( nanosleep( &delay, NULL ) && errno!=EINTR ) ) {
      int err = errno;
      FD_LOG_WARNING(( "%s send wait failed (%i-%s)", fd_iavf_virtchnl_op_name( virtchnl_op ), err, fd_io_strerror( err ) ));
      errno = err;
      return -1;
    }
  }
  FD_LOG_WARNING(( "%s Admin Queue send timed out (%i-%s)", fd_iavf_virtchnl_op_name( virtchnl_op ), ETIMEDOUT, fd_io_strerror( ETIMEDOUT ) ));
  errno = ETIMEDOUT;
  return -1;
}

static int
fd_iavf_adminq_recv( fd_iavf_vfio_t *   vfio,
                     fd_iavf_adminq_t * adminq,
                     uint *             virtchnl_op,
                     int *              virtchnl_status,
                     void *             message,
                     ulong *            message_sz ) {
  uint head = fd_iavf_mmio_read( vfio, FD_IAVF_VF_ARQH ) & FD_IAVF_ARQ_HEAD;
  uint idx  = adminq->arq_cons;
  if( head==idx ) return 0;

  /* Read the message before returning its buffer to the NIC */
  fd_iavf_hw_dma_from_device();
  fd_iavf_aq_desc_t * desc      = fd_iavf_adminq_arq_desc( adminq, idx );
  fd_iavf_aq_desc_t   comp_desc = *desc;
  ulong               comp_sz   = comp_desc.datalen;
  int                 err       = 0;
  if( FD_UNLIKELY( comp_desc.opcode!=FD_IAVF_AQ_SEND_MSG_TO_VF ||
                   (comp_desc.flags & FD_IAVF_AQ_FLAG_ERR) || comp_desc.retval ) ) err = EIO;
  else if( FD_UNLIKELY( comp_sz>*message_sz ) ) err = EMSGSIZE;
  else if( comp_sz ) fd_memcpy( message, fd_iavf_adminq_arq_buf( adminq, idx ), comp_sz );

  /* ARQ tail names the last returned descriptor */
  fd_iavf_adminq_arq_post( adminq, idx );
  fd_iavf_hw_dma_to_device();
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ARQT, idx );
  adminq->arq_cons = (idx+1U) & ((uint)FD_IAVF_ADMINQ_DEPTH-1U);

  if( FD_UNLIKELY( err ) ) {
    errno = err;
    return -1;
  }
  *virtchnl_op     = comp_desc.cookie_high;
  *virtchnl_status = (int)comp_desc.cookie_low;
  *message_sz      = comp_sz;
  return 1;
}

static int
fd_iavf_virtchnl_cache_event( fd_iavf_adminq_t * adminq,
                              uint               op,
                              int                status,
                              void const *       message,
                              ulong              message_sz ) {
  if( FD_UNLIKELY( op!=FD_IAVF_VIRTCHNL_EVENT || status ||
                   message_sz!=sizeof(fd_iavf_virtchnl_event_t) ) ) {
    FD_LOG_WARNING(( "invalid PF event, operation %u, status %i, size %lu, expected %lu (%i-%s)",
                     op, status, message_sz, sizeof(fd_iavf_virtchnl_event_t), EPROTO, fd_io_strerror( EPROTO ) ));
    errno = EPROTO;
    return -1;
  }
  fd_iavf_virtchnl_event_t event;
  fd_memcpy( &event, message, sizeof(event) );
  if( FD_UNLIKELY( event.event==FD_IAVF_EVENT_RESET_IMPENDING ) ) {
    FD_LOG_WARNING(( "PF reset impending (%i-%s)", ECONNRESET, fd_io_strerror( ECONNRESET ) ));
    errno = ECONNRESET;
    return -1;
  }
  if( FD_UNLIKELY( event.event==FD_IAVF_EVENT_PF_DRIVER_CLOSE ) ) {
    FD_LOG_WARNING(( "PF driver closed (%i-%s)", ESHUTDOWN, fd_io_strerror( ESHUTDOWN ) ));
    errno = ESHUTDOWN;
    return -1;
  }
  /* Keep early link reports until resource discovery can apply them */
  fd_memcpy( adminq->pending_event, message, message_sz );
  adminq->pending_event_sz = message_sz;
  return 0;
}

static int
fd_iavf_virtchnl_request( fd_iavf_vfio_t *   vfio,
                          fd_iavf_adminq_t * adminq,
                          uint               virtchnl_op,
                          void const *       request,
                          ulong              request_sz,
                          void *             response,
                          ulong *            response_sz ) {
  ulong response_capacity = *response_sz;
  *response_sz            = 0UL;
  if( FD_UNLIKELY( fd_iavf_adminq_send( vfio, adminq, virtchnl_op, request, request_sz ) ) ) return -1;

  struct timespec delay = { .tv_sec=0L, .tv_nsec=FD_IAVF_POLL_INTERVAL_NS };
  for( ulong retry=0UL; retry<FD_IAVF_ADMINQ_RETRY_CNT; retry++ ) {
    uchar message[ FD_IAVF_ADMINQ_BUF_SZ ];
    ulong message_sz = sizeof(message);
    uint received_op;
    int  received_status;
    int received = fd_iavf_adminq_recv( vfio, adminq, &received_op, &received_status,
                                        message, &message_sz );
    if( FD_UNLIKELY( received<0 ) ) goto fail;
    if( !received ) {
      if( FD_UNLIKELY( nanosleep( &delay, NULL ) && errno!=EINTR ) ) goto fail;
      continue;
    }
    /* PF events can arrive before the request's reply */
    if( received_op==FD_IAVF_VIRTCHNL_EVENT ) {
      if( FD_UNLIKELY( fd_iavf_virtchnl_cache_event( adminq, received_op, received_status,
                                                   message, message_sz ) ) ) return -1;
      continue;
    }
    if( FD_UNLIKELY( received_op!=virtchnl_op ) ) {
      FD_LOG_WARNING(( "unexpected PF operation %u during %s (%i-%s)", received_op, fd_iavf_virtchnl_op_name( virtchnl_op ), EPROTO, fd_io_strerror( EPROTO ) ));
      errno = EPROTO;
      return -1;
    }
    if( FD_UNLIKELY( received_status ) ) {
      FD_LOG_WARNING(( "%s rejected, PF status %i (%i-%s)", fd_iavf_virtchnl_op_name( virtchnl_op ), received_status, EIO, fd_io_strerror( EIO ) ));
      errno = EIO;
      return -1;
    }
    if( FD_UNLIKELY( message_sz>response_capacity ) ) {
      FD_LOG_WARNING(( "%s response size %lu exceeds %lu (%i-%s)", fd_iavf_virtchnl_op_name( virtchnl_op ), message_sz, response_capacity, EMSGSIZE, fd_io_strerror( EMSGSIZE ) ));
      errno = EMSGSIZE;
      return -1;
    }
    if( message_sz ) fd_memcpy( response, message, message_sz );
    *response_sz = message_sz;
    return 0;
  }
  errno = ETIMEDOUT;
fail:
  {
    int err = errno;
    FD_LOG_WARNING(( "%s PF reply failed (%i-%s)", fd_iavf_virtchnl_op_name( virtchnl_op ), err, fd_io_strerror( err ) ));
    errno = err;
    return -1;
  }
}

int
fd_iavf_virtchnl_version( fd_iavf_vfio_t *   vfio,
                          fd_iavf_adminq_t * adminq ) {
  fd_iavf_virtchnl_version_t requested = { .major=1U, .minor=1U };
  fd_iavf_virtchnl_version_t response;
  ulong response_sz = sizeof(response);
  if( FD_UNLIKELY( fd_iavf_virtchnl_request( vfio, adminq, FD_IAVF_VIRTCHNL_VERSION,
                                             &requested, sizeof(requested),
                                             &response, &response_sz ) ) ) return -1;
  if( FD_UNLIKELY( response_sz!=sizeof(response) ) ) {
    FD_LOG_WARNING(( "unsupported virtchnl version reply, size %lu (%i-%s)", response_sz, EPROTONOSUPPORT, fd_io_strerror( EPROTONOSUPPORT ) ));
    errno = EPROTONOSUPPORT;
    return -1;
  }
  if( FD_UNLIKELY( response.major!=1U || response.minor!=1U ) ) {
    FD_LOG_WARNING(( "unsupported virtchnl version %u.%u (%i-%s)", response.major, response.minor, EPROTONOSUPPORT, fd_io_strerror( EPROTONOSUPPORT ) ));
    errno = EPROTONOSUPPORT;
    return -1;
  }
  return 0;
}

/* fd_iavf_virtchnl_apply_event returns 1 for a link report, including down */
static int
fd_iavf_virtchnl_apply_event( fd_iavf_adminq_t *  adminq,
                             fd_iavf_vf_info_t * info ) {
  if( !adminq->pending_event_sz ) return 0;
  fd_iavf_virtchnl_event_t event;
  fd_memcpy( &event, adminq->pending_event, sizeof(event) );
  adminq->pending_event_sz = 0UL;
  if( event.event==FD_IAVF_EVENT_LINK_CHANGE ) {
    info->link_usable = !!event.link_up;
    return 1;
  }
  return 0;
}

/* fd_iavf_virtchnl_wait_link_event accepts an initial down or unknown link
   Tiles exclude the VF from packet traffic until an up report arrives */
static int
fd_iavf_virtchnl_wait_link_event( fd_iavf_vfio_t *    vfio,
                                 fd_iavf_adminq_t *  adminq,
                                 fd_iavf_vf_info_t * info ) {
  if( fd_iavf_virtchnl_apply_event( adminq, info ) ) return 0;

  struct timespec delay = { .tv_sec=0L, .tv_nsec=FD_IAVF_POLL_INTERVAL_NS };
  for( ulong retry=0UL; retry<FD_IAVF_LINK_RETRY_CNT; retry++ ) {
    uchar message[ FD_IAVF_ADMINQ_BUF_SZ ];
    ulong message_sz = sizeof(message);
    uint virtchnl_op;
    int  virtchnl_status;
    int received = fd_iavf_adminq_recv( vfio, adminq, &virtchnl_op, &virtchnl_status,
                                        message, &message_sz );
    if( FD_UNLIKELY( received<0 ) ) {
      int err = errno;
      FD_LOG_WARNING(( "link event receive failed (%i-%s)", err, fd_io_strerror( err ) ));
      errno = err;
      return -1;
    }
    if( !received ) {
      if( FD_UNLIKELY( nanosleep( &delay, NULL ) && errno!=EINTR ) ) {
        int err = errno;
        FD_LOG_WARNING(( "link event wait failed (%i-%s)", err, fd_io_strerror( err ) ));
        errno = err;
        return -1;
      }
      continue;
    }
    if( FD_UNLIKELY( fd_iavf_virtchnl_cache_event( adminq, virtchnl_op, virtchnl_status,
                                                 message, message_sz ) ) ) return -1;
    if( fd_iavf_virtchnl_apply_event( adminq, info ) ) return 0;
  }
  return 0;
}

int
fd_iavf_virtchnl_get_resources( fd_iavf_vfio_t *    vfio,
                                fd_iavf_adminq_t *  adminq,
                                fd_iavf_vf_info_t * info ) {
  fd_memset( info, 0, sizeof(*info) );

  /* Request Ethernet, timed writeback and PF-managed RSS */
  uint requested_caps = FD_IAVF_VIRTCHNL_CAP_L2 | FD_IAVF_VIRTCHNL_CAP_WB_ON_ITR | FD_IAVF_VIRTCHNL_CAP_RSS_PF;
  uchar response[ FD_IAVF_ADMINQ_BUF_SZ ];
  ulong response_sz = sizeof(response);
  if( FD_UNLIKELY( fd_iavf_virtchnl_request( vfio, adminq, FD_IAVF_VIRTCHNL_GET_VF_RESOURCES,
                                             &requested_caps, sizeof(requested_caps),
                                             response, &response_sz ) ) ) return -1;
  if( FD_UNLIKELY( response_sz<sizeof(fd_iavf_virtchnl_vf_resource_t) ) ) {
    FD_LOG_WARNING(( "VF resource reply too short, %lu bytes (%i-%s)", response_sz, EPROTO, fd_io_strerror( EPROTO ) ));
    errno = EPROTO;
    return -1;
  }

  /* Validate reply length and required capabilities */
  fd_iavf_virtchnl_vf_resource_t resources;
  fd_memcpy( &resources, response, sizeof(resources) );
  ulong expected_sz = sizeof(resources) + (ulong)resources.num_vsis*sizeof(fd_iavf_virtchnl_vsi_resource_t);
  /* Linux i40e includes one extra VSI entry in the reply length. */
  ulong legacy_sz = expected_sz + sizeof(fd_iavf_virtchnl_vsi_resource_t);
  if( FD_UNLIKELY( !resources.num_vsis || !resources.num_queue_pairs ||
                   !(resources.capability_flags & FD_IAVF_VIRTCHNL_CAP_L2) ) ) {
    FD_LOG_WARNING(( "invalid VF resources, VSIs %hu, queue pairs %hu, capabilities %#x (L2 required) (%i-%s)",
                     resources.num_vsis, resources.num_queue_pairs, resources.capability_flags, EPROTO, fd_io_strerror( EPROTO ) ));
    errno = EPROTO;
    return -1;
  }
  if( FD_UNLIKELY( response_sz!=expected_sz && response_sz!=legacy_sz ) ) {
    FD_LOG_WARNING(( "VF resource reply size %lu, expected %lu or %lu for %hu VSIs (%i-%s)",
                     response_sz, expected_sz, legacy_sz, resources.num_vsis, EPROTO, fd_io_strerror( EPROTO ) ));
    errno = EPROTO;
    return -1;
  }
  if( FD_UNLIKELY( !(resources.capability_flags & FD_IAVF_VIRTCHNL_CAP_RSS_PF) ) ) {
    FD_LOG_WARNING(( "PF does not support RSS configuration (%i-%s)", EPROTONOSUPPORT, fd_io_strerror( EPROTONOSUPPORT ) ));
    errno = EPROTONOSUPPORT;
    return -1;
  }

  /* Select the SR-IOV VSI used for packet queues */
  fd_iavf_virtchnl_vsi_resource_t selected     = {0};
  ulong                           selected_cnt = 0UL;
  for( ulong vsi_idx=0UL; vsi_idx<(ulong)resources.num_vsis; vsi_idx++ ) {
    fd_iavf_virtchnl_vsi_resource_t vsi;
    fd_memcpy( &vsi, response+sizeof(resources)+vsi_idx*sizeof(vsi), sizeof(vsi) );
    if( vsi.vsi_type==FD_IAVF_VIRTCHNL_VSI_SRIOV ) {
      selected = vsi;
      selected_cnt++;
    }
  }
  if( FD_UNLIKELY( selected_cnt!=1UL ) ) {
    FD_LOG_WARNING(( "VF resources contain %lu SR-IOV VSIs, expected 1 (%i-%s)", selected_cnt, EPROTO, fd_io_strerror( EPROTO ) ));
    errno = EPROTO;
    return -1;
  }
  if( FD_UNLIKELY( !selected.num_queue_pairs ) ) {
    FD_LOG_WARNING(( "SR-IOV VSI %hu has no queue pairs (%i-%s)", selected.vsi_id, EPROTO, fd_io_strerror( EPROTO ) ));
    errno = EPROTO;
    return -1;
  }
  if( FD_UNLIKELY( selected.default_mac_addr[0] & 1U ) ) {
    FD_LOG_WARNING(( "SR-IOV VSI %hu MAC " FD_ETH_MAC_FMT " is multicast (%i-%s)",
                     selected.vsi_id, FD_ETH_MAC_FMT_ARGS( selected.default_mac_addr ), EPROTO, fd_io_strerror( EPROTO ) ));
    errno = EPROTO;
    return -1;
  }
  ulong mac_bits = 0UL;
  fd_memcpy( &mac_bits, selected.default_mac_addr, sizeof(selected.default_mac_addr) );
  if( FD_UNLIKELY( !mac_bits ) ) {
    FD_LOG_WARNING(( "PF returned a zero VF MAC address (%i-%s)", EPROTO, fd_io_strerror( EPROTO ) ));
    errno = EPROTO;
    return -1;
  }

  /* Retain PF limits and the assigned MAC */
  info->vsi_id         = selected.vsi_id;
  info->queue_pair_cnt = fd_ushort_min( resources.num_queue_pairs, selected.num_queue_pairs );
  info->vector_cnt     = resources.max_vectors;
  info->max_mtu        = resources.max_mtu;
  info->rss_key_sz     = resources.rss_key_sz;
  info->rss_lut_sz     = resources.rss_lut_sz;
  info->wb_on_itr      = !!(resources.capability_flags & FD_IAVF_VIRTCHNL_CAP_WB_ON_ITR);
  if( FD_UNLIKELY( !info->rss_key_sz || info->rss_key_sz>FD_IAVF_RSS_KEY_MAX_SZ ||
                   !info->rss_lut_sz || info->rss_lut_sz>FD_IAVF_RSS_LUT_MAX_SZ ) ) {
    FD_LOG_WARNING(( "invalid RSS sizes, key %u must be in [1,%lu], LUT %u must be in [1,%lu] (%i-%s)",
                     info->rss_key_sz, FD_IAVF_RSS_KEY_MAX_SZ, info->rss_lut_sz, FD_IAVF_RSS_LUT_MAX_SZ, EPROTO, fd_io_strerror( EPROTO ) ));
    errno = EPROTO;
    return -1;
  }
  fd_memcpy( info->mac_addr, selected.default_mac_addr, sizeof(info->mac_addr) );
  return fd_iavf_virtchnl_wait_link_event( vfio, adminq, info );
}

int
fd_iavf_virtchnl_poll_link( fd_iavf_vfio_t *    vfio,
                            fd_iavf_adminq_t *  adminq,
                            fd_iavf_vf_info_t * info,
                            int *               changed ) {
  if( FD_UNLIKELY( !vfio || !adminq || !info || !changed ) ) {
    errno = EINVAL;
    return -1;
  }

  int const  old_usable  = info->link_usable;
  /* Detect resets even when no PF event was received */
  uint       reset_state = fd_iavf_mmio_read( vfio, FD_IAVF_VFGEN_RSTAT ) & FD_IAVF_VFGEN_RSTAT_STATE;
  if( FD_UNLIKELY( (reset_state!=FD_IAVF_VFR_STATE_COMPLETED && reset_state!=FD_IAVF_VFR_STATE_ACTIVE) ||
                   !(fd_iavf_mmio_read( vfio, FD_IAVF_VF_ATQLEN ) & FD_IAVF_ATQ_ENABLE) ||
                   !(fd_iavf_mmio_read( vfio, FD_IAVF_VF_ARQLEN ) & FD_IAVF_ARQ_ENABLE) ) ) {
    errno = ECONNRESET;
    return -1;
  }
  fd_iavf_virtchnl_apply_event( adminq, info );

  /* Bound event processing so housekeeping can return */
  for( ulong i=0UL; i<FD_IAVF_ADMINQ_DEPTH; i++ ) {
    uchar message[ FD_IAVF_ADMINQ_BUF_SZ ];
    ulong message_sz = sizeof(message);
    uint virtchnl_op;
    int  virtchnl_status;
    int const received = fd_iavf_adminq_recv( vfio, adminq, &virtchnl_op, &virtchnl_status,
                                              message, &message_sz );
    if( FD_UNLIKELY( received<0 ) ) {
      int err = errno;
      FD_LOG_WARNING(( "link event receive failed (%i-%s)", err, fd_io_strerror( err ) ));
      errno = err;
      return -1;
    }
    if( !received ) break;
    if( FD_UNLIKELY( fd_iavf_virtchnl_cache_event( adminq, virtchnl_op, virtchnl_status,
                                                 message, message_sz ) ) ) return -1;
    fd_iavf_virtchnl_apply_event( adminq, info );
  }

  *changed = old_usable!=info->link_usable;
  return 0;
}

ulong
fd_iavf_queue_footprint( uint tx_depth,
                         uint rx_depth ) {
  if( FD_UNLIKELY( tx_depth<FD_IAVF_QUEUE_DEPTH_MIN || tx_depth>FD_IAVF_QUEUE_DEPTH_MAX || !fd_uint_is_pow2( tx_depth ) ||
                   rx_depth<FD_IAVF_QUEUE_DEPTH_MIN || rx_depth>FD_IAVF_QUEUE_DEPTH_MAX || !fd_uint_is_pow2( rx_depth ) ) ) return 0UL;
  /* TX and RX descriptor rings followed by software TX completion tracking */
  ulong tx_ring_sz = fd_ulong_align_up( (ulong)tx_depth*sizeof(fd_iavf_tx_desc_t), FD_IAVF_PAGE_SZ );
  ulong rx_ring_sz = fd_ulong_align_up( (ulong)rx_depth*sizeof(fd_iavf_hw_rx_desc_t), FD_IAVF_PAGE_SZ );
  ulong tx_comp_sz = fd_ulong_align_up( (ulong)tx_depth*sizeof(ulong), FD_IAVF_PAGE_SZ );
  return tx_ring_sz + rx_ring_sz + tx_comp_sz;
}

int
fd_iavf_virtchnl_configure_queue( fd_iavf_vfio_t *            vfio,
                                  fd_iavf_adminq_t *          adminq,
                                  fd_iavf_vf_info_t const *   info,
                                  fd_iavf_vfio_tile_t const * tile,
                                  ulong                       dma_iova,
                                  uint                        rx_buffer_sz,
                                  uint                        max_frame_sz ) {
  if( FD_UNLIKELY( !info->queue_pair_cnt ) ) {
    FD_LOG_WARNING(( "VF has no queue pairs" ));
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( info->vector_cnt<2U ) ) {
    FD_LOG_WARNING(( "VF has %hu interrupt vectors, queue setup requires at least 2", info->vector_cnt ));
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( !rx_buffer_sz || (rx_buffer_sz & 127U) ) ) {
    FD_LOG_WARNING(( "RX buffer size %u must be a nonzero multiple of 128", rx_buffer_sz ));
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( max_frame_sz<64U || max_frame_sz>=16384U || max_frame_sz>rx_buffer_sz ||
                   (info->max_mtu && max_frame_sz>info->max_mtu) ) ) {
    FD_LOG_WARNING(( "frame size %u must be in [64,16383], fit RX buffer %u and not exceed nonzero VF MTU limit %hu", max_frame_sz, rx_buffer_sz, info->max_mtu ));
    errno = EINVAL;
    return -1;
  }

  if( FD_UNLIKELY( !tile->tx_queue || !tile->rx_queue || tile->tx_queue==tile->rx_queue || !tile->queue_memory ) ) {
    FD_LOG_WARNING(( "queue pair requires distinct non-NULL TX/RX queue state and non-NULL DMA memory" ));
    errno = EINVAL;
    return -1;
  }
  uint const tx_depth = tile->tx_queue->depth;
  uint const rx_depth = tile->rx_queue->depth;
  ulong const footprint = fd_iavf_queue_footprint( tx_depth, rx_depth );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "queue depths TX %u, RX %u must be powers of two in [%u,%u]", tx_depth, rx_depth, FD_IAVF_QUEUE_DEPTH_MIN, FD_IAVF_QUEUE_DEPTH_MAX ));
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( tile->queue_memory_sz<footprint || footprint>ULONG_MAX-dma_iova ) ) {
    FD_LOG_WARNING(( "invalid queue DMA bounds, memory size %lu, required %lu, IOVA %#lx", tile->queue_memory_sz, footprint, dma_iova ));
    errno = EINVAL;
    return -1;
  }

  ulong const tx_ring_sz = fd_ulong_align_up( (ulong)tx_depth*sizeof(fd_iavf_tx_desc_t), FD_IAVF_PAGE_SZ );
  ulong const rx_ring_sz = fd_ulong_align_up( (ulong)rx_depth*sizeof(fd_iavf_hw_rx_desc_t), FD_IAVF_PAGE_SZ );
  if( FD_UNLIKELY( fd_iavf_vfio_dma_map( vfio, tile->queue_memory, footprint, dma_iova ) ) ) return -1;
  fd_memset( tile->queue_memory, 0, footprint );
  *tile->tx_queue = (fd_iavf_queue_t) {
    .ring      = tile->queue_memory,
    .depth     = tx_depth,
    .tail      = (volatile uint *)(vfio->bar0 + FD_IAVF_TX_TAIL( 0U )),
    .comp_ring = (ulong *)((uchar *)tile->queue_memory + tx_ring_sz + rx_ring_sz)
  };
  *tile->rx_queue = (fd_iavf_queue_t) {
    .ring  = (uchar *)tile->queue_memory + tx_ring_sz,
    .depth = rx_depth,
    .tail  = (volatile uint *)(vfio->bar0 + FD_IAVF_RX_TAIL( 0U ))
  };
  fd_iavf_virtchnl_queue_config_t config = { .vsi_id=info->vsi_id, .queue_pair_cnt=1U };
  config.pairs[0].tx = (fd_iavf_virtchnl_txq_info_t) {
    .vsi_id=info->vsi_id, .queue_id=0U, .ring_len=(ushort)tx_depth, .ring_iova=dma_iova
  };
  /* Without flexible RX descriptor negotiation, the PF uses the 32-byte base format */
  config.pairs[0].rx = (fd_iavf_virtchnl_rxq_info_t) {
    .vsi_id=info->vsi_id, .queue_id=0U, .ring_len=rx_depth,
    .data_buffer_sz=rx_buffer_sz, .max_frame_sz=max_frame_sz, .ring_iova=dma_iova+tx_ring_sz
  };
  ulong response_sz = 0UL;
  if( FD_UNLIKELY( fd_iavf_virtchnl_request( vfio, adminq, FD_IAVF_VIRTCHNL_CONFIG_QUEUES,
                                             &config, sizeof(config), NULL, &response_sz ) ) ) return -1;

  /* Virtchnl requires queue interrupt mappings even when polling
     Vector 0 is reserved for Admin Queue events */
  fd_iavf_virtchnl_irq_map_t irq_map = {
    .vector_cnt=1U, .vsi_id=info->vsi_id, .vector_id=1U, .rx_queue_map=1U, .tx_queue_map=1U
  };
  response_sz = 0UL;
  if( FD_UNLIKELY( fd_iavf_virtchnl_request( vfio, adminq, FD_IAVF_VIRTCHNL_CONFIG_IRQ_MAP,
                                             &irq_map, sizeof(irq_map), NULL, &response_sz ) ) ) return -1;

  if( info->wb_on_itr ) {
    /* WB_ON_ITR flushes sparse RX completions without interrupts.
       Use DPDK's interval of 2 hardware timer counts. */
    fd_iavf_mmio_write( vfio, FD_IAVF_VFINT_DYN_CTL,
                        FD_IAVF_VFINT_WB_ON_ITR | (2U<<FD_IAVF_VFINT_INTERVAL_SHIFT) );
    (void)fd_iavf_mmio_read( vfio, FD_IAVF_VFGEN_RSTAT );
  }
  return 0;
}

int
fd_iavf_virtchnl_enable_queue( fd_iavf_vfio_t *            vfio,
                               fd_iavf_adminq_t *          adminq,
                               fd_iavf_vf_info_t *         info,
                               fd_iavf_vfio_tile_t const * tile ) {
  if( FD_UNLIKELY( !vfio || !adminq || !info || !tile || !info->queue_pair_cnt ) ) {
    errno = EINVAL;
    return -1;
  }
  fd_iavf_queue_t * tx_queue = tile->tx_queue;
  fd_iavf_queue_t * rx_queue = tile->rx_queue;
  /* Post RX buffers before enabling reception on the VF */
  if( FD_UNLIKELY( !tx_queue || !rx_queue || tx_queue==rx_queue ||
                   tx_queue->enabled || rx_queue->enabled || !rx_queue->posted ||
                   rx_queue->posted!=rx_queue->prod ||
                   rx_queue->prod-rx_queue->cons>=rx_queue->depth ) ) {
    FD_LOG_WARNING(( "queue pair must have distinct disabled TX/RX queues and posted RX buffers below ring capacity" ));
    errno = EINVAL;
    return -1;
  }
  fd_iavf_virtchnl_queue_select_t select = { .vsi_id=info->vsi_id, .rx_queue_map=1U, .tx_queue_map=1U };
  ulong response_sz = 0UL;
  if( FD_UNLIKELY( fd_iavf_virtchnl_request( vfio, adminq, FD_IAVF_VIRTCHNL_ENABLE_QUEUES,
                                             &select, sizeof(select), NULL, &response_sz ) ) ) return -1;
  tx_queue->enabled = 1;
  rx_queue->enabled = 1;

  /* Queue enable triggers a new PF link report */
  info->link_usable = 0;
  return fd_iavf_virtchnl_wait_link_event( vfio, adminq, info );
}

static int
fd_iavf_virtchnl_add_mac( fd_iavf_vfio_t *          vfio,
                          fd_iavf_adminq_t *        adminq,
                          fd_iavf_vf_info_t const * info ) {
  /* Linux virtchnl_ether_addr_list with one primary address. PF message
     validation requires space for one extra virtchnl_ether_addr entry. */
  struct {
    ushort vsi_id;
    ushort count;
    uchar  mac[ 6 ];
    uchar  type;
    uchar  pad;
    uchar  legacy_padding[ 8 ];
  } request = { .vsi_id=info->vsi_id, .count=1U, .type=FD_IAVF_VIRTCHNL_MAC_PRIMARY };
  FD_STATIC_ASSERT( sizeof(request)==20UL, iavf_mac_request_sz );
  fd_memcpy( request.mac, info->mac_addr, sizeof(request.mac) );
  ulong response_sz = 0UL;
  return fd_iavf_virtchnl_request( vfio, adminq, FD_IAVF_VIRTCHNL_ADD_ETH_ADDR,
                                   &request, sizeof(request), NULL, &response_sz );
}

static int
fd_iavf_virtchnl_configure_rss( fd_iavf_vfio_t *          vfio,
                                fd_iavf_adminq_t *        adminq,
                                fd_iavf_vf_info_t const * info,
                                uint                      queue_cnt ) {
  /* Configure the PF-managed RSS hash key */
  struct {
    ushort vsi_id;
    ushort count;
    uchar  bytes[ FD_IAVF_ADMINQ_BUF_SZ-FD_IAVF_RSS_KEY_HEADER_SZ ];
  } request = { .vsi_id=info->vsi_id, .count=(ushort)info->rss_key_sz };
  FD_STATIC_ASSERT( offsetof(__typeof__(request), bytes)==FD_IAVF_RSS_KEY_HEADER_SZ, iavf_rss_key_header_sz );
  FD_STATIC_ASSERT( offsetof(__typeof__(request), bytes)==FD_IAVF_RSS_LUT_HEADER_SZ, iavf_rss_lut_header_sz );
  FD_STATIC_ASSERT( sizeof(request)==FD_IAVF_ADMINQ_BUF_SZ, iavf_rss_request_sz );
  if( FD_UNLIKELY( !fd_rng_secure( request.bytes, info->rss_key_sz ) ) ) return -1;
  ulong response_sz = 0UL;
  if( FD_UNLIKELY( fd_iavf_virtchnl_request( vfio, adminq, FD_IAVF_VIRTCHNL_CONFIG_RSS_KEY,
                                             &request, FD_IAVF_RSS_KEY_LEGACY_SZ+(ulong)info->rss_key_sz-1UL,
                                             NULL, &response_sz ) ) ) return -1;

  /* Map RSS entries to the configured queue */
  fd_memset( request.bytes, 0, sizeof(request.bytes) );
  request.count = (ushort)info->rss_lut_sz;
  for( uint i=0U; i<info->rss_lut_sz; i++ ) request.bytes[i] = (uchar)(i%queue_cnt);
  response_sz = 0UL;
  return fd_iavf_virtchnl_request( vfio, adminq, FD_IAVF_VIRTCHNL_CONFIG_RSS_LUT,
                                   &request, FD_IAVF_RSS_LUT_LEGACY_SZ+(ulong)info->rss_lut_sz-1UL,
                                   NULL, &response_sz );
}

int
fd_iavf_init( fd_iavf_vfio_t *            vfio,
              fd_iavf_adminq_t *          adminq,
              fd_iavf_vf_info_t *         info,
              fd_iavf_vfio_tile_t const * tile,
              char const *                pci_addr,
              uint                        rx_buffer_sz,
              uint                        max_frame_sz ) {
  if( FD_UNLIKELY( !vfio || !adminq || !info || !tile ) ) {
    errno = EINVAL;
    return -1;
  }

  /* Place Admin Queue and queue IOVAs after packet mappings to avoid overlap */
  if( FD_UNLIKELY( tile->packet_memory_sz>ULONG_MAX-tile->packet_iova ) ) {
    errno = EINVAL;
    return -1;
  }
  ulong const adminq_iova = tile->packet_iova+tile->packet_memory_sz;
  ulong const adminq_memory_sz = fd_iavf_adminq_footprint();
  if( FD_UNLIKELY( adminq_memory_sz>ULONG_MAX-adminq_iova ) ) {
    errno = EINVAL;
    return -1;
  }
  ulong const queue_iova = adminq_iova+adminq_memory_sz;

  /* Open and reset the VF */
  fd_iavf_pci_info_t pci;
  if( FD_UNLIKELY( fd_iavf_pci_probe( &pci, pci_addr ) ) ) return -1;
  if( FD_UNLIKELY( fd_iavf_vfio_init( vfio, &pci ) ) ) return -1;

  /* Establish PF communication and discover VF resources */
  if( FD_UNLIKELY( fd_iavf_adminq_init( vfio, adminq, adminq->dma_memory, adminq_iova ) ) ) return -1;
  if( FD_UNLIKELY( fd_iavf_virtchnl_version( vfio, adminq ) ) ) return -1;
  if( FD_UNLIKELY( fd_iavf_virtchnl_get_resources( vfio, adminq, info ) ) ) return -1;

  /* Configure the queue pair and receive delivery */
  if( FD_UNLIKELY( fd_iavf_virtchnl_configure_queue( vfio, adminq, info, tile,
                                                    queue_iova, rx_buffer_sz, max_frame_sz ) ) ) return -1;
  if( FD_UNLIKELY( fd_iavf_virtchnl_add_mac( vfio, adminq, info ) ) ) return -1;
  if( FD_UNLIKELY( fd_iavf_virtchnl_configure_rss( vfio, adminq, info, 1U ) ) ) return -1;

  /* Map packet buffers before the caller posts RX buffers and enables queues */
  return fd_iavf_vfio_dma_map( vfio, tile->packet_memory, tile->packet_memory_sz, tile->packet_iova );
}
