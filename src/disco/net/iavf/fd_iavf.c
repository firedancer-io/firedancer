#include "fd_iavf_private.h"
#include "../../../util/fd_util.h"

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

/* Intel IAVF_VFGEN_RSTAT register and virtchnl_vfr_states values. */
#define FD_IAVF_VFGEN_RSTAT           (0x8800UL)
#define FD_IAVF_VFGEN_RSTAT_STATE     (0x3U)
#define FD_IAVF_VFR_STATE_COMPLETED   (1U)
#define FD_IAVF_VFR_STATE_ACTIVE      (2U)

/* Intel IAVF Admin Queue registers. */
#define FD_IAVF_VF_ARQBAH  (0x6000UL)
#define FD_IAVF_VF_ARQBAL  (0x6c00UL)
#define FD_IAVF_VF_ARQH    (0x7400UL)
#define FD_IAVF_VF_ARQLEN  (0x8000UL)
#define FD_IAVF_VF_ARQT    (0x7000UL)
#define FD_IAVF_VF_ATQBAH  (0x7800UL)
#define FD_IAVF_VF_ATQBAL  (0x7c00UL)
#define FD_IAVF_VF_ATQH    (0x6400UL)
#define FD_IAVF_VF_ATQLEN  (0x6800UL)
#define FD_IAVF_VF_ATQT    (0x8400UL)
#define FD_IAVF_AQ_ENABLE  (1U<<31)
#define FD_IAVF_AQ_HEAD    (0x3ffU)

#define FD_IAVF_TX_TAIL(queue_id) (0x0000UL + 4UL*(queue_id))
#define FD_IAVF_RX_TAIL(queue_id) (0x2000UL + 4UL*(queue_id))

#define FD_IAVF_ADMINQ_DEPTH       (32UL)
#define FD_IAVF_ADMINQ_BUF_SZ      (4096UL)
#define FD_IAVF_ADMINQ_DESC_OFF    (0UL)
#define FD_IAVF_ADMINQ_RECV_OFF    (4096UL)
#define FD_IAVF_ADMINQ_SEND_BUF_OFF (8192UL)
#define FD_IAVF_ADMINQ_RECV_BUF_OFF (FD_IAVF_ADMINQ_SEND_BUF_OFF + FD_IAVF_ADMINQ_DEPTH*FD_IAVF_ADMINQ_BUF_SZ)
#define FD_IAVF_ADMINQ_FOOTPRINT    (FD_IAVF_ADMINQ_RECV_BUF_OFF + FD_IAVF_ADMINQ_DEPTH*FD_IAVF_ADMINQ_BUF_SZ)

/* Intel libie_aq_desc hardware format. */
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

/* Intel LIBIE_AQ_FLAG_* descriptor flags. */
#define FD_IAVF_AQ_FLAG_ERR (1U<<2)
#define FD_IAVF_AQ_FLAG_LB  (1U<<9)
#define FD_IAVF_AQ_FLAG_RD  (1U<<10)
#define FD_IAVF_AQ_FLAG_BUF (1U<<12)
#define FD_IAVF_AQ_FLAG_SI  (1U<<13)

/* Intel Admin Queue virtualization opcodes and virtchnl operations. */
#define FD_IAVF_AQ_SEND_MSG_TO_PF (0x0801U)
#define FD_IAVF_AQ_SEND_MSG_TO_VF (0x0802U)
#define FD_IAVF_VIRTCHNL_VERSION          (1U)
#define FD_IAVF_VIRTCHNL_GET_VF_RESOURCES (3U)
#define FD_IAVF_VIRTCHNL_CONFIG_QUEUES    (6U)
#define FD_IAVF_VIRTCHNL_CONFIG_IRQ_MAP   (7U)
#define FD_IAVF_VIRTCHNL_ENABLE_QUEUES    (8U)
#define FD_IAVF_VIRTCHNL_ADD_ETH_ADDR    (10U)
#define FD_IAVF_VIRTCHNL_CONFIG_RSS_KEY  (23U)
#define FD_IAVF_VIRTCHNL_CONFIG_RSS_LUT  (24U)
#define FD_IAVF_VIRTCHNL_EVENT            (17U)

#define FD_IAVF_VIRTCHNL_CAP_L2             (1U<<0)
#define FD_IAVF_VIRTCHNL_CAP_ADV_LINK_SPEED (1U<<7)
#define FD_IAVF_VIRTCHNL_CAP_RSS_PF         (1U<<19)
#define FD_IAVF_VIRTCHNL_VSI_SRIOV          (6)

struct fd_iavf_virtchnl_version {
  uint major;
  uint minor;
};

typedef struct fd_iavf_virtchnl_version fd_iavf_virtchnl_version_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_virtchnl_version_t)==8UL, iavf_virtchnl_version_sz );

/* Intel virtchnl_vf_resource header. */
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

/* Intel virtchnl_vsi_resource hardware format. */
struct fd_iavf_virtchnl_vsi_resource {
  ushort vsi_id;
  ushort num_queue_pairs;
  int    vsi_type;
  ushort qset_handle;
  uchar  default_mac_addr[ 6 ];
};

typedef struct fd_iavf_virtchnl_vsi_resource fd_iavf_virtchnl_vsi_resource_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_virtchnl_vsi_resource_t)==16UL, iavf_virtchnl_vsi_resource_sz );

/* Intel virtchnl_pf_event hardware format. */
struct fd_iavf_virtchnl_event {
  int   event;
  uint  link_speed;
  uchar link_up;
  uchar pad[ 3 ];
  int   severity;
};

typedef struct fd_iavf_virtchnl_event fd_iavf_virtchnl_event_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_virtchnl_event_t)==16UL, iavf_virtchnl_event_sz );

/* Intel virtchnl_txq_info hardware format. */
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

/* Intel virtchnl_rxq_info hardware format. */
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

struct fd_iavf_virtchnl_queue_config {
  ushort vsi_id;
  ushort queue_pair_cnt;
  uint   pad;
  fd_iavf_virtchnl_txq_info_t tx;
  fd_iavf_virtchnl_rxq_info_t rx;
  /* Linux virtchnl legacy sizing includes one extra zero queue pair. */
  uchar legacy_padding[ 64 ];
};

typedef struct fd_iavf_virtchnl_queue_config fd_iavf_virtchnl_queue_config_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_virtchnl_queue_config_t)==136UL, iavf_virtchnl_queue_config_sz );

struct fd_iavf_virtchnl_irq_map {
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

typedef struct fd_iavf_virtchnl_irq_map fd_iavf_virtchnl_irq_map_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_virtchnl_irq_map_t)==26UL, iavf_virtchnl_irq_map_sz );

struct fd_iavf_virtchnl_queue_select {
  ushort vsi_id;
  ushort pad;
  uint   rx_queue_map;
  uint   tx_queue_map;
};

typedef struct fd_iavf_virtchnl_queue_select fd_iavf_virtchnl_queue_select_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_virtchnl_queue_select_t)==12UL, iavf_virtchnl_queue_select_sz );

/* Intel Ethernet Adaptive Virtual Function PCI IDs supported by Linux iavf. */
static int
fd_iavf_device_supported( ushort device_id ) {
  return device_id==0x154cU ||
         device_id==0x1571U ||
         device_id==0x1889U ||
         device_id==0x37cdU;
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
  FD_TEST( path_sz>=0 && (ulong)path_sz<sizeof(devices_path) );

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

  struct stat device_stat;
  if( FD_UNLIKELY( stat( device_path, &device_stat ) ) ) return -1;
  if( FD_UNLIKELY( !S_ISDIR( device_stat.st_mode ) ) ) {
    FD_LOG_WARNING(( "PCI path is not a directory, %s (%i-%s)", device_path, ENODEV, fd_io_strerror( ENODEV ) ));
    errno = ENODEV;
    return -1;
  }

  char path[ PATH_MAX ];
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
  if( container_set && vfio->group_fd>=0 ) ioctl( vfio->group_fd, VFIO_GROUP_UNSET_CONTAINER );
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
  struct timespec delay = { .tv_sec=0L, .tv_nsec=1000000L };
  for( ulong retry=0UL; retry<10000UL; retry++ ) {
    uint reset_state = *reset_reg & FD_IAVF_VFGEN_RSTAT_STATE;
    if( reset_state==FD_IAVF_VFR_STATE_COMPLETED ||
        reset_state==FD_IAVF_VFR_STATE_ACTIVE ) {
      vfio->reset_state = reset_state;
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
  vfio->bar0    = (volatile uchar *)bar0_map;
  vfio->bar0_sz = (ulong)bar0.size;

  return 0;
}

int
fd_iavf_vfio_init( fd_iavf_vfio_t *           vfio,
                   fd_iavf_pci_info_t const * info ) {
  if( FD_UNLIKELY( !vfio || !info || strcmp( info->driver, "vfio-pci" ) ) ) {
    errno = EINVAL;
    return -1;
  }

  *vfio = (fd_iavf_vfio_t) {
    .container_fd = -1,
    .group_fd     = -1,
    .device_fd    = -1
  };
  int container_set = 0;
  char const * operation = "open(/dev/vfio/vfio)";

  vfio->container_fd = open( "/dev/vfio/vfio", O_RDWR|O_CLOEXEC );
  if( FD_UNLIKELY( vfio->container_fd<0 ) ) goto fail;
  operation = "VFIO_GET_API_VERSION";
  int api_version = ioctl( vfio->container_fd, VFIO_GET_API_VERSION );
  if( FD_UNLIKELY( api_version<0 ) ) goto fail;
  if( FD_UNLIKELY( api_version!=VFIO_API_VERSION ) ) {
    operation = "unsupported VFIO API version";
    errno = EPROTONOSUPPORT;
    goto fail;
  }
  operation = "VFIO_CHECK_EXTENSION(TYPE1v2)";
  int type1v2_supported = ioctl( vfio->container_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1v2_IOMMU );
  if( FD_UNLIKELY( type1v2_supported<0 ) ) goto fail;
  if( FD_UNLIKELY( !type1v2_supported ) ) {
    operation = "VFIO TYPE1v2 IOMMU unsupported";
    errno = EPROTONOSUPPORT;
    goto fail;
  }

  char group_path[ 64 ];
  int group_path_sz = snprintf( group_path, sizeof(group_path), "/dev/vfio/%u", info->iommu_group );
  FD_TEST( group_path_sz>=0 && (ulong)group_path_sz<sizeof(group_path) );
  operation = "open VFIO group";
  vfio->group_fd = open( group_path, O_RDWR|O_CLOEXEC );
  if( FD_UNLIKELY( vfio->group_fd<0 ) ) goto fail;

  operation = "VFIO_GROUP_GET_STATUS";
  struct vfio_group_status group_status = { .argsz=sizeof(group_status) };
  if( FD_UNLIKELY( ioctl( vfio->group_fd, VFIO_GROUP_GET_STATUS, &group_status ) ) ) goto fail;
  if( FD_UNLIKELY( !(group_status.flags & VFIO_GROUP_FLAGS_VIABLE) ) ) {
    operation = "VFIO group not viable";
    errno = EBUSY;
    goto fail;
  }
  if( FD_UNLIKELY( group_status.flags & VFIO_GROUP_FLAGS_CONTAINER_SET ) ) {
    operation = "VFIO group already has a container";
    errno = EBUSY;
    goto fail;
  }
  operation = "VFIO_GROUP_SET_CONTAINER";
  if( FD_UNLIKELY( ioctl( vfio->group_fd, VFIO_GROUP_SET_CONTAINER, &vfio->container_fd ) ) ) goto fail;
  container_set = 1;
  operation = "VFIO_SET_IOMMU";
  if( FD_UNLIKELY( ioctl( vfio->container_fd, VFIO_SET_IOMMU, VFIO_TYPE1v2_IOMMU ) ) ) goto fail;

  operation = "VFIO_IOMMU_GET_INFO";
  struct vfio_iommu_type1_info iommu_info = { .argsz=sizeof(iommu_info) };
  if( FD_UNLIKELY( ioctl( vfio->container_fd, VFIO_IOMMU_GET_INFO, &iommu_info ) ) ) goto fail;
  if( FD_UNLIKELY( !(iommu_info.flags & VFIO_IOMMU_INFO_PGSIZES) || !iommu_info.iova_pgsizes ) ) {
    operation = "VFIO IOMMU page sizes missing";
    errno = EPROTO;
    goto fail;
  }
  vfio->iova_pgsizes = (ulong)iommu_info.iova_pgsizes;

  operation = "VFIO_GROUP_GET_DEVICE_FD";
  vfio->device_fd = ioctl( vfio->group_fd, VFIO_GROUP_GET_DEVICE_FD, info->pci_addr );
  if( FD_UNLIKELY( vfio->device_fd<0 ) ) goto fail;

  operation = "VFIO_DEVICE_GET_INFO";
  struct vfio_device_info device_info = { .argsz=sizeof(device_info) };
  if( FD_UNLIKELY( ioctl( vfio->device_fd, VFIO_DEVICE_GET_INFO, &device_info ) ) ) goto fail;
  if( FD_UNLIKELY( !(device_info.flags & VFIO_DEVICE_FLAGS_PCI) ||
                    !(device_info.flags & VFIO_DEVICE_FLAGS_RESET) ) ) {
    operation = "VFIO device lacks PCI or reset support";
    errno = EOPNOTSUPP;
    goto fail;
  }
  if( FD_UNLIKELY( device_info.num_regions<=VFIO_PCI_BAR0_REGION_INDEX ) ) {
    operation = "VFIO BAR0 region missing";
    errno = EPROTO;
    goto fail;
  }

  operation = "VFIO BAR0 mapping";
  if( FD_UNLIKELY( fd_iavf_vfio_map_bar( vfio ) ) ) goto fail;

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

  ulong page_sz = vfio->iova_pgsizes & -vfio->iova_pgsizes;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)memory, page_sz ) ||
                   !fd_ulong_is_aligned( memory_sz,     page_sz ) ||
                   !fd_ulong_is_aligned( iova,          page_sz ) ||
                   (ulong)memory>ULONG_MAX-memory_sz ||
                   memory_sz>ULONG_MAX-iova ) ) {
    FD_LOG_WARNING(( "invalid DMA mapping bounds or alignment, size %lu, IOVA %#lx", memory_sz, iova ));
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
  volatile uint const * ptr = (volatile uint const *)(vfio->bar0 + reg);
  uint value = *ptr;
  FD_COMPILER_MFENCE();
  return value;
}

static inline void
fd_iavf_mmio_write( fd_iavf_vfio_t * vfio,
                    ulong            reg,
                    uint             value ) {
  FD_COMPILER_MFENCE();
  volatile uint * ptr = (volatile uint *)(vfio->bar0 + reg);
  *ptr = value;
  FD_COMPILER_MFENCE();
}

static inline void
fd_iavf_dma_to_device( void ) {
#if FD_HAS_X86
  FD_COMPILER_MFENCE();
#elif FD_HAS_ARM
  __asm__ __volatile__( "dmb oshst" ::: "memory" );
#else
  FD_HW_MFENCE_ST();
#endif
}

static inline void
fd_iavf_dma_from_device( void ) {
#if FD_HAS_X86
  __asm__ __volatile__( "lfence" ::: "memory" );
#elif FD_HAS_ARM
  __asm__ __volatile__( "dmb oshld" ::: "memory" );
#else
  FD_HW_MFENCE();
#endif
}

void
fd_iavf_adminq_regs( fd_iavf_vfio_t const *  vfio,
                     fd_iavf_adminq_regs_t * regs ) {
  regs->atq_head = fd_iavf_mmio_read( vfio, FD_IAVF_VF_ATQH   );
  regs->atq_tail = fd_iavf_mmio_read( vfio, FD_IAVF_VF_ATQT   );
  regs->atq_len  = fd_iavf_mmio_read( vfio, FD_IAVF_VF_ATQLEN );
  regs->arq_head = fd_iavf_mmio_read( vfio, FD_IAVF_VF_ARQH   );
  regs->arq_tail = fd_iavf_mmio_read( vfio, FD_IAVF_VF_ARQT   );
  regs->arq_len  = fd_iavf_mmio_read( vfio, FD_IAVF_VF_ARQLEN );
}

static inline fd_iavf_aq_desc_t *
fd_iavf_atq_desc( fd_iavf_adminq_t * adminq,
                  uint               idx ) {
  return (fd_iavf_aq_desc_t *)((uchar *)adminq->dma_memory + FD_IAVF_ADMINQ_DESC_OFF) + idx;
}

static inline fd_iavf_aq_desc_t *
fd_iavf_arq_desc( fd_iavf_adminq_t * adminq,
                  uint               idx ) {
  return (fd_iavf_aq_desc_t *)((uchar *)adminq->dma_memory + FD_IAVF_ADMINQ_RECV_OFF) + idx;
}

static inline uchar *
fd_iavf_atq_buf( fd_iavf_adminq_t * adminq,
                 uint               idx ) {
  return (uchar *)adminq->dma_memory + FD_IAVF_ADMINQ_SEND_BUF_OFF + (ulong)idx*FD_IAVF_ADMINQ_BUF_SZ;
}

static inline uchar *
fd_iavf_arq_buf( fd_iavf_adminq_t * adminq,
                 uint               idx ) {
  return (uchar *)adminq->dma_memory + FD_IAVF_ADMINQ_RECV_BUF_OFF + (ulong)idx*FD_IAVF_ADMINQ_BUF_SZ;
}

static inline ulong
fd_iavf_atq_buf_iova( fd_iavf_adminq_t const * adminq,
                      uint                     idx ) {
  return adminq->dma_iova + FD_IAVF_ADMINQ_SEND_BUF_OFF + (ulong)idx*FD_IAVF_ADMINQ_BUF_SZ;
}

static inline ulong
fd_iavf_arq_buf_iova( fd_iavf_adminq_t const * adminq,
                      uint                     idx ) {
  return adminq->dma_iova + FD_IAVF_ADMINQ_RECV_BUF_OFF + (ulong)idx*FD_IAVF_ADMINQ_BUF_SZ;
}

static inline void
fd_iavf_aq_desc_set_addr( fd_iavf_aq_desc_t * desc,
                          ulong               iova ) {
  desc->addr_high = (uint)(iova>>32);
  desc->addr_low  = (uint)iova;
}

static void
fd_iavf_arq_post( fd_iavf_adminq_t * adminq,
                  uint               idx ) {
  fd_iavf_aq_desc_t * desc = fd_iavf_arq_desc( adminq, idx );
  fd_memset( desc, 0, sizeof(*desc) );
  desc->flags   = FD_IAVF_AQ_FLAG_BUF|FD_IAVF_AQ_FLAG_LB;
  desc->datalen = FD_IAVF_ADMINQ_BUF_SZ;
  fd_iavf_aq_desc_set_addr( desc, fd_iavf_arq_buf_iova( adminq, idx ) );
}

ulong
fd_iavf_adminq_footprint( void ) {
  return FD_IAVF_ADMINQ_FOOTPRINT;
}

int
fd_iavf_adminq_init( fd_iavf_vfio_t *   vfio,
                     fd_iavf_adminq_t * adminq,
                     void *             dma_memory,
                     ulong              dma_memory_sz,
                     ulong              dma_iova ) {
  if( FD_UNLIKELY( !vfio || !vfio->bar0 || !adminq || !dma_memory ||
                   dma_memory_sz<FD_IAVF_ADMINQ_FOOTPRINT ||
                   !fd_ulong_is_aligned( (ulong)dma_memory, 4096UL ) ||
                   !fd_ulong_is_aligned( dma_iova,          4096UL ) ||
                   !(vfio->iova_pgsizes & 4096UL) ) ) {
    errno = EINVAL;
    return -1;
  }

  fd_memset( dma_memory, 0, FD_IAVF_ADMINQ_FOOTPRINT );
  if( FD_UNLIKELY( fd_iavf_vfio_dma_map( vfio, dma_memory, FD_IAVF_ADMINQ_FOOTPRINT, dma_iova ) ) ) return -1;

  *adminq = (fd_iavf_adminq_t) {
    .dma_memory    = dma_memory,
    .dma_memory_sz = FD_IAVF_ADMINQ_FOOTPRINT,
    .dma_iova      = dma_iova
  };
  for( uint idx=0U; idx<(uint)FD_IAVF_ADMINQ_DEPTH; idx++ ) fd_iavf_arq_post( adminq, idx );
  fd_iavf_dma_to_device();

  ulong atq_iova = dma_iova + FD_IAVF_ADMINQ_DESC_OFF;
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ATQH,   0U );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ATQT,   0U );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ATQLEN, (uint)FD_IAVF_ADMINQ_DEPTH|FD_IAVF_AQ_ENABLE );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ATQBAL, (uint)atq_iova );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ATQBAH, (uint)(atq_iova>>32) );

  ulong arq_iova = dma_iova + FD_IAVF_ADMINQ_RECV_OFF;
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ARQH,   0U );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ARQT,   0U );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ARQLEN, (uint)FD_IAVF_ADMINQ_DEPTH|FD_IAVF_AQ_ENABLE );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ARQBAL, (uint)arq_iova );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ARQBAH, (uint)(arq_iova>>32) );
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ARQT,   (uint)FD_IAVF_ADMINQ_DEPTH-1U );

  if( FD_UNLIKELY( fd_iavf_mmio_read( vfio, FD_IAVF_VF_ATQBAL )!=(uint)atq_iova ||
                   fd_iavf_mmio_read( vfio, FD_IAVF_VF_ATQBAH )!=(uint)(atq_iova>>32) ||
                   fd_iavf_mmio_read( vfio, FD_IAVF_VF_ARQBAL )!=(uint)arq_iova ||
                   fd_iavf_mmio_read( vfio, FD_IAVF_VF_ARQBAH )!=(uint)(arq_iova>>32) ||
                   fd_iavf_mmio_read( vfio, FD_IAVF_VF_ATQLEN )!=((uint)FD_IAVF_ADMINQ_DEPTH|FD_IAVF_AQ_ENABLE) ||
                   fd_iavf_mmio_read( vfio, FD_IAVF_VF_ARQLEN )!=((uint)FD_IAVF_ADMINQ_DEPTH|FD_IAVF_AQ_ENABLE) ) ) {
    FD_LOG_WARNING(( "Admin Queue register verification failed (%i-%s)", EIO, fd_io_strerror( EIO ) ));
    errno = EIO;
    return -1;
  }
  return 0;
}

static char const *
fd_iavf_virtchnl_op_name( uint op ) {
  switch( op ) {
  case FD_IAVF_VIRTCHNL_VERSION:          return "version exchange";
  case FD_IAVF_VIRTCHNL_GET_VF_RESOURCES: return "VF resource discovery";
  case FD_IAVF_VIRTCHNL_CONFIG_QUEUES:    return "queue configuration";
  case FD_IAVF_VIRTCHNL_CONFIG_IRQ_MAP:   return "IRQ mapping";
  case FD_IAVF_VIRTCHNL_ENABLE_QUEUES:    return "queue enable";
  case FD_IAVF_VIRTCHNL_ADD_ETH_ADDR:    return "MAC registration";
  case FD_IAVF_VIRTCHNL_CONFIG_RSS_KEY:  return "RSS key configuration";
  case FD_IAVF_VIRTCHNL_CONFIG_RSS_LUT:  return "RSS table configuration";
  default:                                 return "virtchnl request";
  }
}

static int
fd_iavf_atq_send( fd_iavf_vfio_t *   vfio,
                  fd_iavf_adminq_t * adminq,
                  uint               virtchnl_op,
                  void const *       message,
                  ulong              message_sz ) {
  FD_TEST( message || !message_sz );
  FD_TEST( message_sz<=FD_IAVF_ADMINQ_BUF_SZ );

  uint idx  = adminq->atq_prod;
  uint next = (idx+1U) & ((uint)FD_IAVF_ADMINQ_DEPTH-1U);
  fd_iavf_aq_desc_t * desc = fd_iavf_atq_desc( adminq, idx );
  fd_memset( desc, 0, sizeof(*desc) );
  desc->flags       = FD_IAVF_AQ_FLAG_SI;
  desc->opcode      = FD_IAVF_AQ_SEND_MSG_TO_PF;
  desc->cookie_high = virtchnl_op;
  if( message_sz ) {
    fd_memcpy( fd_iavf_atq_buf( adminq, idx ), message, message_sz );
    desc->flags   |= FD_IAVF_AQ_FLAG_BUF|FD_IAVF_AQ_FLAG_RD;
    desc->datalen  = (ushort)message_sz;
    fd_iavf_aq_desc_set_addr( desc, fd_iavf_atq_buf_iova( adminq, idx ) );
  }
  fd_iavf_dma_to_device();
  adminq->atq_prod = next;
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ATQT, next );

  struct timespec delay = { .tv_sec=0L, .tv_nsec=1000000L };
  for( ulong retry=0UL; retry<2000UL; retry++ ) {
    if( (fd_iavf_mmio_read( vfio, FD_IAVF_VF_ATQH ) & FD_IAVF_AQ_HEAD)==next ) {
      fd_iavf_dma_from_device();
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
fd_iavf_arq_recv( fd_iavf_vfio_t *   vfio,
                  fd_iavf_adminq_t * adminq,
                  uint *             virtchnl_op,
                  int *              virtchnl_status,
                  void *             message,
                  ulong *            message_sz ) {
  uint head = fd_iavf_mmio_read( vfio, FD_IAVF_VF_ARQH ) & FD_IAVF_AQ_HEAD;
  uint idx  = adminq->arq_cons;
  if( head==idx ) return 0;

  fd_iavf_dma_from_device();
  fd_iavf_aq_desc_t * desc = fd_iavf_arq_desc( adminq, idx );
  fd_iavf_aq_desc_t completed = *desc;
  ulong completed_sz = completed.datalen;
  int err = 0;
  if( FD_UNLIKELY( completed.opcode!=FD_IAVF_AQ_SEND_MSG_TO_VF ||
                   (completed.flags & FD_IAVF_AQ_FLAG_ERR) || completed.retval ) ) err = EIO;
  else if( FD_UNLIKELY( completed_sz>*message_sz || completed_sz>FD_IAVF_ADMINQ_BUF_SZ ) ) err = EMSGSIZE;
  else if( completed_sz ) fd_memcpy( message, fd_iavf_arq_buf( adminq, idx ), completed_sz );

  fd_iavf_arq_post( adminq, idx );
  fd_iavf_dma_to_device();
  fd_iavf_mmio_write( vfio, FD_IAVF_VF_ARQT, idx );
  adminq->arq_cons = (idx+1U) & ((uint)FD_IAVF_ADMINQ_DEPTH-1U);

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
fd_iavf_virtchnl_request( fd_iavf_vfio_t *   vfio,
                          fd_iavf_adminq_t * adminq,
                          uint               virtchnl_op,
                          void const *       request,
                          ulong              request_sz,
                          void *             response,
                          ulong *            response_sz ) {
  FD_TEST( response_sz );
  FD_TEST( response || !*response_sz );
  ulong response_capacity = *response_sz;
  *response_sz = 0UL;
  if( FD_UNLIKELY( fd_iavf_atq_send( vfio, adminq, virtchnl_op, request, request_sz ) ) ) return -1;

  struct timespec delay = { .tv_sec=0L, .tv_nsec=1000000L };
  for( ulong retry=0UL; retry<2000UL; retry++ ) {
    uchar message[ FD_IAVF_ADMINQ_BUF_SZ ];
    ulong message_sz = sizeof(message);
    uint received_op;
    int received_status;
    int received = fd_iavf_arq_recv( vfio, adminq, &received_op, &received_status,
                                        message, &message_sz );
    if( FD_UNLIKELY( received<0 ) ) goto fail;
    if( !received ) {
      if( FD_UNLIKELY( nanosleep( &delay, NULL ) && errno!=EINTR ) ) goto fail;
      continue;
    }
    if( received_op==FD_IAVF_VIRTCHNL_EVENT ) {
      if( FD_UNLIKELY( message_sz!=sizeof(adminq->pending_event) ) ) {
        FD_LOG_WARNING(( "invalid event size %lu during %s (%i-%s)", message_sz, fd_iavf_virtchnl_op_name( virtchnl_op ), EPROTO, fd_io_strerror( EPROTO ) ));
        errno = EPROTO;
        return -1;
      }
      fd_iavf_virtchnl_event_t event;
      fd_memcpy( &event, message, sizeof(event) );
      if( FD_UNLIKELY( event.event==2 || event.event==3 ) ) {
        errno = event.event==2 ? ECONNRESET : ESHUTDOWN;
        return -1;
      }
      fd_memcpy( adminq->pending_event, message, message_sz );
      adminq->pending_event_sz = message_sz;
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
  if( FD_UNLIKELY( response.major!=1U ) ) {
    FD_LOG_WARNING(( "unsupported virtchnl version %u.%u (%i-%s)", response.major, response.minor, EPROTONOSUPPORT, fd_io_strerror( EPROTONOSUPPORT ) ));
    errno = EPROTONOSUPPORT;
    return -1;
  }
  adminq->version_major = response.major;
  adminq->version_minor = response.minor;
  return 0;
}

static uint
fd_iavf_link_speed_mbps( uint link_speed ) {
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
fd_iavf_apply_pending_event( fd_iavf_adminq_t *  adminq,
                             fd_iavf_vf_info_t * info ) {
  if( !adminq->pending_event_sz ) return 0;
  FD_TEST( adminq->pending_event_sz==sizeof(fd_iavf_virtchnl_event_t) );
  fd_iavf_virtchnl_event_t event;
  fd_memcpy( &event, adminq->pending_event, sizeof(event) );
  adminq->pending_event_sz = 0UL;
  if( event.event==1 ) {
    info->link_state_valid = 1;
    info->link_up          = !!event.link_up;
    info->link_speed_mbps  = (info->capability_flags & FD_IAVF_VIRTCHNL_CAP_ADV_LINK_SPEED)
                             ? event.link_speed
                             : fd_iavf_link_speed_mbps( event.link_speed );
    return 0;
  }
  if( FD_UNLIKELY( event.event==2 ) ) {
    FD_LOG_WARNING(( "PF reset impending (%i-%s)", ECONNRESET, fd_io_strerror( ECONNRESET ) ));
    errno = ECONNRESET;
    return -1;
  }
  if( FD_UNLIKELY( event.event==3 ) ) {
    FD_LOG_WARNING(( "PF driver closed (%i-%s)", ESHUTDOWN, fd_io_strerror( ESHUTDOWN ) ));
    errno = ESHUTDOWN;
    return -1;
  }
  return 0;
}

static int
fd_iavf_wait_link_event( fd_iavf_vfio_t *    vfio,
                         fd_iavf_adminq_t *  adminq,
                         fd_iavf_vf_info_t * info ) {
  if( FD_UNLIKELY( fd_iavf_apply_pending_event( adminq, info ) ) ) return -1;
  if( info->link_state_valid ) return 0;

  struct timespec delay = { .tv_sec=0L, .tv_nsec=1000000L };
  for( ulong retry=0UL; retry<100UL; retry++ ) {
    uchar message[ FD_IAVF_ADMINQ_BUF_SZ ];
    ulong message_sz = sizeof(message);
    uint virtchnl_op;
    int virtchnl_status;
    int received = fd_iavf_arq_recv( vfio, adminq, &virtchnl_op, &virtchnl_status,
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
    if( FD_UNLIKELY( virtchnl_op!=FD_IAVF_VIRTCHNL_EVENT || virtchnl_status ||
                     message_sz!=sizeof(adminq->pending_event) ) ) {
      FD_LOG_WARNING(( "invalid link event, operation %u, status %i, size %lu (%i-%s)", virtchnl_op, virtchnl_status, message_sz, EPROTO, fd_io_strerror( EPROTO ) ));
      errno = EPROTO;
      return -1;
    }
    fd_memcpy( adminq->pending_event, message, message_sz );
    adminq->pending_event_sz = message_sz;
    if( FD_UNLIKELY( fd_iavf_apply_pending_event( adminq, info ) ) ) return -1;
    if( info->link_state_valid ) return 0;
  }
  return 0;
}

int
fd_iavf_get_vf_resources( fd_iavf_vfio_t *    vfio,
                          fd_iavf_adminq_t *  adminq,
                          fd_iavf_vf_info_t * info ) {
  if( FD_UNLIKELY( !vfio || !adminq || !info || adminq->version_major!=1U ) ) {
    errno = EINVAL;
    return -1;
  }
  fd_memset( info, 0, sizeof(*info) );

  uint requested_caps = FD_IAVF_VIRTCHNL_CAP_L2 |
                        FD_IAVF_VIRTCHNL_CAP_ADV_LINK_SPEED |
                        FD_IAVF_VIRTCHNL_CAP_RSS_PF;
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

  fd_iavf_virtchnl_vf_resource_t resources;
  fd_memcpy( &resources, response, sizeof(resources) );
  ulong vsi_capacity = (sizeof(response)-sizeof(resources))/sizeof(fd_iavf_virtchnl_vsi_resource_t);
  ulong expected_sz  = sizeof(resources) + (ulong)resources.num_vsis*sizeof(fd_iavf_virtchnl_vsi_resource_t);
  if( FD_UNLIKELY( !resources.num_vsis || (ulong)resources.num_vsis>vsi_capacity ||
                   response_sz!=expected_sz || !resources.num_queue_pairs ||
                   !(resources.capability_flags & FD_IAVF_VIRTCHNL_CAP_L2) ) ) {
    FD_LOG_WARNING(( "invalid VF resource reply (%i-%s)", EPROTO, fd_io_strerror( EPROTO ) ));
    errno = EPROTO;
    return -1;
  }
  if( FD_UNLIKELY( !(resources.capability_flags & FD_IAVF_VIRTCHNL_CAP_RSS_PF) ) ) {
    FD_LOG_WARNING(( "PF does not support RSS configuration (%i-%s)", EPROTONOSUPPORT, fd_io_strerror( EPROTONOSUPPORT ) ));
    errno = EPROTONOSUPPORT;
    return -1;
  }

  fd_iavf_virtchnl_vsi_resource_t selected = {0};
  ulong selected_cnt = 0UL;
  for( ulong vsi_idx=0UL; vsi_idx<(ulong)resources.num_vsis; vsi_idx++ ) {
    fd_iavf_virtchnl_vsi_resource_t vsi;
    fd_memcpy( &vsi, response+sizeof(resources)+vsi_idx*sizeof(vsi), sizeof(vsi) );
    if( vsi.vsi_type==FD_IAVF_VIRTCHNL_VSI_SRIOV ) {
      selected = vsi;
      selected_cnt++;
    }
  }
  if( FD_UNLIKELY( selected_cnt!=1UL || !selected.num_queue_pairs ||
                   (selected.default_mac_addr[0] & 1U) ) ) {
    FD_LOG_WARNING(( "invalid SR-IOV VSI or MAC address (%i-%s)", EPROTO, fd_io_strerror( EPROTO ) ));
    errno = EPROTO;
    return -1;
  }
  ulong mac_bits = 0UL;
  fd_memcpy( &mac_bits, selected.default_mac_addr, sizeof(selected.default_mac_addr) );
  if( FD_UNLIKELY( !(mac_bits & 0xffffffffffffUL) ) ) {
    FD_LOG_WARNING(( "PF returned a zero VF MAC address (%i-%s)", EPROTO, fd_io_strerror( EPROTO ) ));
    errno = EPROTO;
    return -1;
  }

  info->vsi_id             = selected.vsi_id;
  info->queue_pair_cnt     = fd_ushort_min( resources.num_queue_pairs, selected.num_queue_pairs );
  info->vector_cnt         = resources.max_vectors;
  info->max_mtu            = resources.max_mtu;
  info->capability_flags   = resources.capability_flags;
  info->rss_key_sz         = resources.rss_key_sz;
  info->rss_lut_sz         = resources.rss_lut_sz;
  if( FD_UNLIKELY( !info->rss_key_sz || info->rss_key_sz>FD_IAVF_ADMINQ_BUF_SZ-6UL ||
                   !info->rss_lut_sz || info->rss_lut_sz>FD_IAVF_ADMINQ_BUF_SZ-6UL ) ) {
    errno = EPROTO;
    return -1;
  }
  fd_memcpy( info->mac_addr, selected.default_mac_addr, sizeof(info->mac_addr) );
  return fd_iavf_wait_link_event( vfio, adminq, info );
}

int
fd_iavf_poll_link( fd_iavf_vfio_t *    vfio,
                   fd_iavf_adminq_t *  adminq,
                   fd_iavf_vf_info_t * info,
                   int *               changed ) {
  if( FD_UNLIKELY( !vfio || !adminq || !info || !changed ) ) {
    errno = EINVAL;
    return -1;
  }

  int const old_valid = info->link_state_valid;
  int const old_up    = info->link_up;
  uint const old_speed = info->link_speed_mbps;
  uint reset_state = fd_iavf_mmio_read( vfio, FD_IAVF_VFGEN_RSTAT ) & FD_IAVF_VFGEN_RSTAT_STATE;
  if( FD_UNLIKELY( (reset_state!=FD_IAVF_VFR_STATE_COMPLETED && reset_state!=FD_IAVF_VFR_STATE_ACTIVE) ||
                   !(fd_iavf_mmio_read( vfio, FD_IAVF_VF_ATQLEN ) & FD_IAVF_AQ_ENABLE) ||
                   !(fd_iavf_mmio_read( vfio, FD_IAVF_VF_ARQLEN ) & FD_IAVF_AQ_ENABLE) ) ) {
    errno = ECONNRESET;
    return -1;
  }
  if( FD_UNLIKELY( fd_iavf_apply_pending_event( adminq, info ) ) ) return -1;

  for( ulong i=0UL; i<FD_IAVF_ADMINQ_DEPTH; i++ ) {
    uchar message[ FD_IAVF_ADMINQ_BUF_SZ ];
    ulong message_sz = sizeof(message);
    uint virtchnl_op;
    int virtchnl_status;
    int const received = fd_iavf_arq_recv( vfio, adminq, &virtchnl_op, &virtchnl_status,
                                              message, &message_sz );
    if( FD_UNLIKELY( received<0 ) ) {
      int err = errno;
      FD_LOG_WARNING(( "link event receive failed (%i-%s)", err, fd_io_strerror( err ) ));
      errno = err;
      return -1;
    }
    if( !received ) break;
    if( FD_UNLIKELY( virtchnl_op!=FD_IAVF_VIRTCHNL_EVENT || virtchnl_status ||
                     message_sz!=sizeof(adminq->pending_event) ) ) {
      FD_LOG_WARNING(( "invalid link event, operation %u, status %i, size %lu (%i-%s)", virtchnl_op, virtchnl_status, message_sz, EPROTO, fd_io_strerror( EPROTO ) ));
      errno = EPROTO;
      return -1;
    }
    fd_memcpy( adminq->pending_event, message, message_sz );
    adminq->pending_event_sz = message_sz;
    if( FD_UNLIKELY( fd_iavf_apply_pending_event( adminq, info ) ) ) return -1;
  }

  *changed = old_valid!=info->link_state_valid ||
             old_up!=info->link_up ||
             old_speed!=info->link_speed_mbps;
  return 0;
}

ulong
fd_iavf_queue_footprint( uint tx_depth,
                         uint rx_depth ) {
  if( FD_UNLIKELY( tx_depth<64U || tx_depth>4096U || !fd_uint_is_pow2( tx_depth ) ||
                   rx_depth<64U || rx_depth>4096U || !fd_uint_is_pow2( rx_depth ) ) ) return 0UL;
  ulong tx_ring_sz = fd_ulong_align_up( (ulong)tx_depth*sizeof(fd_iavf_tx_desc_t), 4096UL );
  ulong rx_ring_sz = fd_ulong_align_up( (ulong)rx_depth*sizeof(fd_iavf_rx_desc_t), 4096UL );
  ulong tx_comp_sz = fd_ulong_align_up( (ulong)tx_depth*sizeof(ulong), 4096UL );
  return tx_ring_sz + rx_ring_sz + tx_comp_sz;
}

int
fd_iavf_configure_queue( fd_iavf_vfio_t *          vfio,
                         fd_iavf_adminq_t *        adminq,
                         fd_iavf_vf_info_t const * info,
                         fd_iavf_queue_t *         queue,
                         void *                    dma_memory,
                         ulong                     dma_memory_sz,
                         ulong                     dma_iova,
                         uint                      tx_depth,
                         uint                      rx_depth,
                         uint                      rx_buffer_sz,
                         uint                      max_frame_sz ) {
  ulong footprint = fd_iavf_queue_footprint( tx_depth, rx_depth );
  if( FD_UNLIKELY( !vfio || !adminq || !info || !queue || !dma_memory || !footprint ||
                   !vfio->bar0 || vfio->bar0_sz<FD_IAVF_BAR0_MAP_SZ ||
                   dma_memory_sz<footprint || !fd_ulong_is_aligned( (ulong)dma_memory, 4096UL ) ||
                   !fd_ulong_is_aligned( dma_iova, 4096UL ) || !info->queue_pair_cnt ||
                   info->vector_cnt<2U || !rx_buffer_sz || (rx_buffer_sz & 127U) ||
                   max_frame_sz<64U || max_frame_sz>=16384U || max_frame_sz>rx_buffer_sz ||
                   (info->max_mtu && max_frame_sz>info->max_mtu) ) ) {
    FD_LOG_WARNING(( "invalid queue setup, TX depth %u, RX depth %u, frame %u, buffer %u",
                     tx_depth, rx_depth, max_frame_sz, rx_buffer_sz ));
    errno = EINVAL;
    return -1;
  }

  fd_memset( dma_memory, 0, footprint );
  if( FD_UNLIKELY( fd_iavf_vfio_dma_map( vfio, dma_memory, footprint, dma_iova ) ) ) return -1;
  ulong tx_ring_sz = fd_ulong_align_up( (ulong)tx_depth*sizeof(fd_iavf_tx_desc_t), 4096UL );
  ulong rx_ring_sz = fd_ulong_align_up( (ulong)rx_depth*sizeof(fd_iavf_rx_desc_t), 4096UL );
  *queue = (fd_iavf_queue_t) {
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
    .tx_tail      = (volatile uint *)(vfio->bar0 + FD_IAVF_TX_TAIL( 0U )),
    .rx_tail      = (volatile uint *)(vfio->bar0 + FD_IAVF_RX_TAIL( 0U ))
  };

  fd_iavf_virtchnl_queue_config_t config = {
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
  if( FD_UNLIKELY( fd_iavf_virtchnl_request( vfio, adminq, FD_IAVF_VIRTCHNL_CONFIG_QUEUES,
                                                &config, sizeof(config), NULL, &response_sz ) ) ) return -1;

  fd_iavf_virtchnl_irq_map_t irq_map = {
    .vector_cnt   = 1U,
    .vsi_id       = info->vsi_id,
    .vector_id    = 1U,
    .rx_queue_map = 1U,
    .tx_queue_map = 1U,
    .rx_itr_idx   = 0U,
    .tx_itr_idx   = 0U
  };
  response_sz = 0UL;
  if( FD_UNLIKELY( fd_iavf_virtchnl_request( vfio, adminq, FD_IAVF_VIRTCHNL_CONFIG_IRQ_MAP,
                                                &irq_map, sizeof(irq_map), NULL, &response_sz ) ) ) return -1;
  return 0;
}

int
fd_iavf_enable_queue( fd_iavf_vfio_t *    vfio,
                      fd_iavf_adminq_t *  adminq,
                      fd_iavf_vf_info_t * info,
                      fd_iavf_queue_t *   queue ) {
  if( FD_UNLIKELY( !vfio || !adminq || !info || !queue || queue->enabled || !queue->rx_posted ||
                   queue->rx_posted!=queue->rx_prod ||
                   queue->rx_prod-queue->rx_cons>=queue->rx_depth ) ) {
    errno = EINVAL;
    return -1;
  }
  fd_iavf_virtchnl_queue_select_t select = {
    .vsi_id       = info->vsi_id,
    .rx_queue_map = 1U,
    .tx_queue_map = 1U
  };
  ulong response_sz = 0UL;
  if( FD_UNLIKELY( fd_iavf_virtchnl_request( vfio, adminq, FD_IAVF_VIRTCHNL_ENABLE_QUEUES,
                                                &select, sizeof(select), NULL, &response_sz ) ) ) return -1;
  queue->enabled = 1;
  info->link_state_valid = 0;
  return fd_iavf_wait_link_event( vfio, adminq, info );
}

/* fd_iavf_add_mac registers the PF-assigned primary MAC with the VF VSI. */
int
fd_iavf_add_mac( fd_iavf_vfio_t *          vfio,
                 fd_iavf_adminq_t *        adminq,
                 fd_iavf_vf_info_t const * info ) {
  if( FD_UNLIKELY( !vfio || !adminq || !info || (info->mac_addr[0] & 1U) ||
                   !(info->mac_addr[0] | info->mac_addr[1] | info->mac_addr[2] |
                     info->mac_addr[3] | info->mac_addr[4] | info->mac_addr[5]) ) ) {
    errno = EINVAL;
    return -1;
  }
  struct {
    ushort vsi_id;
    ushort count;
    uchar  mac[ 6 ];
    uchar  type;
    uchar  pad;
    uchar  legacy_padding[ 8 ];
  } request = { .vsi_id=info->vsi_id, .count=1U, .type=1U };
  FD_STATIC_ASSERT( sizeof(request)==20UL, iavf_mac_request_sz );
  fd_memcpy( request.mac, info->mac_addr, sizeof(request.mac) );
  ulong response_sz = 0UL;
  return fd_iavf_virtchnl_request( vfio, adminq, FD_IAVF_VIRTCHNL_ADD_ETH_ADDR,
                                   &request, sizeof(request), NULL, &response_sz );
}

/* fd_iavf_configure_rss selects the first queue_cnt queues in the VF VSI. */
int
fd_iavf_configure_rss( fd_iavf_vfio_t *          vfio,
                       fd_iavf_adminq_t *        adminq,
                       fd_iavf_vf_info_t const * info,
                       uint                      queue_cnt ) {
  if( FD_UNLIKELY( !vfio || !adminq || !info || !queue_cnt ||
                   queue_cnt>info->queue_pair_cnt || queue_cnt>16U ||
                   !info->rss_key_sz || info->rss_key_sz>4090U ||
                   !info->rss_lut_sz || info->rss_lut_sz>4090U ) ) {
    errno = EINVAL;
    return -1;
  }
  struct {
    ushort vsi_id;
    ushort count;
    uchar  bytes[ 4092 ];
  } request = { .vsi_id=info->vsi_id, .count=(ushort)info->rss_key_sz };
  FD_STATIC_ASSERT( sizeof(request)==4096UL, iavf_rss_request_sz );
  if( FD_UNLIKELY( !fd_rng_secure( request.bytes, info->rss_key_sz ) ) ) return -1;
  /* virtchnl RSS messages retain one trailing byte from their legacy size. */
  ulong response_sz = 0UL;
  if( FD_UNLIKELY( fd_iavf_virtchnl_request( vfio, adminq, FD_IAVF_VIRTCHNL_CONFIG_RSS_KEY,
                                             &request, (ulong)info->rss_key_sz+5UL,
                                             NULL, &response_sz ) ) ) return -1;
  fd_memset( request.bytes, 0, sizeof(request.bytes) );
  request.count = (ushort)info->rss_lut_sz;
  for( uint i=0U; i<info->rss_lut_sz; i++ ) request.bytes[i] = (uchar)(i%queue_cnt);
  response_sz = 0UL;
  return fd_iavf_virtchnl_request( vfio, adminq, FD_IAVF_VIRTCHNL_CONFIG_RSS_LUT,
                                   &request, (ulong)info->rss_lut_sz+5UL,
                                   NULL, &response_sz );
}
