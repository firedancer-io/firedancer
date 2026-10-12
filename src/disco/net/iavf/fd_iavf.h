#ifndef HEADER_fd_src_disco_net_iavf_fd_iavf_h
#define HEADER_fd_src_disco_net_iavf_fd_iavf_h

#define FD_IAVF_QUEUE_DEPTH_MIN (64U)
#define FD_IAVF_QUEUE_DEPTH_MAX (4096U)

#if defined(__linux__)
#include "../../../util/bits/fd_bits.h"
#include <net/if.h>

#define FD_IAVF_PCI_ADDR_SZ     (13UL)
#define FD_IAVF_DRIVER_NAME_MAX (32UL)
#define FD_IAVF_MEMBER_MAX      (16UL)
#define FD_IAVF_TILE_MAX        (8UL)

/* fd_iavf_pci_info describes a validated Intel Ethernet Virtual Function. */
struct fd_iavf_pci_info {
  char   pci_addr[ FD_IAVF_PCI_ADDR_SZ ];
  char   pf_pci_addr[ FD_IAVF_PCI_ADDR_SZ ];
  char   driver[ FD_IAVF_DRIVER_NAME_MAX ];
  uint   iommu_group;
  ushort device_id;
};
typedef struct fd_iavf_pci_info fd_iavf_pci_info_t;

FD_PROTOTYPES_BEGIN

/* fd_iavf_vfio_avail returns 1 if the vfio-pci driver is registered with
   the kernel, or 0 otherwise. Does not load the module. */
int
fd_iavf_vfio_avail( void );

/* fd_iavf_vfio_api_check checks the VFIO API version and TYPE1v2 IOMMU
   support through /dev/vfio/vfio
   Returns 0 on success or -1 with errno set
   If diagnostic is non-NULL, sets it to NULL on success or a static
   error message on failure */
int
fd_iavf_vfio_api_check( char const ** diagnostic );

/* fd_iavf_member_interfaces lists PFs for VF creation on interface or its
   802.3ad bond members. Writes names to members and count to member_cnt.
   Each PF must use ice or i40e. Returns 0 on success or -1 with errno set.
   Outputs are valid only on success. Some bond sysfs errors terminate
   the process. */
int
fd_iavf_member_interfaces( char const * interface,
                           char         members[ FD_IAVF_MEMBER_MAX ][ IF_NAMESIZE ],
                           ulong *      member_cnt );

/* fd_iavf_sriov_bios_guide returns a static BIOS setup explanation for the
   detected manufacturer and CPU, with a vendor URL when available.
   Otherwise returns generic advice, or NULL if vendor_only is nonzero */
char const *
fd_iavf_sriov_bios_guide( int vendor_only );

/* fd_iavf_iommu_check checks whether pf_if is in an IOMMU group.
   The iavf provider requires an IOMMU to restrict which memory the NIC
   can access. Returns 0 on success or -1 with errno set.
   If diagnostic is non-NULL, sets it to NULL on success or a static
   explanation on failure. */
int
fd_iavf_iommu_check( char const *  pf_if,
                     char const ** diagnostic );

/* fd_iavf_numvfs_get reads pf_if's enabled VF count from sriov_numvfs.
   A count of zero is valid. Returns 0 on success or -1 with errno set,
   leaving numvfs unchanged on failure. Does not log failures. */
int
fd_iavf_numvfs_get( char const * pf_if,
                    uint *       numvfs );

/* fd_iavf_sriov_resources_check requires assigned VF BAR0 and BAR3 memory
   ranges in pf_if's PCI resource file. Returns 0 on success or -1 with
   errno set, including ENOMEM for missing or unusable allocations.
   Only reads sysfs and does not log failures or create VFs. */
int
fd_iavf_sriov_resources_check( char const * pf_if );

/* fd_iavf_get_last_vf returns the PCI address of the highest enabled VF on pf_if
   Returns 0 on success or -1 with errno set, including ENOENT for no VFs
   vf_idx is optional and outputs are valid only on success */
int
fd_iavf_get_last_vf( char const * pf_if,
                     uint *       vf_idx,
                     char         vf_pci_addr[ FD_IAVF_PCI_ADDR_SZ ] );

/* fd_iavf_pci_probe checks for a supported Intel Ethernet VF and requires
   it to be alone in its IOMMU group so VFIO access cannot include another
   device. Returns 0 on success or -1 with errno set on failure,
   clearing info when non-NULL. Records the current driver, empty if unbound.
   The VF need not use vfio-pci until fd_iavf_vfio_init. */
int
fd_iavf_pci_probe( fd_iavf_pci_info_t * info,
                   char const *         pci_addr );

FD_PROTOTYPES_END
#endif
#endif
