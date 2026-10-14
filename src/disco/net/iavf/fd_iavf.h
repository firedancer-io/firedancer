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

/* fd_iavf_member_interfaces lists PFs for VF creation on interface or its
   802.3ad bond members. Writes names to members and count to member_cnt.
   Each PF must use ice or i40e. Returns 0 on success or -1 with errno set.
   Outputs are valid only on success. Some bond sysfs errors terminate
   the process. */
int
fd_iavf_member_interfaces( char const * interface,
                           char         members[ FD_IAVF_MEMBER_MAX ][ IF_NAMESIZE ],
                           ulong *      member_cnt );

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
