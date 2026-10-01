#ifndef HEADER_fd_src_disco_net_iavf_fd_iavf_h
#define HEADER_fd_src_disco_net_iavf_fd_iavf_h

#if defined(__linux__)
#include "../../../util/bits/fd_bits.h"

#define FD_IAVF_PCI_ADDR_SZ     (13UL)
#define FD_IAVF_DRIVER_NAME_MAX (32UL)
#define FD_IAVF_MEMBER_MAX      (16UL)

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

/* fd_iavf_member_interfaces lists physical PFs for an interface or an
   802.3ad bond. Each PF must use ice or i40e. */
int
fd_iavf_member_interfaces( char const * interface,
                           char         members[ FD_IAVF_MEMBER_MAX ][ 16 ],
                           ulong *      member_cnt );

/* fd_iavf_pci_probe validates an Intel Ethernet VF in an isolated IOMMU
   group.  On failure it clears info and sets errno. */
int
fd_iavf_pci_probe( fd_iavf_pci_info_t * info,
                   char const *         pci_addr );

FD_PROTOTYPES_END
#endif
#endif
