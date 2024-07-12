#ifndef HEADER_fd_src_app_fdctl_run_tiles_wd_c1100_h
#define HEADER_fd_src_app_fdctl_run_tiles_wd_c1100_h

#include "../../../../util/fd_util_base.h"

#include <linux/limits.h>

#define MAX_BARS 6  /* Maximum number of BARs typically */

typedef struct {
    ulong start;
    ulong end;
    ulong size;
    uint num;
    char pcie_device[ PATH_MAX ];
    char path[ PATH_MAX ];
} BarInfo;

typedef struct {
    BarInfo bi;
    void * mapped_addr;
    int fd;
} BarMapped;

uint read_pci_resource_file(const char * pcie_device, BarInfo * bars, uint bars_sz );
void print_bar_infos( BarInfo * bars, uint bars_sz );
void print_bar_maps( BarMapped * bms, uint bms_sz );
void mmap_bar( BarInfo const * bi, BarMapped * bm );

#endif /* HEADER_fd_src_app_fdctl_run_tiles_wd_c1100_h */