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
  BarInfo info;
  void  * addr;
  int     fd;
} BarMap;

typedef struct {
    BarMap bm[ MAX_BARS ];
    uint   sz;
} C1100;

// uint read_pci_resource_file(const char * pcie_device, BarInfo * bars, uint bars_sz );
// void print_bar_infos( BarInfo * bars, uint bars_sz );
// void print_bar_maps( BarMap * bms, uint bms_sz );
// void mmap_bar( BarInfo const * bi, BarMap * bm );
// void * get_bar_handle( uint bar_num, BarMap const * bm, uint bm_sz );

int    wd_pcie_peek( void * h, ulong offset, uint * value );
int    wd_pcie_poke( void * h, ulong offset, uint   value );

int    c1100_init( C1100 * c1100, const char * pcie_device );
void * c1100_bar_handle( C1100 const * c1100, uint bar_num );
int    c1100_bar_info(   C1100 const * c1100, uint bar_num );
uint   c1100_bar_count(  C1100 const * d );
int    c1100_bar_fd( C1100 * d, uint bar_num );
int    c1100_dma_test( C1100 * c1100, void * buf, ulong dma_addr );
int    c1100_dma_benchmark( C1100 * c1100, ulong dma_region_addr );
int    c1100_dma_benchmark2( C1100 * c1100, void * buf, ulong dma_region_addr, uint sz );
int    c1100_dma_benchmark3( C1100 * c1100, void * buf1, ulong dma1, void * buf2, ulong dma2, uint sz );
BarMap const * C1100_bar_get( C1100 const * c1100, uint bar_num );
ulong _wd_get_phys(void * p);





void
dma_block_write( C1100 * c1100,
                 ulong   dma_addr,        ulong dma_offset,
                 ulong   dma_offset_mask, ulong dma_stride,
                 ulong   ram_addr,        ulong ram_offset,
                 ulong   ram_offset_mask, ulong ram_stride,
                 ulong   block_len,       ulong block_count );

void
dma_block_read( C1100 * c1100,
                ulong   dma_addr,        ulong dma_offset,
                ulong   dma_offset_mask, ulong dma_stride,
                ulong   ram_addr,        ulong ram_offset,
                ulong   ram_offset_mask, ulong ram_stride,
                ulong   block_len,       ulong block_count );

void
dma_block_write_bench( C1100 * c1100,
                       ulong   dma_addr, ulong size, ulong stride, ulong count );

void
dma_block_read_bench( C1100 * c1100,
                      ulong   dma_addr, ulong size, ulong stride, ulong count );

#endif /* HEADER_fd_src_app_fdctl_run_tiles_wd_c1100_h */
