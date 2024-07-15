#include "wd_c1100.h"
#include "../../../../util/log/fd_log.h"

#include <stdio.h>
#include <stdlib.h>
#define __USE_MISC
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static
uint read_pci_resource_file(const char * pcie_device, BarInfo * bars, uint bars_sz ) {
  char resource_file[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( resource_file, PATH_MAX, NULL, "/sys/bus/pci/devices/%s/resource", pcie_device ) );

  FILE * file = fopen( resource_file, "r" );
  if( FD_UNLIKELY( !file ) ) {
    perror( "fopen" );
    return UINT_MAX;
  }

  char line[256];
  uint bar_num = 0;
  uint count = 0;

  while( fgets( line, sizeof( line ), file ) && count < bars_sz ) {
    ulong start, end, flags;
    if( FD_LIKELY( sscanf( line, "0x%lx 0x%lx 0x%lx", &start, &end, &flags ) == 3 ) ) {
      if( FD_LIKELY( start != 0 || end != 0) ) {  // Only consider valid BARs
        bars[count].start = start;
        bars[count].end = end;
        bars[count].size = end - start + 1;
        bars[count].num = bar_num;
        strncpy( bars[count].pcie_device, pcie_device, sizeof( bars[count].pcie_device ) - 1 );
        FD_TEST( fd_cstr_printf_check( bars[count].path, sizeof( bars[count].path), NULL, "/sys/bus/pci/devices/%s/resource%d", pcie_device, bars[count].num ) );
        count++;
      }
    }
    bar_num++;
  }

  fclose(file);
  return count;
}

void print_bar_infos( BarInfo * bars, uint bars_sz ) {
  for( uint i=0UL; i<bars_sz; i++ ) {
    FD_LOG_NOTICE(( "BAR%d: Start = 0x%lx, End = 0x%lx, Size = 0x%08lx, Path=%s", i, bars[i].start, bars[i].end, bars[i].size, bars[i].path ));
  }
}

static
void print_bar_maps( BarMap * bms, uint bms_sz ) {
  for( uint i=0UL; i<bms_sz; i++ ) {
    FD_LOG_NOTICE(( "BAR %d: Start = 0x%lx, End = 0x%lx, Size = 0x%08lx, MappedAddr=0x%lx, fd=%d, Path=%s",
        bms[i].info.num, bms[i].info.start, bms[i].info.end, bms[i].info.size, (ulong)bms[i].addr, bms[i].fd, bms[i].info.path ));
  }
}

static
void mmap_bar( BarInfo const * info, BarMap * bm ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/bus/pci/devices/%s/resource0", info->pcie_device ) );
  bm->fd = open( info->path, O_RDWR | O_SYNC );

  if( FD_UNLIKELY( bm->fd == -1 ) ) {
    FD_LOG_ERR(("Error opening device file %s %s", info->path, info->pcie_device ));
    return;
  }

  bm->addr = mmap( (void *)info->start, info->size, PROT_READ | PROT_WRITE, MAP_SHARED, bm->fd, 0);

  bm->info = *info;

  if( FD_UNLIKELY( bm->addr == MAP_FAILED ) ) {
    FD_LOG_ERR(("Error mapping memory: %s\n", strerror(errno)));
    return;
  }
}

int wd_pcie_peek( void * h, ulong offset, uint * value ) {
  BarMap * bm = (BarMap *)h;
  char   * base_addr   = (char *)bm->addr;
  uint   * target_addr = (uint *)(base_addr + offset);
  *value = *target_addr;
  return 0;
}

int wd_pcie_poke( void * h, ulong offset, uint   value ) {
  BarMap * bm = (BarMap *)h;
  char   * base_addr   = (char *)bm->addr;
  uint   * target_addr = (uint *)(base_addr + offset);
  *target_addr = value;
  return 0;
}

static
BarMap const * get_bar( uint bar_num, BarMap const * bm, uint bm_sz ) {
  for( uint i=0; i<bm_sz; i++ ) {
    if( FD_UNLIKELY( bm[i].info.num == bar_num ) ) {
      return &bm[i];
    }
  }
  return NULL;
}

BarMap const * C1100_bar_get( C1100 const * c1100, uint bar_num ) {
  return get_bar( bar_num, c1100->bm, c1100->sz );
}

int c1100_init( C1100 * c1100, const char * pcie_device ) {
  BarInfo bar_infos[ MAX_BARS ];
  c1100->sz = read_pci_resource_file( pcie_device, bar_infos, MAX_BARS );
  for( uint i=0; i<c1100->sz; i++ ) {
    mmap_bar( &bar_infos[i], &c1100->bm[i] );
  }
  print_bar_maps( c1100->bm, c1100->sz );
  return 0;
}

void * c1100_bar_handle( C1100 const * c1100, uint bar_num ) {
  return (void *)C1100_bar_get( c1100, bar_num );
}

uint c1100_bar_count( C1100 const * c1100 ) {
  return c1100->sz;
}

int c1100_bar_fd( C1100 * c1100, uint bar_num ) {
  for( uint i=0; i<c1100->sz; i++ ) {
    if( FD_UNLIKELY( c1100->bm[i].info.num == bar_num ) ) {
      return c1100->bm[i].fd;
    }
  }
  return -1;
}

#include <stdint.h>
ulong _wd_get_phys(void * p)
{
    ulong PAGE_SIZE = (ulong)sysconf(_SC_PAGESIZE);
    int pagemap_fd;
    uint64_t vaddr;
    uintptr_t vpn;
    uint64_t pfn;

    pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap_fd < 0)
    {
        FD_LOG_ERR (( "cannot open pagemap file: %d ", pagemap_fd ));
        return 0;
    }

    vaddr = (uint64_t)p;
    vpn = vaddr / PAGE_SIZE;
    for (size_t nread = 0; nread < sizeof(pfn); )
    {
        ssize_t ret = pread(pagemap_fd, &pfn, sizeof(pfn) - nread, (off_t)((vpn * sizeof(pfn)) + nread));
        if (ret <= 0)
        {
            FD_LOG_ERR (( "pread error: %lu ", ret ));
            close(pagemap_fd);
            return 0;
        }
        nread += (size_t)ret;
    }
    pfn &= (1UL << 55) - 1;
    pfn = (pfn * (long unsigned int)PAGE_SIZE) + (vaddr % (long unsigned int)PAGE_SIZE);

    close(pagemap_fd);

    return pfn;
}

uint c1100_dma_enabled( C1100 * c1100 ) {
  void * handle = c1100_bar_handle( c1100, 0 );

  uint value;
  wd_pcie_peek( handle, 0x0000, &value );
  return value;
}

void c1100_interrupts_enable( C1100 * c1100 ) {
  void * handle = c1100_bar_handle( c1100, 0 );
  wd_pcie_poke( handle, 0x0008, 3 );
}

int c1100_dma_test( C1100 * c1100, void * buf, ulong dma_addr ) {
  FD_LOG_NOTICE(( "virt: %lu phys: %lu", (ulong)buf, dma_addr ));

  for( uint i=0; i<256; i++ ) {
      ((char *)buf)[i] = (char)i;
  }
  FD_LOG_HEXDUMP_NOTICE(( "data", buf, 256 ));

  FD_LOG_NOTICE(( "dma enabled: %u", c1100_dma_enabled( c1100 ) ) );

  c1100_interrupts_enable( c1100 );

  void * bar2 = c1100_bar_handle( c1100, 2 );
  uint value;
  wd_pcie_poke( bar2, 0, 0 );
  wd_pcie_peek( bar2, 0, &value );
  FD_LOG_NOTICE(( "bar2 %08x", value ));
  wd_pcie_poke( bar2, 0, 0x11223344 );
  wd_pcie_peek( bar2, 0, &value );
  FD_LOG_NOTICE(( "bar2 %08x", value ));

  void * bar0 = c1100_bar_handle( c1100, 0 );

  FD_LOG_NOTICE(( "start copy to card" ));
  wd_pcie_poke( bar0, 0x000100, (uint)((dma_addr + 0x0000) & 0xffffffff ) );
  wd_pcie_poke( bar0, 0x000104, (uint)(((dma_addr + 0x0000) >> 32) & 0xffffffff ) );
  wd_pcie_poke( bar0, 0x000108, 0x100 );
  wd_pcie_poke( bar0, 0x00010C, 0x0 );
  wd_pcie_poke( bar0, 0x000110, 0x100 );
  wd_pcie_poke( bar0, 0x000114, 0xAA );

  usleep(1000);

  FD_LOG_NOTICE(( "read status" ));
  wd_pcie_peek( bar0, 0x000000, &value );
  FD_LOG_NOTICE(( "%08x", value ));

  wd_pcie_peek( bar0, 0x000118, &value );
  FD_LOG_NOTICE(( "%08x", value ));

  FD_LOG_NOTICE(( "start copy to host" ));
  wd_pcie_poke( bar0, 0x000200, (uint)((dma_addr + 0x0200) & 0xffffffff ) );
  wd_pcie_poke( bar0, 0x000204, (uint)(((dma_addr + 0x0200) >> 32) & 0xffffffff ) );
  wd_pcie_poke( bar0, 0x000208, 0x100 );
  wd_pcie_poke( bar0, 0x00020C, 0x0 );
  wd_pcie_poke( bar0, 0x000210, 0x100 );
  wd_pcie_poke( bar0, 0x000214, 0x55 );

  usleep( 1000 );

  FD_LOG_NOTICE(( "Read status" ));

  wd_pcie_peek( bar0, 0x000000, &value );
  FD_LOG_NOTICE(( "%08x", value ));

  wd_pcie_peek( bar0, 0x000218, &value );
  FD_LOG_NOTICE(( "%08x", value ));

  FD_LOG_NOTICE(( "read test data" ));
//   FD_LOG_HEXDUMP_NOTICE(( "data", &((char *)buf)[0x200], 256 ));

  FD_LOG_HEXDUMP_NOTICE(( "data", buf, 1024 ));

  if( memcmp( buf, &((char *)buf)[0x200], 256 ) == 0 ) {
    FD_LOG_NOTICE(( "test data matches" ));
    return 0;
  } else {
    FD_LOG_NOTICE(( "test data mismatch" ));
    return 1;
  }
}

void
dma_block_write( C1100 * c1100,
                 ulong   dma_addr,        ulong dma_offset,
                 ulong   dma_offset_mask, ulong dma_stride,
                 ulong   ram_addr,        ulong ram_offset,
                 ulong   ram_offset_mask, ulong ram_stride,
                 ulong   block_len,       ulong block_count ) {
  uint value;
  void * bar0 = c1100_bar_handle( c1100, 0 );

  // DMA base address
  wd_pcie_poke( bar0, 0x001180, (uint)(dma_addr & 0xffffffff) );
  wd_pcie_poke( bar0, 0x001184, (uint)((dma_addr >> 32) & 0xffffffff) );
  // DMA offset address
  wd_pcie_poke( bar0, 0x001188, (uint)(dma_offset & 0xffffffff) );
  wd_pcie_poke( bar0, 0x00118c, (uint)((dma_offset >> 32) & 0xffffffff) );
  // DMA offset mask
  wd_pcie_poke( bar0, 0x001190, (uint)(dma_offset_mask & 0xffffffff) );
  wd_pcie_poke( bar0, 0x001194, (uint)((dma_offset_mask >> 32) & 0xffffffff) );
  // DMA stride
  wd_pcie_poke( bar0, 0x001198, (uint)(dma_stride & 0xffffffff) );
  wd_pcie_poke( bar0, 0x00119c, (uint)((dma_stride >> 32) & 0xffffffff) );
  // RAM base address
  wd_pcie_poke( bar0, 0x0011c0, (uint)(ram_addr & 0xffffffff) );
  wd_pcie_poke( bar0, 0x0011c4, (uint)((ram_addr >> 32) & 0xffffffff) );
  // RAM offset address
  wd_pcie_poke( bar0, 0x0011c8, (uint)(ram_offset & 0xffffffff) );
  wd_pcie_poke( bar0, 0x0011cc, (uint)((ram_offset >> 32) & 0xffffffff) );
  // RAM offset mask
  wd_pcie_poke( bar0, 0x0011d0, (uint)(ram_offset_mask & 0xffffffff) );
  wd_pcie_poke( bar0, 0x0011d4, (uint)((ram_offset_mask >> 32) & 0xffffffff) );
  // RAM stride
  wd_pcie_poke( bar0, 0x0011d8, (uint)(ram_stride & 0xffffffff) );
  wd_pcie_poke( bar0, 0x0011dc, (uint)((ram_stride >> 32) & 0xffffffff) );
  // clear cycle count
  wd_pcie_poke( bar0, 0x001108, 0 );
  wd_pcie_poke( bar0, 0x00110c, 0 );
  // block length
  wd_pcie_poke( bar0, 0x001110, (uint)block_len );
  // block count
  wd_pcie_poke( bar0, 0x001118, (uint)block_count );
  // start
  wd_pcie_poke( bar0, 0x001100, 1 );

  // wait for transfer to complete
  for( uint i=0; i<20000; i++ ) {
    wd_pcie_peek( bar0, 0x001100, &value );
    if( FD_UNLIKELY( (value & 1) == 0 ) )
      break;
    usleep( 1 );
  }

  wd_pcie_peek( bar0, 0x001100, &value );
  // FD_LOG_NOTICE(( "status 0x001100 %u", value ));
  if( FD_UNLIKELY( (value & 1) != 0 ) )
    FD_LOG_ERR(( "operation timed out"  ));
  wd_pcie_peek( bar0, 0x000000, &value );
  // FD_LOG_NOTICE(( "status 0x000000 %u", value ));
  if( FD_UNLIKELY( (value & 0x300) != 0 ) )
    FD_LOG_ERR(( "DMA engine busy"  ));
}

void
dma_block_read( C1100 * c1100,
                ulong   dma_addr,        ulong dma_offset,
                ulong   dma_offset_mask, ulong dma_stride,
                ulong   ram_addr,        ulong ram_offset,
                ulong   ram_offset_mask, ulong ram_stride,
                ulong   block_len,       ulong block_count ) {
  uint value;
  void * bar0 = c1100_bar_handle( c1100, 0 );

  // DMA base address
  wd_pcie_poke( bar0, 0x001080, (uint)(dma_addr & 0xffffffff) );
  wd_pcie_poke( bar0, 0x001084, (uint)((dma_addr >> 32) & 0xffffffff) );
  // DMA offset address
  wd_pcie_poke( bar0, 0x001088, (uint)(dma_offset & 0xffffffff) );
  wd_pcie_poke( bar0, 0x00108c, (uint)((dma_offset >> 32) & 0xffffffff) );
  // DMA offset mask
  wd_pcie_poke( bar0, 0x001090, (uint)(dma_offset_mask & 0xffffffff) );
  wd_pcie_poke( bar0, 0x001094, (uint)((dma_offset_mask >> 32) & 0xffffffff) );
  // DMA stride
  wd_pcie_poke( bar0, 0x001098, (uint)(dma_stride & 0xffffffff) );
  wd_pcie_poke( bar0, 0x00109c, (uint)((dma_stride >> 32) & 0xffffffff) );
  // RAM base address
  wd_pcie_poke( bar0, 0x0010c0, (uint)(ram_addr & 0xffffffff) );
  wd_pcie_poke( bar0, 0x0010c4, (uint)((ram_addr >> 32) & 0xffffffff) );
  // RAM offset address
  wd_pcie_poke( bar0, 0x0010c8, (uint)(ram_offset & 0xffffffff) );
  wd_pcie_poke( bar0, 0x0010cc, (uint)((ram_offset >> 32) & 0xffffffff) );
  // RAM offset mask
  wd_pcie_poke( bar0, 0x0010d0, (uint)(ram_offset_mask & 0xffffffff) );
  wd_pcie_poke( bar0, 0x0010d4, (uint)((ram_offset_mask >> 32) & 0xffffffff) );
  // RAM stride
  wd_pcie_poke( bar0, 0x0010d8, (uint)(ram_stride & 0xffffffff) );
  wd_pcie_poke( bar0, 0x0010dc, (uint)((ram_stride >> 32) & 0xffffffff) );
  // clear cycle count
  wd_pcie_poke( bar0, 0x001008, 0 );
  wd_pcie_poke( bar0, 0x00100c, 0 );
  // block length
  wd_pcie_poke( bar0, 0x001010, (uint)block_len );
  // block count
  wd_pcie_poke( bar0, 0x001018, (uint)block_count );
  // start
  wd_pcie_poke( bar0, 0x001000, 1);

  // wait for transfer to complete
  for( uint i=0; i<20000; i++ ) {
    wd_pcie_peek( bar0, 0x001000, &value );
    if( FD_UNLIKELY( (value & 1) == 0 ) )
      break;
    usleep( 1 );
  }

  wd_pcie_peek( bar0, 0x001000, &value );
  if( FD_UNLIKELY( (value & 1) != 0 ) )
    FD_LOG_ERR(( "operation timed out" ));
  wd_pcie_peek( bar0, 0x000000, &value );
  if( FD_UNLIKELY( (value & 0x300) != 0 ) )
    FD_LOG_ERR(( "DMA engine busy" ));
}

void
dma_block_write_bench( C1100 * c1100,
                       ulong   dma_addr, ulong size, ulong stride, ulong count ) {
  uint cycles;
  uint wr_req;

  usleep(5);

  void * bar0 = c1100_bar_handle( c1100, 0 );
  wd_pcie_peek( bar0, 0x000028, &wr_req );

  dma_block_write( c1100, dma_addr, 0, 0xffffff, stride,
                   0, 0, 0xffffff, stride, size, count );

  wd_pcie_peek( bar0, 0x001108, (uint *)&cycles );

  usleep(5);

  uint wr_req_after;
  wd_pcie_peek( bar0, 0x000028, &wr_req_after );
  wr_req = wr_req_after - wr_req;

  FD_LOG_NOTICE(( "wrote %lu blocks of %lu bytes (total %lu B, stride %lu) in %u ns (%u req): %lu Mbps",
                  count, size, count * size, stride, cycles * 4, wr_req, size * count * 8 * 1000 / (cycles * 4) ));
}

void
dma_block_read_bench( C1100 * c1100,
                      ulong   dma_addr, ulong size, ulong stride, ulong count ) {
  uint cycles;
  uint rd_req;
  uint rd_cpl;

  usleep(5);

  void * bar0 = c1100_bar_handle( c1100, 0 );
  wd_pcie_peek( bar0, 0x000020, &rd_req );
  wd_pcie_peek( bar0, 0x000024, &rd_cpl );

  dma_block_read( c1100, dma_addr, 0, 0xffffff, stride,
                  0, 0, 0xffffff, stride, size, count );

  wd_pcie_peek( bar0, 0x001008, &cycles );

  usleep(5);

  uint rd_req_after;
  uint rd_cpl_after;
  wd_pcie_peek( bar0, 0x000020, &rd_req_after );
  wd_pcie_peek( bar0, 0x000024, &rd_cpl_after );
  rd_req = rd_req_after - rd_req;
  rd_cpl = rd_cpl_after - rd_cpl;

  FD_LOG_NOTICE(( "read %lu blocks of %lu bytes (total %lu B, stride %lu) in %u ns (%u req %u cpl): %lu Mbps",
                  count, size, count * size, stride, cycles * 4, rd_req, rd_cpl, size * count * 8 * 1000 / (cycles * 4) ));
}

int
c1100_dma_benchmark( C1100 * c1100, ulong dma_region_addr ) {
  ulong size;
  ulong stride;
  ulong count;

  FD_LOG_NOTICE(( "disable interrupts" ));
  void * bar0 = c1100_bar_handle( c1100, 0 );
  wd_pcie_poke( bar0, 0x000008, 0x0 );

  FD_LOG_NOTICE(( "perform block reads (dma_alloc_coherent)" ));

  count = 10000;
  for( size = 1; size <= 8192; size *= 2 ) {
    for( stride = size; stride <= (size > 256 ? size : 256); stride *= 2 ) {
      dma_block_read_bench( c1100, dma_region_addr + 0x0000, size, stride, count );
      uint value;
      wd_pcie_peek( bar0, 0x000000, &value );
      if( (value & 0x300) != 0 )
        return 1;
    }
  }

  FD_LOG_NOTICE(( "perform block writes (dma_alloc_coherent)" ));

  count = 10000;
  for( size = 1; size <= 8192; size *= 2 ) {
    for( stride = size; stride <= (size > 256 ? size : 256); stride *= 2 ) {
      dma_block_write_bench( c1100, dma_region_addr + 0x0000, size, stride, count );
      uint value;
      wd_pcie_peek( bar0, 0x000000, &value );
      if( (value & 0x300) != 0 )
        return 1;
    }
  }

  return 0;
}

int
c1100_dma_benchmark2( C1100 * c1100, void * buf, ulong dma_region_addr, uint sz ) {
  ulong size = 2048;
  ulong stride = 2048;
  ulong count = 8192UL;

  for( uint i=0; i<sz; i++ ) {
      ((char *)buf)[i] = (char)i;
  }

  FD_LOG_NOTICE(( "disable interrupts" ));
  void * bar0 = c1100_bar_handle( c1100, 0 );
  wd_pcie_poke( bar0, 0x000008, 0x0 );

  FD_LOG_NOTICE(( "perform block reads (dma_alloc_coherent)" ));

  dma_block_read_bench( c1100, dma_region_addr + 0x0000, size, stride, count );
  uint value;
  wd_pcie_peek( bar0, 0x000000, &value );
  if( (value & 0x300) != 0 )
    return 1;

  FD_LOG_NOTICE(( "perform block writes (dma_alloc_coherent)" ));

  dma_block_write_bench( c1100, dma_region_addr + (1UL<<24UL), size, stride, count );
  wd_pcie_peek( bar0, 0x000000, &value );
  if( (value & 0x300) != 0 )
    return 1;

  for( uint i=0; i<count; i++ ) {
    ulong offset = i*size;
    if( memcmp( (char *)buf+offset, &((char *)buf)[(1UL<<24UL) + offset], size ) != 0 ) {
      FD_LOG_NOTICE(( "test data mismatch" ));
      FD_LOG_HEXDUMP_NOTICE(( "data in",  (char *)buf+offset, 1024 ));
      FD_LOG_HEXDUMP_NOTICE(( "data out", &((char *)buf)[(1UL<<24UL)+offset], 1024 ));
      return 1;
    }
  }

  FD_LOG_NOTICE(( "test data matches" ));
  return 0;
}
