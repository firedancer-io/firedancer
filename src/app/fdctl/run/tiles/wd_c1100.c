#include "wd_c1100.h"
#include "../../../../util/log/fd_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

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
        i, bms[i].bi.start, bms[i].bi.end, bms[i].bi.size, (ulong)bms[i].addr, bms[i].fd, bms[i].bi.path ));
  }
}

static
void mmap_bar( BarInfo const * bi, BarMap * bm ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/bus/pci/devices/%s/resource0", bi->pcie_device ) );
  bm->fd = open( bi->path, O_RDWR | O_SYNC );

  if( FD_UNLIKELY( bm->fd == -1 ) ) {
    FD_LOG_ERR(("Error opening device file %s %s", bi->path, bi->pcie_device ));
    return;
  }

  bm->addr = mmap( (void *)bi->start, bi->size, PROT_READ | PROT_WRITE, MAP_SHARED, bm->fd, 0);

  bm->bi = *bi;

  if( FD_UNLIKELY( bm->addr == MAP_FAILED ) ) {
    FD_LOG_ERR(("Error mapping memory: %s\n", strerror(errno)));
    return;
  }
}

int wd_pcie_peek( void * h, ulong offset, uint * value ) {
  BarMap * bm = (BarMap *)h;
  *value = ((uint *)bm->addr)[offset];
  return 0;
}

int wd_pcie_poke( void * h, ulong offset, uint   value ) {
  BarMap * bm = (BarMap *)h;
  ((uint *)bm->addr)[offset] = value;
  return 0;
}

static
void * get_bar_handle( uint bar_num, BarMap const * bm, uint bm_sz ) {
  for( uint i=0; i<bm_sz; i++ ) {
    if( FD_UNLIKELY( bm[i].bi.num == bar_num ) ) {
      return (void *)&bm[i];
    }
  }
  return NULL;
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
  return get_bar_handle( bar_num, c1100->bm, c1100->sz );
}

uint c1100_bar_count( C1100 const * c1100 ) {
  return c1100->sz;
}

int c1100_bar_fd( C1100 * c1100, uint bar_num ) {
  for( uint i=0; i<c1100->sz; i++ ) {
    if( FD_UNLIKELY( c1100->bm[i].bi.num == bar_num ) ) {
      return c1100->bm[i].fd;
    }
  }
  return -1;
}