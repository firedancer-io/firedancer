#include "fd_memusage.h"
#include "../wksp/fd_wksp_private.h"
#include "../shmem/fd_shmem_private.h"
#include <stdio.h>
#include <stdlib.h>

static const char *
print_smart_sz( char * buf, uint buf_sz, ulong sz ) {
    if( sz < 1024UL/2) {
      snprintf( buf, buf_sz, "%luB", sz);
    } else if( sz < 1024UL*1024/2) {
      snprintf( buf, buf_sz, "%.2fKB", ((double)sz)/1024.0 );
    } else if( sz < 1024UL*1024*1024/2) {
      snprintf( buf, buf_sz, "%.2fMB", ((double)sz)/(1024.0*1024.0) );
    } else {
      snprintf( buf, buf_sz, "%.2fGB", ((double)sz)/(1024.0*1024.0*1024.0) );
    }
    return buf;
}

static int
fd_wksp_private_pinfo_cmp( const void * a, const void * b ) {
  fd_wksp_private_pinfo_t * ptr_a = *(fd_wksp_private_pinfo_t **)a;
  ulong sz_a = ptr_a->gaddr_hi - ptr_a->gaddr_lo;
  fd_wksp_private_pinfo_t * ptr_b = *(fd_wksp_private_pinfo_t **)b;
  ulong sz_b = ptr_b->gaddr_hi - ptr_b->gaddr_lo;
  return (sz_a > sz_b) ? -1 : (( sz_a < sz_b ) ? 1 : 0);
}

#define PART_LIST_MAX_MAX (1U<<20)
static fd_wksp_private_pinfo_t * part_list[PART_LIST_MAX_MAX];

void
fd_memusage_printout_wksp( FILE * fp, fd_wksp_t * wksp ) {
  char buf[128];
  char buf2[128];

  fprintf( fp, "  wksp: part_max=%lu, data_max=%s\n",
           wksp->part_max, print_smart_sz(buf, sizeof(buf), wksp->data_max) );

  // Print out the partition info
  fd_wksp_private_pinfo_t * part_info = (fd_wksp_private_pinfo_t *)((const unsigned char *)wksp + fd_wksp_private_pinfo_off());
  ulong list_cnt = 0UL;
  for( ulong part_idx=0UL; part_idx<wksp->part_max && part_idx<PART_LIST_MAX_MAX; part_idx++ ) {
    if( part_info[part_idx].gaddr_hi == 0UL || part_info[part_idx].tag == 0 ) continue;
    part_list[list_cnt++] = &part_info[part_idx];
  }

  // Sort the list by size
  qsort( part_list, list_cnt, sizeof(fd_wksp_private_pinfo_t *), fd_wksp_private_pinfo_cmp );

  // Print out the partition info
  ulong prev_sz = 0UL;
  ulong prev_tag = 0UL;
  ulong group_cnt = 0UL;
  ulong tot_sz = 0UL;
  for( ulong idx=0UL; idx<list_cnt; idx++ ) {
    fd_wksp_private_pinfo_t * ptr = part_list[idx];
    ulong sz = ptr->gaddr_hi - ptr->gaddr_lo;
    tot_sz += sz;
    // Group by size and tag
    if( group_cnt && !((prev_sz == sz) && (prev_tag == ptr->tag)) ) {
      fprintf( fp, "    parts: sz=%s, tag=%lu, cnt=%lu, tot_sz=%s\n",
               print_smart_sz(buf, sizeof(buf), prev_sz), prev_tag, group_cnt,
               print_smart_sz(buf2, sizeof(buf2), group_cnt*prev_sz) );
      group_cnt = 0UL;
    }
    group_cnt++;
    prev_sz = sz;
    prev_tag = ptr->tag;
  }
  if( group_cnt > 0UL ) {
    fprintf( fp, "    parts: sz=%s, tag=%lu, cnt=%lu, tot_sz=%s\n",
             print_smart_sz(buf, sizeof(buf), prev_sz), prev_tag, group_cnt,
             print_smart_sz(buf2, sizeof(buf2), group_cnt*prev_sz) );
  }
  fprintf( fp, "    parts: tot_tot_sz=%s, wksp usage=%.3f%%\n",
           print_smart_sz(buf, sizeof(buf), tot_sz),
           ((double)tot_sz)/((double)wksp->data_max)*100.0 );

  return;
}

static int fd_shmem_join_info_cmp( const void * a, const void * b ) {
  fd_shmem_join_info_t * ptr_a = *(fd_shmem_join_info_t **)a;
  ulong sz_a = ptr_a->page_sz*ptr_a->page_cnt;
  fd_shmem_join_info_t * ptr_b = *(fd_shmem_join_info_t **)b;
  ulong sz_b = ptr_b->page_sz*ptr_b->page_cnt;
  return (sz_a > sz_b) ? -1 : (( sz_a < sz_b ) ? 1 : 0);
}

void fd_memusage_printout( const char * filename ) {
  char buf[128];

  FILE * fp = ( (filename == NULL) ? stderr : fopen( filename, "w" ) );
  if( !fp ) {
    FD_LOG_WARNING(( "failed to open file %s", filename ));
    return;
  }

  // Loop over all the shmems
  #define SHMEM_PTRS_MAX (1U<<8)
  fd_shmem_join_info_t const * ptrs[SHMEM_PTRS_MAX];
  ulong ptrs_cnt = 0UL;
  for( fd_shmem_join_info_t const * iter = fd_shmem_iter_begin();
       ptrs_cnt<SHMEM_PTRS_MAX && !fd_shmem_iter_done(iter);
       iter = fd_shmem_iter_next(iter) ) {
    ptrs[ptrs_cnt++] = iter;
  }

  // Sort the shmemptrs by size
  qsort( ptrs, ptrs_cnt, sizeof(fd_shmem_join_info_t *), fd_shmem_join_info_cmp );

  // Print out the shmems
  ulong tot_sz = 0UL;
  for( ulong ptr_idx=0UL; ptr_idx<ptrs_cnt; ptr_idx++ ) {
    fd_shmem_join_info_t const * ptr = ptrs[ptr_idx];
    ulong sz = ptr->page_sz*ptr->page_cnt;
    tot_sz += sz;
    const char * name = (ptr->name[0] == '\0') ? "unnamed" : ptr->name;
    fprintf( fp, "shmem: %s %p...%p %s\n", name,
            (void *)ptr->shmem, (void *)(((const uchar *)ptr->shmem)+sz),
            print_smart_sz(buf, sizeof(buf), sz) );

    // Check if the shmem is a wksp
    if( strlen(name) > 5 && strcmp(name + strlen(name) - 5, ".wksp") == 0 ) {
      fd_wksp_t * wksp = (fd_wksp_t *)ptr->join;
      if( FD_UNLIKELY( wksp == NULL || sz < sizeof(fd_wksp_t) || wksp->magic!=FD_WKSP_MAGIC ) ) continue;
      fd_memusage_printout_wksp( fp, wksp );
    }
  }

  fprintf( fp, "all shmem: tot_sz=%s\n", print_smart_sz(buf, sizeof(buf), tot_sz) );

  fflush( fp );
  if( fp != stderr ) { fclose( fp ); }

  return;
}
