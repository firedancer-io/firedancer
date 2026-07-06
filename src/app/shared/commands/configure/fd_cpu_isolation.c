#include "fd_cpu_isolation.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

fd_cpuset_t *
fd_cpu_isolation_tile_cpus( fd_cpuset_t       cpuset[ static fd_cpuset_word_cnt ],
                            fd_topo_t const * topo ) {
  fd_cpuset_new( cpuset );
  ulong cpu_cnt = fd_ulong_min( fd_shmem_cpu_cnt(), FD_TILE_MAX );
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    if( tile->cpu_idx<cpu_cnt ) fd_cpuset_insert( cpuset, tile->cpu_idx );
  }
  return cpuset;
}

fd_cpuset_t *
fd_cpu_isolation_host_cpus( fd_cpuset_t cpuset[ static fd_cpuset_word_cnt ] ) {
  fd_cpuset_new( cpuset );
  ulong cpu_cnt = fd_ulong_min( fd_shmem_cpu_cnt(), FD_TILE_MAX );
  for( ulong cpu_idx=0UL; cpu_idx<cpu_cnt; cpu_idx++ ) fd_cpuset_insert( cpuset, cpu_idx );
  return cpuset;
}

int
fd_cpu_isolation_parse_list( fd_cpuset_t  cpuset[ static fd_cpuset_word_cnt ],
                             char const * list ) {
  fd_cpuset_new( cpuset );

  char const * p = list;
  while( isspace( (uchar)*p ) ) p++;
  if( FD_UNLIKELY( !*p ) ) return 1; /* empty set */

  /* /sys/devices/system/cpu/nohz_full contains the literal string
     "(null)" on kernels with CONFIG_NO_HZ_FULL but no nohz_full= boot
     parameter. */
  if( FD_UNLIKELY( !strncmp( p, "(null)", 6UL ) ) ) return 1;

  for(;;) {
    if( FD_UNLIKELY( !isdigit( (uchar)*p ) ) ) return 0;
    ulong lo = 0UL;
    while( isdigit( (uchar)*p ) ) { lo = lo*10UL + (ulong)(*p-'0'); if( FD_UNLIKELY( lo>FD_TILE_MAX*2UL ) ) return 0; p++; }
    ulong hi = lo;
    if( FD_UNLIKELY( *p=='-' ) ) {
      p++;
      if( FD_UNLIKELY( !isdigit( (uchar)*p ) ) ) return 0;
      hi = 0UL;
      while( isdigit( (uchar)*p ) ) { hi = hi*10UL + (ulong)(*p-'0'); if( FD_UNLIKELY( hi>FD_TILE_MAX*2UL ) ) return 0; p++; }
    }
    if( FD_UNLIKELY( hi<lo ) ) return 0;
    for( ulong cpu=lo; cpu<=hi; cpu++ ) {
      if( FD_LIKELY( cpu<FD_TILE_MAX ) ) fd_cpuset_insert( cpuset, cpu );
    }

    if( FD_LIKELY( *p==',' ) ) { p++; continue; }
    while( isspace( (uchar)*p ) ) p++;
    if( FD_LIKELY( !*p ) ) return 1;
    return 0;
  }
}

char *
fd_cpu_isolation_format_list( char *              buf,
                              ulong               buf_sz,
                              fd_cpuset_t const * cpuset ) {
  char * p   = buf;
  char * end = buf+buf_sz-1UL;
  int first = 1;

  ulong cpu = 0UL;
  while( cpu<FD_TILE_MAX ) {
    if( FD_LIKELY( !fd_cpuset_test( cpuset, cpu ) ) ) { cpu++; continue; }
    ulong lo = cpu;
    while( cpu+1UL<FD_TILE_MAX && fd_cpuset_test( cpuset, cpu+1UL ) ) cpu++;
    ulong hi = cpu;
    cpu++;

    if( FD_UNLIKELY( (ulong)(end-p)<48UL ) ) break; /* can't overflow with LIST_MAX, defensive */
    if( FD_LIKELY( !first ) ) *p++ = ',';
    first = 0;
    p = fd_cstr_append_ulong_as_text( p, 0, 0, lo, fd_ulong_base10_dig_cnt( lo ) );
    if( FD_UNLIKELY( hi>lo ) ) {
      *p++ = '-';
      p = fd_cstr_append_ulong_as_text( p, 0, 0, hi, fd_ulong_base10_dig_cnt( hi ) );
    }
  }
  *p = '\0';
  return buf;
}

int
fd_cpu_isolation_parse_mask( fd_cpuset_t  cpuset[ static fd_cpuset_word_cnt ],
                             char const * mask ) {
  fd_cpuset_new( cpuset );

  char const * end = mask;
  while( *end && !isspace( (uchar)*end ) ) end++;
  if( FD_UNLIKELY( end==mask ) ) return 0;

  ulong cpu_idx = 0UL;
  for( char const * p=end; p>mask; ) {
    p--;
    if( FD_UNLIKELY( *p==',' ) ) continue;

    int digit;
    if(      FD_LIKELY( (*p>='0') & (*p<='9') ) ) digit = *p-'0';
    else if( FD_LIKELY( (*p>='a') & (*p<='f') ) ) digit = 10+*p-'a';
    else if( FD_LIKELY( (*p>='A') & (*p<='F') ) ) digit = 10+*p-'A';
    else return 0;

    for( ulong bit=0UL; bit<4UL; bit++ ) {
      if( FD_UNLIKELY( cpu_idx>=FD_TILE_MAX ) ) return 1;
      if( FD_UNLIKELY( digit & (1<<bit) ) ) fd_cpuset_insert( cpuset, cpu_idx );
      cpu_idx++;
    }
  }
  return 1;
}

char *
fd_cpu_isolation_format_mask( char *              buf,
                              ulong               buf_sz,
                              fd_cpuset_t const * cpuset ) {
  ulong cpu_cnt  = fd_ulong_max( fd_ulong_min( fd_shmem_cpu_cnt(), FD_TILE_MAX ), 1UL );
  ulong word_cnt = fd_ulong_max( (cpu_cnt+31UL)/32UL, 1UL );
  char * p = buf;

  FD_TEST( buf_sz>=word_cnt*9UL+1UL );

  for( ulong word_rem=word_cnt; word_rem; word_rem-- ) {
    ulong word_idx = word_rem-1UL;
    if( FD_UNLIKELY( word_idx!=word_cnt-1UL ) ) *p++ = ',';

    for( ulong nib_rem=8UL; nib_rem; nib_rem-- ) {
      ulong nib_idx = nib_rem-1UL;
      int digit = 0;
      for( ulong bit=0UL; bit<4UL; bit++ ) {
        ulong cpu_idx = word_idx*32UL + nib_idx*4UL + bit;
        if( FD_LIKELY( cpu_idx<FD_TILE_MAX && fd_cpuset_test( cpuset, cpu_idx ) ) ) digit |= (int)(1UL<<bit);
      }
      *p++ = "0123456789abcdef"[ digit ];
    }
  }
  *p = '\0';
  return buf;
}


int
fd_cpu_isolation_read_list( char const * path,
                            fd_cpuset_t  cpuset[ static fd_cpuset_word_cnt ] ) {
  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) return 0;
    FD_LOG_ERR(( "open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }

  char list[ FD_CPU_ISOLATION_LIST_MAX ];
  long list_len = read( fd, list, sizeof(list)-1UL );
  if( FD_UNLIKELY( list_len<0L ) ) FD_LOG_ERR(( "read(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  list[ list_len ] = '\0';

  if( FD_UNLIKELY( !fd_cpu_isolation_parse_list( cpuset, list ) ) )
    FD_LOG_ERR(( "failed to parse `%s` (\"%s\")", path, list ));
  return 1;
}
