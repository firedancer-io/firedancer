#include "fd_proc_interrupts.h"
#include "../../util/tile/fd_tile.h" /* FD_TILE_MAX */
#include "../../util/io/fd_io.h" /* fd_io_buffered_istream */
#include <ctype.h> /* isdigit */

static void
skip_spaces( fd_io_buffered_istream_t * is ) {
  char const * peek    = fd_io_buffered_istream_peek   ( is );
  ulong        peek_sz = fd_io_buffered_istream_peek_sz( is );
  ulong j;
  for( j=0UL; j<peek_sz && peek[j]==' '; j++ ) {}
  fd_io_buffered_istream_skip( is, j );
}

static void
skip_token( fd_io_buffered_istream_t * is ) {
  char const * peek    = fd_io_buffered_istream_peek   ( is );
  ulong        peek_sz = fd_io_buffered_istream_peek_sz( is );
  ulong j;
  for( j=0UL; j<peek_sz && peek[j]!=' ' && peek[j]!='\n'; j++ ) {}
  fd_io_buffered_istream_skip( is, j );
}

static void
skip_line( fd_io_buffered_istream_t * is ) {
  char const * peek    = fd_io_buffered_istream_peek   ( is );
  ulong        peek_sz = fd_io_buffered_istream_peek_sz( is );
  ulong j;
  for( j=0UL; j<peek_sz && peek[j]!='\n'; j++ ) {}
  if( j<peek_sz && peek[j]=='\n' ) j++;
  fd_io_buffered_istream_skip( is, j );
}

/* read_ulong consumes a decimal ulong from buffered unconsumed chars in
   is.  Returns ULONG_MAX if parse failed. */

static ulong
read_ulong( fd_io_buffered_istream_t * is ) {
  char const * peek    = fd_io_buffered_istream_peek   ( is );
  ulong        peek_sz = fd_io_buffered_istream_peek_sz( is );
  char num[ 21 ];
  peek_sz = fd_ulong_min( peek_sz, 20 );
  ulong num_sz;
  for( num_sz=0UL; num_sz<peek_sz && isdigit( peek[num_sz] ); num_sz++ ) {}
  memcpy( num, peek, num_sz );
  num[ num_sz ] = '\0';
  fd_io_buffered_istream_skip( is, num_sz );
  if( FD_UNLIKELY( num_sz==0 ) ) return ULONG_MAX;
  return fd_cstr_to_ulong( num );
}

static int
read_until( fd_io_buffered_istream_t * is,
            ulong                      min_sz,
            void (*skip)( fd_io_buffered_istream_t * is ) ) {

  ulong buf_sz = fd_io_buffered_istream_rbuf_sz( is );
  min_sz = fd_ulong_min( min_sz, buf_sz );

  /* Read until 'skip' leaves some bytes */

  for(;;) {
    skip( is );
    if( fd_io_buffered_istream_peek_sz( is )>0 ) return 0;
    int err = fd_io_buffered_istream_fetch( is );
    if( err==0 ) {
      continue;
    }
    if( err==-1 ) {
      if( fd_io_buffered_istream_peek_sz( is )==0 ) return -1;
      continue;
    }
    return err;
  }

  /* Read ahead */

  if( fd_io_buffered_istream_peek_sz( is )<min_sz ) {
    int err = fd_io_buffered_istream_fetch( is );
    if( err!=0 && err!=-1 ) return err;
  }

  return 0;
}

/* read_cpu_map reads the first line of /proc/interrupt mapping columns
   to CPUs.  Usually 0,1,2,3,... but has gaps for offline CPUs.
   Formatted like this:
   "   CPU0  CPU1  CPU2  CPU3\n" */

static int
read_cpu_map(  fd_io_buffered_istream_t * is,
               ulong *                    out_col_cnt,
               ulong *                    out_cpu_cnt,
               ushort                     col_cpu[ FD_TILE_MAX ] ) {
  *out_col_cnt = 0UL;
  *out_cpu_cnt = 0UL;

  /* Read first line */
  ulong col_cnt = 0UL;
  do {
    int err = read_until( is, 16UL, skip_spaces );
    if( FD_UNLIKELY( err!=0 ) ) return err;
    char const * peek    = fd_io_buffered_istream_peek   ( is );
    ulong        peek_sz = fd_io_buffered_istream_peek_sz( is );
    if( peek[0]=='\n' ) break;
    if( peek_sz<4     ) break;

    /* Filter for 'CPU<num>' column */
    if( 0!=memcmp( peek, "CPU", 3 ) ) break;
    fd_io_buffered_istream_skip( is, 3 );
    peek    = fd_io_buffered_istream_peek   ( is );
    peek_sz = fd_io_buffered_istream_peek_sz( is );

    /* Parse number */
    ulong cpu_idx = read_ulong( is );
    if( FD_UNLIKELY( cpu_idx==ULONG_MAX ) ) {
      FD_LOG_WARNING(( "Failed to parse first line of /proc/interrupts" ));
      break;
    }
    if( FD_UNLIKELY( cpu_idx>=FD_TILE_MAX ) ) {
      FD_LOG_WARNING(( "Out of bounds: CPU%lu", cpu_idx ));
      break;
    }

    col_cpu[ col_cnt++ ] = (ushort)cpu_idx;
  } while( col_cnt<FD_TILE_MAX );

  /* Skip rest of line */
  int err = read_until( is, 0UL, skip_line );
  if( FD_UNLIKELY( err!=0 ) ) return err;

  /* Verify CPU map */
  if( FD_UNLIKELY( col_cnt==0UL ) ) {
    FD_LOG_WARNING(( "No CPUs found reading /proc/interrupts" ));
    return 0;
  }
  ulong cpu_cnt = 0UL;
  for( ulong col_idx=0UL; col_idx<col_cnt; col_idx++ ) {
    ulong next_cpu_cnt = col_cpu[ col_idx ]+1UL;
    if( FD_UNLIKELY( next_cpu_cnt<=cpu_cnt ) ) {
      FD_LOG_WARNING(( "CPU%u out of order reading /proc/interrupts", col_cpu[ col_idx ] ));
      return 0;
    }
    cpu_cnt = next_cpu_cnt;
  }
  if( FD_UNLIKELY( cpu_cnt>FD_TILE_MAX ) ) {
    FD_LOG_WARNING(( "Too many CPUs found reading /proc/interrupts" ));
    return 0;
  }

  *out_cpu_cnt = cpu_cnt;
  *out_col_cnt = col_cnt;
  return 0;
}

ulong
fd_proc_interrupts_colwise( int   fd,
                            ulong per_cpu[ FD_TILE_MAX ] ) {
  fd_io_buffered_istream_t is[1];
  char buf[ 4096 ];
  fd_io_buffered_istream_init( is, fd, buf, sizeof(buf) );

  /* Read first line */

  ushort col_cpu[ FD_TILE_MAX ];
  ulong  col_cnt;
  ulong  cpu_cnt;
  int err = read_cpu_map( is, &col_cnt, &cpu_cnt, col_cpu );
  if( FD_UNLIKELY( err!=0 ) ) goto failed;
  if( FD_UNLIKELY( !col_cnt || !cpu_cnt ) ) return 0UL;

  for( ulong cpu=0UL; cpu<cpu_cnt; cpu++ ) {
    per_cpu[ cpu ] = 0UL;
  }

  /* Read interrupt table
     Device interrupt counters look like this:
     "  123:  41  42  43  44"
     Special interrupts look like this:
     "  NMI:   1   2   3   4" */

  for(;;) { /* each line */

    /* Read prefix */
    err = read_until( is, 64UL, skip_spaces );
    if( FD_UNLIKELY( err!=0 ) ) goto failed;
    if( fd_io_buffered_istream_peek_sz( is )==0 ) return cpu_cnt;
    if( !isdigit( ((char const *)fd_io_buffered_istream_peek( is ))[0] ) ) {
      /* Only count numbered interrupts */
      goto skip_line;
    }
    err = read_until( is, 0UL, skip_token );
    if( FD_UNLIKELY( err!=0 ) ) goto failed;

    /* Read interrupt counters */
    for( ulong col_idx=0UL; col_idx<col_cnt; col_idx++ ) {
      err = read_until( is, 21UL, skip_spaces );
      if( FD_UNLIKELY( err!=0 ) ) goto failed;

      ulong irq_cnt = read_ulong( is );
      irq_cnt = fd_ulong_if( irq_cnt!=ULONG_MAX, irq_cnt, 0UL );
      per_cpu[ col_cpu[ col_idx ] ] += irq_cnt;
    }

  skip_line:
    /* Ignore rest of line */
    err = read_until( is, 0UL, skip_line );
    if( FD_UNLIKELY( err!=0 ) ) {
      if( err==-1 ) break;
      goto failed;
    }

  }
  return cpu_cnt;

failed:
  if( err!=0 ) {
    FD_LOG_WARNING(( "read failed (%i-%s)", err, fd_io_strerror( err ) ));
  }
  return 0UL;
}

ulong
fd_proc_softirqs_sum( int   fd,
                      ulong per_cpu[ FD_METRICS_ENUM_SOFTIRQ_CNT ][ FD_TILE_MAX ] ) {
  fd_io_buffered_istream_t is[1];
  char buf[ 4096 ];
  fd_io_buffered_istream_init( is, fd, buf, sizeof(buf) );

  /* Read first line */

  ushort col_cpu[ FD_TILE_MAX ];
  ulong  col_cnt;
  ulong  cpu_cnt;
  int err = read_cpu_map( is, &col_cnt, &cpu_cnt, col_cpu );
  if( FD_UNLIKELY( err!=0 ) ) goto failed;
  if( FD_UNLIKELY( !col_cnt || !cpu_cnt ) ) return 0UL;
  for( ulong i=0UL; i<FD_METRICS_ENUM_SOFTIRQ_CNT; i++ ) {
    for( ulong c=0UL; c<cpu_cnt; c++ ) per_cpu[ i ][ c ] = 0UL;
  }

  /* Read softirq table
     Looks like this:
     "   NET_TX:   1   2   3   5" */

  for(;;) { /* each line */

    /* Read prefix */
    err = read_until( is, 64UL, skip_spaces );
    if( FD_UNLIKELY( err!=0 ) ) goto failed;
    if( fd_io_buffered_istream_peek_sz( is )==0 ) return cpu_cnt;

    /* Match prefix */
    int          kind       = FD_METRICS_ENUM_SOFTIRQ_V_OTHER_IDX;
    char const * prefix     = fd_io_buffered_istream_peek   ( is );
    ulong        prefix_max = fd_io_buffered_istream_peek_sz( is );
    if( prefix_max>=7 && fd_memeq( prefix, "NET_TX:", 7 ) ) {
      kind = FD_METRICS_ENUM_SOFTIRQ_V_NET_IDX;
    } else if( prefix_max>=7 && fd_memeq( prefix, "NET_RX:", 7 ) ) {
      kind = FD_METRICS_ENUM_SOFTIRQ_V_NET_IDX;
    } else if( prefix_max>=6 && fd_memeq( prefix, "BLOCK:", 6 ) ) {
      kind = FD_METRICS_ENUM_SOFTIRQ_V_DISK_IDX;
    }
    err = read_until( is, 0UL, skip_token );
    if( FD_UNLIKELY( err!=0 ) ) goto failed;

    /* Read interrupt counters */
    for( ulong col_idx=0UL; col_idx<col_cnt; col_idx++ ) {
      err = read_until( is, 21UL, skip_spaces );
      if( FD_UNLIKELY( err!=0 ) ) goto failed;

      ulong irq_cnt = read_ulong( is );
      irq_cnt = fd_ulong_if( irq_cnt!=ULONG_MAX, irq_cnt, 0UL );
      per_cpu[ kind ][ col_cpu[ col_idx ] ] += irq_cnt;
    }

    /* Ignore rest of line */
    err = read_until( is, 0UL, skip_line );
    if( FD_UNLIKELY( err!=0 ) ) {
      if( err==-1 ) break;
      goto failed;
    }

  }
  return cpu_cnt;

failed:
  if( err!=0 ) {
    FD_LOG_WARNING(( "read failed (%i-%s)", err, fd_io_strerror( err ) ));
  }
  return 0UL;
}
