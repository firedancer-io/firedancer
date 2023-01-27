#ifndef HEADER_fd_quic_util_h
#define HEADER_fd_quic_util_h

#include <stdint.h>
#include <string.h>
#include "../../util/fd_util_base.h"
#include <stdlib.h>

/* calculate and write ipv4 header
   caller ensures buf has at least 20 bytes containing a 20 byte ipv4 headers
   checksum is written into pkt */
inline void
fd_quic_net_ipv4_checksum( uchar * pkt ) {
  memset( pkt + 10, 0, 2 ); /* set checksum to 0 at start */

  uint32_t tmp[5];
  memcpy( tmp, pkt, 20 );

  uint64_t check = (uint64_t)tmp[0] + (uint64_t)tmp[1] + (uint64_t)tmp[2] + (uint64_t)tmp[3] + (uint64_t)tmp[4];
  check = ( check & 0xffffu ) + ( check >> 16u );
  check = (uint32_t)( check >> 16u ) + (uint16_t)check;
  if( check >> 16u ) {
    abort();
  }
  check = (unsigned)check ^ (unsigned)0xffff;

  memcpy( pkt + 10, &check, 2 );
}


#endif

