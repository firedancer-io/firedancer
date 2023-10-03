#ifndef HEADER_fd_src_disco_fd_disco_base_h
#define HEADER_fd_src_disco_fd_disco_base_h

#include "../tango/fd_tango.h"
#include "../ballet/txn/fd_txn.h"

#include "../util/wksp/fd_wksp_private.h"

#define SRC_TILE_NET  (0UL)
#define SRC_TILE_QUIC (1UL)

/* FD_NET_MTU is the max full packet size, with ethernet, IP, and UDP
   headers that can go in or out of the net tile.  2048 is the maximum
   XSK entry size, so this value follows naturally. */
#define FD_NET_MTU (2048UL)

/* FD_TPU_MTU is the max serialized byte size of a txn sent over TPU. */
#define FD_TPU_MTU (1232UL)

/* FD_TPU_DCACHE_MTU is the max size of a dcache entry */
#define FD_TPU_DCACHE_MTU (FD_TPU_MTU + FD_TXN_MAX_SZ + 2UL)

#define SCRATCH_ALLOC( a, s ) (__extension__({                    \
    ulong _scratch_alloc = fd_ulong_align_up( scratch_top, (a) ); \
    scratch_top = _scratch_alloc + (s);                           \
    (void *)_scratch_alloc;                                       \
  }))

/* FD_APP_CNC_DIAG_* are FD_CNC_DIAG_* style diagnostics and thus the
   same considerations apply.  Further they are harmonized with the
   standard FD_CNC_DIAG_*.  Specifically:

     IN_BACKP is same as standard IN_BACKP

     BACKP_CNT is same as standard BACKP_CNT

     {HA,SV}_FILT_{CNT,SZ} is app specific and the number of times a
     transaction was dropped by a verify tile due to failing signature
     verification. */

#define FD_APP_CNC_DIAG_IN_BACKP    FD_CNC_DIAG_IN_BACKP  /* ==0 */
#define FD_APP_CNC_DIAG_BACKP_CNT   FD_CNC_DIAG_BACKP_CNT /* ==1 */
#define FD_APP_CNC_DIAG_HA_FILT_CNT (2UL)                 /* updated by verify tile, frequently in ha situations, never o.w. */
#define FD_APP_CNC_DIAG_HA_FILT_SZ  (3UL)                 /* " */
#define FD_APP_CNC_DIAG_SV_FILT_CNT (4UL)                 /* ", ideally never */
#define FD_APP_CNC_DIAG_SV_FILT_SZ  (5UL)                 /* " */

#define FD_APP_CNC_DIAG_PID         (128UL)

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_disco_netmux_sig( ulong  ip_addr,
                     ushort port,
                     ushort src_tile,
                     ushort dst_idx ) {
  return (((ulong)ip_addr)<<32UL) | (((ulong)port)<<16UL) | ((src_tile&0xFUL)<<12UL) | (dst_idx&0xFUL);
}

FD_FN_CONST static inline ulong  fd_disco_netmux_sig_ip_addr ( ulong sig ) { return (sig>>32UL) & 0xFFFFUL; }
FD_FN_CONST static inline ushort fd_disco_netmux_sig_port    ( ulong sig ) { return (sig>>16UL) & 0xFFFFUL; }
FD_FN_CONST static inline ushort fd_disco_netmux_sig_src_tile( ulong sig ) { return (sig>>12UL) & 0xFUL; }
FD_FN_CONST static inline ushort fd_disco_netmux_sig_dst_idx ( ulong sig ) { return (sig>> 0UL) & 0xFUL; }

FD_FN_PURE static inline ulong
fd_disco_compact_chunk0( void * wksp ) {
  return (((struct fd_wksp_private *)wksp)->gaddr_lo) >> FD_CHUNK_LG_SZ;
}

FD_FN_PURE static inline ulong
fd_disco_compact_wmark( void * wksp, ulong mtu ) {
  ulong chunk_mtu  = ((mtu + 2UL*FD_CHUNK_SZ-1UL) >> (1+FD_CHUNK_LG_SZ)) << 1;
  ulong wksp_hi = ((struct fd_wksp_private *)wksp)->gaddr_hi;
  return (wksp_hi >> FD_CHUNK_LG_SZ) - chunk_mtu;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_fd_disco_base_h */

