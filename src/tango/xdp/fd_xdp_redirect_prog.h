#ifndef HEADER_fd_src_tango_xdp_fd_xdp_redirect_prog_h
#define HEADER_fd_src_tango_xdp_fd_xdp_redirect_prog_h

/* Cross-platform definitions about fd_xdp_redirect_prog.c */

/* FD_XDP_XSKS_MAP_CNT: Max supported number of XSKs (queues).
   The actual limit may be lower in practice depending on hardware. */
#define FD_XDP_XSKS_MAP_CNT 256U

/* FD_XDP_UDP_MAP_CNT: Max supported number of UDP port mappings. */
#define FD_XDP_UDP_MAP_CNT  64U

#endif /* HEADER_fd_src_tango_xdp_fd_xdp_redirect_prog_h */
