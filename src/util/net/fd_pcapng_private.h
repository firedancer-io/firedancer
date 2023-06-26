#ifndef HEADER_fd_src_util_net_fd_pcapng_private_h
#define HEADER_fd_src_util_net_fd_pcapng_private_h

#include "fd_pcapng.h"

/* FD_PCAPNG_BLOCK_SZ: max size of serialized block
   (including packet content)  FIXME allow for jumbos? */
#define FD_PCAPNG_BLOCK_SZ (4096UL)

/* FD_PCAPNG_BLOCK_TYPE_*: Block type identifiers */

#define FD_PCAPNG_BLOCK_TYPE_SHB (0x0A0D0D0AU) /* Section Header Block        */
#define FD_PCAPNG_BLOCK_TYPE_IDB (0x00000001U) /* Interface Description Block */
#define FD_PCAPNG_BLOCK_TYPE_SPB (0x00000003U) /* Simple Packet Block         */
#define FD_PCAPNG_BLOCK_TYPE_EPB (0x00000006U) /* Enhanced Packet Block       */
#define FD_PCAPNG_BLOCK_TYPE_DSB (0x0000000AU) /* Decryption Secrets Block    */

/* FD_PCAPNG_BYTE_ORDER_MAGIC: BOM in logical order */

#define FD_PCAPNG_BYTE_ORDER_MAGIC (0x1A2B3C4D)

/* fd_pcapng_option_t points to a variable-length option value.
   Kind of option value depends on option type.  Strings (char *) are
   UTF-8 encoded and are not zero terminated. */

struct fd_pcapng_option {
  ushort type;  /* FD_PCAPNG_*_OPT_* */
  ushort sz;    /* byte size of option data at value */
  void * value; /* points to first byte of option data */
};
typedef struct fd_pcapng_option fd_pcapng_option_t;

/* Common option codes */

#define FD_PCAPNG_OPT_END     ((ushort)0) /* end of options */
#define FD_PCAPNG_OPT_COMMENT ((ushort)1)

#define FD_PCAPNG_MAX_OPT_CNT 256

/* fd_pcapng_hdr_t: Common block header */

struct __attribute__((packed)) fd_pcapng_block_hdr {
  uint block_type;
  uint block_sz;
};
typedef struct fd_pcapng_block_hdr fd_pcapng_block_hdr_t;

/* fd_pcapng_shb_t: Section Header Block */

#define FD_PCAPNG_SHB_OPT_HARDWARE ((ushort)2)  /* char * hardware; max once */
#define FD_PCAPNG_SHB_OPT_OS       ((ushort)3)  /* char * os_name ; max once */
#define FD_PCAPNG_SHB_OPT_USERAPPL ((ushort)4)  /* char * app_name; max once */

struct __attribute__((packed)) fd_pcapng_shb {
  uint   block_type;       /* ==FD_PCAPNG_BLOCK_TYPE_SHB */
  uint   block_sz;         /* ==sizeof(fd_pcapng_shb_t) */
  uint   byte_order_magic; /* ==FD_PCAPNG_BYTE_ORDER_MAGIC */
  ushort version_major;    /* ==1 */
  ushort version_minor;    /* ==0 */
  ulong  section_sz;       /* ==ULONG_MAX (undefined) */
};
typedef struct fd_pcapng_shb fd_pcapng_shb_t;

/* fd_pcapng_idb_t: Interface Description Block */

#define FD_PCAPNG_IDB_OPT_NAME      ((ushort) 2) /* char * if_name;        max once */
#define FD_PCAPNG_IDB_OPT_IPV4_ADDR ((ushort) 4) /* uint   ip4;            multiple */
#define FD_PCAPNG_IDB_OPT_MAC_ADDR  ((ushort) 6) /* char   hwaddr[6];      max once */
#define FD_PCAPNG_IDB_OPT_TSRESOL   ((ushort) 9) /* uchar  tsresol;        max once */
#define FD_PCAPNG_IDB_OPT_HARDWARE  ((ushort)15) /* char * device_name;    max once */

struct __attribute__((packed)) fd_pcapng_idb {
  uint   block_type; /* ==FD_PCAPNG_BLOCK_TYPE_IDB */
  uint   block_sz;   /* ==sizeof(fd_pcapng_idb_t) */
  ushort link_type;  /* ==FD_PCAPNG_LINKTYPE_ETHERNET */
  ushort _pad_0a;    /* ==0 */
  uint   snap_len;   /* packet payload sz limit, 0==unlim */
};
typedef struct fd_pcapng_idb fd_pcapng_idb_t;

/* fd_pcapng_spb_t: Simple Packet Block */

struct __attribute__((packed)) fd_pcapng_spb {
  uint   block_type; /* ==FD_PCAPNG_BLOCK_TYPE_SPB      */
  uint   block_sz;   /* >=sizeof(fd_pcapng_spb_t)       */
  uint   orig_len;   /* Original packet size (bytes)    */
};
typedef struct fd_pcapng_spb fd_pcapng_spb_t;

/* fd_pcapng_epb_t: Enhanced Packet Block */

struct __attribute__((packed)) fd_pcapng_epb {
  uint   block_type; /* ==FD_PCAPNG_BLOCK_TYPE_EPB      */
  uint   block_sz;   /* >=sizeof(fd_pcapng_epb_t)       */
  uint   if_idx;     /* Index of related IDB in section */
  uint   ts_hi;      /* High 32 bits of timestamp       */
  uint   ts_lo;      /* Low 32 bits of timestamp        */
  uint   cap_len;    /* Captured packet size (bytes)    */
  uint   orig_len;   /* Original packet size (bytes)    */
};
typedef struct fd_pcapng_epb fd_pcapng_epb_t;

/* fd_pcapng_dsb_t: Decryption Secrets Block */

#define FD_PCAPNG_SECRET_TYPE_TLS (0x544c534bU)

struct __attribute__((packed)) fd_pcapng_dsb {
  uint   block_type;  /* ==FD_PCAPNG_BLOCK_TYPE_DSB */
  uint   block_sz;    /* >=sizeof(fd_pcapng_dsb_t)  */
  uint   secret_type; /* ==FD_PCAPNG_SECRET_TYPE_*  */
  uint   secret_sz;   /* byte sz of secrets data    */
};
typedef struct fd_pcapng_dsb fd_pcapng_dsb_t;

struct fd_pcapng_idb_desc {
  uint                 link_type;
  fd_pcapng_idb_opts_t opts;
};
typedef struct fd_pcapng_idb_desc fd_pcapng_idb_desc_t;

struct __attribute__((aligned(FD_PCAPNG_ITER_ALIGN))) fd_pcapng_iter {
  void * stream;
  int    error;

# define FD_PCAPNG_IFACE_CNT 16
  fd_pcapng_idb_desc_t iface[ FD_PCAPNG_IFACE_CNT ];
  uint                 iface_cnt;
};

#endif /* HEADER_fd_src_util_net_fd_pcapng_private_h */

