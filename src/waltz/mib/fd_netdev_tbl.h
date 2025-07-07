#ifndef HEADER_fd_src_waltz_mib_fd_netdev_h
#define HEADER_fd_src_waltz_mib_fd_netdev_h

/* fd_netdev_tbl.h provides a network interface table.
   The entrypoint of this API is fd_netlink_tbl_t. */

#include "../../util/fd_util_base.h"

/* FD_OPER_STATUS_* give the operational state of a network interface.
   See RFC 2863 Section 3.1.14: https://datatracker.ietf.org/doc/html/rfc2863#section-3.1.14 */

#define FD_OPER_STATUS_INVALID          (0)
#define FD_OPER_STATUS_UP               (1)  /* ready to pass packets */
#define FD_OPER_STATUS_DOWN             (2)
#define FD_OPER_STATUS_TESTING          (3) /* in some test mode */
#define FD_OPER_STATUS_UNKNOWN          (4) /* status can not be determined */
#define FD_OPER_STATUS_DORMANT          (5)
#define FD_OPER_STATUS_NOT_PRESENT      (6) /* some component is missing */
#define FD_OPER_STATUS_LOWER_LAYER_DOWN (7) /* down due to state of lower-layer interface(s) */

/* fd_netdev_t holds basic configuration of a network device. */

struct fd_netdev {
  ushort mtu;            /* Largest layer-3 payload that fits in a packet */
  uchar  mac_addr[6];    /* MAC address */
  ushort if_idx;         /* Interface index */
  short  slave_tbl_idx;  /* index to bond slave table, -1 if not a bond master */
  short  master_idx;     /* index of bond master, -1 if not a bond slave */
  char   name[16];       /* cstr interface name (max 15 length) */
  uchar  oper_status;    /* one of FD_OPER_STATUS_{...} */
  ushort dev_type;       /* one of ARPHRD_ETHER/_LOOPBACK_/IPGRE*/
  uint   gre_dst_ip;
  uint   gre_src_ip;
};

typedef struct fd_netdev fd_netdev_t;

/* FD_NETDEV_BOND_SLAVE_MAX is the max supported number of bond slaves. */

#define FD_NETDEV_BOND_SLAVE_MAX (16)

/* fd_netdev_bond_t lists active slaves of a bond device. */

struct fd_netdev_bond {
  uchar  slave_cnt;
  ushort slave_idx[ FD_NETDEV_BOND_SLAVE_MAX ];
};

typedef struct fd_netdev_bond fd_netdev_bond_t;

/* fd_netdev_tbl_t provides an interface table.

   This table is optimized for frequent reads and rare writes.  It is
   generally not thread-safe to modify the table in-place.  The only safe
   way to sync modifications to other threads is by copying the table in
   its entirety. */

struct fd_netdev_tbl_private;
typedef struct fd_netdev_tbl_private fd_netdev_tbl_t;

struct fd_netdev_tbl_hdr {
  ushort dev_max;
  ushort bond_max;
  ushort dev_cnt;
  ushort bond_cnt;
};
typedef struct fd_netdev_tbl_hdr fd_netdev_tbl_hdr_t;

struct fd_netdev_tbl_join {
  fd_netdev_tbl_hdr_t * hdr;
  fd_netdev_t *         dev_tbl;
  fd_netdev_bond_t *    bond_tbl;
};
typedef struct fd_netdev_tbl_join fd_netdev_tbl_join_t;

#define FD_NETDEV_TBL_MAGIC (0xd5f9ba2710d6bf0aUL) /* random */

/* FD_NETDEV_TBL_ALIGN is the return value of fd_netdev_tbl_align() */

#define FD_NETDEV_TBL_ALIGN (16UL)

FD_PROTOTYPES_BEGIN

/* fd_netdev_tbl_{align,footprint} describe a memory region suitable to
   back a netdev_tbl with dev_max interfaces and bond_max bond masters. */

FD_FN_CONST ulong
fd_netdev_tbl_align( void );

FD_FN_CONST ulong
fd_netdev_tbl_footprint( ulong dev_max,
                         ulong bond_max );

/* fd_netdev_tbl_new formats a memory region as an empty netdev_tbl.
   Returns shmem on success.  On failure returns NULL and logs reason for
   failure. */

void *
fd_netdev_tbl_new( void * shmem,
                   ulong  dev_max,
                   ulong  bond_max );

/* fd_netdev_tbl_join joins a netdev_tbl at shtbl.  ljoin points to a
   fd_netdev_tbl_join_t[1] to which object information is written to.
   Returns ljoin on success.  On failure, returns NULL and logs reason for
   failure. */

fd_netdev_tbl_join_t *
fd_netdev_tbl_join( void * ljoin,
                    void * shtbl );

/* fd_netdev_tbl_leave undoes a fd_netdev_tbl_join.  Returns ownership
   of the region backing join to the caller.  (Warning: This returns ljoin,
   not shtbl) */

void *
fd_netdev_tbl_leave( fd_netdev_tbl_join_t * join );

/* fd_netdev_tbl_delete unformats the memory region backing a netdev_tbl
   and returns ownership of the region back to the caller. */

void *
fd_netdev_tbl_delete( void * shtbl );

/* fd_netdev_tbl_reset resets the table to the state of a newly constructed
   empty object (clears all devices and bonds). */

void
fd_netdev_tbl_reset( fd_netdev_tbl_join_t * tbl );

#if FD_HAS_HOSTED

/* fd_netdev_tbl_fprintf prints the interface table to the given FILE *
   pointer (or target equivalent).  Outputs ASCII encoding with LF
   newlines.  Returns errno on failure and 0 on success. */

int
fd_netdev_tbl_fprintf( fd_netdev_tbl_join_t const * tbl,
                       void *                       file );

#endif /* FD_HAS_HOSTED */

FD_PROTOTYPES_END

char const *
fd_oper_status_cstr( uint oper_status );

#endif /* HEADER_fd_src_waltz_mib_fd_netdev_h */
