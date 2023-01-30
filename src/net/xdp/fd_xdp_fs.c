#include "fd_xdp.h"
#include "fd_xdp_private.h"
#include "../../util/fd_util.h"

#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <unistd.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

/*
   fd_bpf_install
   Used to install a bpf program on an interface and pin it via files
   in /sys/fs/bpf
   This allows us to separate the bpf program installation from the
   firedancer runtime, meaning the minimum set of capabilities are
   needed for the runtime.
   The bpf program is responsible for flow steering.
   Some examples. Flow steering by:
     Ethertype
     IP Port
     UDP port
     whitelists/blacklists
   Flow steering rules are defined in the bpf program and configured
   via bpf maps in the kernel and exposed via /sys/fs/bpf

   Args
    bpf_file        the name of the bpf file to install
    intf            the name of the interface
    bpf_pin_name    the name of the pinned object in /sys/fs/bpf
    bpf_pin_dir     the name of the directory for pinning the bpf
                      program and maps

   Returns
     0          success
     rc         return code from libbpf
*/

int
fd_bpf_install( const char* bpf_file,
                const char* intf,
                const char* bpf_pin_dir,
                const char* bpf_pin_name,
                int         mode,
                int         log_level ) {
  int rc       = 0;
  int fd       = -1;
  int attached = 0;

  /* find interface */
  int ifindex = (int)if_nametoindex( intf );
  if( ifindex == 0 ) {
    FD_LOG_WARNING(( "Unable to find interface %s: %d %s", intf, errno, strerror( errno ) ));
    return -1;
  }

  /* load pbf program */
  struct bpf_prog_load_attr prog_load_attr = {
    .file      = bpf_file,
    .prog_type = BPF_PROG_TYPE_XDP,
    .log_level = log_level
  };

  if( mode == XDP_FLAGS_HW_MODE ) {
    prog_load_attr.ifindex = ifindex;
  }

  struct bpf_object *bpf_obj;
  rc = bpf_prog_load_xattr( &prog_load_attr, &bpf_obj, &fd );
  if( rc < 0 ) {
    FD_LOG_WARNING(( "bpf_prog_load_xattr failed with rc: %d  errno: %d %s", rc, errno, strerror( errno ) ));
    goto fd_bpf_install_err;
  }

  /* attach program to interface */
  if( mode == 0 ) mode = XDP_FLAGS_SKB_MODE;

  rc = bpf_set_link_xdp_fd( ifindex, fd, (uint32_t)mode );
  if( rc < 0 ) {
    FD_LOG_WARNING(( "bpf_set_link_xdp_fd failed with rc: %d  errno: %d %s", rc, errno, strerror( errno ) ));
    goto fd_bpf_install_err;
  }

  attached = 1;

  /* pin the program in /sys/fs/bpf for later programs to access */
  // TODO pin at "%s/%s/%s" % ( bpf_pin_name )
  rc = bpf_obj_pin( fd, bpf_pin_name );
  if( rc < 0 ) {
    FD_LOG_WARNING(( "bpf_obj_pin failed on %s with rc: %d  errno: %d %s", bpf_pin_name, rc, errno, strerror( errno ) ));
    goto fd_bpf_install_err;
  }

  /* pin the maps in the bpf program in /sys/fs/bpf for later use */
  // TODO pin maps in "%s/%s/maps" % ( bpf_pin_dir, intf )
  rc = bpf_object__pin_maps( bpf_obj, bpf_pin_dir );
  if( rc < 0 ) {
    FD_LOG_WARNING(( "bpf_object__pin_maps failed with rc: %d  errno: %d %s", rc, errno, strerror( errno ) ));
    goto fd_bpf_install_err;
  }

  /* close */
  close( fd );

  return 0;

fd_bpf_install_err:
  if( fd != -1 ) close( fd );

  if( attached ) {
    /* detach */
    rc = bpf_set_link_xdp_fd( ifindex, -1, (uint32_t)mode );

    if( rc < 0 ) {
      FD_LOG_WARNING(( "Failed to detach xdp prog from interface during error handling" ));
    }
  }

  /* no handling for the pinning
     as part of pinning, a directory and files are created in /sys/fs/bpf
     it seems unsafe to delete these files, and users already
     have tools to do such */

  return rc;
}


/* fd_bpf_detach
   detach a bpf program from an interface

   Args
     intf       the interface to remove bpf programs from

   Return
     0          the operation completed successfully
     -1         the operation failed. Possibly the interface wasn't found */
int
fd_bpf_detach( char const * intf ) {
  uint32_t id  = 0;
  int      err = 0;

  /* find interface */
  int ifindex = (int)if_nametoindex( intf );
  if( ifindex == 0 ) {
    FD_LOG_WARNING(( "Unable to find interface %s: %d %s", intf, errno, strerror( errno ) ));
    return -1;
  }

  err = bpf_get_link_xdp_id( ifindex, &id, 0 /* xpd flags */ );
  if( err ) {
    FD_LOG_WARNING(( "Error in bpf_get_link_xdp_id: %d\n", err ));
    return -1;
  }

  /* no bpf program to detach */
  if( !id ) {
    return 0;
  }

  err = bpf_set_link_xdp_fd( ifindex, -1, XDP_FLAGS_SKB_MODE );
  if( err ) {
    FD_LOG_WARNING(( "Error in bpf_set_link_xdp_fd. Error: %d %s\n", errno, strerror( errno ) ));
    return -1;
  }

  err = bpf_set_link_xdp_fd( ifindex, -1, 0 );
  if( err ) {
    FD_LOG_WARNING(( "Error in bpf_set_link_xdp_fd. Error: %d %s\n", errno, strerror( errno ) ));
    return -1;
  }

  return 0;
}

