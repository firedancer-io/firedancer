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
  (void)bpf_file;
  (void)intf;
  (void)bpf_pin_dir;
  (void)bpf_pin_name;
  (void)mode;
  (void)log_level;
  return -1;
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
  (void)intf;
  return -1;
}

