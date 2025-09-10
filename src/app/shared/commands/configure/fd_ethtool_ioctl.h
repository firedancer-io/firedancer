#ifndef HEADER_fd_src_app_shared_commands_configure_fd_ethtool_ioctl_h
#define HEADER_fd_src_app_shared_commands_configure_fd_ethtool_ioctl_h

/* fd_ethtool_ioctl is a wrapper around the ethtool ioctl commands
   for managing network devices.

   Generic netlink is a more modern API for this, but not all operations
   are supported and it is more complicated.  All the following
   operations seem to be supported by the older ioctl interface across
   the commonly used network drivers.

   - channels: Modern NICs generally support multiqueue, a feature that
     steers packets to multiple rx/tx queues, allowing CPU processing to
     be distributed.  In the ethtool terminology a queue is called a
     channel.

   - rxfh: To route a packet into the multiple queues, the kernel will
     hash incoming packets and then lookup a queue index in the RXFH
     indirection table.  The RXFH APIs allow us to modify this table
     to change how incoming packets are steered to various queues.

   - feature: Network devices have many feature flags to enable or
     disable particular behaviors.  These APIs manage those features.

   - ntuple: n-tuple is a kernel name for hardware flow steering. These
     APIs allow us to create rules that match packets and perform actions
     on them, such as steering them towards specific queues. */

#include <linux/if.h>

#include "../../../../util/fd_util_base.h"

#define FD_ETHTOOL_MAX_RXFH_TABLE_SIZE (32768)

#define FD_ETHTOOL_FEATURE_NTUPLE "rx-ntuple-filter"

struct fd_ethtool_ioctl {
  int          fd;
  struct ifreq ifr;
};
typedef struct fd_ethtool_ioctl fd_ethtool_ioctl_t;

FD_PROTOTYPES_BEGIN

/* fd_ethtool_ioctl_init prepares the resources necessary for issuing
   ioctl system calls for the given network device.  Returns ioc on
   success and NULL on failure. */

fd_ethtool_ioctl_t *
fd_ethtool_ioctl_init( fd_ethtool_ioctl_t * ioc,
                       char const * device );

/* fd_ethtool_ioctl_fini closes any resources used by ioc */

void
fd_ethtool_ioctl_fini( fd_ethtool_ioctl_t * ioc );

/* fd_ethtool_ioctl_channels_set_num sets the number of active channels
   or queues.  If 0 is given, it will set to the maximum number of
   queues allowed by the hardware.  Returns nonzero on failure. */

int
fd_ethtool_ioctl_channels_set_num( fd_ethtool_ioctl_t * ioc,
                                   uint                 num /* 0 for max */ );

/* fd_ethtool_ioctl_channels_get_num gets information about the state
   of hardware channels, including whether multiqueue is supported at
   all, how many queues are currently in use, and the max allowed.
   Returns nonzero on failure. */

struct fd_ethtool_ioctl_channels {
  int  supported;
  uint current;
  uint max;
};
typedef struct fd_ethtool_ioctl_channels fd_ethtool_ioctl_channels_t;

int
fd_ethtool_ioctl_channels_get_num( fd_ethtool_ioctl_t *          ioc,
                                   fd_ethtool_ioctl_channels_t * channels );

/* fd_ethtool_ioctl_rxfh_set_default sets the RXFH indirection table
   to its default state, which is to round-robin all hashes across all
   active queues.  In this state, changing the active queue count will
   not be blocked by the RXFH table.  Returns nonzero on failure. */

int
fd_ethtool_ioctl_rxfh_set_default( fd_ethtool_ioctl_t * ioc );

/* fd_ethtool_ioctl_rxfh_set_suffix modifies the RXFH table to isolate
   a prefix of queues.  The typical use case is to prevent general
   packets from landing on these queues so ntuple rules can steer
   special packets to them instead.  start_idx is inclusive, so the
   table will be distributed across [start_idx, num_channels).
   Returns nonzero on failure. */

int
fd_ethtool_ioctl_rxfh_set_suffix( fd_ethtool_ioctl_t * ioc,
                                  uint                 start_idx );

/* fd_ethtool_ioctl_rxfh_get_table writes the current state of the
   RXFH table into the user-supplied table array, which must be of
   size FD_ETHTOOL_MAX_RXFH_TABLE_SIZE.  The actual size of the
   table is stored in table_size.  Returns nonzero on failure. */

int
fd_ethtool_ioctl_rxfh_get_table( fd_ethtool_ioctl_t * ioc,
                                 uint *               table,
                                 uint *               table_size );

/* fd_ethtool_ioctl_feature_set enables or disables the network device
   feature with the given name.  Returns nonzero on failure. */

int
fd_ethtool_ioctl_feature_set( fd_ethtool_ioctl_t * ioc,
                              char const *         name,
                              int                  enabled );

/* fd_ethtool_ioctl_feature_test sets enabled to 1 if the feature
   with the given name is enabled.  Returns nonzero on failure. */

int
fd_ethtool_ioctl_feature_test( fd_ethtool_ioctl_t * ioc,
                               char const *         name,
                               int *                enabled );

/* fd_ethtool_ioctl_ntuple_clear deletes any active ntuple flow steering
   rules, which is the default state.  Returns nonzero on failure. */

int
fd_ethtool_ioctl_ntuple_clear( fd_ethtool_ioctl_t * ioc );

/* fd_ethtool_ioctl_ntuple_set_udp_dport installs a flow steering rule
   at the given rule_idx to route all UDP/IPv4 packets with the given
   destination port to the given queue_idx.  Note that if a rule already
   exists at rule_idx, it will be overwritten.  Returns nonzero on failure. */

int
fd_ethtool_ioctl_ntuple_set_udp_dport( fd_ethtool_ioctl_t * ioc,
                                       uint                 rule_idx,
                                       ushort               dport,
                                       uint                 queue_idx );

/* fd_ethtool_ioctl_ntuple_validate_udp_dport queries all ntuple
   rules and then sets valid to 1 if they match the expected set of
   rules for the given UDP destination ports.  In other words,
   this makes sure the existing rules are correct and that no other
   rules are active.  If num_dports is zero, then this effectively
   checks whether any rules exist.  dports is left in an
   indeterminate state after this function returns.  Returns
   nonzero on failure (uncertain if valid or not). */

int
fd_ethtool_ioctl_ntuple_validate_udp_dport( fd_ethtool_ioctl_t * ioc,
                                            ushort *             dports,
                                            uint                 num_dports,
                                            uint                 queue_idx,
                                            int *                valid );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_commands_configure_fd_ethtool_ioctl_h */
