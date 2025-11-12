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
     on them, such as steering them towards specific queues.

   There is special handling in many of these functions for EOPNOTSUPP.
   This is to facilitate correct behavior on network devices that do not
   support these ioctl commands.  For example, if the ioctl to get the
   number of channels is not supported, then we can assume the channel
   count is one and return success.  Similarly, if the ioctl to manage
   ntuple rules is not supported, we can assume that the clear function
   is successful. */

#include <linux/if.h>

#include "../../../../util/fd_util_base.h"

#define FD_ETHTOOL_MAX_RXFH_TABLE_CNT (32768)

#define FD_ETHTOOL_FEATURE_NTUPLE        "rx-ntuple-filter"
#define FD_ETHTOOL_FEATURE_TXUDPSEG      "tx-udp-segmentation"
#define FD_ETHTOOL_FEATURE_TXGRESEG      "tx-gre-segmentation"
#define FD_ETHTOOL_FEATURE_TXGRECSUMSEG  "tx-gre-csum-segmentation"
#define FD_ETHTOOL_FEATURE_RXUDPGROFWD   "rx-udp-gro-forwarding"

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
   table will be distributed across [start_idx, queue_cnt).
   Returns nonzero on failure. */

int
fd_ethtool_ioctl_rxfh_set_suffix( fd_ethtool_ioctl_t * ioc,
                                  uint                 start_idx );

/* fd_ethtool_ioctl_rxfh_get_queue_cnt gets the maximum number of queues
   that the RXFH table can indirect to.  Usually, this is equal to the
   current number of active channels.  However, some devices have further
   restrictions and not all queues can be used.  Returns nonzero on
   failure. */

int
fd_ethtool_ioctl_rxfh_get_queue_cnt( fd_ethtool_ioctl_t * ioc,
                                     uint *               queue_cnt );

/* fd_ethtool_ioctl_rxfh_get_table writes the current state of the
   RXFH table into the user-supplied table array, which must have space
   for FD_ETHTOOL_MAX_RXFH_TABLE_CNT elements.  The actual element
   count of the table is stored in table_ele_cnt.  Returns nonzero on
   failure. */

int
fd_ethtool_ioctl_rxfh_get_table( fd_ethtool_ioctl_t * ioc,
                                 uint *               table,
                                 uint *               table_ele_cnt );

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

/* fd_ethtool_ioctl_feature_gro_set enables or disables the
   generic-receive-offload feature.  Returns nonzero on failure. */

int
fd_ethtool_ioctl_feature_gro_set( fd_ethtool_ioctl_t * ioc,
                                  int                  enabled );

/* fd_ethtool_ioctl_feature_gro_test sets enabled to 1 if the
   generic-receive-offload feature is enabled.  Sets supported to 1
   if this feature is supported.  Returns nonzero on failure. */

int
fd_ethtool_ioctl_feature_gro_test( fd_ethtool_ioctl_t * ioc,
                                   int *                enabled,
                                   int *                supported );

/* fd_ethtool_ioctl_ntuple_clear deletes any active ntuple flow steering
   rules, which is the default state.  Returns nonzero on failure. */

int
fd_ethtool_ioctl_ntuple_clear( fd_ethtool_ioctl_t * ioc );

/* fd_ethtool_ioctl_ntuple_set_udp_dport installs a flow steering rule
   at the given rule_idx to route all UDP/IPv4 packets with the given
   destination port to the given queue_idx.  Note that if a rule already
   exists at rule_idx, it will be overwritten.

   In order to facilitate load balancing flows across multiple queues,
   a nonzero rule_group_idx can be given.  rule_group_cnt must be a
   nonzero power of 2.  This forms a mask of the lowest N bits of the
   IPv4 source address and masked addresses matching rule_group_idx
   are steered to the given queue_idx.  For example, we can create a
   group of rules for queue 0 where the lowest bit of the address is 0
   and a second set of rules for queue 1 where the lowest bit is 1.

   Returns nonzero on failure. */

int
fd_ethtool_ioctl_ntuple_set_udp_dport( fd_ethtool_ioctl_t * ioc,
                                       uint                 rule_idx,
                                       ushort               dport,
                                       uint                 rule_group_idx,
                                       uint                 rule_group_cnt,
                                       uint                 queue_idx );

/* fd_ethtool_ioctl_ntuple_validate_udp_dport queries all ntuple
   rules and then sets valid to 1 if they match the expected set of
   rules for the given UDP destination ports and the given number of
   queues (each queue should have a group of rules, one for each port
   in dports).  In other words, this makes sure the existing rules are
   correct and that no other rules are active.  If dports_cnt is zero,
   then this effectively checks whether any rules exist.  Returns
   nonzero on failure (uncertain if valid or not). */

int
fd_ethtool_ioctl_ntuple_validate_udp_dport( fd_ethtool_ioctl_t * ioc,
                                            ushort const *       dports,
                                            uint                 dports_cnt,
                                            uint                 queue_cnt,
                                            int *                valid );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_commands_configure_fd_ethtool_ioctl_h */
