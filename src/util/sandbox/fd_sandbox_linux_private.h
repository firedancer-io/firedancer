#ifndef HEADER_fd_src_util_sandbox_fd_sandbox_linux_h
#define HEADER_fd_src_util_sandbox_fd_sandbox_linux_h

#include <fcntl.h>
#include "fd_sandbox_util_private.h"

/* consts */
static const uint fd_oveflow_user = 65533;
static const uint fd_oveflow_group = 65533;

typedef struct fd_sandbox_profile_linux fd_sandbox_profile_linux_t;

FD_PROTOTYPES_BEGIN

/* fd_sandbox_private_drop_current_thread_capabilities drops all capabilities
   attached to the current thread by using SYS_capset. */
void fd_sandbox_private_drop_current_thread_capabilities( void );

/* fd_sandbox_private_set_and_lock_securebits sets and locks securebits.
   Please see the set flags and look up `man capabilities 7` to
   understand full effect. */
void fd_sandbox_private_set_and_lock_securebits( void );

/* fd_sandbox_private_drop_bounding_ambient_inheritable_set drops
   ambient, bset and inheritable capabilities thourgh prctl and SYS_capset.
   This is meant to be called at process start as well as after switching
   user namespace. */
void fd_sandbox_private_drop_bounding_ambient_inheritable_set( void );

/* fd_sandbox_private_assert_thread_no_capabilities ensures that
   the calling thread does not have capabilities. */
void fd_sandbox_private_assert_thread_no_capabilities( void );

/* fd_sandbox_private_setup_user moves the calling process to a new
   userns. */
void fd_sandbox_private_setup_user( void );

/* fd_sandbox_private_close_fds_beyond forcefuly closes all fds beyond
   the value configured through `fd_sandbox_set_highest_fd_to_keep( int )`.
   If not configured, FD=2 is the highest FD to remain opened.   */
void fd_sandbox_private_close_fds_beyond( void );

/* fd_sandbox_private_set_resource_limits sets the maximum number of files
   that can be opened beyond this call. */
void fd_sandbox_private_set_resource_limits( void );

/* fd_sandbox_private_setup_netns moves the process to a new netns
   containing only a loopback interface. */
void fd_sandbox_private_setup_netns( void );

/* fd_sandbox_private_setup_mountns moves the process to a new mountns
   with a new disjoint root mount. */
void fd_sandbox_private_setup_mountns( void );

/* fd_sandbox_private_seccomp enables seccomp on the calling process. */
void fd_sandbox_private_seccomp( void );

/* fd_sandbox_private_secure_clear_environment wipes the environment out. */
void fd_sandbox_private_secure_clear_environment( void );

/* fd_sandbox_private_write_id_maps writes the uid and gid mapping for the
   given process. */
void fd_sandbox_private_write_id_maps( uint  outer_uid,
                                       uint  inner_uid,
                                       uint  outer_gid,
                                       uint  inner_gid,
                                       pid_t parent_pid );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_sandbox_fd_sandbox_linux_h */
