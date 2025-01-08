#ifndef HEADER_fd_src_util_sandbox_fd_sandbox_private_h
#define HEADER_fd_src_util_sandbox_fd_sandbox_private_h

#include "fd_sandbox.h"

FD_PROTOTYPES_BEGIN

/* Clears the environment variables of the process by explicitly zeroing
   any memory containing environment variable strings (both keys and
   values).  The envirnment is also cleared using clearenv(3) to make
   sure any callers of getenv(3) will no longer see the environment as
   being present (albeit zeroed).

   Environment variables are a common source of information leakage:
   they can appear in logs and crash dumps, and are accessible to other
   processses on the machine.
   
   Firedancer does not use environment variables to pass information,
   but it is possible an operator has passed unneeded variables in when
   launching the program, and we discard them here to make sure they do
   not get leaked. */
   
void FD_FN_SENSITIVE
fd_sandbox_private_explicit_clear_environment_variables( void );

/* Checks that the open file descriptors in the current process exactly
   matches the list of allowed file descriptors provided.

   If a file descriptor is open in the process that is not in the list,
   or a file descriptor that's present in the list is not open in the
   process an error is raised and the program is aborted.

   The security of the sandbox depends on the file descriptor table
   being exactly as expected.  For example if the process has a handle
   open to /etc/shadow, the sandbox is not secure.

   This is a defense in depth measure and mostly catches programming
   errors introduced when changing the startup sequence of the program,
   but it also catches cases where systemd or some other init system has
   spawned the Firedancer process with unexpected file descriptors still
   open.

   allowed_file_descriptors_cnt must be less than 256, and the
   allowed_file_descriptor list must not have any duplicate entries or
   else the process will be exited with an error. */

void
fd_sandbox_private_check_exact_file_descriptors( ulong       allowed_file_descriptor_cnt /* Must be in [0, 256] */,
                                                 int const * allowed_file_descriptor );  /* Assumed to have allowed_file_descriptor_cnt entries */

/* Sets the real, effective, and saved set-user-ID of the calling
   thread to the desired UID, and the real, effective, and saved
   set-group-ID to the desired GID. 
   
   Contrary to the POSIX specification (and the glibc implementation)
   this function only changes the IDs for the calling thread and not
   all threads in the process.

   If the UID and GID need to be switched, the calling process must
   have both CAP_SETUID and CAP_SETGID, or the function will print an
   error and exit the process.  If either the UID or GID is switched,
   the dumpable bit might have been set to 0 by setresgid/setreuid.
   This function restores the dumpable bit to what it was before
   switching user, and the caller does not need to restore the dumpable
   bit. */
   
void
fd_sandbox_private_switch_uid_gid( uint desired_uid,
                                   uint desired_gid );

/* User namespaces have a mapping from user and group IDs inside the
   namespace to corresponding IDs outside the namespace.  When creating
   a namespace the process gets one chance to write these mappings into
   special /proc files before they are locked in place.  See
   user_namespaces(7) for more details.

   This function writes these special files, with a single mapping: the
   UID and GID of "1" inside the namespace are mapped to the provided
   UID and GID in the parent namespace.  The function should be called
   immediately after creating a user namespace, before doing anything
   else in the namespace. The provided UID and GID should be the same
   as the effective UID and GID of the process that created the user
   namespace.

   The IDs inside the namespace are arbitrary, we could use any number,
   but theres a small benefit to avoiding zero, as we won't be "root"
   within the namespace.  This doesn't matter in practice, root within
   the namespace has no permissions outside of it -- but it protects
   against a potential unknown kernel bug.
   
   Before writing these maps we have to do an additional step: write
   the string "deny" to /proc/self/setgroups.  This is required by the
   kernel as a security measure.  See user_namespaces(7) again for more
   information */

void
fd_sandbox_private_write_userns_uid_gid_maps( uint uid_in_parent,   /* The UID in the parent to map UID 1 in the namespace to */
                                              uint gid_in_parent ); /* The GID in the parent to map GID 1 in the namespace to */

/* Many Linux privilege escalations are because of the ability to create
   new user namespaces, so we deny this (along with all other
   namespaces) within the sandbox.  This is an in depth prevention, as
   the unshare(2) and clone(2) syscalls are also already prevented by
   seccomp-bpf.
   
   To support this, the caller needs to create two nested user
   namespaces, and call this inside the first user namespace.  It will
   set the maximum allowed namespaces to zero for everything except
   user namespaces where one more (the soon to be nested one) is
   allowed.
   
   This is done so that the process can no longer flip the denied
   namespaces back to allowed, since the limits are now governed by the
   parent user namespace where we have no permissions. */

void
fd_sandbox_private_deny_namespaces( void );

/* Similar to chroot(2), this changes the root filesystem visible to
   the process to a new directory with nothing in it.  All mounts are
   unmounted and not visible in this directory, and the old filesystem
   is not accessible in any way.

   This is a bit more secure than just calling chroot(2), as it pivots
   the root mount of the filesystem to a new directory.

   This creates a new mount namespace and does the pivot inside it. */

void
fd_sandbox_private_pivot_root( void );

/* Restrict all resource limits (RLIMIT_*) for the calling process to
   zero.  Except RLIMIT_NOFILE which is restricted to the provided
   rlimit_file_cnt argument, RLIMIT_AS which is restricted to the
   provided rlimit_address_space argument, RLIMIT_DATA which is
   restricted to the provided rlimit_data argument, and RLIMIT_CPU,
   RLIMIT_FSIZE, and RLIMIT_RSS which are left as they are (unlimited). */

void
fd_sandbox_private_set_rlimits( ulong rlimit_file_cnt,
                                ulong rlimit_address_space,
                                ulong rlimit_data );

/* Read the value of cap_last_cap from /proc/sys/kernel/cap_last_cap
   and return it.  Any error reading or parsing the file will log an
   error and exit the program. */

ulong
fd_sandbox_private_read_cap_last_cap( void );

/* Drop all capabilities (effective, permitted, and inherited) in the
   current thread, clear the capability bounding set, and set the
   securebits flags of the current thread to be maximally restrictive.
   Also clear the ambient capabilities.

   cap_last_cap should be the value of /proc/sys/kernel/cap_last_cap,
   the highest capability known to the running Linux kernel. */

void
fd_sandbox_private_drop_caps( ulong cap_last_cap );

/* Apply an empty landlock restriction to the current process.  This
   prevents all filesystem operations: writes, reads truncates,
   execution, and others.  This is a defense in depth measure, as the
   seccomp-bpf filter should already prevent these operations.

   These restrictions only apply when a file descriptor is opened, so
   existing file descriptors created before sandboxing can still be
   used as normal.

   Unlike most other mitigations, this function will return without an
   error or exiting the program if the kernel does not support landlock.
   In future it should be made required. */

void
fd_sandbox_private_landlock_restrict_self( void );

/* Install a seccomp-bpf to the current process.  This filter looks at
   all syscalls and will terminate the process with SIGSYS if a syscall
   is attempted that does not pass the whitelist specified in the
   seccomp_filter argument.  The no_new_privs bit must be set before
   setting a seccomp filter.
   
   The seccomp_filter is a BPF program and should not be constructed by
   hand.  Instead, the filter instructions should be generated by the
   script in contrib/generate_filters.py */

void
fd_sandbox_private_set_seccomp_filter( ushort               seccomp_filter_cnt,
                                       struct sock_filter * seccomp_filter );

/* The same as fd_sandbox_enter, enters the full sandbox with one
   difference: the seccomp-bpf filter is not installed.  This is only
   used in testing, to be able to verify the security properties of a
   process after entering the sandbox we need to be able to make
   syscalls. */

void
fd_sandbox_private_enter_no_seccomp( uint        desired_uid,
                                     uint        desired_gid,
                                     int         keep_host_networking,
                                     int         keep_controlling_terminal,
                                     ulong       rlimit_file_cnt,
                                     ulong       rlimit_address_space,
                                     ulong       rlimit_data,
                                     ulong       allowed_file_descriptor_cnt,
                                     int const * allowed_file_descriptor );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_sandbox_fd_sandbox_private_h */
