#ifndef HEADER_fd_src_util_sandbox_fd_sandbox_h
#define HEADER_fd_src_util_sandbox_fd_sandbox_h

#if defined(__linux__)

#include "../fd_util_base.h"

#include <linux/filter.h> /* FIXME: HMMMM */

FD_PROTOTYPES_BEGIN

/* fd_sandbox_requires_cap_sys_admin checks if the current environment
   requires CAP_SYS_ADMIN to fully establish the sandbox.  Ideally this
   is not required, but certain Linux distributions restrict
   unprivileged user namespaces which are required.  AppArmor and
   SELinux potentially also restrict this, but aren't yet checked for
   here.

   See https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces
   and https://ubuntu.com/blog/whats-new-in-security-for-ubuntu-24-04-lts
   for more information on the Ubuntu restrictions.

   desired_uid and desired_gid should be the UID and GID that will be
   switched to when entering the sandbox, as whether the namespace can
   be created unprivileged on Ubuntu depends on the AppArmor
   configuration of this pair. */

int
fd_sandbox_requires_cap_sys_admin( uint desired_uid,
                                   uint desired_gid );

/* fd_sandbox_enter takes various steps to enter the process into a
   fully sandboxed execution environment where it has very limited
   access to the system.
   
   Any errors encountered while sandboxing the process are fatal: the
   program will print an error and exit rather than continuing
   unsandboxed.  The sandbox must be entered while the process is single
   threaded, otherwise it is an error.

   Calling fd_sandbox_enter may require capabilities,

     (a) CAP_SETGID, CAP_SETUID are required to switch to the desired
         UID and GID, although these are only required if the user
         actually needs to be switched (we are not already the desired
         IDs).

     (b) CAP_SYS_ADMIN is required to unshare the user namespace on
         certain Linux distributions which restrict unprivileged
         user namespaces for security reasons.

   The security of the sandbox is more important than the security of
   code which runs before sandboxing.  It is strongly preferred to do
   privileged operations before sandboxing, rather than allowing the
   privileged operations to occur inside the sanbox.

   The specific list of things that happen when entering the sandbox
   are:

     (1) All environment variables (both key and value) are overwritten
         with zeros, and the environment is cleared.

     (2) The list of open file descriptors is checked to make sure it
         exactly matches the list provided in allowed_file_descriptor.

     (3) The supplementary groups of the process are checked to make
         sure the only group present is the effective one.

     (4) The session keyring is replaced with an anonymous keyring.

     (5) If keep_controlling_terminal is 0, the process is placed into a
          new process group and session, with no controlling terminal.
          This means Ctrl+C from a launching terminal will not deliver
          SIGINT.

     (6) The effective, real, and saved-set user ID and GID are switched
         to the desired_uid and desired_gid respectively if they are not
         already.

     (7) The CLONE_NEWNS, CLONE_NEWNET, CLONE_NEWCGROUP, CLONE_NEWIPC,
         and CLONE_NEWUTS namespaces are unshared.

     (8) The CLONE_NEWUSER namespace is unshared.  The new user
         namespace is set to deny the setgroups(2) syscall, and then a
         new UID and GID mapping is established: UID 1 and GID 1 in the
         namespace map to the desired_uid and desired_gid outside the
         namespace.

     (9) The /proc/sys/user/ sysctls are reduced to zero to prevent
         creation of any new namespaces, except one more user and one
         more mount namespace are allowed (to be created soon).

     (10) The CLONE_NEWUSER namespace is unshared again, to enter
          another nested user namespace.  This is required to prevent
          modification of the namespace sysctls set above.  The new
          nested namespace is also set to deny the setgroups(2) syscall
          and has a UID and GID mapping set up: UID 1 and GID 1 in the
          namespace map to UID 1 and GID 1 in the parent (and so map to
          the desired_uid and desired_gid outside the parent).

     (11) The process dumpable bit is cleared.

     (12) The root filesystem is pivoted into a new empty directory
          created in /tmp.  This unmounts all other mounts, including
          the prior root.  The cwd is set to the new root with chdir(2).

     (13) Most resource limits are reduced to zero, except RLIMIT_NOFILE
          which is set to the provided rlimit_file_cnt argument,
          RLIMIT_ADDRESS_SPACE which is set to the provided
          rlimit_address_space argument, RLIMIT_DATA which is set to the
          provided rlimit_data argument, and RLIMIT_NICE which is set to
          1.  RLIMIT_CPU and RLIMIT_FSIZE are left unlimited.
          RLIMIT_LOCKS and RLIMIT_RSS are deprecated and left unchanged.

     (14) All capabilities in the nested user namespace are dropped: the
          effective, permitted, and inherited sets are all cleared.  The
          ambient capability set is cleared, and the capability bounding
          set is zeroed.  The securebits are set to be maximally
          restrictive: keep caps locked, noroot, etc...

     (15) The no_new_privs bit is set.

     (16) An empty landlock restriction is applied to prevent any and
          all filesystem operations.

     (17) Finally, a seccomp-bpf filter is installed to prevent most
          syscalls from being made.  The filter is provided in the
          seccomp_filter argument.

   The seccomp_filter argument is a list of BPF instructions which will
   get loaded into the kernel seccomp filter.  This filter should not be
   constructed by hand, and should be generated from a policy file with
   the script in contrib/generate_filters.py.
   
   Calling fd_sandbox_enter alone is not enough to sandbox a process, as
   it will not be in a PID namespace.  The caller must ensure the
   sandboxed process lives in its own PID namespace so it cannot attempt
   to send signals or ptrace (or be ptraced by) other processes. */

void
fd_sandbox_enter( uint                 desired_uid,                  /* User ID to switch the process to inside the sandbox */
                  uint                 desired_gid,                  /* Group ID to switch the process to inside the sandbox */
                  int                  keep_host_networking,         /* True to keep the host networking namespace and not unshare it */
                  int                  keep_controlling_terminal,    /* True to disconnect from the controlling terminal session */
                  ulong                rlimit_file_cnt,              /* Maximum open file value to provide to setrlimit(RLIMIT_NOFILE) */
                  ulong                rlimit_address_space,         /* Maximum address space sizeto provide to setrlimit(RLIMIT_AS) */
                  ulong                rlimit_data,                  /* Maximum address space sizeto provide to setrlimit(RLIMIT_AS) */
                  ulong                allowed_file_descriptor_cnt,  /* Number of entries in the allowed_file_descriptor array */
                  int const *          allowed_file_descriptor,      /* Entries [0, allowed_file_descriptor_cnt) describe the allowed file descriptors */
                  ulong                seccomp_filter_cnt,           /* Number of entries in the seccomp_filter array */
                  struct sock_filter * seccomp_filter );             /* Entries [0, seccomp_filter_cnt) describe the instructions of the seccomp-bpf program to apply */

/* fd_sandbox_switch_uid_gid switches the calling process effective,
   real, and saved-set user ID and GID are switched to the desired_uid
   and desired_gid respectively if they are not already.

   Contrary to the POSIX specification (and the glibc implementation)
   this function only changes the IDs for the calling thread and not
   all threads in the process.  It can be called from a multi-threaded
   process, unlike fd_sandbox_enter.

   Calling fd_sandbox_switch_uid_gid may require CAP_SETGID and
   CAP_SETUID to switch to the desired UID and GID, although these are
   only required if the user actually needs to be switched (we are not
   already the desired IDs).

   The Linux kernel clears the dumpable bit on a thread when it
   switches UID or GID as a security measure, but this function restores
   the dumpable bit to true. */

void
fd_sandbox_switch_uid_gid( uint desired_uid,   /* User ID to switch the process to */
                           uint desired_gid ); /* Group ID to switch the process to */

/* fd_sandbox_getpid returns the true PID of the current process as it
   appears in the root PID namespace of the system.
   
   Calling `getpid(2)` from a process inside a PID namespace will
   return a renumbered PID within that namespace, not the PID seen from
   most other processes on the system.  For example, if you want to do a
   `kill -p <pid>` it should be the PID in the root namespace.
   
   This function cannot be called from within the sandbox (it will
   likely SIGSYS due to the seccomp filter) and should be called after
   entering a PID namespace but before entering the sandbox.

   This is retrieved by reading the value of /proc/self.  The calling
   process will be terminated with an error if the file cannot be read
   or is malformed. */

ulong
fd_sandbox_getpid( void );

/* fd_sandbox_getpid returns the true TID of the current process as it
   appears in the root PID namespace of the system.
   
   Calling `gettid(2)` from a process inside a PID namespace will
   return a renumbered TID within that namespace, not the TID seen from
   most other processes on the system.
   
   This function cannot be called from within the sandbox (it will
   likely SIGSYS due to the seccomp filter) and should be called after
   entering a PID namespace but before entering the sandbox.

   This is retrieved by reading the value of /proc/thread-self.  The
   calling process will be terminated with an error if the file cannot
   be read or is malformed. */

ulong
fd_sandbox_gettid( void );

FD_PROTOTYPES_END

#endif /* defined(__linux__) */

#endif /* HEADER_fd_src_util_sandbox_fd_sandbox_h */
