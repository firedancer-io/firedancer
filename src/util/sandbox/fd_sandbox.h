#ifndef HEADER_fd_src_util_sandbox_fd_sandbox_h
#define HEADER_fd_src_util_sandbox_fd_sandbox_h

#ifndef FD_HAS_FFI
#ifdef FD_HAS_HOSTED

#include "../fd_util_base.h"
#include "../env/fd_env.h"
#include "../log/fd_log.h"

#include <linux/filter.h>
#include <sys/types.h>

/* The purpose of the sandbox is to reduce the impact of a Firedancer
   compromise.

   A process should call fd_sandbox as soon as is practically possible,
   by identifying the specific set of privileged actions it needs to
   perform.  A typical boot sequence might look something like,

      fd_boot();
      perform_privileged_setup();
      fd_sandbox();
      run_as_sandboxed();

   Calling fd_sandbox() itself requires root or CAP_SYS_ADMIN, which is
   counterintuitive but a limitation of the Linux kernel.  This is not
   because it is doing anything privileged, but unsharing a user
   namespace is a privileged operation.

   If full_sandbox is zero, then the sandbox is not enabled at all.  The
   only step that will be performed is switching UID and GID to the
   provided ones.  All other arguments are ignored.

   The seccomp_filter argument is a list of BPF instructions which will
   get loaded into the kernel seccomp filter.  You should never
   construct such a filter by hand.  ALWAYS generate filters from a
   policy file with the script in contrib/generate_filters.py

   Note that it is preferable to minimize the amount of code that
   happens before sandboxing, but it is even more preferable to have a
   stronger sandbox by allowing less system calls.  Where these two are
   in conflict, the privileged setup should do more, and the sandbox
   should allow less.  For example, it is much better to call socket()
   to open a socket during the privileged stage and save the descriptor
   for the unprivileged phase, than to allow the socket() syscall while
   sandboxed.

   After sandboxing almost nothing will be available.  The process
   cannot make syscalls except those allowed, has no filesystem, no
   network access, no privileges or capabilities.  Almost all it can do
   absent additional syscalls is read and write memory, and execute
   already mapped code pages.

   Typically the only things are process will need to do while
   privileged are read files and map memory. 

   Calling fd_sandbox will do each of the following, in order,

    * The list of open file descriptors for the process is checked
      against the allowed list, allow_fds.  If the file descriptor table
      is not an exact match (an expected file descriptor is not present,
      or an unexpected one is open) the program will abort with an
      error.

    * The real user ID, effective user ID, and the saved set-user-ID of
      the process are switched to the provided uid, if they are not
      already.  Your process will now be running as the unprivileged
      user.

    * The real group ID, effecetive group ID, and the saved-set-group-ID
      of the process are switched to the provided gid, if they are not
      already.

    * Almost all namespaces that can be unshared are unshared,
      CLONE_NEWUSER, CLONE_NEWNS, CLONE_NEWNET, CLONE_NEWCGROUP,
      CLONE_NEWIPC, CLONE_NEWUTS.  The PID namespace, CLONE_NEWPID is
      not unshared, as it requires cloning a new child.

    * The user namespace is set up so that Firedancer runs as root
      inside it, but that the root user in the namespace maps to the
      provided UID and GID outside.

    * The dumpable bit is cleared, so the process will not produce core
      dumps.

    * The capability bounding set is cleared.

    * The RLIMIT_NOFILE rlimit is set to zero, so no new files can be
      opened.

    * CLONE_NEWNS, the mount namespace is unshared.  The process is
      given a new global mount namespace, a temporary directory with
      nothing in it.

    * All capabilities are dropped in the running process, which were
      already only applying to the user namespace.

    * Secure bits, (SECBIT_KEEP_CAPS_LOCKED, SECBIT_NO_SETUID_FIXUP,
      ...) are all cleared.

    * Ambient capabilities are cleared.

    * The process environment is fully cleared, and the memory is
      overwritten with zeros to prevent any secrets from being leaked.

    * The PR_SET_NO_NEW_PRIVS bit is set.

    * Finally, a seccomp filter is installed which restricts which
      syscalls are allowed, and their arguments, to a list provided by
      the user. */
void
fd_sandbox( int                  full_sandbox,
            uint                 uid,
            uint                 gid,
            ulong                allow_fds_cnt,
            int *                allow_fds,
            ulong                seccomp_filter_cnt,
            struct sock_filter * seccomp_filter );

/* fd_sandbox_alloc_protected_pages allocates `page_cnt` regular (4 kB)
   pages of memory protected by `guard_page_cnt` pages of unreadable and
   unwritable memory on each side.  Additionally the OS is configured so
   that the page_cnt pages in the middle will not be paged out to disk
   in a swap file, appear in core dumps, or be inherited by any child
   process forked off from this process.  Terminates the calling process
   with FD_LOG_ERR with details if the operation fails.  Returns a
   pointer to the first byte of the protected memory.  Precisely, if ptr
   is the returned pointer, then ptr[i] for i in [0, 4096*page_cnt) is
   readable and writable, but ptr[i] for i in [-4096*guard_page_cnt, 0)
   U [4096*page_cnt, 4096*(page_cnt+guard_page_cnt) ) will cause a
   SIGSEGV.  For current use cases, there's no use in freeing the pages
   allocated by this function, so no free function is provided. */
void *
fd_sandbox_alloc_protected_pages( ulong page_cnt,
                                  ulong guard_page_cnt );

#endif /* FD_HAS_HOSTED */
#endif /* FD_HAS_FFI */

#endif /* HEADER_fd_src_util_sandbox_fd_sandbox_h */
