#ifndef HEADER_fd_src_util_sandbox_fd_sandbox_h
#define HEADER_fd_src_util_sandbox_fd_sandbox_h

#include "../fd_util_base.h"
#include "../env/fd_env.h"
#include "../log/fd_log.h"

#include <sys/types.h>

/* The purpose of the sandbox is to reduce the impact of a Firedancer
   compromise.

   When starting, before executing any task code and/or processing
   user-provided input, a Firedancer process prepares everything it
   needs in order to function properly. This initialization mostly
   consists in:

   * Creating new tiles which will be used for task execution (clone
      syscall)
   * Opening the relevant workspaces which will be used to perform work
      and communicate (mmap syscall)
   * Immediately after performing those operations, Firedancer sandboxes
      itself. Note that firedancer has to be started as root or with
      various capabilities in order to be able to sandbox itself.

   Here are the mechanisms currently used by Firedancer to achieve
   sandboxing:

   * The environment variable are cleared. Environment variables are
      commonly used to hold secrets. If Firedancer is compromised, no
      secrets living in the operator's environment will be leaked.
   * The process loses access to network interfaces. The process
      unshares the network namespace to keep the principle of least
      privilege: in the event where the process was able to interact
      with a network interface, it should not be able to perform any
      communication.
   * The process gets a restricted view of the filesystem. It is jailed
      into a mount namespace with a root of its own. The process should
      only be able to interact with files that it needs to function.
   * The process is restricted from opening any new files with
      restrictive resource limits. In the future, more resources types
      can be limited. Firedancer processes have well understood expected
      behaviors and resource needs. A process should not be able to
      exceed those limits, potentially leading to availability issues.
   * The process enters a new user namespace, and the user it runs as
      inside the namespace is mapped to the overflow user outside of the
      namespace. In the case where another control was to fail, the
      process should be interacting with the system as an unprivileged
      user.
   * All file descriptors above a specified number are forcefully
      closed. Similar to and more impactful than clearenv, an operator's
      process can have FDs opened that are 1. not relevant to Firedancer
      2. references to sensitive resources. Those resources should not
      be made available to Firedancer.
   * We prevent the usage of most syscalls, only allowing those
      explicitly needed by the specific Firedancer component. Syscalls
      are used to interact with the operating system. There exists close
      to 400 syscalls. While running, A Firedancer process requires 14
      syscalls out of those 400 in order to perform its functions.
      Firedancer will crash if it attempts to use a syscall that is not
      expected. Note: It also happens that the syscalls that Firedancer
      is using are ubiquitous and well understood. They have stood the
      test of time (not that time is an ultimate metric for greatness).
      We have the luxury of disallowing all of the syscalls that might
      have received less scrutiny. */

/* fd_sandbox sandboxes the current process, performing both privileged and
   private steps. */
void
fd_sandbox( int    full_sandbox,
            uint   uid,
            uint   gid,
            ulong  allow_fds_sz,
            int *  allow_fds,
            ushort allow_syscalls_cnt,
            long * allow_syscalls );


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
#endif /* HEADER_fd_src_util_sandbox_fd_sandbox_h */
