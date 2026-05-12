#ifndef HEADER_fd_src_util_sandbox_fd_pkeys_h
#define HEADER_fd_src_util_sandbox_fd_pkeys_h

/* fd_pkeys.h provides APIs for userland memory protection keys.

   ### Protection Keys

   https://man7.org/linux/man-pages/man7/pkeys.7.html
   https://man7.org/linux/man-pages/man2/pkey_alloc.2.html
   https://man7.org/linux/man-pages/man2/pkey_mprotect.2.html

   Modern x86 and Arm CPUs allow labelling pages with a protection key
   (usually a 4 bit number).  Using a special userland instruction,
   permission bits for such a key can then be modified very cheaply
   without kernel involvement.

   Example operation:
   - exec tile creates a pkey: pkey 3
     (using pkey_alloc(2))
   - exec tile installs pkey 3 on the 'database' workspace
     (using fd_wksp_pkey_install, wrapping pkey_mprotect(2))
   - whenever exec tile runs untrusted code (a user transaction), the
     exec tile sets pkey 3 to read-only, preventing stray writes to the
     database */

#include "../wksp/fd_wksp.h"

#if defined(__linux__)

FD_PROTOTYPES_BEGIN

/* Syscall wrappers.  Behavior matches glibc wrappers. */

int
fd_syscall_pkey_alloc( uint flags,
                       uint access_rights );
int
fd_syscall_pkey_free( int pkey );

int
fd_syscall_pkey_mprotect( void * addr,
                          ulong  size,
                          int    prot,
                          int    pkey );

/* Setup APIs.  These are typically only used at startup. */

/* fd_wksp_pkey_install protects a workspace with a memory protection
   key.  Wraps fd_shmem_pkey_install.  Uses syscall pkey_mprotect.
   Returns 0 on success, errno otherwise. */

int
fd_wksp_pkey_install( fd_wksp_t * wksp,
                      int         pkey );

/* fd_shmem_pkey_install protects an fd_shmem segment with a memory
   protection key.  Uses syscall pkey_mprotect.  Returns 0 on success,
   errno otherwise. */

int
fd_shmem_pkey_install( fd_shmem_join_info_t const * join_info,
                       int                          pkey );

FD_PROTOTYPES_END

#endif /* defined(__linux__) */

/* APIs to update the PKRU register */

#if defined(__x86_64__)

static inline ulong
fd_x86_pkru_read( void ) {
  ulong pkru;
  __asm__ volatile (
    "xor %%ecx, %%ecx\n"
    ".byte 0x0f,0x01,0xee\n" /* rdpkru */
    : "=a" (pkru)
    : /* no inputs */
    : "rcx", "rdx" /* rcx and rdx are clobbered */
  );
  return pkru;
}

static inline void
fd_x86_pkru_write( ulong pkru ) {
  __asm__ volatile (
    "xor %%ecx, %%ecx\n"
    "xor %%edx, %%edx\n"
    ".byte 0x0f,0x01,0xef\n" /* wrpkru */
    : /* no outputs */
    : "a" (pkru)
    : "rcx", "rdx" /* rcx and rdx are clobbered */
  );
}

static inline void
fd_x86_pkey_update( int pkey,
                    int access_disable,
                    int write_disable ) {
  FD_TEST( pkey>=0 && pkey<16 ); /* x86 supports 16 pkeys (4 bits) */
  int   perm = (!!access_disable) | ((!!write_disable)<<1);
  int   idx  = pkey<<1;
  ulong pkru = fd_x86_pkru_read();
  pkru &= ~(3UL<<idx);
  pkru |= ((ulong)perm)<<idx;
  fd_x86_pkru_write( pkru );
}

#endif /* defined(__x86_64__) */

#endif /* HEADER_fd_src_util_sandbox_fd_pkeys_h */
