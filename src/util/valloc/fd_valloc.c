#include "fd_valloc.h"
#include <stdlib.h>

static void *
fd_libc_malloc_virtual( void * _self __attribute__((unused)),
                        ulong  align,
                        ulong  sz ) {
  return aligned_alloc( align, sz );
}

static void
fd_libc_free_virtual( void * _self __attribute__((unused)),
                      void * _addr ) {
  free( _addr );
}

const fd_valloc_vtable_t
fd_libc_vtable = {
  .malloc = fd_libc_malloc_virtual,
  .free   = fd_libc_free_virtual
};
