#include "fd_runtime_spad.h"

/* fd_valloc virtual function table for the runtime spad */
void *
fd_runtime_spad_valloc_malloc( void * _self,
                               ulong  align,
                               ulong  sz ) {
  fd_spad_t * spad = _self;
  void * rv = fd_spad_alloc( spad, align, sz );
  if( FD_UNLIKELY( fd_spad_mem_used( spad )>fd_spad_mem_max( spad ) ) ) {
    FD_LOG_ERR(( "spad overflow mem_used=%lu mem_max=%lu", fd_spad_mem_used( spad ), fd_spad_mem_max( spad ) ));
  }
  return rv;
}

void
fd_runtime_spad_valloc_free( void * _self,
                             void * _addr ) {
  (void)_self; (void)_addr;
}

const fd_valloc_vtable_t
fd_runtime_spad_vtable = {
  .malloc = fd_runtime_spad_valloc_malloc,
  .free   = fd_runtime_spad_valloc_free
};
