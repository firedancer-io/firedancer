#include "fd_mem_usage.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

struct fd_mem_usage_private {
    char descript[64];
    ulong usage;
    struct fd_mem_usage_private * next;
    struct fd_mem_usage_private * prev;
};

typedef struct fd_mem_usage_private fd_mem_usage_private_t;

static int fd_mem_usage_private_shared_lock_local[1] __attribute__((aligned(128)));
volatile int * fd_mem_usage_private_shared_lock = fd_mem_usage_private_shared_lock_local;

static fd_mem_usage_private_t * fd_mem_usage_private_head = NULL;
static fd_mem_usage_private_t * fd_mem_usage_private_tail = NULL;

static inline void
fd_mem_usage_private_lock( void ) {
  FD_COMPILER_MFENCE();
# if FD_HAS_ATOMIC
  while(( FD_UNLIKELY( FD_ATOMIC_CAS( fd_mem_usage_private_shared_lock, 0, 1 ) ) )) ;
# else
  while( *fd_mem_usage_private_shared_lock ) ;
  *fd_mem_usage_private_shared_lock = 1;
# endif
  FD_COMPILER_MFENCE();
}

static inline void
fd_mem_usage_private_unlock( void ) {
  FD_COMPILER_MFENCE();
# if FD_HAS_ATOMIC
  FD_VOLATILE( *fd_mem_usage_private_shared_lock ) = 0;
# else
  *fd_mem_usage_private_shared_lock = 0;
# endif
  FD_COMPILER_MFENCE();
}

fd_mem_usage_handle_t
fd_mem_usage_get_handle( const char * descript, ... ) {
    fd_mem_usage_private_lock();

    fd_mem_usage_private_t * p = (fd_mem_usage_private_t *)malloc( sizeof(fd_mem_usage_private_t) );
    if ( p == NULL ) {
        fd_mem_usage_private_unlock();
        return NULL;
    }

    va_list args;
    va_start( args, descript );
    vsnprintf( p->descript, sizeof(p->descript), descript, args );
    va_end( args );

    p->next = NULL;
    p->prev = NULL;
    if ( fd_mem_usage_private_head == NULL ) {
        fd_mem_usage_private_head = p;
        fd_mem_usage_private_tail = p;
    } else {
        fd_mem_usage_private_tail->next = p;
        p->prev = fd_mem_usage_private_tail;
        fd_mem_usage_private_tail = p;
    }

    fd_mem_usage_private_unlock();
    return p;
}

void
fd_mem_usage_free_handle( fd_mem_usage_handle_t handle ) {
    fd_mem_usage_private_lock();
    fd_mem_usage_private_t * p = (fd_mem_usage_private_t *)handle;
    if ( p == NULL ) {
        fd_mem_usage_private_unlock();
        return;
    }
    
    if ( p->prev == NULL ) {
        fd_mem_usage_private_head = p->next;
    } else {
        p->prev->next = p->next;
    }
    if ( p->next == NULL ) {
        fd_mem_usage_private_tail = p->prev;
    } else {
        p->next->prev = p->prev;
    }

    free( p );

    fd_mem_usage_private_unlock();
}

void
fd_mem_usage_set( fd_mem_usage_handle_t handle, ulong usage ) {
    fd_mem_usage_private_lock();
    fd_mem_usage_private_t * p = (fd_mem_usage_private_t *)handle;
    if ( p == NULL ) {
        fd_mem_usage_private_unlock();
        return;
    }
    p->usage = usage;
    fd_mem_usage_private_unlock();
}

ulong
fd_mem_usage_get( fd_mem_usage_handle_t handle ) {
    fd_mem_usage_private_lock();
    fd_mem_usage_private_t * p = (fd_mem_usage_private_t *)handle;
    if ( p == NULL ) {
        fd_mem_usage_private_unlock();
        return 0;
    }
    ulong usage = p->usage;
    fd_mem_usage_private_unlock();
    return usage;
}

void
fd_mem_usage_add( fd_mem_usage_handle_t handle, ulong usage ) {
    fd_mem_usage_private_lock();
    fd_mem_usage_private_t * p = (fd_mem_usage_private_t *)handle;
    if ( p == NULL ) {
        fd_mem_usage_private_unlock();
        return;
    }
    p->usage += usage;
    fd_mem_usage_private_unlock();
}

void
fd_mem_usage_sub( fd_mem_usage_handle_t handle, ulong usage ) {
    fd_mem_usage_private_lock();
    fd_mem_usage_private_t * p = (fd_mem_usage_private_t *)handle;
    if ( p == NULL ) {
        fd_mem_usage_private_unlock();
        return;
    }
    p->usage -= usage;
    fd_mem_usage_private_unlock();
}
