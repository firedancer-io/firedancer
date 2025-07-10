#ifndef FD_MEM_USAGE_H
#define FD_MEM_USAGE_H

//#ifdef FD_MEM_USAGE_ENABLE

#include "../fd_util.h"

typedef void * fd_mem_usage_handle_t;

/* Allocate a handle for memory usage tracking. The argument is a description in printf format.
   It is meant to describe the reason for the memory usage. */
fd_mem_usage_handle_t fd_mem_usage_get_handle( void const * mem, ulong usage, const char * descript, ... );

/* Free the memory usage handle. */
void fd_mem_usage_free_handle( fd_mem_usage_handle_t handle );

/* Set the current memory usage associated with the handle. */
void fd_mem_usage_set( fd_mem_usage_handle_t handle, ulong usage );

/* Get the current memory usage associated with the handle. */
ulong fd_mem_usage_get( fd_mem_usage_handle_t handle );

/* Add to the total memory usage associated with the handle. */
void fd_mem_usage_add( fd_mem_usage_handle_t handle, ulong usage );

/* Subtract from the total memory usage associated with the handle. */
void fd_mem_usage_sub( fd_mem_usage_handle_t handle, ulong usage );

//#endif /* FD_MEM_USAGE_ENABLE */

#endif /* FD_MEM_USAGE_H */