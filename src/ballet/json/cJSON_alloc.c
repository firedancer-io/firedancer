#include "cJSON_alloc.h"
#include "cJSON.h"

#include "../../util/fd_util_base.h"

#include <stddef.h>

static ulong g_initialized;
static FD_TL fd_alloc_t * cjson_alloc_ctx;

static void *
cjson_alloc( ulong sz ) {
  return fd_alloc_malloc( cjson_alloc_ctx, alignof(max_align_t), sz );
}

static void
cjson_free( void * ptr ) {
  fd_alloc_free( cjson_alloc_ctx, ptr );
}

void
cJSON_alloc_install( fd_alloc_t * alloc ) {
  cjson_alloc_ctx = alloc;

  if( FD_ATOMIC_CAS( &g_initialized, 0UL, 1UL )==0UL ) {
    cJSON_Hooks hooks = {
      .malloc_fn = cjson_alloc,
      .free_fn   = cjson_free,
    };
    cJSON_InitHooks( &hooks );
  } else {
    while( g_initialized!=1UL ) FD_SPIN_PAUSE();
  }
}
