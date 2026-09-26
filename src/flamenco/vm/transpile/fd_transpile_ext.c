#include "fd_transpile_runtime.h"

/* Empty default, overridden by fd_transpiled_export.o when transpiled
   programs are linked in.  This lives apart from fd_transpile_bind.c
   on purpose: a sized definition visible there lets the compiler assume
   the array has exactly one element and fold the lookup loop. */

__attribute__((weak)) fd_transpile_export_t const * const fd_transpiled_ext[1] = {NULL};
