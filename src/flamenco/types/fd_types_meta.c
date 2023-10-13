#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

#include "fd_types_meta.h"
#include "fd_types.h"

// do NOT delete this code... it causes the linker to link in the types file so that we can access it dynamically
//
// TBD: There must be a better way...
ulong foo_lkasjdf( void ) {
  return fd_vote_state_versioned_footprint();
}

int fd_flamenco_type_lookup(const char *type, fd_types_funcs_t * t) {
  char fp[255];

#pragma GCC diagnostic ignored "-Wpedantic"
  sprintf(fp, "%s_footprint", type);
  t->footprint_fun = dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_align", type);
  t->align_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_new", type);
  t->new_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_decode", type);
  t->decode_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_walk", type);
  t->walk_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_encode", type);
  t->encode_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_destroy", type);
  t->destroy_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_size", type);
  t->size_fun =  dlsym(RTLD_DEFAULT, fp);

  if ((  t->footprint_fun == NULL) ||
      (  t->align_fun == NULL) ||
      (  t->new_fun == NULL) ||
      (  t->decode_fun == NULL) ||
      (  t->walk_fun == NULL) ||
      (  t->encode_fun == NULL) ||
      (  t->destroy_fun == NULL) ||
      (  t->size_fun == NULL))
    return -1;
  return 0;
}
