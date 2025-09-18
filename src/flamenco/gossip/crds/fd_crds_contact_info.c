#include "../fd_gossip_types.h"
#include "../fd_gossip_private.h"

struct fd_crds_contact_info_entry {
  fd_contact_info_t contact_info[1];
  struct{
    ulong next;
  } pool;
};

typedef struct fd_crds_contact_info_entry fd_crds_contact_info_entry_t;

#define POOL_NAME  crds_contact_info_pool
#define POOL_T     fd_crds_contact_info_entry_t
#define POOL_NEXT  pool.next
#include "../../../util/tmpl/fd_pool.c"
