#ifndef HEADER_fd_src_waltz_resolv_fd_netdb_h
#define HEADER_fd_src_waltz_resolv_fd_netdb_h

#include "../../util/fd_util_base.h"

typedef struct fd_addrinfo fd_addrinfo_t;
struct fd_addrinfo {
  int               ai_flags;
  int               ai_family;
  int               ai_protocol;
  uint              ai_addrlen;
  struct sockaddr * ai_addr;
  char *            ai_canonname;
  fd_addrinfo_t *   ai_next;
};

#define FD_AI_PASSIVE      0x01
#define FD_AI_NUMERICHOST  0x04
#define FD_AI_V4MAPPED     0x08
#define FD_AI_ALL          0x10

#define FD_EAI_BADFLAGS   -1
#define FD_EAI_NONAME     -2
#define FD_EAI_AGAIN      -3
#define FD_EAI_FAIL       -4
#define FD_EAI_NODATA     -5
#define FD_EAI_FAMILY     -6
#define FD_EAI_MEMORY     -10
#define FD_EAI_SYSTEM     -1000

int
fd_getaddrinfo( char const * restrict          node,
                fd_addrinfo_t const * restrict hints,
                fd_addrinfo_t **  restrict     res,
                void **                        out_mem,
                ulong                          out_max );

char const *
fd_gai_strerror( int );

#endif /* HEADER_fd_src_waltz_resolv_fd_netdb_h */
