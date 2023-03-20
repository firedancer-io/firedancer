#ifndef HEADER_fd_src_util_bc_types_fd_bc_types_h
#define HEADER_fd_src_util_bc_types_fd_bc_types_h
#include "../fd_util.h"
#include <netinet/in.h>

#define FD_SOCKETADDR_IPV4 0
#define FD_SOCKETADDR_IPV6 1

#define FD_ADDR_LEN_IPV4   4
#define FD_ADDR_LEN_IPV6   16

struct fd_blockchain_signature {
    uchar signature[64];
};

typedef struct fd_blockchain_signature   fd_signature_t;

struct fd_blockchain_pubkey {
    uchar pubkey[32];
};

typedef struct fd_blockchain_pubkey      fd_pubkey_t;

struct fd_blockchain_socketaddr {
   uchar fam;
   union {
       struct in_addr ipv4_sin_addr;
       struct in6_addr ipv6_sin_addr;
   } addr;
   ushort port;
};

typedef struct fd_blockchain_socketaddr  fd_socketaddr_t;

struct fd_blockchain_ipaddr {
   uchar fam;
   union {
       struct in_addr ipv4_sin_addr;
       struct in6_addr ipv6_sin_addr;
   } addr;
};

typedef struct fd_blockchain_ipaddr fd_ipaddr_t;

#endif
