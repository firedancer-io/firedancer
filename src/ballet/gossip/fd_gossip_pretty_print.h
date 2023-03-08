#ifndef HEADER_fd_src_util_gossip_fd_gossip_pretty_print_h
#define HEADER_fd_src_util_gossip_fd_gossip_pretty_print_h

#include "fd_gossip_crds.h"

FD_PROTOTYPES_BEGIN

void
fd_gossip_pretty_print_crds_object( fd_gossip_crds_header_t ** crds_hdr );

void
fd_gossip_pretty_print_pubkey( char * member_name,
                               void * pubkey );

void
fd_gossip_pretty_print_signature( char * member_name,
                                  void * signature );

void
fd_gossip_pretty_print( void * data );

void
fd_gossip_pretty_print_arbitrary_hex( char * member_name,
                                      void * data,
                                      ulong data_sz );

FD_PROTOTYPES_END

#endif

