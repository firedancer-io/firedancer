#ifndef HEADER_fd_src_ballet_zksdk_fd_zksdk_private_h
#define HEADER_fd_src_ballet_zksdk_fd_zksdk_private_h

#include "fd_zksdk.h"
#include "rangeproofs/fd_rangeproofs.h"

/* Basepoints for Pedersen commitments.
   They're the same as rangeproofs, but some ZKP don't use rangeproofs. */
#define fd_zksdk_basepoint_G fd_rangeproofs_basepoint_G
#define fd_zksdk_basepoint_H fd_rangeproofs_basepoint_H

#endif /* HEADER_fd_src_ballet_zksdk_fd_zksdk_private_h */
