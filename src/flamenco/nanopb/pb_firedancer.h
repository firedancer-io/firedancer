#ifndef HEADER_fd_src_flamenco_nanopb_pb_firedancer_h
#define HEADER_fd_src_flamenco_nanopb_pb_firedancer_h

#ifdef PB_H_INCLUDED
#error "Only include pb_firedancer.h"
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

#include <stdlib.h>
/* TODO provide fd_alloc based malloc/realloc/free */

#define PB_BUFFER_ONLY
#define PB_FIELD_32BIT 1
#define PB_ENABLE_MALLOC 1

#include "pb.h"
#include "../../util/fd_util.h"

#endif /* HEADER_fd_src_flamenco_nanopb_pb_firedancer_h */
