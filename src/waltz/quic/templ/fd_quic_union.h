#ifndef HEADER_fd_quic_union_h
#define HEADER_fd_quic_union_h

#include "../../../util/fd_util_base.h"

#include "../fd_quic_proto_structs.h"

/* define a union of all the frame structures */
union fd_quic_frame_union {
#include "fd_quic_union_decl.h"
#include "fd_quic_frames_templ.h"
#include "fd_quic_undefs.h"
};
typedef union fd_quic_frame_union fd_quic_frame_u;

/* define a union of all the quic packet structures */
union fd_quic_pkt_union {
#include "fd_quic_union_decl.h"
#include "fd_quic_templ.h"
#include "fd_quic_undefs.h"
};
typedef union fd_quic_pkt_union fd_quic_pkt_u;

#endif

