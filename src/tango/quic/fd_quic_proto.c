/* This file instantiates all the structures and functions
   of the QUIC protocol */

/* there are cases where we make tests in generic macros
   that fail for certain types
   TODO replace with code that passes these checks */
#pragma GCC diagnostic ignored "-Wtype-limits"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "fd_quic_types.h"
#include "fd_quic_common.h"

#include "templ/fd_quic_parse_util.h"

#include "templ/fd_quic_defs.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_parsers.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_encoders.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_encoders_footprint.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_templ_dump.h"
#include "templ/fd_quic_templ.h"
#include "templ/fd_quic_frames_templ.h"
#include "templ/fd_quic_undefs.h"

#include "templ/fd_quic_transport_params.h"
