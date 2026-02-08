#ifndef HEADER_fd_src_util_fxt_fd_fxt_proto_h
#define HEADER_fd_src_util_fxt_fd_fxt_proto_h

/* fd_fxt_proto.h provides APIs for generating Fuchsia Trace Format
   protocol output.  This API generally does not support inline strings
   (use indexed string references). */

#include "../../util/bits/fd_bits.h"

/* FD_FXT_MAGIC is the 'FxT\x16' magic number. */

#define FD_FXT_MAGIC 0x16547846U

/* FD_FXT_REC_* give record types */

#define FD_FXT_REC_META    0
#define FD_FXT_REC_INIT    1
#define FD_FXT_REC_STRING  2
#define FD_FXT_REC_THREAD  3
#define FD_FXT_REC_EVENT   4
#define FD_FXT_REC_BLOB    5
#define FD_FXT_REC_KOBJ    7
#define FD_FXT_REC_LOG     9
#define FD_FXT_REC_LARGE  15

/* FD_FXT_META_* give metadata types */

#define FD_FXT_META_PROVIDER_INFO  1
#define FD_FXT_META_PROVIDER_EVENT 3
#define FD_FXT_META_TRACE_INFO     4

/* FD_FXT_EVENT_* give event types */

#define FD_FXT_EVENT_INSTANT            0
#define FD_FXT_EVENT_COUNTER            1
#define FD_FXT_EVENT_DURATION_BEGIN     2
#define FD_FXT_EVENT_DURATION_END       3
#define FD_FXT_EVENT_DURATION_COMPLETE  4
#define FD_FXT_EVENT_ASYNC_BEGIN        5
#define FD_FXT_EVENT_ASYNC_INSTANT      6
#define FD_FXT_EVENT_ASYNC_END          7
#define FD_FXT_EVENT_FLOW_BEGIN         8
#define FD_FXT_EVENT_FLOW_STEP          9
#define FD_FXT_EVENT_FLOW_END          10

/* FD_FXT_ARG_* give argument types */

#define FD_FXT_ARG_NULL  0
#define FD_FXT_ARG_S32   1
#define FD_FXT_ARG_U32   2
#define FD_FXT_ARG_S64   3
#define FD_FXT_ARG_U64   4
#define FD_FXT_ARG_F64   5
#define FD_FXT_ARG_STR   6
#define FD_FXT_ARG_PTR   7
#define FD_FXT_ARG_KOID  8
#define FD_FXT_ARG_BOOL  9
#define FD_FXT_ARG_BLOB 10

/* FD_FXT_PROVIDER_EVENT_* give provider events */

#define FD_FXT_META_PROVIDER_EVENT_OVERRUN 0

/* FD_FXT_KOBJ_TYPE_* give ZX kernel object types */

#define FD_FXT_KOBJ_TYPE_PROCESS 1
#define FD_FXT_KOBJ_TYPE_THREAD  2

FD_PROTOTYPES_BEGIN

/* Event record *******************************************************/

static inline ulong
fd_fxt_rec_event_hdr( ulong record_sz,    /* in [0,32767] */
                      ulong event_type,   /* FD_FXT_EVENT_* */
                      ulong arg_cnt,      /* in [0,15] */
                      ulong thread_ref,   /* in [0,255] */
                      ulong category_ref, /* in [0,32767] */
                      ulong name_ref ) {  /* in [0,32767] */
  ulong words = record_sz>>3;
  return
    ( FD_FXT_REC_EVENT<< 0 ) |
    ( words           << 4 ) |
    ( event_type      <<16 ) |
    ( arg_cnt         <<20 ) |
    ( thread_ref      <<24 ) |
    ( category_ref    <<32 ) |
    ( name_ref        <<48 );
}

/* Magic number record ************************************************/

static inline ulong
fd_fxt_rec_magic_number_hdr( void ) {
  return
    ( FD_FXT_REC_META       << 0 ) |
    ( 1UL                   << 4 ) |
    ( FD_FXT_META_TRACE_INFO<<16 ) |
    ( ((ulong)FD_FXT_MAGIC) <<24 );
}

/* Provider info metadata record **************************************/

/* fd_fxt_rec_provider_info_sz gives the size of a provider info
   metadata record in bytes (multiple of 8). */

static inline ulong
fd_fxt_rec_provider_info_sz( ulong name_sz ) {
  return 8UL + fd_ulong_align_up( name_sz, 8UL );
}

/* fd_fxt_rec_provider_hdr constructs a provider info metadata record
   header. */

static inline ulong
fd_fxt_rec_provider_info_hdr( ulong provider_id, /* in [0,2^32-1] */
                              ulong name_len ) { /* in [0,255] */
  ulong words = fd_fxt_rec_provider_info_sz( name_len )>>3;
  return
    ( FD_FXT_REC_META          << 0 ) |
    ( words                    << 4 ) |
    ( FD_FXT_META_PROVIDER_INFO<<16 ) |
    ( provider_id              <<20 ) |
    ( name_len                 <<52 );
}

/* Kernel object record ***********************************************/

/* fd_fxt_rec_kobj_sz gives the size of a kernel object record in bytes
   (multiple of 8). */

static inline ulong
fd_fxt_rec_kobj_sz( ulong name_sz ) {
  return 16UL + fd_ulong_align_up( name_sz, 8UL );
}

/* fd_fxt_rec_kobj_hdr constructs a kernel object record header. */

static inline ulong
fd_fxt_rec_kobj_hdr( ulong record_sz,
                     ulong zx_obj_type,
                     ulong name_ref,
                     ulong arg_cnt ) {
  ulong words = record_sz>>3;
  return
    ( FD_FXT_REC_KOBJ<< 0 ) |
    ( words          << 4 ) |
    ( zx_obj_type    <<16 ) |
    ( name_ref       <<24 ) |
    ( arg_cnt        <<40 );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_fxt_fd_fxt_proto_h */
