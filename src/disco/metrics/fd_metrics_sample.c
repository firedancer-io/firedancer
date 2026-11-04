#include "fd_metrics_sample.h"

int
fd_metrics_sample_encode( fd_pb_encoder_t *                  encoder,
                          fd_metrics_sample_schema_t const * s,
                          ulong const volatile *             area,
                          double                             ns_per_tick ) {
  int ok = 1;
  for( ulong i=0UL; i<s->field_cnt; i++ ) {
    fd_metrics_sample_field_t const * f = s->field+i;
    switch( f->kind ) {
      case FD_METRICS_SAMPLE_OPEN:
        if( FD_UNLIKELY( !fd_pb_submsg_open( encoder, f->num ) ) ) return -1;
        continue;
      case FD_METRICS_SAMPLE_CLOSE:
        ok &= !!fd_pb_submsg_close( encoder );
        continue;
      default: break;
    }

    ulong v = area[ f->off ];
    /* A zero field is omitted (decodes as 0), except a state: raw 0 is
       a real state, while an absent enum decodes as unspecified */
    if( !v && f->kind!=FD_METRICS_SAMPLE_STATE ) continue;

    switch( f->kind ) {
      case FD_METRICS_SAMPLE_U64:   ok &= !!fd_pb_push_uint64( encoder, f->num, v ); break;
      case FD_METRICS_SAMPLE_NS: {
        double ns = (double)v*ns_per_tick; /* saturate: out of range is undefined */
        ok &= !!fd_pb_push_uint64( encoder, f->num, ns<0x1p64 ? (ulong)ns : ULONG_MAX );
        break;
      }
      case FD_METRICS_SAMPLE_BOOL:  ok &= !!fd_pb_push_bool( encoder, f->num, 1 ); break;
      case FD_METRICS_SAMPLE_STATE: if( FD_LIKELY( v<f->map_cnt ) ) ok &= !!fd_pb_push_int32( encoder, f->num, (int)f->map[ v ] ); break;
      default: FD_LOG_CRIT(( "unknown metrics sample kind %u", f->kind ));
    }
  }
  return ok ? 0 : -1;
}
