#include "fd_metrics.h"
#include "fd_metrics_impl.h"
#include <stdio.h>
#include <stdbool.h>

/* metrics_definition is used to define the metrics which are
 * available for ALL tiles. This is used by the fd_metrics_pop
 * function to convert the tag into a string name and ulong value
 * into the correct InfluxDB wire protocol type.
 */
Measurement metrics_definition[] = {
    {
        .name = "__test_seq",
        .type = METRICS_DATATYPE_INT,
    },
};

const int metrics_definition_sz = sizeof( metrics_definition )/sizeof( metrics_definition[ 0 ] );

FD_TLS metrics_t metrics_tls;
FD_TLS bool      metrics_initialized    = false;
FD_TLS bool      metrics_warning_issued = false;

/* Used in conjunction with metrics_tile_t */
char * metrics_tile_names[] = { "quic", "verify", "dedup", "pack", "bank" };

/* metrics_boot_unmanaged is used to initialize the metrics_t struct
 * for a given tile and index. This is used by the fd_metrics_boot function
 * to initialize the TLS metrics_t struct.
 */
void
metrics_boot_unmanaged( uchar const * pod, const metrics_tile_t tile, const ulong idx, metrics_t * m ) {
  char path[ 32 ];

  snprintf( path, 32, "mcache%lu", idx );
  FD_LOG_INFO(( "joining %s", path ));
  m->mcache = fd_mcache_join( fd_wksp_pod_map( pod, path ) );
  if( FD_UNLIKELY( !m->mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));

  m->tile         = tile;
  m->idx          = idx;
  m->sync         = fd_mcache_seq_laddr( m->mcache );
  m->seq          = fd_mcache_seq_query( m->sync );
  m->seq_consumer = fd_mcache_seq_query( m->sync );
  m->depth        = fd_mcache_depth( m->mcache );

  metrics_initialized = true;
}

/* fd_metrics_boot is used to initialize the TLS metrics_t struct
 * for a given tile and index. This function is called by any
 * tile which needs to push metrics.
 */
void
fd_metrics_boot( uchar const * pod, const metrics_tile_t tile, const ulong idx ) {
  metrics_boot_unmanaged( pod, tile, idx, &metrics_tls );
}

metrics_status_t
metrics_pop_unmanaged( metrics_t * m, uint * tag, ulong * value ) {
  if( FD_UNLIKELY( !metrics_initialized ) ) {
    if( FD_UNLIKELY( !metrics_warning_issued )) {
      FD_LOG_WARNING(( "metrics not initialized" ));
      metrics_warning_issued = true;
    }
    return METRICS_STATUS_UNINITIALIZED;
  }

  fd_frag_meta_t const * mline = m->mcache + fd_mcache_line_idx( m->seq_consumer, m->depth );

  ulong seq_found = fd_frag_meta_seq_query( mline );
  long  diff      = fd_seq_diff( seq_found, m->seq_consumer );
  if( FD_UNLIKELY( diff ) ) { /* caught up or overrun, optimize for expected sequence number ready */
    if( FD_LIKELY( diff<0L ) ) { /* caught up */
      return METRICS_STATUS_EMPTY;
    } else {
      m->seq_consumer = fd_mcache_seq_query( m->sync );
      FD_LOG_NOTICE(( "overrun1 %s: seq=%lu seq_found=%lu diff=%ld", metrics_tile_names[ m->tile ], m->seq_consumer, seq_found, diff ));
      return METRICS_STATUS_OVERRUN;
    }
  }

  *tag   = mline->chunk;
  *value = mline->seq;

  seq_found = fd_frag_meta_seq_query( mline );
  if( FD_UNLIKELY( fd_seq_ne( seq_found, m->seq_consumer ) ) ) {
    m->seq_consumer = seq_found;
    FD_LOG_NOTICE(( "overrun2" ));
    return METRICS_STATUS_OVERRUN;
  }

  /* a successful read of the data, move to the next */
  m->seq_consumer++;
  return METRICS_STATUS_OK;
}

int
fd_metrics_format( char          * buf,
                   ulong           buf_sz,
                   char          * tile_name,
                   metrics_kv_t  * tags,
                   ulong           tags_sz,
                   Datapoint     * datapoints,
                   ulong           datapoints_sz,
                   long            ts ) {
  char * offset = buf;
  ulong capacity_remaining = buf_sz;

  int ret = snprintf( offset, capacity_remaining, "%s", tile_name );
  offset += ret;
  capacity_remaining -= (ulong) ret;

  /* Write tags */
  for( ulong i=0; i<tags_sz; i++ ) {
    ret = snprintf( offset, capacity_remaining, ",%s=%s", tags[ i ].key, tags[ i ].value );
    if( FD_UNLIKELY( ret<0 || ret>=(long)capacity_remaining ) ) {
      FD_LOG_WARNING(( "snprintf error %d", ret ));
      return -1;
    }
    offset += ret;
    capacity_remaining -= (ulong) ret;
  }

  /* Write datapoints */
  for( ulong i=0; i<datapoints_sz; i++ ) {
    switch( datapoints[i].measurement.type ) {
      case METRICS_DATATYPE_FLOAT:
        ret = snprintf( offset, capacity_remaining, " %s=%f",  datapoints[ i ].measurement.name, datapoints[ i ].value.f );
        break;
      case METRICS_DATATYPE_INT:
        ret = snprintf( offset, capacity_remaining, " %s=%ld", datapoints[ i ].measurement.name, datapoints[ i ].value.i );
        break;
      case METRICS_DATATYPE_STRING:
        ret = snprintf( offset, capacity_remaining, " %s=\"%s\"",  datapoints[ i ].measurement.name, datapoints[ i ].value.s );
        break;
      case METRICS_DATATYPE_BOOL:
        if( datapoints[ i ].value.b ) {
          ret = snprintf( offset, capacity_remaining, " %s=t", datapoints[ i ].measurement.name );
        } else {
          ret = snprintf( offset, capacity_remaining, " %s=f", datapoints[ i ].measurement.name );
        }
        break;
    }
    if( FD_UNLIKELY( ret<0 || ret>=(long)capacity_remaining ) ) {
      FD_LOG_WARNING(( "snprintf error %d", ret ));
      return -1;
    }
    offset += ret;
    capacity_remaining -= (ulong) ret;
  }

  /* Write timestamp */
  ret = snprintf( offset, capacity_remaining, " %ld\n", ts );
  if( FD_UNLIKELY( ret<0 || ret>=(long)capacity_remaining ) ) {
    FD_LOG_WARNING(( "snprintf error %d", ret ));
    return -1;
  }
  capacity_remaining -= (ulong) ret;

  return (int)( buf_sz - capacity_remaining );
}

void
fd_metrics_push( uint tag, ulong value ) {
  metrics_push_unmanaged( &metrics_tls, tag, value );
}

void
metrics_push_unmanaged( metrics_t * m, uint tag, ulong value ) {
  if( FD_UNLIKELY( !metrics_initialized ) ) {
    if( FD_UNLIKELY( !metrics_warning_issued ) ) {
      FD_LOG_WARNING(( "metrics not initialized" ));
      metrics_warning_issued = true;
    }
    return;
  }

  ulong tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  ulong ctl    = fd_frag_meta_ctl( m->idx, 1, 1, 0 );
  /* we put the tag in the chunk field, and the value in the seq field */
  fd_mcache_publish( m->mcache, m->depth, m->seq, value, tag, sizeof( Datapoint ), ctl, 0UL, tspub );
  m->seq++;
  fd_mcache_seq_update( m->sync, m->seq );
}

void
fd_metrics_tag_value_to_datapoint( uint tag, ulong val, Datapoint * d ) {
  if( FD_UNLIKELY( tag >= (uint)metrics_definition_sz ) ) {
    FD_LOG_WARNING(( "tag %u out of range", tag ));
    return;
  }

  d->measurement = metrics_definition[ tag ];

  switch( d->measurement.type ) {
    case METRICS_DATATYPE_FLOAT:
      d->value.f = (double)val;
      break;
    case METRICS_DATATYPE_INT:
      d->value.i = (long)val;
      break;
    case METRICS_DATATYPE_STRING:
      // TODO: unsupported for now
      break;
    case METRICS_DATATYPE_BOOL:
      d->value.b = (bool)val;
      break;
  }
}
