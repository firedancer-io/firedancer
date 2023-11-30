#ifndef HEADER_fd_src_disco_metrics_fd_metrics_base_h
#define HEADER_fd_src_disco_metrics_fd_metrics_base_h

#include "../../util/fd_util.h"

#define FD_METRICS_TYPE_GAUGE     (0UL)
#define FD_METRICS_TYPE_COUNTER   (1UL)
#define FD_METRICS_TYPE_HISTOGRAM (2UL)

#define FD_METRICS_CONVERTER_NONE    (0UL)
#define FD_METRICS_CONVERTER_SECONDS (1UL)

#define MIDX( type, group, measurement ) (FD_METRICS_##type##_##group##_##measurement##_OFF)

#define DECLARE_METRIC_GAUGE( GROUP, MEASUREMENT ) {          \
    .name = FD_METRICS_GAUGE_##GROUP##_##MEASUREMENT##_NAME,  \
    .type = FD_METRICS_TYPE_GAUGE,                            \
    .desc = FD_METRICS_GAUGE_##GROUP##_##MEASUREMENT##_DESC,  \
    .offset = FD_METRICS_GAUGE_##GROUP##_##MEASUREMENT##_OFF, \
  }

#define DECLARE_METRIC_COUNTER( GROUP, MEASUREMENT ) {          \
    .name = FD_METRICS_COUNTER_##GROUP##_##MEASUREMENT##_NAME,  \
    .type = FD_METRICS_TYPE_COUNTER,                            \
    .desc = FD_METRICS_COUNTER_##GROUP##_##MEASUREMENT##_DESC,  \
    .offset = FD_METRICS_COUNTER_##GROUP##_##MEASUREMENT##_OFF, \
  }

#define DECLARE_METRIC_HISTOGRAM_NONE( GROUP, MEASUREMENT ) {      \
    .name = FD_METRICS_HISTOGRAM_##GROUP##_##MEASUREMENT##_NAME,   \
    .type = FD_METRICS_TYPE_HISTOGRAM,                             \
    .desc = FD_METRICS_HISTOGRAM_##GROUP##_##MEASUREMENT##_DESC,   \
    .offset = FD_METRICS_HISTOGRAM_##GROUP##_##MEASUREMENT##_OFF,  \
    .histogram = {                                                 \
      .converter = FD_METRICS_CONVERTER_NONE,                      \
      .none = {                                                    \
        .min = FD_METRICS_HISTOGRAM_##GROUP##_##MEASUREMENT##_MIN, \
        .max = FD_METRICS_HISTOGRAM_##GROUP##_##MEASUREMENT##_MAX, \
      },                                                           \
    },                                                             \
  }

#define DECLARE_METRIC_HISTOGRAM_SECONDS( GROUP, MEASUREMENT ) {   \
    .name = FD_METRICS_HISTOGRAM_##GROUP##_##MEASUREMENT##_NAME,   \
    .type = FD_METRICS_TYPE_HISTOGRAM,                             \
    .desc = FD_METRICS_HISTOGRAM_##GROUP##_##MEASUREMENT##_DESC,   \
    .offset = FD_METRICS_HISTOGRAM_##GROUP##_##MEASUREMENT##_OFF,  \
    .histogram = {                                                 \
      .converter = FD_METRICS_CONVERTER_SECONDS,                   \
      .seconds = {                                                 \
        .min = FD_METRICS_HISTOGRAM_##GROUP##_##MEASUREMENT##_MIN, \
        .max = FD_METRICS_HISTOGRAM_##GROUP##_##MEASUREMENT##_MAX, \
      },                                                           \
    },                                                             \
  }

typedef struct {
  char const * name;
  int          type;
  char const * desc;
  ulong        offset;

  union {
    struct {
      int converter;

      union {
        struct {
          ulong min;
          ulong max;
        } none;
        
        struct {
          double min;
          double max;
        } seconds;
      };
    } histogram;
  };
} fd_metrics_meta_t;

FD_PROTOTYPES_BEGIN

FD_FN_PURE static inline char *
fd_metrics_meta_type_str( fd_metrics_meta_t const * metric ) {
  switch( metric->type ) {
    case FD_METRICS_TYPE_GAUGE:     return "gauge";
    case FD_METRICS_TYPE_COUNTER:   return "counter";
    case FD_METRICS_TYPE_HISTOGRAM: return "histogram";
    default:                        return "unknown";
  }
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_metrics_fd_metrics_base_h */
