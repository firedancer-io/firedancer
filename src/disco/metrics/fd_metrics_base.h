#ifndef HEADER_fd_src_disco_metrics_fd_metrics_base_h
#define HEADER_fd_src_disco_metrics_fd_metrics_base_h

#include "../../util/fd_util.h"

#define FD_METRICS_TYPE_GAUGE     (0UL)
#define FD_METRICS_TYPE_COUNTER   (1UL)
#define FD_METRICS_TYPE_HISTOGRAM (2UL)

#define FD_METRICS_CONVERTER_NONE        (0UL)
#define FD_METRICS_CONVERTER_SECONDS     (1UL)
#define FD_METRICS_CONVERTER_NANOSECONDS (2UL)

#define MIDX( type, group, measurement ) (FD_METRICS_##type##_##group##_##measurement##_OFF)

#define DECLARE_METRIC( MEASUREMENT, TYPE ) {              \
    .name      = FD_METRICS_##TYPE##_##MEASUREMENT##_NAME, \
    .type      = FD_METRICS_TYPE_##TYPE,                   \
    .desc      = FD_METRICS_##TYPE##_##MEASUREMENT##_DESC, \
    .offset    = FD_METRICS_##TYPE##_##MEASUREMENT##_OFF,  \
    .converter = FD_METRICS_##TYPE##_##MEASUREMENT##_CVT   \
  }

#define DECLARE_METRIC_ENUM( MEASUREMENT, TYPE, ENUM_NAME, ENUM_VARIANT ) { \
    .name         = FD_METRICS_##TYPE##_##MEASUREMENT##_NAME,               \
    .enum_name    = FD_METRICS_ENUM_##ENUM_NAME##_NAME,                     \
    .enum_variant = FD_METRICS_ENUM_##ENUM_NAME##_V_##ENUM_VARIANT##_NAME,  \
    .type         = FD_METRICS_TYPE_##TYPE,                                 \
    .desc         = FD_METRICS_##TYPE##_##MEASUREMENT##_DESC,               \
    .offset       = FD_METRICS_##TYPE##_##MEASUREMENT##_OFF +               \
                    FD_METRICS_ENUM_##ENUM_NAME##_V_##ENUM_VARIANT##_IDX,   \
    .converter    = FD_METRICS_##TYPE##_##MEASUREMENT##_CVT                 \
  }

#define DECLARE_METRIC_HISTOGRAM_NONE( MEASUREMENT ) {     \
    .name = FD_METRICS_HISTOGRAM_##MEASUREMENT##_NAME,     \
    .type = FD_METRICS_TYPE_HISTOGRAM,                     \
    .desc = FD_METRICS_HISTOGRAM_##MEASUREMENT##_DESC,     \
    .offset = FD_METRICS_HISTOGRAM_##MEASUREMENT##_OFF,    \
    .converter = FD_METRICS_HISTOGRAM_##MEASUREMENT##_CVT, \
    .histogram = {                                         \
      .none = {                                            \
        .min = FD_METRICS_HISTOGRAM_##MEASUREMENT##_MIN,   \
        .max = FD_METRICS_HISTOGRAM_##MEASUREMENT##_MAX,   \
      },                                                   \
    },                                                     \
  }

#define DECLARE_METRIC_HISTOGRAM_SECONDS( MEASUREMENT ) {  \
    .name = FD_METRICS_HISTOGRAM_##MEASUREMENT##_NAME,     \
    .type = FD_METRICS_TYPE_HISTOGRAM,                     \
    .desc = FD_METRICS_HISTOGRAM_##MEASUREMENT##_DESC,     \
    .offset = FD_METRICS_HISTOGRAM_##MEASUREMENT##_OFF,    \
    .converter = FD_METRICS_HISTOGRAM_##MEASUREMENT##_CVT, \
    .histogram = {                                         \
      .seconds = {                                         \
        .min = FD_METRICS_HISTOGRAM_##MEASUREMENT##_MIN,   \
        .max = FD_METRICS_HISTOGRAM_##MEASUREMENT##_MAX,   \
      },                                                   \
    },                                                     \
  }

typedef struct {
  char const * name;
  char const * enum_name;
  char const * enum_variant;
  int          type;
  char const * desc;
  ulong        offset;

  int converter;

  union {
    struct {

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
