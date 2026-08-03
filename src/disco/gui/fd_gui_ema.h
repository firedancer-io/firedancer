#ifndef HEADER_fd_src_disco_gui_fd_gui_ema_h
#define HEADER_fd_src_disco_gui_fd_gui_ema_h

#include "../../util/fd_util_base.h"

#include <float.h>
#include <math.h>

struct fd_gui_ema {
  double value; /* filtered value */
  double weight; /* used for Adam-style startup debiasing */
  long   last_update_nanos; /* last recorded sample timestamp */
  long   half_life_nanos; /* Time horizon for the filter */
};

typedef struct fd_gui_ema fd_gui_ema_t;

static inline void
fd_gui_ema_init( fd_gui_ema_t * ema,
                 long           now_nanos,
                 long           half_life_nanos ) {
  ema->value             = 0.0;
  ema->weight            = 0.0;
  ema->last_update_nanos = now_nanos;
  ema->half_life_nanos   = half_life_nanos;
}

static inline double
fd_gui_ema_advance( fd_gui_ema_t * ema,
                    long           now_nanos,
                    double         sample ) {
  long dt = now_nanos - ema->last_update_nanos;
  if( FD_UNLIKELY( dt<=0L ) ) return ema->value;

  double alpha      = 1.0 - exp( -0.69314718055994 * (double)dt / (double)ema->half_life_nanos );
  double new_weight = fmax( alpha + (1.0 - alpha) * ema->weight, DBL_EPSILON );
  ema->value = (alpha * sample + (1.0 - alpha) * ema->weight * ema->value) / new_weight;
  ema->weight            = new_weight;
  ema->last_update_nanos = now_nanos;
  return ema->value;
}

static inline double
fd_gui_ema_value( fd_gui_ema_t const * ema,
                  long                 now_nanos,
                  double               sample ) {
  fd_gui_ema_t cpy = *ema;
  return fd_gui_ema_advance( &cpy, now_nanos, sample );
}

#endif /* HEADER_fd_src_disco_gui_fd_gui_ema_h */
