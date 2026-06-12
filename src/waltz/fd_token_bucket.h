#ifndef HEADER_fd_src_waltz_fd_token_bucket_h
#define HEADER_fd_src_waltz_fd_token_bucket_h

#include "../util/fd_util_base.h"
#include <math.h>

struct fd_token_bucket {
  long  ts;       /* timestamp in ticks (see fd_tickcount()) */
  float rate;     /* tokens per tick, how often do we probe */
  float burst;    /* in tokens, how many probes can we send at once */
  float balance;  /* in tokens, can be negative if bucket is overdrawn */
};

typedef struct fd_token_bucket fd_token_bucket_t;

FD_PROTOTYPES_BEGIN

static inline int
fd_token_bucket_consume( fd_token_bucket_t * bucket,
                         float               delta,
                         long                ts ) {
  /* Refill bucket */
  long  elapsed = ts - bucket->ts;
  float balance = bucket->balance + ((float)elapsed * bucket->rate);
  balance = fminf( balance, bucket->burst );

  /* Consume tokens */
  int ok = delta <= balance;
  balance -= (float)ok * delta;

  /* Store bucket */
  bucket->balance = balance;
  bucket->ts      = ts;
  return ok;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_fd_token_bucket_h */
