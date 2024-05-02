#include "fd_shred_cap.h"
#include <time.h>

#define MAX_STABLE_PREFIX 200

int
fd_shred_cap_mark_stable( fd_replay_t * replay, ulong slot ) {
  if( replay->shred_cap == NULL ) return FD_SHRED_CAP_OK;

  if (replay->stable_slot_start == 0)
    replay->stable_slot_start = slot;
  if (slot > replay->stable_slot_end)
    replay->stable_slot_end = slot;

  if (replay->stable_slot_start + MAX_STABLE_PREFIX < replay->stable_slot_end) {
    FD_LOG_WARNING( ("reaching max stable prefix length (%lu..%lu more than %u slots) in shred_cap",
                     replay->stable_slot_start,
                     replay->stable_slot_end,
                     MAX_STABLE_PREFIX) );
  }

  return FD_SHRED_CAP_OK;
}

int
fd_shred_cap_archive( fd_replay_t * replay, fd_shred_t const * shred, uchar flags) {
  if( replay->shred_cap == NULL ) return FD_SHRED_CAP_OK;

  ulong n = fd_shred_sz( shred );
  fd_shred_cap_hdr_t cap_header = {.size = n, .flags = flags};
  fwrite( &cap_header, sizeof( fd_shred_cap_hdr_t ), 1UL, replay->shred_cap );

  if( FD_UNLIKELY( fwrite( shred, sizeof( uchar ), n, replay->shred_cap ) != n ) ) {
    FD_LOG_WARNING( ( "failed at logging shred idx=%d for slot#%lu", shred->idx, shred->slot ) );
    return FD_SHRED_CAP_ERR;
  }
  // FD_LOG_NOTICE( ( "logging shred idx=%d for slot#%u", shred->idx, shred->slot ) );
  return FD_SHRED_CAP_OK;
}

int
fd_shred_cap_replay( const char *      shred_cap_fpath,
                     fd_replay_t *     replay ) {
  FILE * shred_cap = fopen( shred_cap_fpath, "rb" );
  FD_TEST( shred_cap );

  ulong cnt = 0, size = 0;
  for( ;; ) {
    fd_shred_cap_hdr_t header;
    ulong nshredcap_hdr = fread( &header, sizeof( fd_shred_cap_hdr_t ), 1, shred_cap );
    FD_TEST( nshredcap_hdr = 1 );
    ulong n          = header.size;

    uchar buffer[FD_SHRED_MAX_SZ];
    ulong bytes_read = fread( buffer, sizeof( uchar ), n, shred_cap );
    FD_TEST( bytes_read == n );

    fd_shred_t const * shred = fd_shred_parse( buffer, n );

    if ( FD_SHRED_CAP_FLAG_IS_TURBINE(header.flags) ) {
      fd_replay_turbine_rx( replay, shred, fd_shred_sz( shred ));
    } else {
      fd_replay_repair_rx( replay, shred );
    }

    size += sizeof(fd_shred_cap_hdr_t) + n;
    if (++cnt % 1000 == 0)
      FD_LOG_NOTICE( ("Replayed %lu shreds (%lu bytes)", cnt, size) );
    struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)1e6 };
    nanosleep( &ts, NULL );
  }
  FD_LOG_NOTICE( ("Finish replaying %lu shreds", cnt) );
  return 0;
}
