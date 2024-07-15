#include "fd_shred_cap.h"
#include <unistd.h>

/* int */
/* fd_shred_cap_mark_stable( fd_replay_t * replay, ulong slot ) { */
/*   if( replay->shred_cap == NULL ) return FD_SHRED_CAP_OK; */

/*   if (replay->stable_slot_start == 0) */
/*     replay->stable_slot_start = slot; */
/*   if (slot > replay->stable_slot_end) */
/*     replay->stable_slot_end = slot; */

/*   if (replay->stable_slot_start + MAX_STABLE_PREFIX < replay->stable_slot_end) { */
/*     FD_LOG_WARNING( ("reaching max stable prefix length (%lu..%lu more than %u slots) in shred_cap", */
/*                      replay->stable_slot_start, */
/*                      replay->stable_slot_end, */
/*                      MAX_STABLE_PREFIX) ); */
/*   } */

/*   return FD_SHRED_CAP_OK; */
/* } */

int
fd_shred_cap_archive( fd_shred_cap_ctx_t * ctx FD_PARAM_UNUSED,
                      fd_shred_t const *   shred,
                      uchar                flags  FD_PARAM_UNUSED) {
  ulong  wsz;
  ulong  shred_len = fd_shred_sz( shred );
  ushort hdr_len = sizeof( fd_shred_cap_hdr_t );
  fd_shred_cap_hdr_t cap_header = {.sz = shred_len, .flags = flags};
  fd_io_write( ctx->shred_cap_fileno, &cap_header, (ulong)hdr_len, (ulong)hdr_len, &wsz );
  FD_TEST( wsz == hdr_len );
  fd_io_write( ctx->shred_cap_fileno, shred, shred_len, shred_len, &wsz );
  FD_TEST( wsz == shred_len );
  fsync( ctx->shred_cap_fileno );

  return FD_SHRED_CAP_OK;
}

int
fd_shred_cap_replay( const char *      shred_cap_fpath,
                     fd_store_t *      store ) {
  FILE * shred_cap = fopen( shred_cap_fpath, "rb" );
  FD_TEST( shred_cap );

  ulong cnt = 0;
  for( ;; ) {
    fd_shred_cap_hdr_t header;
    ulong nshredcap_hdr = fread( &header, sizeof( fd_shred_cap_hdr_t ), 1, shred_cap );
    if ( nshredcap_hdr != 1 ) break;

    uchar buffer[FD_SHRED_MAX_SZ];
    ulong shred_len = header.sz;
    ulong bytes_read = fread( buffer, sizeof( uchar ), shred_len, shred_cap );
    if ( bytes_read != shred_len ) break;

    fd_shred_t const * shred = fd_shred_parse( buffer, shred_len );
    if ( fd_store_shred_insert( store, shred ) < FD_BLOCKSTORE_OK ) return FD_SHRED_CAP_ERR;
    cnt++;
    /*
    if ( FD_SHRED_CAP_FLAG_IS_TURBINE(header.flags) ) {
      fd_replay_turbine_rx( replay, shred, fd_shred_sz( shred ));
    } else {
      fd_replay_repair_rx( replay, shred );
    }
    */
  }
  FD_LOG_WARNING( ("Finish inserting %lu shreds from the shredcap file", cnt) );
  return FD_SHRED_CAP_OK;
}
