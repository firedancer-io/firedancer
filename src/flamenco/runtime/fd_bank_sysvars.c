#include "fd_bank_sysvars.h"

fd_bank_sysvars_t *
fd_bank_sysvars_init( fd_bank_sysvars_t * sysvars,
                      fd_accdb_t *        accdb,
                      uchar *             nocache_buf ) {
  sysvars->accdb       = accdb;
  sysvars->nocache_buf = nocache_buf;
  sysvars->bank_seq    = 0UL;
  FD_TEST( fd_sysvar_cache_new( sysvars->cache ) );
  return sysvars;
}

fd_sysvar_cache_t *
fd_bank_sysvars_query( fd_bank_sysvars_t * sysvars,
                       fd_bank_t const *   bank ) {
  if( FD_LIKELY( sysvars->bank_seq==bank->bank_seq ) ) return sysvars->cache;
  return fd_bank_sysvars_refresh( sysvars, bank );
}

fd_sysvar_cache_t *
fd_bank_sysvars_refresh( fd_bank_sysvars_t * sysvars,
                         fd_bank_t const *   bank ) {
  int ok = sysvars->nocache_buf
    ? fd_sysvar_cache_restore_nocache( sysvars->cache, sysvars->accdb, bank->accdb_fork_id, sysvars->nocache_buf )
    : fd_sysvar_cache_restore        ( sysvars->cache, sysvars->accdb, bank->accdb_fork_id );
  FD_TEST( ok );
  sysvars->bank_seq = bank->bank_seq;
  return sysvars->cache;
}
