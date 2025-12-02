#include "fd_pcapng_private.h"
#include "../fd_util.h"

/* Capture related ****************************************************/

#include <errno.h>
#if defined(__linux__) || defined(__FreeBSD__)
#include <net/if.h>
#endif

void
fd_pcapng_shb_defaults( fd_pcapng_shb_opts_t * opt ) {
# if FD_HAS_X86
  opt->hardware = "x86_64";
# endif

# if defined(__linux__)
  opt->os       = "Linux";
# endif

  opt->userappl = "Firedancer";
}

int
fd_pcapng_idb_defaults( fd_pcapng_idb_opts_t * opt,
                        uint                   if_idx ) {
# if defined(__linux__) || defined(__FreeBSD__)
  static FD_TL char _name[ IF_NAMESIZE ];
  char * name = if_indextoname( if_idx, _name );
  if( FD_UNLIKELY( !name ) ) return 0;
  FD_STATIC_ASSERT( 16>=IF_NAMESIZE, ifname_sz );
  memcpy( opt->name, _name, 16UL );
# else
  (void)if_idx;
# endif

  opt->tsresol = FD_PCAPNG_TSRESOL_NS;

  /* TODO get ip4_addr, mac_addr, hardware from rtnetlink */

  return 1;
}

#if FD_HAS_HOSTED

#include <stdio.h>

/* fwrite-style funcs *************************************************/

/* What follows are a bunch of serialization / writer functions.  They
   maintain the following properties:

     - file handle is 4 byte aligned
     - buf is the write buffer up to
     - cursor is the next free byte in buffer (or next byte after end of
       buf is space exhausted)
     - Invariant: cursor <= FD_PCAPNG_BLOCK_SZ
     - fwrite is called once per func and write size is 4 byte aligned
       and no larger than FD_PCAPNG_BLOCK_SZ */

/* FD_PCAPNG_FWRITE_OPT writes an option in the context of an fwrite-
   style function.  Assumes that given length is <=65532.

   Args:
     ushort t (option type)
     ushort l (option length)
     void * v (ptr to option data) */

#define FD_PCAPNG_FWRITE_OPT(t,l,v)                                    \
  do {                                                                 \
    ulong _sz       = (ushort)( l );                                   \
    ulong _sz_align = (ushort)fd_ulong_align_up( _sz, 4UL );           \
    if( FD_UNLIKELY( cursor+4UL+_sz_align > FD_PCAPNG_BLOCK_SZ ) ) {   \
      FD_LOG_WARNING(( "oversz pcapng block" ));                       \
      return 0UL;                                                      \
    }                                                                  \
    *(ushort *)( buf+cursor ) = ( (ushort)(t) ); cursor+=2UL;          \
    *(ushort *)( buf+cursor ) = ( (ushort)_sz ); cursor+=2UL;          \
    if( _sz ) fd_memcpy( buf+cursor, (v), _sz );                       \
    fd_memset( buf+cursor+_sz, 0, _sz_align-_sz );                     \
    cursor+=_sz_align;                                                 \
  } while(0);

#define FD_PCAPNG_FWRITE_NULLOPT()                                     \
  do {                                                                 \
    if( FD_UNLIKELY( cursor+4UL > FD_PCAPNG_BLOCK_SZ ) ) {             \
      FD_LOG_WARNING(( "oversz pcapng block" ));                       \
      return 0UL;                                                      \
    }                                                                  \
    fd_memset( buf+cursor, 0, 4UL );                                   \
    cursor+=4UL;                                                       \
  } while(0);


/* FD_PCAPNG_FWRITE_BLOCK_TERM terminates a block buffer being
   serialized in the context of an fwrite-style function. */

#define FD_PCAPNG_FWRITE_BLOCK_TERM()                                  \
  do {                                                                 \
    if( FD_UNLIKELY( cursor+4UL > FD_PCAPNG_BLOCK_SZ ) ) {             \
      FD_LOG_WARNING(( "oversz pcapng block" ));                       \
      return 0UL;                                                      \
    }                                                                  \
    block->block_sz         = (uint)(cursor+4UL);                      \
    *(uint *)( buf+cursor ) = (uint)(cursor+4UL);                      \
    cursor+=4UL;                                                       \
  } while(0);

ulong
fd_pcapng_fwrite_shb( fd_pcapng_shb_opts_t const * opt,
                      void *                       file ) {

  uchar buf[ FD_PCAPNG_BLOCK_SZ ];

  fd_pcapng_shb_t * block = (fd_pcapng_shb_t *)buf;

  ulong cursor = sizeof(fd_pcapng_shb_t);
  *block = (fd_pcapng_shb_t) {
    .block_type       = FD_PCAPNG_BLOCK_TYPE_SHB,
    /* block_sz set later */
    .byte_order_magic = FD_PCAPNG_BYTE_ORDER_MAGIC,
    .version_major    = (ushort)1,
    .version_minor    = (ushort)0,
    .section_sz       = ULONG_MAX
  };

  if( opt ) {
    if( opt->hardware ) FD_PCAPNG_FWRITE_OPT( FD_PCAPNG_SHB_OPT_HARDWARE, strlen( opt->hardware ), opt->hardware );
    if( opt->os       ) FD_PCAPNG_FWRITE_OPT( FD_PCAPNG_SHB_OPT_OS,       strlen( opt->os       ), opt->os       );
    if( opt->userappl ) FD_PCAPNG_FWRITE_OPT( FD_PCAPNG_SHB_OPT_USERAPPL, strlen( opt->userappl ), opt->userappl );
  }
  FD_PCAPNG_FWRITE_NULLOPT();

  FD_PCAPNG_FWRITE_BLOCK_TERM();

  return fwrite( buf, cursor, 1UL, (FILE *)file );
}

ulong
fd_pcapng_fwrite_idb( uint                         link_type,
                      fd_pcapng_idb_opts_t const * opt,
                      void *                       file ) {

  uchar buf[ FD_PCAPNG_BLOCK_SZ ];

  fd_pcapng_idb_t * block = (fd_pcapng_idb_t *)buf;

  ulong cursor = sizeof(fd_pcapng_idb_t);
  *block = (fd_pcapng_idb_t) {
    .block_type       = FD_PCAPNG_BLOCK_TYPE_IDB,
    /* block_sz set later */
    .link_type        = (ushort)link_type,
    .snap_len         = 0U, /* FIXME should appropriately set snap_len
                               But this is not trivial.  Needs balancing
                               between buffer space available for meta
                               and payload. (meta is variable length) */
  };

  uchar tsresol = FD_PCAPNG_TSRESOL_NS;
  FD_PCAPNG_FWRITE_OPT( FD_PCAPNG_IDB_OPT_TSRESOL, 1UL, &tsresol );

  if( opt ) {

    if( opt->name[0] )
      FD_PCAPNG_FWRITE_OPT( FD_PCAPNG_IDB_OPT_NAME,      fd_cstr_nlen( opt->name, 16UL ),     opt->name     );
    if( fd_uint_load_4( opt->ip4_addr ) )
      FD_PCAPNG_FWRITE_OPT( FD_PCAPNG_IDB_OPT_IPV4_ADDR, 4UL,                                 opt->ip4_addr );
    if( fd_ulong_load_6( opt->mac_addr ) )
      FD_PCAPNG_FWRITE_OPT( FD_PCAPNG_IDB_OPT_MAC_ADDR,  6UL,                                 opt->mac_addr );

    if( opt->hardware[0] )
      FD_PCAPNG_FWRITE_OPT( FD_PCAPNG_IDB_OPT_HARDWARE,  fd_cstr_nlen( opt->hardware, 64UL ), opt->hardware );

  }
  FD_PCAPNG_FWRITE_NULLOPT();

  FD_PCAPNG_FWRITE_BLOCK_TERM();

  return fwrite( buf, cursor, 1UL, (FILE *)file );
}

ulong
fd_pcapng_fwrite_pkt1( void *       _file,
                       void const * payload,
                       ulong        payload_sz,
                       void const * options,
                       ulong        options_sz,
                       uint         if_idx,
                       long         ts ) {

  FILE * file = (FILE *)_file;
  FD_TEST( fd_ulong_is_aligned( (ulong)ftell( file ), 4UL ) );

  ulong cursor = sizeof(fd_pcapng_epb_t);
  fd_pcapng_epb_t block = {
    .block_type = FD_PCAPNG_BLOCK_TYPE_EPB,
    /* block_sz set later */
    .if_idx     = if_idx,
    .ts_hi      = (uint)( (ulong)ts >> 32UL ),
    .ts_lo      = (uint)( (ulong)ts         ),
    .cap_len    = (uint)payload_sz,
    .orig_len   = (uint)payload_sz
  };

  ulong payload_sz_align = fd_ulong_align_up( payload_sz, 4UL );
  uchar pad[8UL]={0};
  ulong pad_sz = payload_sz_align-payload_sz;
  cursor+=payload_sz_align;

  /* option list */
  cursor += options_sz;
  cursor += 4UL;

  /* Trailer */
  block.block_sz = (uint)cursor+4U;

  /* write header */
  if( FD_UNLIKELY( 1UL!=fwrite( &block,  sizeof(fd_pcapng_epb_t), 1UL, file ) ) )
    return 0UL;
  /* copy payload */
  if( FD_UNLIKELY( 1UL!=fwrite( payload, payload_sz,              1UL, file ) ) )
    return 0UL;
  /* align */
  if( pad_sz )
    if( FD_UNLIKELY( 1UL!=fwrite( pad, pad_sz, 1UL, file ) ) )
      return 0UL;
  if( options_sz )
    if( FD_UNLIKELY( 1UL!=fwrite( options, options_sz, 1UL, file ) ) )
      return 0UL;
  /* empty options */
  if( FD_UNLIKELY( 1UL!=fwrite( pad, 4UL,    1UL, file ) ) )
    return 0UL;
  /* write length trailer */
  if( FD_UNLIKELY( 1UL!=fwrite( &block.block_sz, 4UL, 1UL, file ) ) )
    return 0UL;

  return 1UL;
}

ulong
fd_pcapng_fwrite_tls_key_log( uchar const * log,
                              uint          log_sz,
                              void *        _file ) {

  FILE * file = (FILE *)_file;
  FD_TEST( fd_ulong_is_aligned( (ulong)ftell( file ), 4UL ) );

  ulong cursor = sizeof(fd_pcapng_dsb_t);
  fd_pcapng_dsb_t block = {
    .block_type  = FD_PCAPNG_BLOCK_TYPE_DSB,
    /* block_sz set later */
    .secret_type = FD_PCAPNG_SECRET_TYPE_TLS,
    .secret_sz   = log_sz
  };

  uint log_sz_align = fd_uint_align_up( log_sz, 4UL );
  uchar pad[8] = {0};
  ulong pad_sz = log_sz_align-log_sz;
  cursor+=log_sz_align;

  /* end of options block */
  cursor+=4UL;

  /* derive size ahead of time */
  block.block_sz = (uint)cursor + 4U;

  /* write header */
  if( FD_UNLIKELY( 1UL!=fwrite( &block, sizeof(fd_pcapng_dsb_t), 1UL, file ) ) )
    return 0UL;
  /* copy log */
  if( FD_UNLIKELY( 1UL!=fwrite( log, log_sz, 1UL, file ) ) )
    return 0UL;
  /* align */
  if( pad_sz )
    if( FD_UNLIKELY( 1UL!=fwrite( pad, pad_sz, 1UL, file ) ) )
      return 0UL;
  /* empty options */
  if( FD_UNLIKELY( 1UL!=fwrite( pad, 4UL,    1UL, file ) ) )
    return 0UL;
  /* write length trailer */
  if( FD_UNLIKELY( 1UL!=fwrite( &block.block_sz, sizeof(uint), 1, file ) ) )
    return 0UL;

  return 1UL;
}

#endif /* FD_HAS_HOSTED */
