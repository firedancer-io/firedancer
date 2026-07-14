#ifndef HEADER_fd_src_waltz_tls_fd_tls_cs_h
#define HEADER_fd_src_waltz_tls_fd_tls_cs_h

/* fd_tls_cs.h provides TLS 1.3 cipher suite descriptors (RFC 8446 B.4) */

#include "../fd_waltz_base.h"
#include "../../ballet/hmac/fd_hmac.h"

#define FD_TLS_CS_IDX_AES_128_GCM_SHA256 (0)
#define FD_TLS_CS_IDX_AES_256_GCM_SHA384 (1)
#define FD_TLS_CS_CNT                    (2)

typedef struct {
  void * (* init  )( void * state );
  void * (* append)( void * state, void const * data, ulong data_sz );
  void * (* fini  )( void * state, void * hash );
  ulong  state_sz;
} fd_tls_hash_vt_t;

typedef struct fd_tls_cs {
  ushort             suite_id;
  uchar              hash_sz;
  uchar              key_sz;
  fd_hmac_fn_t       hmac_fn;
  fd_tls_hash_vt_t   hash_vt;
  char const *       name;
} fd_tls_cs_t;

FD_PROTOTYPES_BEGIN

fd_tls_cs_t const * fd_tls_cs_lookup( ushort suite_id );

extern fd_tls_cs_t const fd_tls_cs_table[ FD_TLS_CS_CNT ];

FD_PROTOTYPES_END

#endif
