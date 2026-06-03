#define _GNU_SOURCE
#include "fd_event_auth.h"

#if !FD_HAS_OPENSSL
#error "Building fd_event_auth requires FD_HAS_OPENSSL"
#endif

#include "../keyguard/fd_keyguard.h"

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/tls1.h>

#include <stdint.h>

#define FD_EVENT_RPK_PROVIDER_NAME "fd_event_rpk"
#define FD_EVENT_RPK_KEYGUARD_PARAM "fd-keyguard"

typedef struct fd_event_rpk_key {
  uchar                  pubkey[ 32UL ];
  fd_keyguard_client_t * keyguard_client;
  int                    has_public;
  int                    has_private;
} fd_event_rpk_key_t;

typedef struct fd_event_rpk_sig_ctx {
  fd_event_rpk_key_t * key;
  uchar                msg[ FD_KEYGUARD_SIGN_REQ_MTU ];
  ulong                msg_sz;
} fd_event_rpk_sig_ctx_t;

static void *
fd_event_rpk_keymgmt_new( void * provctx FD_PARAM_UNUSED ) {
  return OPENSSL_zalloc( sizeof(fd_event_rpk_key_t) );
}

static void
fd_event_rpk_keymgmt_free( void * keydata ) {
  OPENSSL_free( keydata );
}

static void *
fd_event_rpk_keymgmt_dup( void const * keydata_from,
                          int          selection FD_PARAM_UNUSED ) {
  fd_event_rpk_key_t const * from = keydata_from;
  fd_event_rpk_key_t * to = OPENSSL_malloc( sizeof(fd_event_rpk_key_t) );
  if( FD_UNLIKELY( !to ) ) return NULL;
  *to = *from;
  return to;
}

static int
fd_event_rpk_keymgmt_import( void *             keydata,
                             int                selection,
                             OSSL_PARAM const * params ) {
  fd_event_rpk_key_t * key = keydata;

  if( selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) {
    OSSL_PARAM const * pub = OSSL_PARAM_locate_const( params, OSSL_PKEY_PARAM_PUB_KEY );
    if( FD_UNLIKELY( !pub || pub->data_size!=32UL ) ) return 0;
    fd_memcpy( key->pubkey, pub->data, 32UL );
    key->has_public = 1;
  }

  if( selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) {
    OSSL_PARAM const * kg = OSSL_PARAM_locate_const( params, FD_EVENT_RPK_KEYGUARD_PARAM );
    ulong keyguard_ptr = 0UL;
    if( FD_UNLIKELY(
        !kg ||
        !OSSL_PARAM_get_ulong( kg, &keyguard_ptr ) ||
        !keyguard_ptr ) ) {
      return 0;
    }
    key->keyguard_client = (fd_keyguard_client_t *)(uintptr_t)keyguard_ptr;
    key->has_private = 1;
  }

  return 1;
}

static OSSL_PARAM const *
fd_event_rpk_keymgmt_import_types( int selection FD_PARAM_UNUSED ) {
  static OSSL_PARAM const import_types[] = {
    OSSL_PARAM_octet_string( OSSL_PKEY_PARAM_PUB_KEY, NULL, 0 ),
    OSSL_PARAM_ulong       ( FD_EVENT_RPK_KEYGUARD_PARAM, NULL ),
    OSSL_PARAM_END
  };
  return import_types;
}

static OSSL_PARAM const *
fd_event_rpk_keymgmt_import_types_ex( void * provctx   FD_PARAM_UNUSED,
                                      int    selection FD_PARAM_UNUSED ) {
  return fd_event_rpk_keymgmt_import_types( selection );
}

static int
fd_event_rpk_keymgmt_export( void const *   keydata,
                             int            selection,
                             OSSL_CALLBACK * param_cb,
                             void *         cbarg ) {
  fd_event_rpk_key_t const * key = keydata;
  if( FD_UNLIKELY( selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ) ) return 0;
  if( FD_UNLIKELY( (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) && !key->has_public ) ) return 0;

  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_octet_string( OSSL_PKEY_PARAM_PUB_KEY, (void *)key->pubkey, 32UL ),
    OSSL_PARAM_END
  };
  return param_cb( params, cbarg );
}

static OSSL_PARAM const *
fd_event_rpk_keymgmt_export_types( int selection FD_PARAM_UNUSED ) {
  static OSSL_PARAM const export_types[] = {
    OSSL_PARAM_octet_string( OSSL_PKEY_PARAM_PUB_KEY, NULL, 0 ),
    OSSL_PARAM_END
  };
  return export_types;
}

static OSSL_PARAM const *
fd_event_rpk_keymgmt_export_types_ex( void * provctx   FD_PARAM_UNUSED,
                                      int    selection FD_PARAM_UNUSED ) {
  return fd_event_rpk_keymgmt_export_types( selection );
}

static int
fd_event_rpk_keymgmt_get_params( void *      keydata,
                                 OSSL_PARAM params[] ) {
  fd_event_rpk_key_t * key = keydata;

  OSSL_PARAM * p = OSSL_PARAM_locate( params, OSSL_PKEY_PARAM_BITS );
  if( p && FD_UNLIKELY( !OSSL_PARAM_set_int( p, 256 ) ) ) return 0;
  p = OSSL_PARAM_locate( params, OSSL_PKEY_PARAM_SECURITY_BITS );
  if( p && FD_UNLIKELY( !OSSL_PARAM_set_int( p, 128 ) ) ) return 0;
  p = OSSL_PARAM_locate( params, OSSL_PKEY_PARAM_MAX_SIZE );
  if( p && FD_UNLIKELY( !OSSL_PARAM_set_int( p, 64 ) ) ) return 0;
  p = OSSL_PARAM_locate( params, OSSL_PKEY_PARAM_MANDATORY_DIGEST );
  if( p && FD_UNLIKELY( !OSSL_PARAM_set_utf8_string( p, "" ) ) ) return 0;
  p = OSSL_PARAM_locate( params, OSSL_PKEY_PARAM_PUB_KEY );
  if( p && FD_UNLIKELY( !key->has_public || !OSSL_PARAM_set_octet_string( p, key->pubkey, 32UL ) ) ) return 0;
  return 1;
}

static OSSL_PARAM const *
fd_event_rpk_keymgmt_gettable_params( void * provctx FD_PARAM_UNUSED ) {
  static OSSL_PARAM const gettable[] = {
    OSSL_PARAM_int         ( OSSL_PKEY_PARAM_BITS, NULL ),
    OSSL_PARAM_int         ( OSSL_PKEY_PARAM_SECURITY_BITS, NULL ),
    OSSL_PARAM_int         ( OSSL_PKEY_PARAM_MAX_SIZE, NULL ),
    OSSL_PARAM_utf8_string ( OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0 ),
    OSSL_PARAM_octet_string( OSSL_PKEY_PARAM_PUB_KEY, NULL, 0 ),
    OSSL_PARAM_END
  };
  return gettable;
}

static int
fd_event_rpk_keymgmt_has( void const * keydata,
                          int          selection ) {
  fd_event_rpk_key_t const * key = keydata;
  if( (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) && !key->has_public  ) return 0;
  if( (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && !key->has_private ) return 0;
  return 1;
}

static int
fd_event_rpk_keymgmt_validate( void const * keydata,
                               int          selection,
                               int          checktype FD_PARAM_UNUSED ) {
  return fd_event_rpk_keymgmt_has( keydata, selection );
}

static int
fd_event_rpk_keymgmt_match( void const * keydata1,
                            void const * keydata2,
                            int          selection ) {
  fd_event_rpk_key_t const * key1 = keydata1;
  fd_event_rpk_key_t const * key2 = keydata2;
  if( selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) {
    return key1->has_public && key2->has_public && !memcmp( key1->pubkey, key2->pubkey, 32UL );
  }
  return 1;
}

static char const *
fd_event_rpk_keymgmt_query_operation_name( int operation_id ) {
  return operation_id==OSSL_OP_SIGNATURE ? "ED25519" : NULL;
}

static void *
fd_event_rpk_signature_newctx( void *       provctx FD_PARAM_UNUSED,
                               char const * propq   FD_PARAM_UNUSED ) {
  return OPENSSL_zalloc( sizeof(fd_event_rpk_sig_ctx_t) );
}

static void
fd_event_rpk_signature_freectx( void * ctx ) {
  OPENSSL_free( ctx );
}

static int
fd_event_rpk_signature_digest_sign_init( void *             ctx,
                                         char const *       mdname,
                                         void *             provkey,
                                         OSSL_PARAM const * params FD_PARAM_UNUSED ) {
  fd_event_rpk_sig_ctx_t * sig_ctx = ctx;
  if( FD_UNLIKELY( mdname && mdname[0] ) ) return 0;
  sig_ctx->key    = provkey;
  sig_ctx->msg_sz = 0UL;
  return !!sig_ctx->key;
}

static int
fd_event_rpk_signature_sign_init( void *             ctx,
                                  void *             provkey,
                                  OSSL_PARAM const * params ) {
  return fd_event_rpk_signature_digest_sign_init( ctx, NULL, provkey, params );
}

static int
fd_event_rpk_signature_sign( void *        ctx,
                             uchar *       sig,
                             size_t *      siglen,
                             size_t        sigsize,
                             uchar const * tbs,
                             size_t        tbslen ) {
  fd_event_rpk_sig_ctx_t * sig_ctx = ctx;
  if( FD_UNLIKELY( !sig_ctx->key || !sig_ctx->key->keyguard_client ) ) return 0;
  if( !sig ) {
    *siglen = 64UL;
    return 1;
  }
  if( FD_UNLIKELY( sigsize<64UL || tbslen>FD_KEYGUARD_SIGN_REQ_MTU ) ) return 0;

  fd_keyguard_client_sign( sig_ctx->key->keyguard_client,
                           sig,
                           tbs,
                           (ulong)tbslen,
                           FD_KEYGUARD_SIGN_TYPE_ED25519 );
  *siglen = 64UL;
  return 1;
}

static int
fd_event_rpk_signature_digest_sign( void *        ctx,
                                    uchar *       sigret,
                                    size_t *      siglen,
                                    size_t        sigsize,
                                    uchar const * tbs,
                                    size_t        tbslen ) {
  return fd_event_rpk_signature_sign( ctx, sigret, siglen, sigsize, tbs, tbslen );
}

static int
fd_event_rpk_signature_digest_sign_update( void *        ctx,
                                           uchar const * data,
                                           size_t        datalen ) {
  fd_event_rpk_sig_ctx_t * sig_ctx = ctx;
  if( FD_UNLIKELY( datalen>FD_KEYGUARD_SIGN_REQ_MTU-sig_ctx->msg_sz ) ) return 0;
  fd_memcpy( sig_ctx->msg+sig_ctx->msg_sz, data, datalen );
  sig_ctx->msg_sz += datalen;
  return 1;
}

static int
fd_event_rpk_signature_digest_sign_final( void *   ctx,
                                          uchar *  sig,
                                          size_t * siglen,
                                          size_t   sigsize ) {
  fd_event_rpk_sig_ctx_t * sig_ctx = ctx;
  return fd_event_rpk_signature_sign( ctx, sig, siglen, sigsize, sig_ctx->msg, sig_ctx->msg_sz );
}

static int
fd_event_rpk_signature_get_ctx_params( void *      ctx FD_PARAM_UNUSED,
                                       OSSL_PARAM params[] ) {
  OSSL_PARAM * p = OSSL_PARAM_locate( params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID );
  if( p ) {
    static uchar const ed25519_alg_id[] = { 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70 };
    if( FD_UNLIKELY( !OSSL_PARAM_set_octet_string( p, ed25519_alg_id, sizeof(ed25519_alg_id) ) ) ) return 0;
  }
  return 1;
}

static OSSL_PARAM const *
fd_event_rpk_signature_gettable_ctx_params( void * ctx     FD_PARAM_UNUSED,
                                            void * provctx FD_PARAM_UNUSED ) {
  static OSSL_PARAM const gettable[] = {
    OSSL_PARAM_octet_string( OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0 ),
    OSSL_PARAM_END
  };
  return gettable;
}

static OSSL_DISPATCH const fd_event_rpk_keymgmt_fns[] = {
  { OSSL_FUNC_KEYMGMT_NEW,                  (void (*)(void))fd_event_rpk_keymgmt_new                  },
  { OSSL_FUNC_KEYMGMT_FREE,                 (void (*)(void))fd_event_rpk_keymgmt_free                 },
  { OSSL_FUNC_KEYMGMT_DUP,                  (void (*)(void))fd_event_rpk_keymgmt_dup                  },
  { OSSL_FUNC_KEYMGMT_IMPORT,               (void (*)(void))fd_event_rpk_keymgmt_import               },
  { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,         (void (*)(void))fd_event_rpk_keymgmt_import_types         },
  { OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX,      (void (*)(void))fd_event_rpk_keymgmt_import_types_ex      },
  { OSSL_FUNC_KEYMGMT_EXPORT,               (void (*)(void))fd_event_rpk_keymgmt_export               },
  { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,         (void (*)(void))fd_event_rpk_keymgmt_export_types         },
  { OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX,      (void (*)(void))fd_event_rpk_keymgmt_export_types_ex      },
  { OSSL_FUNC_KEYMGMT_GET_PARAMS,           (void (*)(void))fd_event_rpk_keymgmt_get_params           },
  { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,      (void (*)(void))fd_event_rpk_keymgmt_gettable_params      },
  { OSSL_FUNC_KEYMGMT_HAS,                  (void (*)(void))fd_event_rpk_keymgmt_has                  },
  { OSSL_FUNC_KEYMGMT_VALIDATE,             (void (*)(void))fd_event_rpk_keymgmt_validate             },
  { OSSL_FUNC_KEYMGMT_MATCH,                (void (*)(void))fd_event_rpk_keymgmt_match                },
  { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))fd_event_rpk_keymgmt_query_operation_name },
  OSSL_DISPATCH_END
};

static OSSL_DISPATCH const fd_event_rpk_signature_fns[] = {
  { OSSL_FUNC_SIGNATURE_NEWCTX,              (void (*)(void))fd_event_rpk_signature_newctx              },
  { OSSL_FUNC_SIGNATURE_FREECTX,             (void (*)(void))fd_event_rpk_signature_freectx             },
  { OSSL_FUNC_SIGNATURE_SIGN_INIT,           (void (*)(void))fd_event_rpk_signature_sign_init           },
  { OSSL_FUNC_SIGNATURE_SIGN,                (void (*)(void))fd_event_rpk_signature_sign                },
  { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,    (void (*)(void))fd_event_rpk_signature_digest_sign_init    },
  { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,         (void (*)(void))fd_event_rpk_signature_digest_sign         },
  { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,  (void (*)(void))fd_event_rpk_signature_digest_sign_update  },
  { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,   (void (*)(void))fd_event_rpk_signature_digest_sign_final   },
  { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,      (void (*)(void))fd_event_rpk_signature_get_ctx_params      },
  { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))fd_event_rpk_signature_gettable_ctx_params },
  OSSL_DISPATCH_END
};

static OSSL_ALGORITHM const fd_event_rpk_keymgmt_algs[] = {
  { "ED25519:1.3.101.112", "provider=" FD_EVENT_RPK_PROVIDER_NAME, fd_event_rpk_keymgmt_fns, "Firedancer event Ed25519 keyguard keymgmt" },
  { NULL, NULL, NULL, NULL }
};

static OSSL_ALGORITHM const fd_event_rpk_signature_algs[] = {
  { "ED25519:1.3.101.112", "provider=" FD_EVENT_RPK_PROVIDER_NAME, fd_event_rpk_signature_fns, "Firedancer event Ed25519 keyguard signature" },
  { NULL, NULL, NULL, NULL }
};

static OSSL_ALGORITHM const *
fd_event_rpk_provider_query( void * provctx FD_PARAM_UNUSED,
                             int    operation_id,
                             int *  no_cache ) {
  *no_cache = 0;
  switch( operation_id ) {
  case OSSL_OP_KEYMGMT:   return fd_event_rpk_keymgmt_algs;
  case OSSL_OP_SIGNATURE: return fd_event_rpk_signature_algs;
  default:                return NULL;
  }
}

static OSSL_DISPATCH const fd_event_rpk_provider_fns[] = {
  { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fd_event_rpk_provider_query },
  OSSL_DISPATCH_END
};

static int
fd_event_rpk_provider_init( OSSL_CORE_HANDLE const * handle FD_PARAM_UNUSED,
                            OSSL_DISPATCH const *    in     FD_PARAM_UNUSED,
                            OSSL_DISPATCH const **   out,
                            void **                  provctx ) {
  *provctx = NULL;
  *out     = fd_event_rpk_provider_fns;
  return 1;
}

static void
fd_event_rpk_provider_ensure_loaded( void ) {
  static OSSL_PROVIDER * provider;
  FD_ONCE_BEGIN {
    if( FD_UNLIKELY( !OSSL_PROVIDER_add_builtin( NULL, FD_EVENT_RPK_PROVIDER_NAME, fd_event_rpk_provider_init ) ) ) {
      FD_LOG_ERR(( "OSSL_PROVIDER_add_builtin(" FD_EVENT_RPK_PROVIDER_NAME ") failed" ));
    }
    provider = OSSL_PROVIDER_load( NULL, FD_EVENT_RPK_PROVIDER_NAME );
    if( FD_UNLIKELY( !provider ) ) {
      FD_LOG_ERR(( "OSSL_PROVIDER_load(" FD_EVENT_RPK_PROVIDER_NAME ") failed" ));
    }
  } FD_ONCE_END;
}

static EVP_PKEY *
fd_event_rpk_pkey_new( uchar const *          identity_pubkey,
                       fd_keyguard_client_t * keyguard_client ) {
  fd_event_rpk_provider_ensure_loaded();

  EVP_PKEY_CTX * pkey_ctx = EVP_PKEY_CTX_new_from_name( NULL, "ED25519", "provider=" FD_EVENT_RPK_PROVIDER_NAME );
  if( FD_UNLIKELY( !pkey_ctx ) ) return NULL;
  if( FD_UNLIKELY( EVP_PKEY_fromdata_init( pkey_ctx )<=0 ) ) {
    EVP_PKEY_CTX_free( pkey_ctx );
    return NULL;
  }

  ulong keyguard_ptr = (ulong)(uintptr_t)keyguard_client;
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_octet_string( OSSL_PKEY_PARAM_PUB_KEY, (void *)identity_pubkey, 32UL ),
    OSSL_PARAM_construct_ulong       ( FD_EVENT_RPK_KEYGUARD_PARAM, &keyguard_ptr ),
    OSSL_PARAM_END
  };

  EVP_PKEY * pkey = NULL;
  int const ok = EVP_PKEY_fromdata( pkey_ctx, &pkey, OSSL_KEYMGMT_SELECT_KEYPAIR, params );
  EVP_PKEY_CTX_free( pkey_ctx );
  return ok>0 ? pkey : NULL;
}

int
fd_event_auth_set_identity( SSL *                  ssl,
                            uchar const *          identity_pubkey,
                            fd_keyguard_client_t * keyguard_client ) {
  uchar client_cert_type = TLSEXT_cert_type_rpk;
  if( FD_UNLIKELY( !SSL_set1_client_cert_type( ssl, &client_cert_type, 1UL ) ) ) return 0;

  EVP_PKEY * rpk = fd_event_rpk_pkey_new( identity_pubkey, keyguard_client );
  if( FD_UNLIKELY( !rpk ) ) return 0;

  int const ok = SSL_use_PrivateKey( ssl, rpk );
  EVP_PKEY_free( rpk );
  return ok;
}
