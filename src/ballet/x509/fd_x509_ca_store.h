#ifndef HEADER_fd_src_ballet_x509_fd_x509_ca_store_h
#define HEADER_fd_src_ballet_x509_fd_x509_ca_store_h

/* fd_x509_ca_store.h implements a CA trust store for verifying X.509
   certificate chains. */

#include "fd_x509.h"

#define FD_X509_CA_STORE_MAX (512UL)
#define FD_X509_CA_SUBJECT_MAX (512UL)

struct fd_x509_ca_entry {
  uchar subject[ FD_X509_CA_SUBJECT_MAX ];
  ulong subject_len;

  uchar pubkey[ 65 ];   /* {32,65} for {Ed25519,P256} */
  ulong pubkey_len;
  uchar key_type;        /* FD_X509_KEY_{...} */
};

typedef struct fd_x509_ca_entry fd_x509_ca_entry_t;

/* fd_x509_ca_store_t holds the complete trust store. */

struct fd_x509_ca_store {
  fd_x509_ca_entry_t entries[ FD_X509_CA_STORE_MAX ];
  ulong              cnt;
};

typedef struct fd_x509_ca_store fd_x509_ca_store_t;

FD_PROTOTYPES_BEGIN

#if FD_HAS_HOSTED

/* fd_x509_ca_store_load clears store, then loads supported CA certificates
   from the PEM bundle at pem_path.  Malformed, unsupported, non-CA, and
   unusable entries are skipped.  Bundles exceeding FD_X509_CA_STORE_MAX are
   truncated.

   Returns the number of loaded trust anchors, or -1 for a file-level error.
   store and pem_path must be non-NULL. */

long
fd_x509_ca_store_load( fd_x509_ca_store_t * store,
                       char const *         pem_path );

/* fd_x509_ca_store_load_system loads the host's system CA bundle into
   store, trying the well known bundle paths of the common distros in
   order.  Returns the number of trust anchors loaded from the first bundle
   that could be read, or -1 if no bundle was found. */

long
fd_x509_ca_store_load_system( fd_x509_ca_store_t * store );

#endif /* FD_HAS_HOSTED */

/* fd_x509_ca_store_find_next returns the trust anchor at index *idx or
   later whose subject matches, and advances *idx past it.  Returns NULL
   when no further match exists.  *idx should be 0 on the first call. */

fd_x509_ca_entry_t const *
fd_x509_ca_store_find_next( fd_x509_ca_store_t const * store,
                            uchar const *              subject,
                            ulong                      subject_len,
                            ulong *                    idx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_x509_fd_x509_ca_store_h */
