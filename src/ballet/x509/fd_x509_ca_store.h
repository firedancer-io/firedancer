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

  uchar pubkey[ 97 ];   /* {32,65,97} for {Ed25519,P256,P384} */
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

long
fd_x509_ca_store_load( fd_x509_ca_store_t * store,
                       char const *         pem_path );

fd_x509_ca_entry_t const *
fd_x509_ca_store_find( fd_x509_ca_store_t const * store,
                       uchar const *              subject,
                       ulong                      subject_len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_x509_fd_x509_ca_store_h */
