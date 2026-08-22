#ifndef HEADER_fd_src_waltz_fd_fqdn_h
#define HEADER_fd_src_waltz_fd_fqdn_h

/* Cstr storage capacity for host names used by Waltz URL and resolver
   APIs: up to 255 bytes plus the terminating NUL.  This is a storage
   bound, not a DNS validity limit; DNS syntax and its 253-byte textual
   limit without a trailing dot are enforced separately. */
#define FD_FQDN_BUF_MAX (255UL+1UL)

/* TLS SNI contains a host name. */
#define FD_SNI_BUF_MAX FD_FQDN_BUF_MAX

/* Cstr storage capacity for a maximum-sized host followed by ':', a
   five-digit port, and the terminating NUL.  FD_FQDN_BUF_MAX already
   accounts for the terminating NUL. */
#define FD_HOSTPORT_BUF_MAX (FD_FQDN_BUF_MAX+6UL)

#endif /* HEADER_fd_src_waltz_fd_fqdn_h */
