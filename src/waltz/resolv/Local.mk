ifdef FD_HAS_HOSTED

# High level API
$(call add-hdrs,fd_netdb.h)
$(call add-objs,fd_getaddrinfo,fd_waltz)

# Config
$(call add-hdrs,fd_io_readline.h)
$(call add-objs,fd_io_readline,fd_waltz)
$(call add-objs,fd_netdb_open_fds,fd_waltz)
$(call add-hdrs,fd_lookup.h)
$(call add-objs,fd_resolvconf,fd_waltz)
$(call add-objs,fd_lookup_name fd_lookup_ipliteral,fd_waltz)

# Low level DNS
$(call add-hdrs,fd_resolv.h)
$(call add-objs,fd_dn_expand,fd_waltz)
$(call add-objs,fd_dns_parse,fd_waltz)
$(call add-objs,fd_res_mkquery fd_res_msend,fd_waltz)

$(call make-unit-test,test_getaddrinfo,test_getaddrinfo,fd_waltz fd_util)
$(call make-fuzz-test,fuzz_dn_expand,fuzz_dn_expand,fd_waltz fd_util)
$(call make-fuzz-test,fuzz_lookup_literal,fuzz_lookup_literal,fd_waltz fd_util)
$(call make-fuzz-test,fuzz_dns_parse,fuzz_dns_parse,fd_waltz fd_util)

$(call make-unit-test,test_resolv,test_resolv,fd_waltz fd_util)
$(call run-unit-test,test_resolv)

endif
