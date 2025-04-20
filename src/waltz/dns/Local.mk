$(call add-hdrs,fd_dns_cache.h)
$(call add-objs,fd_dns_cache,fd_waltz)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_dns_cache,test_dns_cache,fd_waltz fd_util)
$(call run-unit-test,test_dns_cache)
endif
