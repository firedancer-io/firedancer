$(call add-hdrs,fd_url.h)
$(call add-objs,fd_url,fd_waltz)
$(call make-fuzz-test,fuzz_url_parse,fuzz_url_parse,fd_waltz fd_util)
