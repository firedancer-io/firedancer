$(call add-hdrs,fd_textstream.h)
$(call add-objs,fd_textstream,fd_util)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_textstream,fuzz_textstream,fd_util)
endif