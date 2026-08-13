ifdef FD_HAS_BLST

$(call make-lib,ag_alpenglow)
$(call add-hdrs,ag_alpenglow_base.h)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_alpenglow_base,test_alpenglow_base,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_alpenglow_base)
endif

else

# Alpenglow is only a valid protocol with BLS, so the whole library is a
# no-op without libblst rather than being stubbed out source by source.

$(warning alpenglow disabled due to lack of libblst)

endif
