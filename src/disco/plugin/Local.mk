$(call add-hdrs,fd_bundle_crank.h)
ifdef FD_HAS_INT128
$(call add-objs,fd_bundle_crank,fd_disco,fd_flamenco)

$(call make-unit-test,test_bundle_crank,test_bundle_crank,fd_disco fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_bundle_crank,)
endif
