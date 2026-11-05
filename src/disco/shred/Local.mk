$(call add-objs,fd_shred_dest,fd_disco)
$(call add-objs,fd_shredder,fd_disco)
$(call add-objs,fd_stake_ci,fd_disco)
ifdef FD_HAS_HOSTED
$(call add-objs,fd_fec_resolver,fd_disco)
$(call add-objs,fd_shred_dest_resolver fd_shred_tile,fd_disco)
$(call make-unit-test,test_fec_resolver,test_fec_resolver,fd_flamenco fd_disco fd_ballet fd_tango fd_reedsol fd_util_test fd_util)
$(call run-unit-test,test_fec_resolver)
$(call make-unit-test,test_shred_dest,test_shred_dest,fd_disco fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_shred_dest_conformance,test_shred_dest_conformance,fd_disco fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_stake_ci,test_stake_ci,fd_disco fd_flamenco fd_ballet fd_util fd_tango fd_reedsol)
$(call run-unit-test,test_shred_dest)
$(call run-unit-test,test_shred_dest_conformance)
$(call run-unit-test,test_stake_ci)
endif
$(call make-unit-test,test_rnonce_ss,test_rnonce_ss,fd_util)
$(call make-unit-test,test_shred_batch,test_shred_batch,fd_disco fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_rnonce_ss)
$(call run-unit-test,test_shred_batch)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_shredder,test_shredder,fd_disco fd_flamenco fd_ballet fd_util_extra fd_util fd_reedsol)
$(call run-unit-test,test_shredder)
endif

ifdef FD_HAS_HOSTED
# Include the actual callbacks/resolver in the regression TU; discard unused
# application initialization so the test needs no node state or hugepages.
$(OBJDIR)/obj/disco/shred/test_shred_dispatch.o: CFLAGS+=-ffunction-sections -fdata-sections
$(call make-unit-test,test_shred_dispatch,test_shred_dispatch,fd_flamenco fd_disco fd_waltz fd_ballet fd_tango fd_reedsol fd_util_test fd_util,-Wl$(comma)--gc-sections)
$(call run-unit-test,test_shred_dispatch)
# Do not root every unrelated topology/application symbol through -rdynamic.
$(OBJDIR)/unit-test/test_shred_dispatch: LDFLAGS:=$(filter-out -rdynamic,$(LDFLAGS))
endif
