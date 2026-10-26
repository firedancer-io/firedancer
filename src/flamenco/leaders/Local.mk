$(call add-hdrs,fd_leaders.h fd_multi_epoch_leaders.h)
$(call add-objs,fd_leaders fd_multi_epoch_leaders,fd_flamenco)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_leaders,test_leaders,fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_multi_leaders,test_multi_leaders,fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_leaders_geo,test_leaders_geo,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_leaders)
$(call run-unit-test,test_multi_leaders)
$(call run-unit-test,test_leaders_geo)
ifdef FD_HAS_DOUBLE
$(call make-unit-test,test_leaders_geo_sim,test_leaders_geo_sim,fd_flamenco fd_ballet fd_util)
endif
$(call make-fuzz-test,fuzz_leaders_geo,fuzz_leaders_geo,fd_flamenco fd_ballet fd_util)
endif
