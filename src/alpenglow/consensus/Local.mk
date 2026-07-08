$(call add-hdrs,ag_vote.h ag_epoch_info.h ag_cert.h ag_votor.h ag_pool.h)
$(call add-objs,ag_vote ag_epoch_info ag_cert ag_votor ag_pool,ag_alpenglow)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_vote,test_vote,ag_alpenglow fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_epoch_info,test_epoch_info,ag_alpenglow fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_cert,test_cert,ag_alpenglow fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_votor,test_votor,ag_alpenglow fd_flamenco fd_ballet fd_util)
#$(call make-unit-test,test_alpenglow_pool,test_pool,ag_alpenglow fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_vote)
$(call run-unit-test,test_epoch_info)
$(call run-unit-test,test_cert)
$(call run-unit-test,test_votor)
$(call run-unit-test,test_alpenglow_pool)
endif
