$(call add-hdrs,fd_vote.h fd_epoch_info.h fd_cert.h fd_votor.h fd_pool.h)
$(call add-objs,fd_vote fd_epoch_info fd_cert fd_votor fd_pool,fd_alpenglow)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_vote,test_vote,fd_alpenglow fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_epoch_info,test_epoch_info,fd_alpenglow fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_cert,test_cert,fd_alpenglow fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_votor,test_votor,fd_alpenglow fd_flamenco fd_ballet fd_util)
#$(call make-unit-test,test_alpenglow_pool,test_pool,fd_alpenglow fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_vote)
$(call run-unit-test,test_epoch_info)
$(call run-unit-test,test_cert)
$(call run-unit-test,test_votor)
$(call run-unit-test,test_alpenglow_pool)
endif
