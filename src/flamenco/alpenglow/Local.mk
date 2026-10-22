$(call add-hdrs,fd_alpenglow.h fd_footer_cache.h fd_vote_queue.h fd_block_marker.h fd_block_marker_serde.h)
$(call add-objs,fd_alpenglow fd_footer_cache fd_vote_queue fd_block_marker fd_block_marker_serde,fd_flamenco)
$(call make-unit-test,test_block_marker,test_block_marker,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_block_marker)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_footer_cache,test_footer_cache,fd_flamenco fd_ballet fd_util,$(BLST_LIBS))
$(call run-unit-test,test_footer_cache)
$(call make-unit-test,test_alpenglow_v5,test_alpenglow_v5,fd_flamenco_test fd_flamenco fd_tango fd_ballet fd_util fd_disco,$(BLST_LIBS))
$(call run-unit-test,test_alpenglow_v5)
endif
