ifdef FD_HAS_SSE
$(call add-objs,fd_alpen_tile,fd_discof)
$(call add-objs,fd_alpenv_tile,fd_discof)
$(call add-objs,fd_alpen,fd_discof)
endif
$(call make-unit-test,test_alpen_vote,test_alpen_vote,fd_discof fd_ballet fd_util)
$(call make-unit-test,test_alpen,test_alpen,fd_discof fd_ballet fd_util)
$(call run-unit-test,test_alpen_vote,)
$(call run-unit-test,test_alpen,)
