ifdef FD_HAS_SSE
$(call add-objs,fd_alpen_tile,fd_discof)
$(call add-objs,fd_alpen_verify_tile,fd_discof)
endif
$(call make-unit-test,test_alpen_vote,test_alpen_vote,fd_discof fd_ballet fd_util)
