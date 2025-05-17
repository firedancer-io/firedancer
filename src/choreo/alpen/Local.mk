$(call add-hdrs,fd_alpen.h)
$(call add-objs,fd_alpen,fd_choreo)
ifdef FD_HAS_SSE
# TODO remove?
# $(call add-objs,fd_alpen_tile,fd_discof)
# $(call add-objs,fd_alpen_verify_tile,fd_discof)
endif
$(call make-unit-test,test_alpen_vote,test_alpen_vote,fd_choreo fd_ballet fd_util)