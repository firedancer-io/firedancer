$(call add-hdrs,fd_merlin.h)
$(call add-objs,fd_merlin,fd_flamenco)
$(call make-unit-test,test_merlin,test_merlin,fd_flamenco fd_ballet fd_util)
# $(call fuzz-test,fuzz_fd_merlin,fuzz_fd_merlin,fd_flamenco fd_util)
