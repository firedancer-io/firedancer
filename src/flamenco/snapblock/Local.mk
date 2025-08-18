ifdef FD_HAS_INT128
$(call add-hdrs,fd_snapblock.h)
$(call add-objs,fd_snapblock,fd_flamenco)
$(call make-unit-test,test_snapblock,test_snapblock,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_snapblock)
endif
