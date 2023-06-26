$(call add-hdrs,fd_tile.h)
ifdef FD_HAS_THREADS
$(call add-objs,fd_tile_threads,fd_util)
else
$(call add-objs,fd_tile_nothreads,fd_util)
endif
$(call make-unit-test,test_tile,test_tile,fd_util)
$(call run-unit-test,test_tile,)

