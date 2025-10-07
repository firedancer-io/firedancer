ifdef FD_HAS_INT128
$(call add-hdrs,fd_prog_load.h)
$(call add-objs,fd_prog_load,fd_flamenco)
$(call add-hdrs,fd_progcache.h fd_progcache_rec.h)
$(call add-objs,fd_progcache fd_progcache_rec fd_progcache_evict,fd_flamenco)
$(call make-unit-test,test_progcache,test_progcache,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_progcache)
endif
