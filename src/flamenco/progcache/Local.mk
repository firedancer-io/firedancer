# Public APIs

$(call add-hdrs,fd_prog_load.h)
$(call add-objs,fd_prog_load,fd_flamenco)

$(call add-hdrs,fd_progcache_admin.h)
$(call add-objs,fd_progcache_admin,fd_flamenco)

ifdef FD_HAS_SECP256K1
$(call add-hdrs,fd_progcache_user.h)
$(call add-objs,fd_progcache_user,fd_flamenco)

$(call make-unit-test,test_progcache,test_progcache,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_progcache)

# Internals
$(call add-objs,fd_progcache_rec,fd_flamenco)

endif
