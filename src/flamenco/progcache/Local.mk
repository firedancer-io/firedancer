# Public APIs

$(call add-hdrs,fd_prog_load.h)
$(call add-objs,fd_prog_load,fd_flamenco)

$(call add-hdrs,fd_progcache_base.h fd_progcache.h)
$(call add-objs,fd_progcache,fd_flamenco)

$(call add-hdrs,fd_progcache_admin.h)
$(call add-objs,fd_progcache_admin,fd_flamenco)

$(call add-hdrs,fd_progcache_user.h)
$(call add-objs,fd_progcache_user,fd_flamenco)

$(call add-hdrs,fd_progcache_lineage.h)
$(call add-objs,fd_progcache_lineage,fd_flamenco)

$(call add-objs,fd_progcache_clock,fd_flamenco)
$(call add-objs,fd_progcache_rec,fd_flamenco)
$(call add-objs,fd_progcache_reclaim,fd_flamenco)

ifdef FD_HAS_ATOMIC
ifdef FD_HAS_INT128
$(call make-unit-test,test_progcache,test_progcache,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_progcache)
ifdef FD_HAS_RACESAN
$(call make-unit-test,test_progcache_racesan,test_progcache_racesan,fd_flamenco fd_ballet fd_util)
endif
endif
endif

# Internals
$(call add-objs,fd_progcache_rec,fd_flamenco)
