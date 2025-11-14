# Admin API
$(call add-hdrs,fd_accdb_admin.h)
$(call add-objs,fd_accdb_admin,fd_flamenco)

# User API
$(call add-hdrs,fd_accdb_user.h fd_accdb_sync.h)
$(call add-objs,fd_accdb_user,fd_flamenco)

# Debug APIs
$(call add-hdrs,fd_accdb_fsck.h)
$(call add-objs,fd_accdb_fsck_funk fd_accdb_fsck_vinyl,fd_flamenco)
ifdef FD_HAS_LZ4
$(call make-bin,fd_accdb_ctl,fd_accdb_ctl,fd_vinyl fd_tango fd_ballet fd_util)
endif

ifdef FD_HAS_ATOMIC
$(call make-unit-test,test_accdb,test_accdb,fd_flamenco fd_funk fd_util)
$(call run-unit-test,test_accdb)
endif
