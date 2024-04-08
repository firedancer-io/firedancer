$(call add-hdrs,fd_shmem.h)
$(call add-objs,fd_shmem_admin fd_shmem_user,fd_util)
$(call add-scripts,fd_shmem_cfg)
$(call make-bin,fd_shmem_ctl,fd_shmem_ctl,fd_util)
$(call make-unit-test,test_shmem,test_shmem,fd_util)
$(call add-test-scripts,test_shmem_ctl)

ifdef FD_HAS_HOSTED
$(call add-objs,fd_numa_linux,fd_util)
else
$(call add-objs,fd_numa_stub,fd_util)
endif
