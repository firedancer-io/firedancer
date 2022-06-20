$(call add-hdrs,fd_shmem.h)
$(call add-objs,fd_shmem,fd_util)
$(call add-scripts,fd_shmem_cfg)
$(call make-unit-test,test_shmem,test_shmem,fd_util)
