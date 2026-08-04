$(call add-hdrs,fd_mlx5.h)

ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
$(call add-objs,fd_mlx5,fd_waltz)

$(call make-unit-test,test_mlx5,test_mlx5,fd_waltz fd_util)
$(call run-unit-test,test_mlx5)
endif # FD_HAS_LINUX
endif # FD_HAS_HOSTED
