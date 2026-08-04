ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
$(call add-objs,fd_mlx5 fd_mlx5_tile,fd_disco)
$(call make-unit-test,test_mlx5_tile,test_mlx5_tile,fd_disco fd_waltz fd_tango fd_util)
$(call run-unit-test,test_mlx5_tile)
endif
endif
