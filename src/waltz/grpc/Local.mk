$(call add-hdrs,fd_grpc.h)
$(call add-objs,fd_grpc,fd_waltz)
$(call make-unit-test,test_grpc,test_grpc,fd_waltz fd_util)
$(call run-unit-test,test_grpc)
