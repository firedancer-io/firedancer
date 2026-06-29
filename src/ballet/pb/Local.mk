$(call add-hdrs,fd_pb_wire.h fd_pb_encode.h fd_pb_tokenize.h)
$(call add-objs,fd_pb_tokenize,fd_ballet)
$(call make-unit-test,test_pb,test_pb,fd_ballet fd_util)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_pb_tokenize,fuzz_pb_tokenize,fd_ballet fd_util)
endif
