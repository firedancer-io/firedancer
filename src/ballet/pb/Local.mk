$(call add-hdrs,fd_pb_wire.h)
$(call add-hdrs,fd_pb_encode.h)

$(call add-hdrs,fd_pb_tokenize.h)
$(call add-objs,fd_pb_tokenize,fd_ballet)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_pb_tokenize,fuzz_pb_tokenize,fd_ballet fd_util)
endif

$(call add-hdrs,fd_pb_less.h)
$(call add-objs,fd_pb_less,fd_ballet)

$(call make-unit-test,test_pb,test_pb,fd_ballet fd_util)
