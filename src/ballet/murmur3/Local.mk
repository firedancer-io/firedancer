$(call add-hdrs,fd_murmur3.h)
$(call add-objs,fd_murmur3,fd_ballet)
$(call make-unit-test,test_murmur3,test_murmur3,fd_ballet fd_util)
$(call fuzz-test,fuzz_murmur3,fuzz_murmur3,fd_ballet fd_util)
