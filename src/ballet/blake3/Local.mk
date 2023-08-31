$(call add-hdrs,fd_blake3.h)
$(call add-objs,fd_blake3,fd_ballet)
$(call add-asms,blake3_avx2_x86-64,fd_ballet)

$(call make-unit-test,test_blake3,test_blake3,fd_ballet fd_util)
