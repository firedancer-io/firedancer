$(call add-hdrs,fd_chacha20.h fd_chacha20rng.h)
$(call add-objs,fd_chacha20rng,fd_ballet)

ifdef FD_HAS_AVX
$(call add-objs,fd_chacha20_avx,fd_ballet)
endif

ifdef FD_HAS_SSE
$(call add-objs,fd_chacha20_sse,fd_ballet)
else
$(call add-objs,fd_chacha20,fd_ballet)
endif

$(call make-unit-test,test_chacha20,test_chacha20,fd_ballet fd_util)
$(call make-unit-test,test_chacha20rng,test_chacha20rng,fd_ballet fd_util)
$(call make-unit-test,test_chacha20rng_roll,test_chacha20rng_roll,fd_ballet fd_util)
$(call run-unit-test,test_chacha20)
$(call run-unit-test,test_chacha20rng)
