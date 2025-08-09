# Base ChaCha support
$(call add-hdrs,fd_chacha.h)
ifdef FD_HAS_SSE
$(call add-objs,fd_chacha_sse,fd_ballet)
else
$(call add-objs,fd_chacha,fd_ballet)
endif
$(call make-unit-test,test_chacha,test_chacha,fd_ballet fd_util)
$(call run-unit-test,test_chacha)

# ChaCha-RNG support (Rust rand_chacha compatible)
$(call add-hdrs,fd_chacha_rng.h)
$(call add-objs,fd_chacha_rng,fd_ballet)
ifdef FD_HAS_AVX512
$(call add-objs,fd_chacha_rng_avx512,fd_ballet)
endif
ifdef FD_HAS_AVX
$(call add-objs,fd_chacha_rng_avx,fd_ballet)
endif
$(call make-unit-test,test_chacha_rng,test_chacha_rng,fd_ballet fd_util)
$(call make-unit-test,test_chacha_rng_roll,test_chacha_rng_roll,fd_ballet fd_util)
$(call run-unit-test,test_chacha_rng)
