# Unit test only works if there is an accessable rocksdb

ifneq ($(FD_HAS_ROCKSDB),)

$(call make-lib,fd_sol_tests)

$(call add-objs,generated/test_native_programs_0 generated/test_native_programs_1000 generated/test_native_programs_100 generated/test_native_programs_1100 generated/test_native_programs_1200 generated/test_native_programs_1300 generated/test_native_programs_1400 generated/test_native_programs_1500 generated/test_native_programs_1600 generated/test_native_programs_1700 generated/test_native_programs_200 generated/test_native_programs_300 generated/test_native_programs_400 generated/test_native_programs_500 generated/test_native_programs_600 generated/test_native_programs_700 generated/test_native_programs_800 generated/test_native_programs_900,fd_sol_tests)

$(call make-unit-test,test_native_programs,test_native_programs,fd_ballet fd_funk fd_util fd_sol_tests fd_flamenco)
$(call make-unit-test,test_sign_programs,test_sign_programs fd_tests,fd_ballet fd_funk fd_util fd_flamenco)

endif
