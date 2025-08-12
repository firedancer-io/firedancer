ifdef FD_HAS_SSE
$(call add-objs,fd_snaprd_tile,fd_discof)
ifdef FD_HAS_ZSTD
$(call add-objs,fd_snapdc_tile,fd_discof)
endif
ifdef FD_HAS_INT128
$(call add-objs,fd_snapin_tile,fd_discof)
endif
endif
ifdef FD_HAS_INT128
$(call add-objs,utils/fd_snapshot_parser,fd_discof)
$(call add-objs,utils/fd_ssmanifest_parser,fd_discof)
$(call add-objs,utils/fd_ssload,fd_discof)
$(call make-unit-test,test_ssmanifest_parser,utils/test_ssmanifest_parser,fd_discof fd_flamenco fd_ballet fd_util)

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_snapshot_parser,utils/fuzz_snapshot_parser,fd_discof fd_flamenco fd_ballet fd_util)
$(call make-fuzz-test,fuzz_ssmanifest_parser,utils/fuzz_ssmanifest_parser,fd_discof fd_flamenco fd_ballet fd_util)
$(call make-fuzz-test,fuzz_ssarchive_parser,utils/fuzz_ssarchive_parser,fd_discof fd_flamenco fd_ballet fd_util)
endif

endif
$(call add-objs,utils/fd_ssping,fd_discof)
$(call add-objs,utils/fd_sshttp,fd_discof)
$(call add-objs,utils/fd_ssarchive,fd_discof)
