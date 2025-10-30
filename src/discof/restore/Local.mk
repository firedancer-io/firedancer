ifdef FD_HAS_SSE
$(call add-hdrs,fd_snapct_tile.h)
$(call add-objs,fd_snapct_tile,fd_discof)
$(call add-objs,fd_snapld_tile,fd_discof)
ifdef FD_HAS_ZSTD
$(call add-objs,fd_snapdc_tile,fd_discof)
endif
ifdef FD_HAS_INT128
$(call add-objs,fd_snapin_tile,fd_discof)
endif
endif
ifdef FD_HAS_INT128
$(call add-objs,utils/fd_ssparse,fd_discof)
$(call add-objs,utils/fd_ssmanifest_parser,fd_discof)
$(call add-objs,utils/fd_ssload,fd_discof)
$(call add-objs,utils/fd_ssping,fd_discof)
$(call add-objs,utils/fd_http_resolver,fd_discof)
$(call add-objs,utils/fd_slot_delta_parser,fd_discof)
$(call make-unit-test,test_ssmanifest_parser,utils/test_ssmanifest_parser,fd_discof fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_slot_delta_parser,utils/test_slot_delta_parser,fd_discof fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_sspeer_selector,utils/test_sspeer_selector,fd_discof fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_zstd_pipeline,utils/test_zstd_pipeline,fd_ballet fd_util fd_tango)
$(call run-unit-test,test_slot_delta_parser)
$(call run-unit-test,test_sspeer_selector)

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_snapshot_parser,utils/fuzz_snapshot_parser,fd_discof fd_flamenco fd_ballet fd_util)
$(call make-fuzz-test,fuzz_ssmanifest_parser,utils/fuzz_ssmanifest_parser,fd_discof fd_flamenco fd_ballet fd_util)
$(call make-fuzz-test,fuzz_ssarchive_parser,utils/fuzz_ssarchive_parser,fd_discof fd_flamenco fd_ballet fd_util)
$(call make-fuzz-test,fuzz_slot_delta_parser,utils/fuzz_slot_delta_parser,fd_discof fd_flamenco fd_ballet fd_util)
endif

endif
$(call add-objs,utils/fd_ssresolve,fd_discof)
$(call add-objs,utils/fd_sshttp,fd_discof)
$(call add-objs,utils/fd_ssarchive,fd_discof)
$(call add-objs,utils/fd_sspeer_selector,fd_discof)
