ifdef FD_HAS_ALLOCA
ifdef FD_HAS_SSE
$(call add-hdrs,fd_snapct_tile.h)
$(call add-objs,fd_snapct_tile,fd_discof)
$(call add-objs,fd_snapld_tile,fd_discof)
ifdef FD_HAS_ZSTD
$(call add-objs,fd_snapdc_tile,fd_discof)
endif # FD_HAS_ZSTD
$(call add-objs,fd_snapin_tile fd_snapin_tile_funk fd_snapin_tile_vinyl,fd_discof)
endif # FD_HAS_SSE
$(call add-objs,fd_snapwh_tile,fd_discof)
$(call add-objs,fd_snapwr_tile,fd_discof)
$(call add-objs,fd_snapla_tile,fd_discof)
$(call add-objs,fd_snapls_tile,fd_discof)
$(call add-objs,fd_snaplh_tile,fd_discof)
$(call add-objs,fd_snaplv_tile,fd_discof)
endif # FD_HAS_ALLOCA
$(call add-objs,utils/fd_ssparse,fd_discof)
$(call add-objs,utils/fd_ssmanifest_parser,fd_discof)
$(call add-objs,utils/fd_ssload,fd_discof)
$(call add-objs,utils/fd_ssping,fd_discof)
ifdef FD_HAS_HOSTED
$(call add-objs,utils/fd_http_resolver,fd_discof)
endif # FD_HAS_HOSTED
$(call add-objs,utils/fd_slot_delta_parser,fd_discof)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_ssmanifest_parser,utils/test_ssmanifest_parser,fd_discof fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_slot_delta_parser,utils/test_slot_delta_parser,fd_discof fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_sspeer_selector,utils/test_sspeer_selector,fd_discof fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_slot_delta_parser)
$(call run-unit-test,test_sspeer_selector)
endif

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_snapshot_parser,utils/fuzz_snapshot_parser,fd_discof fd_flamenco fd_ballet fd_util)
$(call make-fuzz-test,fuzz_ssmanifest_parser,utils/fuzz_ssmanifest_parser,fd_discof fd_flamenco fd_ballet fd_util)
$(call make-fuzz-test,fuzz_ssarchive_parser,utils/fuzz_ssarchive_parser,fd_discof fd_flamenco fd_ballet fd_util)
$(call make-fuzz-test,fuzz_slot_delta_parser,utils/fuzz_slot_delta_parser,fd_discof fd_flamenco fd_ballet fd_util)
endif

$(call add-objs,utils/fd_ssresolve,fd_discof)
ifdef FD_HAS_HOSTED
$(call add-objs,utils/fd_sshttp,fd_discof)
endif
$(call add-objs,utils/fd_ssarchive,fd_discof)
$(call add-objs,utils/fd_sspeer_selector,fd_discof)
$(call add-objs,utils/fd_vinyl_io_wd,fd_discof)

ifdef FD_HAS_HOSTED
ifdef FD_HAS_ZSTD
$(call make-bin,fd_snapmk_para,fd_snapmk_para,fd_discof fd_flamenco fd_ballet fd_tango fd_util)
endif
endif
