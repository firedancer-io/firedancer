$(call make-lib,fd_snp)

# fd_snp_app, e.g. for shred tile
$(call add-hdrs,fd_snp_app.h fd_snp_common.h)
$(call add-objs,fd_snp_app,fd_snp)

# fd_snp for snp tile
$(call add-hdrs,fd_snp.h fd_snp_proto.h)
$(call add-objs,fd_snp,fd_snp)

# fd_snp_v1 header is not needed by applications
# $(call add-hdrs,fd_snp_v1.h)
$(call add-objs,fd_snp_v1,fd_snp)

ifdef FD_HAS_HOSTED
SNP_TEST_LIBS:=fd_snp fd_util fd_ballet

$(call make-unit-test,test_snp_v1,test_snp_v1,$(SNP_TEST_LIBS))
$(call run-unit-test,test_snp_v1)

$(call make-unit-test,test_snp_live, test_snp_live, $(SNP_TEST_LIBS))
$(call run-unit-test,test_snp_live)

$(call make-unit-test,test_snp_app,test_snp_app,$(SNP_TEST_LIBS))
$(call run-unit-test,test_snp_app)

$(call make-unit-test,test_snp_common,test_snp_common,$(SNP_TEST_LIBS))
$(call run-unit-test,test_snp_common)

endif
