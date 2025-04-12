$(call make-lib,fd_snp)

$(call add-hdrs,fd_snp.h fd_snp_proto.h fd_snp_base.h)
$(call add-objs,fd_snp,fd_snp)

$(call add-hdrs,fd_snp_app.h)
$(call add-objs,fd_snp_app,fd_snp)

$(call add-hdrs,fd_snp_private.h)
$(call add-objs,fd_snp_common,fd_snp)

$(call add-hdrs,fd_snp_s0_client.h fd_snp_s0_server.h)
$(call add-objs,fd_snp_s0,fd_snp)

ifdef FD_HAS_HOSTED
SNP_TEST_LIBS:=fd_snp fd_util fd_ballet

# fd_snp unit tests
$(call make-unit-test,test_snp_hs,test_snp_hs,$(SNP_TEST_LIBS))
$(call run-unit-test,test_snp_hs)

#$(call make-unit-test,test_snp_client_server, test_snp_client_server, $(SNP_TEST_LIBS))
#$(call run-unit-test,test_snp_client_server)

#$(call make-unit-test,test_snp_live, test_snp_live, $(SNP_TEST_LIBS))
#$(call run-unit-test,test_snp_live)

$(call make-unit-test,test_snp_app,test_snp_app,$(SNP_TEST_LIBS))
$(call run-unit-test,test_snp_app)

endif
