$(call make-lib,fd_util)
$(call add-hdrs,fd_util_base.h fd_util.h)
$(call add-objs,fd_hash fd_util,fd_util)
$(call add-hdrs,fd_version.h,fd_util)
$(call add-objs,fd_version,fd_util)
$(call make-unit-test,test_util,test_util,fd_util)
$(call run-unit-test,test_util)

ifndef FD_HAS_UBSAN
# The point of test_util_base is to diagnose compatibility of the build
# target with the FD machine model.  It does this in part by extensively
# probing the linguistic UB/IB behaviors of the target.  As such, we
# expect this test to fail by design if running under ubsan and thus
# don't bother building it if FD_HAS_UBSAN is defined.
$(call make-unit-test,test_util_base,test_util_base,fd_util)
$(call run-unit-test,test_util_base)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_hash,fuzz_hash,fd_util)
endif
endif

$(file >src/util/fd_version_generated1.h,#define FIREDANCER_COMMIT_REF_CSTR "$(shell git rev-parse HEAD)")
ifneq ($(shell cmp -s src/util/fd_version_generated.h src/util/fd_version_generated1.h && echo "same"),same)
src/util/fd_version_generated.h: src/util/fd_version_generated1.h
	cp -f src/util/fd_version_generated1.h $@
endif
$(OBJDIR)/info: src/util/fd_version_generated.h
$(OBJDIR)/obj/util/fd_version.o:     src/util/fd_version_generated.h
$(OBJDIR)/obj/util/fd_version.d:     src/util/fd_version_generated.h
$(OBJDIR)/obj/util/fd_version.check: src/util/fd_version_generated.h
