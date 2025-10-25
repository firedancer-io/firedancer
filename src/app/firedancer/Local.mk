include src/app/firedancer/version.mk
$(shell echo "#define FIREDANCER_MAJOR_VERSION $(VERSION_MAJOR)"                          >  src/app/firedancer/version2.h)
$(shell echo "#define FIREDANCER_MINOR_VERSION $(VERSION_MINOR)"                          >> src/app/firedancer/version2.h)
$(shell echo "#define FIREDANCER_PATCH_VERSION $(VERSION_PATCH)"                          >> src/app/firedancer/version2.h)
$(shell echo "#define FIREDANCER_VERSION \"$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)\"" >> src/app/firedancer/version2.h)
$(shell echo '#define FIREDANCER_COMMIT_REF_CSTR "$(FIREDANCER_CI_COMMIT)"'                          >> src/app/firedancer/version2.h)
$(shell echo "#define FIREDANCER_COMMIT_REF_U32 0x$(shell echo $(FIREDANCER_CI_COMMIT) | cut -c -8)" >> src/app/firedancer/version2.h)

# Update version.h only if version changed or doesn't exist
ifneq ($(shell cmp -s src/app/firedancer/version.h src/app/firedancer/version2.h && echo "same"),same)
src/app/firedancer/version.h: src/app/firedancer/version2.h
	cp -f src/app/firedancer/version2.h $@
endif

# Always generate a version file
include src/app/firedancer/version.h

ifdef FD_HAS_HOSTED
ifdef FD_HAS_THREADS
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_DOUBLE
ifdef FD_HAS_INT128
ifdef FD_HAS_SECP256K1
ifdef FD_HAS_ZSTD

$(OBJDIR)/obj/app/firedancer/config.o: src/app/firedancer/config/default.toml
$(OBJDIR)/obj/app/firedancer/config.o: src/app/firedancer/config/testnet.toml
$(OBJDIR)/obj/app/firedancer/config.o: src/app/firedancer/config/devnet.toml
$(OBJDIR)/obj/app/firedancer/config.o: src/app/firedancer/config/mainnet.toml
$(OBJDIR)/obj/app/firedancer/version.d: src/app/firedancer/version.h

.PHONY: firedancer

# firedancer core
$(call add-objs,topology,fd_firedancer)
$(call add-objs,config,fd_firedancer)
$(call add-objs,callbacks callbacks_vinyl,fd_firedancer)

# commands
$(call add-objs,commands/shred_version,fd_firedancer)

# version
$(call make-lib,firedancer_version)
$(call add-objs,version,firedancer_version)

$(call make-bin,firedancer,main,fd_firedancer fdctl_shared fdctl_platform fd_discof fd_disco fd_choreo fd_flamenco fd_vinyl fd_funk fd_quic fd_tls fd_reedsol fd_waltz fd_tango fd_ballet fd_util firedancer_version,$(SECP256K1_LIBS) $(OPENSSL_LIBS))

else
$(warning firedancer build disabled due to lack of zstd)
endif
endif
endif
endif
endif
endif
endif
