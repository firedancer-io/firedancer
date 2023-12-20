CPPFLAGS+=-DFD_HAS_FFI=1 -fPIC
FD_HAS_FFI:=1

##############################
# Usage: $(call maybe-add-env-obj,env,lib)

define _maybe-add-env-obj

$(BASEDIR)/$(BUILDDIR)/lib/lib$(2).a: $(patsubst %.c,%.o,$(1))

$(patsubst %.c,%.o,$(1)): $(1)
	$(CC) -I. -I.. -Iffi/rust/firedancer-sys $(CPPFLAGS) $(CFLAGS) -c $$< -o $$@

endef

maybe-add-env-obj = $(eval $(call _maybe-add-env-obj,$(1),$(2)))

$(call maybe-add-env-obj,$(UTIL_STATIC_EXTERN_OBJECT),fd_util)
$(call maybe-add-env-obj,$(TANGO_STATIC_EXTERN_OBJECT),fd_tango)
$(call maybe-add-env-obj,$(DISCO_STATIC_EXTERN_OBJECT),fd_disco)
$(call maybe-add-env-obj,$(BALLET_STATIC_EXTERN_OBJECT),fd_ballet)
