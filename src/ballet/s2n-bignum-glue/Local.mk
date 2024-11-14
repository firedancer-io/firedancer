
ifeq ($(wildcard src/ballet/s2n-bignum),)

$(warning "s2n-bignum not found.  Please run 'git submodule update --init'")

else

FD_HAS_S2N_BIGNUM:=1
CPPFLAGS+=-DFD_HAS_S2N_BIGNUM=1
CPPFLAGS+=-isystem src/ballet/s2n-bignum/include
include src/ballet/s2n-bignum-glue/glue.mk

ifdef FD_HAS_X86

S2N_X86_OBJ_FULL = $(addprefix src/ballet/s2n-bignum/x86/,$(S2N_X86_OBJ))

$(OBJDIR)/lib/libfd_ballet.a: $(S2N_X86_OBJ_FULL)
$(S2N_X86_OBJ_FULL): src/ballet/s2n-bignum/x86/libs2nbignum.a
src/ballet/s2n-bignum/x86/libs2nbignum.a:
	$(MAKE) -C src/ballet/s2n-bignum/x86 libs2nbignum.a

clean: clean_s2n_bignum
.PHONY: clean_s2n_bignum
clean_s2n_bignum:
	$(MAKE) -C src/ballet/s2n-bignum/x86 clean

endif # FD_HAS_X86

endif # detect s2n-bignum

