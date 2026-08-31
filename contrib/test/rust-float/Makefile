# Runs the C and Rust floating point corpora and diffs them.
#
#   make -C contrib/test/rust-float
#
# Builds the C unit test too, so this is the only step needed.  The usual
# MACHINE/CC/EXTRAS (or an explicit OBJDIR) select which Firedancer build
# to use, RUSTC which Rust compiler.
#
#   MACHINE=linux_clang_icelake make -C contrib/test/rust-float
#
# Both programs print raw results on stdout, nan payloads included, so
# the diff names the exact operation and operands that disagree.  A
# difference fails the run unless its "op operand [operand]" key is
# listed in known-divergences.txt.
#
# Without --dump both are silent on stdout and only report their hash,
# which is the form CI runs as a unit test.

FD_ROOT := ../../..
# derive the keyed build dir under the same CC/MACHINE/EXTRAS/BUILDDIR the
# recipe's sub-make will see; MAKEFLAGS dropped (-n/-w corrupt the output)
FD_VARS := $(foreach v,CC MACHINE EXTRAS BASEDIR BUILDDIR BUILDDIR1,$(if $(filter command% environment,$(origin $(v))),'$(v)=$($(v))'))
OBJDIR  ?= $(shell MAKEFLAGS= $(MAKE) --silent --no-print-directory -C ../../.. objdir $(FD_VARS) 2>/dev/null)
RUSTC   ?= rustc
OUT     := out
C_BIN   := $(if $(filter /%,$(OBJDIR)),,$(FD_ROOT)/)$(OBJDIR)/unit-test/test_rust_float

.PHONY: test diff clean
test: $(OUT)/rust-float
	@$(MAKE) --no-print-directory -C $(FD_ROOT) test_rust_float >/dev/null
	@$(C_BIN) --dump 2>/dev/null > $(OUT)/c.txt
	@$(OUT)/rust-float --dump > $(OUT)/rust.txt
	@diff $(OUT)/c.txt $(OUT)/rust.txt > $(OUT)/diff.txt || true
	@grep '^<' $(OUT)/diff.txt | sed 's/^< //' \
	  | awk '{ if( NF==5 ) print $$1, $$2, $$3; else print $$1, $$2 }' \
	  | sort -u > $(OUT)/keys.txt
	@grep -vE '^#|^$$' known-divergences.txt | sort -u > $(OUT)/known.txt
	@comm -23 $(OUT)/keys.txt $(OUT)/known.txt > $(OUT)/new.txt
	@lines=$$(wc -l < $(OUT)/c.txt); \
	 diverged=$$(wc -l < $(OUT)/keys.txt); \
	 unknown=$$(wc -l < $(OUT)/new.txt); \
	 if [ "$$unknown" -ne 0 ]; then \
	   echo "FAIL: $$unknown case(s) differ that are not in known-divergences.txt"; \
	   while read -r k; do grep -A2 -- " $$k " $(OUT)/diff.txt | head -4; done < $(OUT)/new.txt; \
	   exit 1; \
	 fi; \
	 echo "OK: $$lines cases, $$diverged known nan divergence(s), 0 unexpected"; \
	 echo "    streams $(OUT)/c.txt $(OUT)/rust.txt, differences $(OUT)/diff.txt"

# Print the differing lines, '<' C and '>' Rust.
diff: test
	@cat $(OUT)/diff.txt

$(OUT)/rust-float: main.rs | $(OUT)
	@$(RUSTC) -O $< -o $@

$(OUT):
	@mkdir -p $(OUT)

clean:
	rm -rf $(OUT)
