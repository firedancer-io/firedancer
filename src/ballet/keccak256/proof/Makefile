# Build artifacts needed by the HOL Light proof of keccak1eo.
#
# Targets:
#   keccak1eo_proofobj.o   ELF object containing the proof-only macro body.
#                          The .S includes ../proof/fd_keccak256_keccak1eo_proof.inc
#                          (BMI1-free variant of the production .inc).
#
# All paths are relative to the firedancer repo root, so run as:
#   make -C src/ballet/keccak256/proof
#
# After (re)building the .o, regenerate the byte-literal .ml from a HOL Light
# session via mcp__hol-light__eval:
#   save_literal_from_elf
#       "src/ballet/keccak256/proof/keccak1eo_mc.ml"
#       "src/ballet/keccak256/proof/keccak1eo_proofobj.o";;
# (then prepend  `let keccak1eo_mc = define_assert_from_elf "keccak1eo_mc"` etc.)

ROOT := $(abspath $(CURDIR)/../../../..)
INC := fd_keccak256_keccak1eo_proof.inc

keccak1eo_proofobj.o: keccak1eo_proofobj.S $(INC)
	cd $(ROOT) && gcc -c -o src/ballet/keccak256/proof/$@ src/ballet/keccak256/proof/$<

# Re-derive the proof-only inc from the production inc.  Keep in sync if the
# generator changes.  ANDN -> NOT/AND/MOV expansion (rax is the only dst).
$(INC): ../fd_keccak256_keccak1eo.inc gen_proof_inc.sh
	./gen_proof_inc.sh ../fd_keccak256_keccak1eo.inc > $@

clean:
	rm -f keccak1eo_proofobj.o
