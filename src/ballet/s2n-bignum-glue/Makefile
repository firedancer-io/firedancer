# This is a meta-Makefile that generates glue.mk
# See README.md

.PHONY: glue
glue:
	rm -vf glue.mk
	$(MAKE) -C ../s2n-bignum/x86 --eval="print-obj:"$$'\n'$$'\t'"echo S2N_X86_OBJ=\$$(OBJ) >> ../../s2n-bignum-glue/glue.mk" print-obj
	$(MAKE) -C ../s2n-bignum/arm --eval="print-obj:"$$'\n'$$'\t'"echo S2N_ARM_OBJ=\$$(OBJ) >> ../../s2n-bignum-glue/glue.mk" print-obj
