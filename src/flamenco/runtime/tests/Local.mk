$(call add-hdrs,fd_exec_test.pb.h)
$(call add-objs,fd_exec_test.pb,fd_flamenco)

ifdef FD_HAS_INT128
$(call add-hdrs,fd_exec_instr_test.h)
$(call add-objs,fd_exec_instr_test,fd_flamenco)

$(call make-unit-test,test_exec_instr,test_exec_instr,fd_flamenco fd_funk fd_ballet fd_util,$(SECP256K1_LIBS))
$(call make-shared,libfd_exec_sol_compat.so,fd_exec_sol_compat,fd_flamenco fd_funk fd_ballet fd_util,$(SECP256K1_LIBS))
endif

run-runtime-test: run-runtime-test-1 run-runtime-test-2 run-runtime-test-3

run-runtime-test-1: $(OBJDIR)/bin/fd_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -t 2 -X 1
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l helloworld -s snapshot-100-92rXQxDb3gbNU4YEjof4PjAQ9wDvqAXL4Ma3757kHPRs.tar.zst -e 199
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l v118-multi
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l testnet-519 -s snapshot-255311992-Fju7xb3XaTY6SBxkGcsKko15EGAqnvdfkXBd1o6agPDq.tar.zst -p 32 -y 32 -m 1000000 -e 255312007
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-251418170 -s snapshot-251418170-8sAkojR9PYTZvqiQZ1VWu27ewX5tXeVdC97wMXAtgHnT.tar.zst -p 32 -y 32 -m 2000000 -e 251418233
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257066033 -s snapshot-257066033-AD2nFFTCtZVmo5nXLVsQMV1hiQDjzoEBXibRicBJc5Vw.tar.zst -p 16 -y 16 -m 5000000 -e 257066038 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257066844 -s snapshot-257066844-B5JpRYzvMa4iyQeR8w9co4y7oEayphgbXVeQHXLDoWvV.tar.zst -p 16 -y 16 -m 5000000 -e 257066849 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257067457 -s snapshot-257067457-DxbpHefwdjLkPecZG2jLuqyQp8me9dFZQMQ8hZMyfhsw.tar.zst -p 16 -y 16 -m 5000000 -e 257067461 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257068890 -s snapshot-257068890-uRVtagPzKhYorycp4CRtKdWrYPij6iBxCYYXmqRvdSp.tar.zst -p 16 -y 16 -m 5000000 -e 257068895 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257181622 -s snapshot-257181622-Fy996aeLW7kZ6AbBcPd3Vst77pkHDSAXpaexGiVHbB4S.tar.zst -p 16 -y 16 -m 5000000 -e 257181624 --zst

#	src/flamenco/runtime/run_bpf_tests.sh

run-runtime-test-2: $(OBJDIR)/bin/fd_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-254462437 -s snapshot-254462620-BEn8r5dNrKtaKo92pCXx2ZGrHm6cv6UrQ3ePmByEjj34.tar.zst -p 32 -y 32 -m 20000000 -e 254462622 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-254462437 -s snapshot-254462437-9HqBi19BJJRZfHeBS3ZpkeP9B5SAxBxz6Kwug29yLHac.tar.zst -p 32 -y 32 -m 20000000 -e 254463436 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-586 -s snapshot-253151900-HVhfam8TtRFVwFto5fWkhgR4mbBJmUxcnxeKZoW5MrSD.tar.zst -p 32 -y 32 -m 5000000 -e 253152100

run-runtime-test-3: $(OBJDIR)/bin/fd_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-262654839 --snapshot-no-verify snapshot-262654838-B6GkEWuehxZTZ77Ht9vWUzdX87BiWP5ohi84LMicYTBZ.tar.zst -p 32 -y 32 -m 20000000 -e 262654840 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257039990 -s snapshot-257039990-BSgErEc6ppN4p91meqPvUiXPiEhbakBNHMQQ4wKmceYv.tar.zst -p 32 -y 32 -m 20000000 -e 257040003 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257037451 -s snapshot-257037451-36ERh35nFMRFB8sLHLTUnAd41TuzKYSTyxsa2bgBoMEj.tar.zst -p 16 -y 16 -m 5000000 -e 257037454 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257035225 -s snapshot-257035225-EgwCNhhmffR38XWBXVp3GFs6fmtHKgzw5vEcD9e2oz14.tar.zst -p 16 -y 16 -m 5000000 -e 257035233 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257465453 -s snapshot-257465452-3QExADnJwC756Law388ELX6xhtjnBGwToKVoQUFDcQfn.tar.zst -p 32 -y 32 -m 80000000 -e 257465454 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257058865 -s snapshot-257058865-6SFEm7u5pLAhkm4vfiHiN3vMNkmZuyL2ACuaHznU52fi.tar.zst -p 16 -y 16 -m 5000000 -e 257058870 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257059815 -s snapshot-257059815-AmWkVebTmg6ih2VTEjMmU9WtXhT3RygEoSJBHfDpyAG3.tar.zst -p 16 -y 16 -m 5000000 -e 257059818 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257061172 -s snapshot-257061172-8e6cUSMUx2VZZBDzwXjEY6bGkzPgnUmqrDyr4uErG8BF.tar.zst -p 16 -y 16 -m 5000000 -e 257061175 --zst
#	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l v20-ledger

run-runtime-test-nightly: $(OBJDIR)/bin/fd_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257033306 -s snapshot-257033306-EE3WdRoE4J1LTjegJMK3ZzxKZbSMQhLMaTM5Jp4SygMU.tar.zst -p 50 -P 40 -y 350 -m 500000000 -M 20000000 -e 257213306 --zst -cp /data/nightly_checkpt -cf 10000 -pf 1
