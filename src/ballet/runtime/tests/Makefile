all:
	python3.8 gen_c_tests.py -j system_program_tests.json > test_native_programs.c
	uncrustify  -c ../../../../lint.cfg --no-backup --replace test_native_programs.c

cleanup:
	uncrustify  -c ../../../../lint.cfg --no-backup --replace fd_tests.c
	uncrustify  -c ../../../../lint.cfg --no-backup --replace test_native_programs.c
	uncrustify  -c ../../../../lint.cfg --no-backup --replace fd_tests.h


