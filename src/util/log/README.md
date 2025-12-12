# Log utilities

## Building and running `test_log`

`test_log` is not produced by default. Build it explicitly from the repo root:

```sh
make -j test_log
# or
make -j build/native/gcc/unit-test/test_log
```

The binary is written to `build/native/gcc/unit-test/test_log`. Run it from the
same directory:

```sh
./build/native/gcc/unit-test/test_log
```

To force the backtrace/abort path that prints source file and line numbers, pass the
flag or environment variable:

```sh
./build/native/gcc/unit-test/test_log --force-backtrace
# or
FD_TEST_BACKTRACE=1 ./build/native/gcc/unit-test/test_log
```

If the `build/` tree does not exist yet, the build command above will create it and
produce the binary under `build/native/gcc/unit-test/`.
