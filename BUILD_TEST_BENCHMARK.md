# Firedancer Build, Test, and Benchmark Guide

This guide covers how to compile, run tests, and perform benchmarks on the Firedancer validator project.

## Table of Contents
- [Quick Start Scripts](#quick-start-scripts)
- [Prerequisites](#prerequisites)
- [Compilation](#compilation)
- [Running Tests](#running-tests)
- [Performance Benchmarks](#performance-benchmarks)
- [Code Coverage](#code-coverage)
- [Advanced Build Options](#advanced-build-options)

---

## Quick Start Scripts

For convenience, three shell scripts are provided that handle compilation, testing, and benchmarking with proper error handling:

### compile.sh

Compiles the Firedancer project with configurable options:

```bash
# Basic compilation
./compile.sh

# Clean and rebuild
./compile.sh --clean

# Build with debug symbols
./compile.sh --extras debug

# Build with specific number of jobs
./compile.sh --jobs 8

# Show all options
./compile.sh --help
```

**Environment Variables:**
- `MACHINE`: Build machine type (default: native)
- `EXTRAS`: Build extras like "debug" or "llvm-cov"
- `JOBS`: Number of parallel jobs
- `CLEAN`: Set to 1 to clean before build

### tests.sh

Runs all or specific test suites:

```bash
# Run all tests
./tests.sh

# Run only unit tests
./tests.sh --type unit

# Run without rebuilding
./tests.sh --no-build

# Run with verbose output
./tests.sh --test-opts "--verbose"

# Show all options
./tests.sh --help
```

**Test Types:**
- `all`: Run all test suites (default)
- `unit`: Unit tests only
- `integration`: Integration tests only
- `script`: Script tests only
- `vectors`: Test vectors only
- `solcap`: Solcap tests only
- `fuzz`: Fuzz tests only

### benchmark.sh

Runs performance benchmarks:

```bash
# Run all benchmarks
./benchmark.sh

# Run specific benchmarks
./benchmark.sh --filter funk

# Run without rebuilding
./benchmark.sh --no-build

# Specify output directory
./benchmark.sh --output my_results

# Show all options
./benchmark.sh --help
```

**Features:**
- Automatically finds all `bench_*` executables
- Saves timestamped results to output directory
- Reports success/failure for each benchmark

**Important:** All three scripts use strict error handling (`set -e`, `set -u`, `set -o pipefail`) and will exit with a non-zero status code if any command fails. This makes them suitable for CI/CD pipelines.

---

## Prerequisites

Firedancer requires:
- **Operating System**: Linux (kernel v4.18 or later)
- **Build Tools**: GNU Make, GCC or Clang
- **Dependencies**: Installed via `deps.sh` script

### Installing Dependencies

```bash
# Clone the repository with submodules
git clone --recurse-submodules https://github.com/firedancer-io/firedancer.git
cd firedancer

# Install development dependencies
./deps.sh +dev
```

---

## Compilation

### Basic Compilation

The simplest way to build the project:

```bash
# Build all targets for native machine
make -j
```

This is equivalent to:
```bash
make -j all
```

The `all` target builds:
- All binaries (`bin`)
- All include files (`include`)
- All libraries (`lib`)
- All unit tests (`unit-test`)
- All fuzz tests (`fuzz-test`)

### Building Specific Targets

```bash
# Build only binaries
make -j bin

# Build only libraries
make -j lib

# Build only unit tests
make -j unit-test

# Build only integration tests
make -j integration-test

# Build info file
make -j info
```

### Machine-Specific Builds

You can build for different machine configurations using the `MACHINE` environment variable:

```bash
# Default (native machine)
MACHINE=native make -j

# Custom machine configuration
MACHINE=my_machine make -j
```

Machine configurations are defined in `config/machine/<machine>.mk`.

### Build with Debug/Extra Features

Enable optional build features using the `EXTRAS` environment variable:

```bash
# Build with debug symbols
make -j EXTRAS="debug"

# Build with LLVM coverage instrumentation
make -j EXTRAS="llvm-cov"

# Multiple extras
make -j EXTRAS="debug sanitize"
```

Extra configurations are in `config/extra/with-*.mk` files.

### Build Artifacts Location

Build artifacts are placed in machine-specific directories:
```
build/
└── <machine>/
    └── <compiler>/
        ├── bin/          # Executables
        ├── lib/          # Libraries
        ├── include/      # Header files
        ├── unit-test/    # Unit test executables
        └── obj/          # Object files
```

For example: `build/native/gcc/bin/`

---

## Running Tests

### Unit Tests

Unit tests verify individual components and functions.

```bash
# Compile unit tests
make -j unit-test

# Run all unit tests
make run-unit-test
```

Run unit tests with additional options:
```bash
# Run with custom test options
make run-unit-test TEST_OPTS="--verbose"
```

The test runner script is located at: `contrib/test/run_unit_tests.sh`

### Integration Tests

Integration tests verify the interaction between components.

```bash
# Compile integration tests
make -j integration-test

# Run all integration tests
make run-integration-test
```

### Script Tests

Script-based tests for various components:

```bash
make run-script-test
```

### Test Vectors

Run test vectors for validation:

```bash
make run-test-vectors
```

### Solcap Tests

Run Solana capture tests:

```bash
make run-solcap-tests
```

### Fuzz Tests

Fuzzing tests require a special build profile:

```bash
# Build fuzz tests
make -j fuzz-test

# Run all fuzz tests over existing corpora
make run-fuzz-test

# Run specific fuzz test in explore mode (600 seconds)
make fuzz_TARGET_run

# Re-run specific fuzz test over existing corpus
make fuzz_TARGET_unit
```

### Quick Compile Check

Check for obvious compile errors without full build:

```bash
make check
```

---

## Performance Benchmarks

### Individual Benchmark Tests

Firedancer includes several benchmark tests that can be compiled and run:

```bash
# Benchmark tests are compiled as unit tests
make -j unit-test

# Example benchmarks included:
# - bench_funk_index    (Funk index performance)
# - bench_frag_tx       (Fragment transmission performance)
```

To find all benchmark executables:
```bash
find build/*/*/unit-test -name 'bench_*'
```

Run a specific benchmark:
```bash
./build/native/gcc/unit-test/bench_funk_index
./build/native/gcc/unit-test/bench_frag_tx
```

### Integrated Benchmark System

The development tools (`fddev`, `fdctl`, `firedancer-dev`) have built-in benchmark commands:

```bash
# Build the development tools
make -j bin

# Run benchmark mode (after proper configuration)
# The bench command uses special benchmark tiles:
# - bencho: Orchestrates benchmarks
# - benchg: Generates transactions
# - benchs: Sends transactions
```

Benchmark configuration is in the `[development.bench]` section of the config file:
- `benchg_tile_count`: Number of transaction generator tiles
- `benchs_tile_count`: Number of transaction sender tiles
- `affinity`: CPU affinity for benchmark tiles
- Other benchmark-specific settings

### Running Development Environment with Benchmarks

```bash
# Quick development run (includes benchmarking capabilities)
make -j run
```

This executes `fddev dev` which sets up a local development cluster.

---

## Code Coverage

Generate code coverage reports to see which lines of code are tested:

### Single Build Coverage

```bash
# 1. Build with coverage instrumentation
make -j EXTRAS="llvm-cov"

# 2. Run tests (this generates coverage data)
make run-unit-test

# 3. Generate HTML coverage report
make cov-report

# 4. View the report
# Open build/<machine>/<compiler>/cov/html/index.html in a browser
```

### Multi-Build Coverage

Merge coverage data from multiple build profiles:

```bash
# Build and test multiple configurations
MACHINE=native EXTRAS="llvm-cov" make -j run-unit-test
MACHINE=x86_64 EXTRAS="llvm-cov" make -j run-unit-test

# Merge coverage reports
make dist-cov-report OBJDIRS="build/native/gcc build/x86_64/gcc"

# View merged report at build/cov/html/index.html
```

Coverage data locations:
- Raw profile data: `$(OBJDIR)/cov/raw/*.profraw`
- Indexed profile: `$(OBJDIR)/cov/cov.profdata`
- LCOV tracefile: `$(OBJDIR)/cov/cov.lcov`
- HTML report: `$(OBJDIR)/cov/html/index.html`

---

## Advanced Build Options

### Show Build Configuration

```bash
# Display current build configuration
make help
```

This shows:
- Machine configuration
- Compiler settings
- Build flags
- Available targets

### Show Dependencies

```bash
# List all dependency files
make show-deps
```

### Generate Assembly

```bash
# Generate assembly files for all sources
make asm
```

Assembly files are generated at: `$(OBJDIR)/obj/**/*.S`

### Generate Preprocessed Files

```bash
# Run preprocessor on all sources
make ppp
```

Preprocessed files are generated at: `$(OBJDIR)/obj/**/*.i`

### Clean Build Artifacts

```bash
# Clean current machine build
make clean

# Clean all builds (all machines)
make distclean
```

### Parallel Builds

Make will automatically use available CPU cores:

```bash
# Use all cores
make -j

# Use specific number of jobs
make -j8
```

**Note**: On systems with CPU isolation (e.g., `isolcpus` kernel parameter), make may only use non-isolated CPUs. See `contrib/make-j` script for building efficiently on isolated systems.

### Build Info

View build information:
```bash
make info
```

This creates a build info file at: `$(OBJDIR)/info`

---

## Common Workflows

### Quick Development Workflow (Using Scripts)

```bash
# 1. Setup
git clone --recurse-submodules https://github.com/firedancer-io/firedancer.git
cd firedancer
./deps.sh +dev

# 2. Compile, test, and benchmark
./compile.sh
./tests.sh
./benchmark.sh
```

### Development Workflow (Using Make)

```bash
# 1. Setup
git clone --recurse-submodules https://github.com/firedancer-io/firedancer.git
cd firedancer
./deps.sh +dev

# 2. Build and test
make -j
make run-unit-test

# 3. Run development validator
make -j run
```

### Testing Workflow

```bash
# Build with debug and run all tests
make -j EXTRAS="debug"
make run-unit-test
make run-integration-test
make run-script-test
```

### Coverage Workflow

```bash
# Build with coverage, test, and generate report
make -j EXTRAS="llvm-cov"
make run-unit-test
make cov-report

# View coverage in browser
xdg-open build/native/gcc/cov/html/index.html
```

### Performance Testing Workflow

```bash
# Build optimized binaries
make -j

# Run specific benchmarks
./build/native/gcc/unit-test/bench_funk_index
./build/native/gcc/unit-test/bench_frag_tx
```

---

## Troubleshooting

### Build Fails

```bash
# Clean and rebuild
make clean
make -j
```

### Tests Fail

Check test output logs at:
- `$(OBJDIR)/log/` directory

### Insufficient CPU Cores

If building on a system with CPU isolation:
```bash
# Use the make-j helper script
contrib/make-j
```

### Permission Issues

Some development commands require privileged access:
```bash
# Run with sudo if needed
sudo make run
```

Or configure your system to allow the required operations without sudo.

---

## Additional Resources

- [Main Documentation](https://docs.firedancer.io/)
- [Contributing Guide](CONTRIBUTING.md)
- [Code Organization](doc/organization.txt)
- Machine configurations: `config/machine/`
- Build extras: `config/extra/`
- Test scripts: `contrib/test/`

---

## Quick Reference

### Shell Scripts

| Script | Description |
|--------|-------------|
| `./compile.sh` | Compile the project |
| `./compile.sh --clean` | Clean and compile |
| `./compile.sh --extras debug` | Compile with debug symbols |
| `./tests.sh` | Run all tests |
| `./tests.sh --type unit` | Run unit tests only |
| `./tests.sh --no-build` | Run tests without rebuilding |
| `./benchmark.sh` | Run all benchmarks |
| `./benchmark.sh --filter <pattern>` | Run filtered benchmarks |
| `./benchmark.sh --no-build` | Run benchmarks without rebuilding |

### Make Commands

| Command | Description |
|---------|-------------|
| `make -j` | Build all targets |
| `make -j bin` | Build binaries only |
| `make -j unit-test` | Compile unit tests |
| `make run-unit-test` | Run unit tests |
| `make run-integration-test` | Run integration tests |
| `make check` | Quick compile check |
| `make clean` | Clean current build |
| `make distclean` | Clean all builds |
| `make help` | Show configuration |
| `make cov-report` | Generate coverage report |
| `make -j run` | Run development validator |
| `MACHINE=<machine> make -j` | Build for specific machine |
| `EXTRAS="debug" make -j` | Build with debug symbols |
| `EXTRAS="llvm-cov" make -j` | Build with coverage |
