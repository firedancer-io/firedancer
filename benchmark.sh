#!/bin/bash

# Firedancer Benchmark Script
# This script runs performance benchmarks and fails if any benchmark fails.

set -e  # Exit immediately if any command fails
set -u  # Exit if undefined variables are used
set -o pipefail  # Exit if any command in a pipeline fails

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_bench() {
    echo -e "${MAGENTA}[BENCHMARK]${NC} $1"
}

# Parse command line arguments
MACHINE="${MACHINE:-native}"
BUILD_BENCH="${BUILD_BENCH:-1}"
BENCH_FILTER="${BENCH_FILTER:-}"
OUTPUT_DIR="${OUTPUT_DIR:-benchmark_results}"

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Run performance benchmarks for the Firedancer project.

OPTIONS:
    -m, --machine MACHINE    Run benchmarks for specific machine (default: native)
    -b, --no-build           Skip building benchmarks (default: build)
    -f, --filter PATTERN     Run only benchmarks matching pattern
    -o, --output DIR         Directory for benchmark results (default: benchmark_results)
    -h, --help               Show this help message

EXAMPLES:
    $0                       # Run all benchmarks
    $0 --filter funk         # Run only funk-related benchmarks
    $0 --no-build            # Run benchmarks without rebuilding
    $0 --output my_results   # Save results to custom directory

ENVIRONMENT VARIABLES:
    MACHINE                  Override machine type
    BUILD_BENCH              Set to 0 to skip building
    BENCH_FILTER             Filter benchmarks by pattern
    OUTPUT_DIR               Output directory for results
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--machine)
            MACHINE="$2"
            shift 2
            ;;
        -b|--no-build)
            BUILD_BENCH=0
            shift
            ;;
        -f|--filter)
            BENCH_FILTER="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

print_info "=========================================="
print_info "Firedancer Benchmarks"
print_info "=========================================="
print_info "Machine: $MACHINE"
print_info "Build Benchmarks: $([ "$BUILD_BENCH" = "1" ] && echo "yes" || echo "no")"
print_info "Filter: ${BENCH_FILTER:-none (run all)}"
print_info "Output Directory: $OUTPUT_DIR"
print_info "=========================================="

# Check if we're in the right directory
if [ ! -f "GNUmakefile" ]; then
    print_error "GNUmakefile not found. Are you in the Firedancer root directory?"
    exit 1
fi

# Determine build directory
COMPILER="gcc"
if [ -d "build/${MACHINE}/clang" ]; then
    COMPILER="clang"
fi
BUILDDIR="build/${MACHINE}/${COMPILER}"

# Build benchmarks if requested
if [ "$BUILD_BENCH" = "1" ]; then
    print_info "Building benchmarks..."
    
    # Build unit tests which includes benchmarks
    if ! MACHINE="$MACHINE" make -j unit-test; then
        print_error "Failed to build benchmarks!"
        exit 1
    fi
    
    print_info "Benchmark build completed successfully"
fi

# Check if build directory exists
if [ ! -d "$BUILDDIR" ]; then
    print_error "Build directory not found: $BUILDDIR"
    print_error "Please run with --build or run compile.sh first"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_FILE="${OUTPUT_DIR}/benchmark_results_${TIMESTAMP}.txt"

print_info "Results will be saved to: $RESULTS_FILE"

# Find all benchmark executables
print_info "Searching for benchmark executables..."

BENCH_TESTS=()
if [ -d "${BUILDDIR}/unit-test" ]; then
    while IFS= read -r -d '' bench; do
        bench_name=$(basename "$bench")
        if [ -n "$BENCH_FILTER" ]; then
            if [[ "$bench_name" == *"$BENCH_FILTER"* ]]; then
                BENCH_TESTS+=("$bench")
            fi
        else
            BENCH_TESTS+=("$bench")
        fi
    done < <(find "${BUILDDIR}/unit-test" -type f -name 'bench_*' -executable -print0)
fi

if [ ${#BENCH_TESTS[@]} -eq 0 ]; then
    print_warning "No benchmark executables found in ${BUILDDIR}/unit-test"
    print_warning "Benchmark executables should be named 'bench_*'"
    print_info "Available test executables:"
    find "${BUILDDIR}/unit-test" -type f -executable 2>/dev/null | head -10 || true
    exit 0
fi

print_info "Found ${#BENCH_TESTS[@]} benchmark(s) to run"

# Initialize results file
{
    echo "=========================================="
    echo "Firedancer Benchmark Results"
    echo "=========================================="
    echo "Date: $(date)"
    echo "Machine: $MACHINE"
    echo "Compiler: $COMPILER"
    echo "Build Directory: $BUILDDIR"
    echo "Filter: ${BENCH_FILTER:-none}"
    echo "=========================================="
    echo ""
} > "$RESULTS_FILE"

# Track benchmark results
BENCHMARKS_RUN=0
BENCHMARKS_FAILED=0
FAILED_BENCHMARKS=()

# Run each benchmark
print_info "=========================================="
print_info "Running Benchmarks"
print_info "=========================================="

for bench_path in "${BENCH_TESTS[@]}"; do
    bench_name=$(basename "$bench_path")
    print_bench "Running: $bench_name"
    
    # Create temporary file for this benchmark's output
    BENCH_OUTPUT=$(mktemp)
    
    # Run the benchmark
    if "$bench_path" > "$BENCH_OUTPUT" 2>&1; then
        print_info "✓ $bench_name completed successfully"
        BENCHMARKS_RUN=$((BENCHMARKS_RUN + 1))
        
        # Append results to main results file
        {
            echo "=========================================="
            echo "Benchmark: $bench_name"
            echo "Status: SUCCESS"
            echo "=========================================="
            cat "$BENCH_OUTPUT"
            echo ""
        } >> "$RESULTS_FILE"
    else
        EXIT_STATUS=$?
        print_error "✗ $bench_name FAILED (exit code: $EXIT_STATUS)"
        BENCHMARKS_FAILED=$((BENCHMARKS_FAILED + 1))
        FAILED_BENCHMARKS+=("$bench_name")
        
        # Append failure to results file
        {
            echo "=========================================="
            echo "Benchmark: $bench_name"
            echo "Status: FAILED (exit code: $EXIT_STATUS)"
            echo "=========================================="
            cat "$BENCH_OUTPUT"
            echo ""
        } >> "$RESULTS_FILE"
    fi
    
    # Clean up temp file
    rm -f "$BENCH_OUTPUT"
done

# Print summary
print_info "=========================================="
print_info "Benchmark Summary"
print_info "=========================================="
print_info "Benchmarks Run: $BENCHMARKS_RUN"
print_info "Benchmarks Failed: $BENCHMARKS_FAILED"
print_info "Results saved to: $RESULTS_FILE"

# Append summary to results file
{
    echo "=========================================="
    echo "Summary"
    echo "=========================================="
    echo "Total Benchmarks: $BENCHMARKS_RUN"
    echo "Failed: $BENCHMARKS_FAILED"
    if [ $BENCHMARKS_FAILED -gt 0 ]; then
        echo "Failed Benchmarks:"
        for failed in "${FAILED_BENCHMARKS[@]}"; do
            echo "  - $failed"
        done
    fi
    echo "=========================================="
} >> "$RESULTS_FILE"

if [ $BENCHMARKS_FAILED -gt 0 ]; then
    print_error "Failed benchmarks: ${FAILED_BENCHMARKS[*]}"
    print_error "=========================================="
    print_error "BENCHMARKS FAILED!"
    print_error "=========================================="
    exit 1
else
    print_info "=========================================="
    print_info "ALL BENCHMARKS PASSED!"
    print_info "=========================================="
    exit 0
fi
