#!/bin/bash

# Firedancer Testing Script
# This script runs all tests and fails if any test fails.

set -e  # Exit immediately if any command fails
set -u  # Exit if undefined variables are used
set -o pipefail  # Exit if any command in a pipeline fails

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

print_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

# Parse command line arguments
MACHINE="${MACHINE:-native}"
TEST_TYPE="${TEST_TYPE:-all}"
BUILD_TESTS="${BUILD_TESTS:-1}"
TEST_OPTS="${TEST_OPTS:-}"

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Run tests for the Firedancer project.

OPTIONS:
    -m, --machine MACHINE    Test for specific machine (default: native)
    -t, --type TYPE          Type of tests to run: all, unit, integration, 
                             script, vectors, solcap, fuzz (default: all)
    -b, --no-build           Skip building tests (default: build tests)
    -o, --test-opts OPTS     Additional options to pass to test runner
    -h, --help               Show this help message

EXAMPLES:
    $0                       # Run all tests
    $0 --type unit           # Run only unit tests
    $0 --no-build            # Run tests without rebuilding
    $0 --test-opts "--verbose"

ENVIRONMENT VARIABLES:
    MACHINE                  Override machine type
    TEST_TYPE                Override test type
    BUILD_TESTS              Set to 0 to skip building
    TEST_OPTS                Additional test options
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--machine)
            MACHINE="$2"
            shift 2
            ;;
        -t|--type)
            TEST_TYPE="$2"
            shift 2
            ;;
        -b|--no-build)
            BUILD_TESTS=0
            shift
            ;;
        -o|--test-opts)
            TEST_OPTS="$2"
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

# Validate test type
case $TEST_TYPE in
    all|unit|integration|script|vectors|solcap|fuzz)
        ;;
    *)
        print_error "Invalid test type: $TEST_TYPE"
        print_error "Valid types: all, unit, integration, script, vectors, solcap, fuzz"
        exit 1
        ;;
esac

print_info "=========================================="
print_info "Firedancer Testing"
print_info "=========================================="
print_info "Machine: $MACHINE"
print_info "Test Type: $TEST_TYPE"
print_info "Build Tests: $([ "$BUILD_TESTS" = "1" ] && echo "yes" || echo "no")"
print_info "Test Options: ${TEST_OPTS:-none}"
print_info "=========================================="

# Check if we're in the right directory
if [ ! -f "GNUmakefile" ]; then
    print_error "GNUmakefile not found. Are you in the Firedancer root directory?"
    exit 1
fi

# Track test results
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()

# Function to run a test
run_test() {
    local test_name=$1
    local test_command=$2
    
    print_test "Running $test_name tests..."
    
    if eval "$test_command"; then
        print_info "✓ $test_name tests PASSED"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        print_error "✗ $test_name tests FAILED"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        FAILED_TESTS+=("$test_name")
        return 1
    fi
}

# Build tests if requested
if [ "$BUILD_TESTS" = "1" ]; then
    print_info "Building tests..."
    
    case $TEST_TYPE in
        all)
            print_info "Building unit tests..."
            if ! MACHINE="$MACHINE" make -j unit-test; then
                print_error "Failed to build unit tests!"
                exit 1
            fi
            
            print_info "Building integration tests..."
            if ! MACHINE="$MACHINE" make -j integration-test; then
                print_error "Failed to build integration tests!"
                exit 1
            fi
            
            if MACHINE="$MACHINE" make -j fuzz-test 2>/dev/null; then
                print_info "Fuzz tests built successfully"
            else
                print_warning "Fuzz tests not built (may require special configuration)"
            fi
            ;;
        unit)
            if ! MACHINE="$MACHINE" make -j unit-test; then
                print_error "Failed to build unit tests!"
                exit 1
            fi
            ;;
        integration)
            if ! MACHINE="$MACHINE" make -j integration-test; then
                print_error "Failed to build integration tests!"
                exit 1
            fi
            ;;
        fuzz)
            if ! MACHINE="$MACHINE" make -j fuzz-test; then
                print_error "Failed to build fuzz tests!"
                exit 1
            fi
            ;;
        *)
            print_info "No build required for $TEST_TYPE tests"
            ;;
    esac
    
    print_info "Test build completed successfully"
fi

# Run tests
print_info "=========================================="
print_info "Running Tests"
print_info "=========================================="

EXIT_CODE=0

case $TEST_TYPE in
    all)
        # Run unit tests
        run_test "unit" "MACHINE=$MACHINE TEST_OPTS=\"$TEST_OPTS\" make run-unit-test" || EXIT_CODE=1
        
        # Run integration tests
        run_test "integration" "MACHINE=$MACHINE TEST_OPTS=\"$TEST_OPTS\" make run-integration-test" || EXIT_CODE=1
        
        # Run script tests
        run_test "script" "MACHINE=$MACHINE make run-script-test" || EXIT_CODE=1
        
        # Run test vectors
        run_test "test-vectors" "MACHINE=$MACHINE make run-test-vectors" || EXIT_CODE=1
        
        # Run solcap tests
        run_test "solcap" "MACHINE=$MACHINE make run-solcap-tests" || EXIT_CODE=1
        ;;
    
    unit)
        run_test "unit" "MACHINE=$MACHINE TEST_OPTS=\"$TEST_OPTS\" make run-unit-test" || EXIT_CODE=1
        ;;
    
    integration)
        run_test "integration" "MACHINE=$MACHINE TEST_OPTS=\"$TEST_OPTS\" make run-integration-test" || EXIT_CODE=1
        ;;
    
    script)
        run_test "script" "MACHINE=$MACHINE make run-script-test" || EXIT_CODE=1
        ;;
    
    vectors)
        run_test "test-vectors" "MACHINE=$MACHINE make run-test-vectors" || EXIT_CODE=1
        ;;
    
    solcap)
        run_test "solcap" "MACHINE=$MACHINE make run-solcap-tests" || EXIT_CODE=1
        ;;
    
    fuzz)
        run_test "fuzz" "MACHINE=$MACHINE make run-fuzz-test" || EXIT_CODE=1
        ;;
esac

# Print summary
print_info "=========================================="
print_info "Test Summary"
print_info "=========================================="
print_info "Tests Passed: $TESTS_PASSED"
print_info "Tests Failed: $TESTS_FAILED"

if [ $TESTS_FAILED -gt 0 ]; then
    print_error "Failed test suites: ${FAILED_TESTS[*]}"
    print_error "=========================================="
    print_error "TESTS FAILED!"
    print_error "=========================================="
    exit $EXIT_CODE
else
    print_info "=========================================="
    print_info "ALL TESTS PASSED!"
    print_info "=========================================="
    exit 0
fi
