#!/bin/bash

# Firedancer Compilation Script
# This script compiles the Firedancer project and fails if compilation fails.

set -e  # Exit immediately if any command fails
set -u  # Exit if undefined variables are used
set -o pipefail  # Exit if any command in a pipeline fails

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Parse command line arguments
MACHINE="${MACHINE:-native}"
EXTRAS="${EXTRAS:-}"
JOBS="${JOBS:-}"
CLEAN="${CLEAN:-0}"

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Compile the Firedancer project.

OPTIONS:
    -m, --machine MACHINE    Build for specific machine (default: native)
    -e, --extras EXTRAS      Enable build extras (e.g., "debug", "llvm-cov")
    -j, --jobs JOBS          Number of parallel jobs (default: auto)
    -c, --clean              Clean before building
    -h, --help               Show this help message

EXAMPLES:
    $0                       # Build with default settings
    $0 --clean               # Clean and build
    $0 --machine native --extras debug
    $0 --jobs 8              # Build with 8 parallel jobs

ENVIRONMENT VARIABLES:
    MACHINE                  Override machine type
    EXTRAS                   Override build extras
    JOBS                     Override number of jobs
    CLEAN                    Set to 1 to clean before build
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--machine)
            MACHINE="$2"
            shift 2
            ;;
        -e|--extras)
            EXTRAS="$2"
            shift 2
            ;;
        -j|--jobs)
            JOBS="$2"
            shift 2
            ;;
        -c|--clean)
            CLEAN=1
            shift
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

# Determine number of jobs
if [ -z "$JOBS" ]; then
    JOBS_FLAG="-j"
else
    JOBS_FLAG="-j${JOBS}"
fi

print_info "=========================================="
print_info "Firedancer Compilation"
print_info "=========================================="
print_info "Machine: $MACHINE"
print_info "Extras: ${EXTRAS:-none}"
print_info "Jobs: ${JOBS:-auto}"
print_info "Clean: $([ "$CLEAN" = "1" ] && echo "yes" || echo "no")"
print_info "=========================================="

# Check if we're in the right directory
if [ ! -f "GNUmakefile" ]; then
    print_error "GNUmakefile not found. Are you in the Firedancer root directory?"
    exit 1
fi

# Clean if requested
if [ "$CLEAN" = "1" ]; then
    print_info "Cleaning previous build..."
    if ! MACHINE="$MACHINE" make clean; then
        print_error "Clean failed!"
        exit 1
    fi
    print_info "Clean completed successfully"
fi

# Build the project
print_info "Starting compilation..."
print_info "Command: MACHINE=$MACHINE EXTRAS=\"$EXTRAS\" make $JOBS_FLAG"

if [ -z "$EXTRAS" ]; then
    if ! MACHINE="$MACHINE" make "$JOBS_FLAG"; then
        print_error "Compilation failed!"
        exit 1
    fi
else
    if ! MACHINE="$MACHINE" EXTRAS="$EXTRAS" make "$JOBS_FLAG"; then
        print_error "Compilation failed!"
        exit 1
    fi
fi

print_info "=========================================="
print_info "Compilation completed successfully!"
print_info "=========================================="

# Show build artifacts location
BUILDDIR="build/${MACHINE}"
if [ -d "$BUILDDIR" ]; then
    print_info "Build artifacts are located in: $BUILDDIR"
    
    # Show what was built
    if [ -d "$BUILDDIR/gcc/bin" ] || [ -d "$BUILDDIR/clang/bin" ]; then
        print_info "Built binaries:"
        find "$BUILDDIR" -type d -name "bin" -exec ls -la {} \; 2>/dev/null || true
    fi
fi

exit 0
