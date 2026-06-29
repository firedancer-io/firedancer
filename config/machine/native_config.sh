#!/bin/bash
# Detect native compiler features.
# Writes a Make include fragment to the given output path.
#
# Usage: native_config.sh <OUT> <CC> [CC args...]

set -eu

if [ "$#" -lt 2 ]; then
  echo "Usage: native_config.sh <OUT> <CC> [CC args...]" >&2
  exit 1
fi

OUT="$1"
shift
mkdir -p "$(dirname "$OUT")"

printf '\n' | "$@" -march=native -E -dM - | awk '
  $1=="#define" { define[$2]=$3 }

  function emit_feature(var, macro) {
    if( macro in define ) {
      print var ":=1"
      cppflags = cppflags "CPPFLAGS_NATIVE+=-D" var "=1\n"
    }
  }

  END {
    if( "__clang__" in define ) print "FD_USING_CLANG:=1"
    if( "__GNUC__"  in define ) print "FD_IS_GNU:=1"

    if( "__clang__" in define ) {
      print "FD_COMPILER_MAJOR_VERSION:=" define["__clang_major__"]
      print "CC_MAJOR_VERSION:=" define["__clang_major__"]
    } else if( "__GNUC__" in define ) {
      print "FD_COMPILER_MAJOR_VERSION:=" define["__GNUC__"]
      print "CC_MAJOR_VERSION:=" define["__GNUC__"]
    }

    emit_feature( "FD_HAS_SHANI",   "__SHA__" )
    emit_feature( "FD_HAS_INT128",  "__SIZEOF_INT128__" )
    emit_feature( "FD_HAS_ALLOCA",  "__linux__" )
    emit_feature( "FD_HAS_THREADS", "__linux__" )
    emit_feature( "FD_HAS_X86",     "__x86_64__" )
    emit_feature( "FD_HAS_SSE",     "__SSE4_2__" )
    emit_feature( "FD_HAS_AVX",     "__AVX2__" )
    emit_feature( "FD_HAS_GFNI",    "__GFNI__" )
    emit_feature( "FD_IS_X86_64",   "__x86_64__" )
    emit_feature( "FD_HAS_AESNI",   "__AES__" )

    # Older versions of GCC (<10) do not fully support AVX512.
    if( !( "__GNUC__" in define && !( "__clang__" in define ) && define["__GNUC__"]<10 ) )
      emit_feature( "FD_HAS_AVX512", "__AVX512IFMA__" )

    print "FD_HAS_DOUBLE:=1"
    print ""
    print "CPPFLAGS_NATIVE:="
    print "CPPFLAGS_NATIVE+=-march=native -mtune=native"
    print "CPPFLAGS_NATIVE+=-DFD_HAS_DOUBLE=1"
    printf "%s", cppflags
  }
' > "$OUT"
