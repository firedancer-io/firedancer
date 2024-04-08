CC:=clang
CXX:=clang++
LD:=clang++

# Sigh ... strict clang builds will not let you even let you get the
# address of a packed structure element and this is pretty elementary
# operation in real world packet parsing.  Importantly, this prevents
# the workaround used in for strict gcc builds done by
# FD_ADDRESS_OF_PACKED_MEMBER from working.  So instead we disable this
# check here.  This technically makes clang builds less safe than gcc
# builds, at least for code that we want to be robust _and_ interact
# with things in the outside world.  That is we want the compiler to
# tell us when there is a potentially unaligned access so we can take
# appropriate measures for the compiler / build target / etc.  But clang
# won't do that for us, seems to be in denial that networks with packets
# are in a thing in the real world and that code that needs to interact
# with such might actually want to be robust.  (Unfortunately, this is
# not the only area where clang is less mature than gcc in important
# ways.)
#
# FIXME: We also disable strict clang builds failing due to unused
# command line arguments.  This only occurs when trying to assembling .s
# files (clang sees all the C/C++ defaults and warns).  This could be
# fixed by tweaking everything.mk and what not to not pass through C/C++
# related arguments to clang when applied to .s targets.  But this is a
# fair amount of build system surgery that arguably makes things mildly
# less robust (e.g. safer to keep arguments to all build targets
# consistent and let the compiler filter out the ones that don't apply
# than try to make bespoke arguments for each and keep fingers crossed
# there wasn't some subtle inconsistency created between them in the
# process).

CPPFLAGS+=-DFD_USING_CLANG=1 -Wno-address-of-packed-member -Wno-unused-command-line-argument -Wno-bitwise-instead-of-logical

# Sigh ... clang doesn't understand some important command line
# arguments (a couple of the more esoteric warnings in the brutality,
# some of the optimizer arguments for getting high performance / low
# jitter results from x86 targets).  So we define this here to allow
# other make fragments to take evasive action as necessary (the value
# itself doesn't matter ... only that the variable is defined).

FD_USING_CLANG:=1

# Don't attempt to transform vsprtps into vrsqrtps (not IEEE-compliant)

CPPFLAGS+=-Xclang -target-feature -Xclang +fast-vector-fsqrt
