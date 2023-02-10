SHELL:=/bin/bash
CPPFLAGS:=
CC:=gcc
CFLAGS:=-std=c17
CXX:=g++
CXXFLAGS:=-std=c++17
LD:=g++
LDFLAGS:=-lm
AR:=ar
ARFLAGS:=rv
RANLIB:=ranlib
CP:=cp -pv
RM:=rm -fv
MKDIR:=mkdir -pv
RMDIR:=rm -rfv
SED:=sed
FIND:=find
SCRUB:=$(FIND) . -type f -name "*~" -o -name "\#*" | xargs $(RM)
