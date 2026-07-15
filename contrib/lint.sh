#!/bin/sh

(git grep -n 'for (' -- ':!src/third_party') && exit 1
(git grep -n 'if (' -- ':!src/third_party') && exit 1
