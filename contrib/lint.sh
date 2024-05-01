#!/bin/sh

(git grep -n 'for (') && exit 1
(git grep -n 'if (') && exit 1
