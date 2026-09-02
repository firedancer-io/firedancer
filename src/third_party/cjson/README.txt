This directory contains a modified copy of the cJSON library at
https://github.com/DaveGamble/cJSON

The upstream cJSON.c and cJSON.h files come from tag v1.7.19 (commit
c859b25da02955fef659d658b8f324b5cde87be3).  Firedancer-specific
changes are recorded in cJSON.patch.  Do not edit the vendored files
directly; update the patch and rerun vendor.sh instead.

cJSON_alloc.c and cJSON_alloc.h are Firedancer-owned integration files
and are not part of upstream cJSON.

For licensing information, refer to NOTICE in the root of this repo.
