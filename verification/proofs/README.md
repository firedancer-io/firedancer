CBMC proofs
===========

This directory contains the CBMC proofs.  Each proof is in its own
directory.

This directory includes four Makefiles.

One Makefile describes the basic workflow for building and running proofs:

* Makefile.common:
  * make goto: builds the goto binary
  * make result: does cbmc property checking
  * make coverage: does cbmc coverage checking
  * make report: builds the final report

Running `make` or `make report` builds the final report.  Running
`make report-no-coverage` builds the final report but without checking
coverage.  Coverage checking can be slow, and it is usually not
interesting until after the issues raised by property checking have
been resolved.

Three included Makefiles describe project-specific settings and can override
definitions in Makefile.common:

* Makefile-project-defines: definitions like compiler flags
  required to build the goto binaries, and definitions to override
  definitions in Makefile.common.
* Makefile-project-targets: other make targets needed for the project
* Makefile-project-testing: other definitions and targets needed for
  unit testing or continuous integration.
