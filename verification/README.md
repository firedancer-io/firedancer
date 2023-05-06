Verification with CBMC
======================

This proof framework was made with the CBMC starter kit

https://github.com/model-checking/cbmc-starter-kit

Installing
==========

https://github.com/model-checking/cbmc-starter-kit/wiki/Installation

```
$ pip install cbmc-starter-kit cbmc-viewer ninja
```

You'll need to install litani, follow these instructions:

https://github.com/awslabs/aws-build-accumulator/releases/tag/1.28.0

Alternatively, cloning the repo and adding it to PATH worked

Running
=======

You can run all of the proofs by doing the following:

```
$ cd proofs
$ ./run-cbmc-proofs.py
```

there will then be a report located at `proofs/output/latest/html/index.html`

You can also run each test individually:

```
$ cd proofs/quic/fd_quic_decode_initial
$ make
```

And a report will be at `report/html/index.html` in that directory
