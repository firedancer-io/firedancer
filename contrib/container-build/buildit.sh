#!/bin/sh

OUTDIR=~/build/out
SCRIPTSDIR=$PWD/scripts

# Allow for a tag, release, or branch
[ -n "$1" ] && TAG="$1"

chmod +x "$SCRIPTSDIR/*.sh"
mkdir -p $OUTDIR

if which podman >/dev/null 2>&1
  then DOCKER=podman
elif which docker >/dev/null 2>&1
  then DOCKER=docker
else echo "Please install docker or podman"
  exit 1
fi



$DOCKER image exists fdbuilder:latest || $DOCKER build -t fdbuilder:latest .

$DOCKER run --rm \
        --volume "$OUTDIR:/build/out:Z" \
        --volume "$SCRIPTSDIR:/build/scripts:ro,Z" \
        fdbuilder:latest \
        /build/scripts/fdbuild.sh $TAG
