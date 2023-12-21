#!/bin/sh

OUTDIR=~/build
SCRIPTDIR=${PWD}/scripts
MACHINE=linux_gcc_x86_64

GETOPT=$(getopt -o :t:m:h -l tag:,machine:,help -n $0 -- "$@")
eval set -- "$GETOPT"

usage () {
echo -e "\nUsage: $0 [ -t|--tag release|tag|branchname ] [ -m|--machine machinetype ]
\nWhere machinetype is one of the targets in ../../config and defaults to
linux_gcc_x86_64 if not specified\n"
}

while : ; do
  case "${1}" in
    -t | --tag )  TAG="$2" ; shift 2
      ;;
    -m | --machine )
        if [ -f ../../config/${2}.mk ]
          then MACHINE="$2" ; shift 2
        else echo "$2 does not appear to be a valid machine type, please review types in ../../config"
          exit 1
        fi
      ;;
    -h | --help ) usage ; exit 1
      ;;
    -- ) shift ; break
      ;;
    * ) usage ; exit 1
      ;;
  esac
done

chmod +x "$SCRIPTDIR/fdbuild.sh"
mkdir -p "$OUTDIR"

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
        --volume "$SCRIPTDIR:/build/scripts:ro,Z" \
        fdbuilder:latest \
        /build/scripts/fdbuild.sh "$MACHINE" "$TAG"
