#!/bin/sh

OUTDIR=~/build
SCRIPTDIR=${PWD}/scripts

#Defaults
MACHINE=linux_gcc_x86_64
PLATFORM=rhel

#Bump this any time there's a change to a Dockerfile
IMAGETAG=0.7

GETOPT=$(getopt -o :t:m:p:h -l tag:,machine:,platform:,help -n $0 -- "$@")
eval set -- "$GETOPT"

usage () {
echo -e "\nUsage: $0 [ -t|--tag release|tag|branchname ] [ -m|--machine machinetype ] [ -p|--platform platform ]
\nWhere machinetype is one of the targets in ../../config and defaults to \"linux_gcc_x86_64\" if not specified
Where platform is \"rhel\" or \"debian\" and defaults to \"rhel\"\n"
}

while : ; do
  case "${1}" in
    -t | --tag )  TAG="$2" ; shift 2
      ;;
    -m | --machine )
        if [ -f "../../config/${2}.mk" ]
          then MACHINE="$2" ; shift 2
        else echo "$2 does not appear to be a valid machine type, please review types in ../../config"
          exit 1
        fi
      ;;
    -p | --platform )
        if [ "$2" = rhel ]
          then PLATFORM=rhel ; shift 2
        elif [ "$2" = debian ]
          then PLATFORM=debian ; shift 2
        else
          echo -e "\nThat is not a valid platform selection"
          usage ; exit 1
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

if command -v podman >/dev/null
  then DOCKER=podman
elif command -v docker >/dev/null
  then DOCKER=docker
else echo "Please install docker or podman"
  exit 1
fi



$DOCKER image exists fdbuilder_${PLATFORM}:$IMAGETAG || $DOCKER build -f Dockerfile.${PLATFORM} -t fdbuilder_${PLATFORM}:$IMAGETAG -t fdbuilder_${PLATFORM}:latest .

$DOCKER run --rm \
        --volume "$OUTDIR:/build/out:Z" \
        --volume "$SCRIPTDIR:/build/scripts:ro,Z" \
        fdbuilder_${PLATFORM}:latest \
        /build/scripts/fdbuild.sh "$MACHINE" "$PLATFORM" "$TAG"
