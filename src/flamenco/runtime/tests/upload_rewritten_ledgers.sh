while [[ $# -gt 0 ]]; do
  case $1 in
    -l|--ledger-list)
       LEDGER_LIST="$2"
       shift
       shift
       ;;
    -i|--ledgers-location)
       LEDGERS_LOCATION="$2"
       shift
       shift
       ;;
    -*|--*)
       echo "unknown option $1"
       exit 1
       ;;
    *)
       POSITION_ARGS+=("$1")
       shift
       ;;
  esac
done

cd ${LEDGERS_LOCATION}

while IFS= read -r line; do
  unset entry
  declare -A entry

  args=($line)
  i=0
  while [ $i -lt ${#args[@]} ]; do
    key="${args[$i]}"
  if [[ $key == -* ]]; then
      value="${args[$((i + 1))]}"
      entry[${key:1}]="$value"
      ((i+=2))
    else
      ((i++))
    fi
  done

  LEDGER=${entry[l]}
  LEDGER_TAR_FILE="${LEDGER}.tar.gz"
  GCLOUD_LEDGER_PATH="gs://firedancer-ci-resources/${LEDGER}.tar.gz"

  tar -czvf ${LEDGER_TAR_FILE} ${LEDGER}

  if gsutil ls "${GCLOUD_LEDGER_PATH}" >/dev/null 2>&1; then
    echo "File '${GCLOUD_LEDGER_PATH}' already exists."
  else
    echo "Uploading '${LEDGER_TAR_FILE}' to '${GCLOUD_LEDGER_PATH}'..."
    gsutil cp ${LEDGER_TAR_FILE} "${GCLOUD_LEDGER_PATH}"
    echo "Upload complete."
  fi

done < "$LEDGER_LIST"
