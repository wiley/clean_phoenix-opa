#!/bin/bash

set -x
set -o errexit
set -o pipefail
env

CURRENT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
PARENT_DIR="$(CDPATH='' cd -- "${CURRENT_DIR}/.." && pwd -P)"
if ! command -v docker >/dev/null 2>&1; then
    (echo >&2 "this script needs docker command")
    exit 1
fi

declare REPORTS_DIR="${PARENT_DIR}/reports/${BUILD_NUMBER:-}"

# create reports folder if not exists
mkdir -p "${REPORTS_DIR}"

docker build -f "${PARENT_DIR}/Dockerfile-test" -t opa-test "${PARENT_DIR}"
docker run --rm -v "${REPORTS_DIR}":/app/reports opa-test
