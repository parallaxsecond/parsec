#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

DOCKER_IMAGE_DIR="$SCRIPT_DIR"
DOCKER_IMAGE_NAME="parsec"

docker build -t ${DOCKER_IMAGE_NAME} ${DOCKER_IMAGE_DIR}
DOCKER_CONTAINER_ID=$(docker run -d \
                                 --rm \
                                 --tmpfs /run \
                                 --tmpfs /run/lock \
                                 --tmpfs /tmp:exec \
                                 -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
                                 -v $(git rev-parse --show-toplevel):/home/parsec/parsec \
                                 ${DOCKER_IMAGE_NAME})

# Give the systemd daemon some time to spin up.
sleep 3

echo "Running tests inside container..."
docker exec ${DOCKER_CONTAINER_ID} /root/run-tests.sh
TEST_STATUS=$?

echo "Testing complete, stopping container."
docker stop ${DOCKER_CONTAINER_ID}

exit ${TEST_STATUS}
