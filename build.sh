#!/usr/bin/env bash

set -e

HERE="$(cd "$(dirname $0)" && pwd -P)"
TARGET="${HERE}"/target
VERSION=$(grep version pom.xml | grep -v -e '<\?xml\|~'| head -n 1 | sed 's/<version>//' | sed 's/<\/version>//'| awk '{print $1}')
JARNAME=snf-cdmi-${VERSION}.jar
JAR="${TARGET}/${JARNAME}"
IMAGE="snf-cdmi-build:${VERSION}"
DOCKERFILE=Dockerfile.build

# Make the master image with a lot of maven dependencies resolved
docker build --rm -t "${IMAGE}" -f "${DOCKERFILE}" "${HERE}"
docker images | grep snf-cdmi-build

# Ensure target/ exists

[ -d "${TARGET}" ] && rm -rf "${TARGET}"
mkdir -p "${TARGET}"

docker run --rm \
    -e VERSION="${VERSION}" \
    -v "${TARGET}":/home/snfcdmi/target \
    "${IMAGE}"

echo ${JAR}
