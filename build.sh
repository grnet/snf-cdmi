#!/usr/bin/env bash

HERE="$(cd "$(dirname $0)" && pwd -P)"
TARGET="${HERE}"/target
VERSION=$(grep version pom.xml | grep -v -e '<\?xml\|~'| head -n 1 | sed 's/<version>//' | sed 's/<\/version>//'| awk '{print $1}')
JARNAME=snf-cdmi-${VERSION}.jar
JAR="${TARGET}/${JARNAME}"
IMAGE="snf-cdmi-build:${VERSION}"
DOCKERFILE="${HERE}"/Dockerfile.build

function rm_image() {
  docker rmi ${IMAGE}
}

# Ensure a clean target/ exists
[ -d "${TARGET}" ] && rm -rf "${TARGET}"
mkdir -p "${TARGET}"

docker build --rm -t "${IMAGE}" -f "${DOCKERFILE}" "${HERE}"
echo
docker images | grep snf-cdmi-build

echo
docker run --rm \
  -v $HOME/.m2:/home/snfcdmi/.m2 \
  -v ${TARGET}:/home/snfcdmi/target \
  ${IMAGE} && \
rm_image && \
echo && \
echo ${JAR}

STATUS=$?
[ "${STATUS}" != "0" ] && rm_image
exit ${STATUS}
