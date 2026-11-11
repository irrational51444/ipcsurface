FROM gcr.io/oss-fuzz-base/base-builder-python
RUN apt-get update && apt-get install -y make autoconf automake libtool
COPY . $SRC/ipcsurface
WORKDIR $SRC/ipcsurface
COPY fuzz/build.sh $SRC/build.sh
