FROM debian:latest
RUN apt-get update && apt-get install gcc build-essential git wget curl vim astyle cmake ninja-build  python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml pkg-config autoconf libtool -y

WORKDIR /apps

RUN git clone --depth=1  https://github.com/openssl/openssl.git
RUN cd openssl && ./config enable-ssl-trace  && make -j`nproc` && make install

ENV LD_LIBRARY_PATH /usr/local/lib/:/usr/local/lib64/

# ENTRYPOINT ["openssl"]

