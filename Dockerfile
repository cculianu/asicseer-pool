FROM debian:12-slim AS builder

RUN apt-get update
RUN apt-get dist-upgrade -y

RUN apt-get install -y build-essential libzmq3-dev cmake

WORKDIR /build

COPY cmake/ ./cmake/
COPY CMakeFiles/ ./CMakeFiles/
COPY src/ ./src/
COPY CMakeLists.txt .

RUN mkdir out && cd out && cmake -DCMAKE_BUILD_TYPE=Release .. && make

RUN apt-get download \
	libzmq5 \
	libgssapi-krb5-2 \
	libnorm1 \
	libpgm-5.3-0 \
	libsodium23 \
	libbsd0 \
	libk5crypto3 \
	libkrb5-3 \
	libkrb5support0 \
	libkeyutils1 \
	libssl3 \
	netcat-traditional

FROM debian:12-slim AS asicseer

COPY --from=builder /build/*.deb /tmp/
RUN dpkg -i /tmp/*.deb
RUN rm -rf /tmp/*

COPY --from=builder /build/out/src/notifier /usr/bin/
COPY --from=builder /build/out/src/summariser /usr/bin/
COPY --from=builder /build/out/src/asicseer-* /usr/bin/

HEALTHCHECK --interval=60s \
            --timeout=5s \
            --retries=30 \
	    --start-period=30s \
	    CMD [ "nc", "-z", "localhost", "3333" ]
            
CMD ["/usr/bin/asicseer-pool", "-B", "-k", "-c", "/asicseer/conf/asicseer-pool.conf"]

