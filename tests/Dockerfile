ARG TEST_BASE=debian:trixie-slim
FROM ${TEST_BASE}
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-dnspython python3-protobuf libnetfilter-log1 protobuf-compiler unbound nftables iproute2 iputils-ping openssl nodejs kmod procps \
    && rm -rf /var/lib/apt/lists/*
