# Builds Proton Mail Bridge and runs it headless with the web interface.
#
#   docker build -t proton-bridge .
#   docker run -d --name proton-bridge -v proton-bridge:/data \
#     -p 8143:8143 -p 1143:1143 -p 1025:1025 proton-bridge
#
# On the first start, the setup token for the web interface is printed in the container log
# (docker logs proton-bridge).

FROM golang:1.26-trixie AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends libsecret-1-dev libfido2-dev libcbor-dev pkg-config make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make build-bridge


FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends libsecret-1-0 libfido2-1 ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 bridge \
    && mkdir /data \
    && chown bridge:bridge /data

# The bridge executable is run directly instead of through the launcher,
# so that Bridge never starts an update downloaded from Proton in place of this build.
COPY --from=build /src/bridge /usr/local/bin/bridge

# All settings, accounts, the message cache and logs live under /data.
# No keychain is available in the container, so Bridge keeps its vault unencrypted in /data.
ENV XDG_CONFIG_HOME=/data/config \
    XDG_DATA_HOME=/data/data \
    XDG_CACHE_HOME=/data/cache

USER bridge
VOLUME /data

# 8143 is the web interface; 1143 and 1025 are the default IMAP and SMTP ports.
EXPOSE 8143 1143 1025

# tini forwards stop signals to Bridge, which does not handle them itself when it runs as PID 1.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/bridge"]
