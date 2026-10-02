# syntax=docker/dockerfile:1
#
# TeiFS for the benchmarks: built from this checkout in Docker, so it runs on the same
# kernel, file system and limits as the servers it's compared with.

FROM rust:1.98.0-trixie AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p teifs && cp target/release/teifs /teifs

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /teifs /usr/local/bin/teifs
ENV TEIFS_DIR=/data TEIFS_LISTEN=0.0.0.0:9000 TEIFS_LOG=warn XDG_CONFIG_HOME=/config
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/teifs"]
CMD ["serve"]
