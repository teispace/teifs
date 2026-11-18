# syntax=docker/dockerfile:1
#
# TeiFS: a static (musl) `teifs` on distroless, as a non-root user, serving /data.
# Built by .github/workflows/image.yml from a release's own binaries; the context holds
# linux-amd64/teifs, linux-arm64/teifs and an empty folder, `empty/`.
#
#   docker run -p 9000:9000 -v teifs-data:/data -v teifs-config:/config IMAGE
#
# /data is the drive. /config holds the encryption keyring (keep it, and back it up:
# encrypted objects can't be read without it) and aliases. Set the keys with
# TEIFS_ACCESS_KEY and TEIFS_SECRET_KEY_FILE (a Docker secret) or TEIFS_SECRET_KEY;
# without them the drive makes its own, in /data/.teifs/credentials.json.

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

ARG TARGETARCH
COPY --chmod=0755 linux-${TARGETARCH}/teifs /usr/local/bin/teifs
# Owned by the image's user, so fresh volumes are writable.
COPY --chown=nonroot:nonroot empty/ /data/
COPY --chown=nonroot:nonroot empty/ /config/

ENV TEIFS_DIR=/data \
    TEIFS_LISTEN=0.0.0.0:9000 \
    XDG_CONFIG_HOME=/config
VOLUME ["/data", "/config"]
EXPOSE 9000
USER nonroot:nonroot

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/teifs", "-q", "health"]
ENTRYPOINT ["/usr/local/bin/teifs"]
CMD ["serve"]
