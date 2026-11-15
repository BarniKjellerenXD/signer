# syntax=docker/dockerfile:1
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data TMPDIR=/data/tmp

# zsign 1.1.3 (release binaries from github.com/zhlynn/zsign, checksums pinned in vendor/zsign-1.1.3/SHA256SUMS)
# amd64: fully static musl build. arm64: glibc build, needs libstdc++.
ARG TARGETARCH
COPY vendor/zsign-1.1.3/ /tmp/zsign/
RUN set -e; cd /tmp/zsign; \
    case "${TARGETARCH:-amd64}" in \
      amd64) f=zsign-linux-musl-static.tar.gz; bin=zsign-musl ;; \
      arm64) f=zsign-linux-aarch64.tar.gz; bin=zsign; \
             apt-get update && apt-get install -y --no-install-recommends libstdc++6 && rm -rf /var/lib/apt/lists/* ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    grep " ${f}\$" SHA256SUMS | sha256sum -c -; \
    tar xzf "$f"; install -m 755 "$bin" /usr/local/bin/zsign; \
    cd /; rm -rf /tmp/zsign; zsign -v

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
# /data owned by the app user so a fresh named volume is writable without any chown
RUN useradd -u 10001 -M -d /data -s /usr/sbin/nologin signer && mkdir -p /data && chown 10001:10001 /data
USER 10001
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3)" || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header"]
