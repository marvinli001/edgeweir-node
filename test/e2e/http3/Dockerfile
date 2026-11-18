FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update -qq \
  && apt-get install -y --no-install-recommends curl \
  && curl --version | grep -w HTTP3 \
  && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["curl"]
