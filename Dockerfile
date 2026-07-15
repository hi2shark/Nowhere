# syntax=docker/dockerfile:1.7

FROM --platform=$TARGETPLATFORM rust:1-alpine AS build

WORKDIR /src

RUN apk add --no-cache build-base perl

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
  cargo build --release --locked && \
  mkdir -p /out && \
  cp target/release/nowhere /out/nowhere

FROM scratch

COPY --from=build /out/nowhere /usr/local/bin/nowhere

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/nowhere"]
