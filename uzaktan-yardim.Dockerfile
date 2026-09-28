# Uzaktan Yardım — hbbs/hbbr (izin listesi yamalı) imajı.
# Resmi rustdesk/rustdesk-server imajıyla aynı kullanım: `hbbs ...` / `hbbr ...`, veri /root.

FROM rust:1.90-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin hbbs --bin hbbr

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/hbbs /src/target/release/hbbr /usr/bin/
WORKDIR /root
ENV HOME=/root
EXPOSE 21115 21116 21116/udp 21117
