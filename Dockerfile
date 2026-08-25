# ── Stage 1: сборка ──────────────────────────────────────────
FROM rust:1-alpine AS builder

WORKDIR /build

# Кэшируем зависимости
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release && rm -rf src

# Копируем исходники и собираем бинарник
COPY src/ src/
RUN touch src/main.rs && cargo build --release

# ── Stage 2: рантайм ────────────────────────────────────────
FROM alpine:3.24

# Базовые сетевые утилиты + WireGuard + unzip (для Xray)
RUN apk add --no-cache \
        iproute2 \
        iptables \
        nftables \
        iputils-ping \
        curl \
        ca-certificates \
        unzip \
        wireguard-tools

# AmneziaWG (awg + awg-quick) — сборка из исходников
RUN apk add --no-cache git make gcc musl-dev linux-headers bash \
    && git clone https://github.com/amnezia-vpn/amneziawg-tools.git /tmp/awg-tools \
    && cd /tmp/awg-tools/src && make && make install \
    && cd / && rm -rf /tmp/awg-tools \
    && apk del git make gcc musl-dev

# Xray (Go — статическая линковка, работает на musl)
RUN curl -fsSL https://github.com/XTLS/Xray-core/releases/latest/download/xray-linux-64.zip -o /tmp/xray.zip \
    && unzip /tmp/xray.zip -d /usr/local/bin xray \
    && chmod +x /usr/local/bin/xray \
    && rm /tmp/xray.zip

COPY --from=builder /build/target/release/vpn-orchestrator /usr/local/bin/vpn-orchestrator

# busybox resolvconf падает при вызове из awg-quick/wg-quick.
# Ставим заглушку в /usr/local/sbin (первый в PATH).
RUN printf '#!/bin/sh\nexit 0\n' > /usr/bin/resolvconf && \
    chmod +x /usr/bin/resolvconf

# Конфиги монтируются извне
VOLUME ["/etc/vpn-orchestrator", "/etc/wireguard", "/etc/amnezia", "/etc/xray"]

ENTRYPOINT ["vpn-orchestrator"]
CMD ["-c", "/etc/vpn-orchestrator/config.toml"]
