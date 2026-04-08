# Stage 1: Build camostream binary
FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY main.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /camostream main.go

WORKDIR /src/sim
COPY sim/udp_server.go ./
RUN go mod init udp_echo && CGO_ENABLED=0 GOOS=linux go build -o /udp_server udp_server.go

# Stage 2: Runtime with network analysis tools
FROM alpine:3.20

RUN apk add --no-cache \
    tshark \
    tcpdump \
    curl \
    python3 \
    py3-pip \
    bash \
    netcat-openbsd \
    coreutils \
    && rm -rf /var/cache/apk/*

COPY --from=builder /camostream /usr/local/bin/camostream
COPY --from=builder /udp_server /usr/local/bin/udp_server

# Copy test scripts
COPY tests/scripts/ /opt/tests/scripts/
COPY tests/backend/ /opt/tests/backend/

RUN chmod +x /usr/local/bin/camostream /usr/local/bin/udp_server

WORKDIR /opt/tests
ENTRYPOINT ["/bin/bash"]
