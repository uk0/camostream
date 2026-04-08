# CamoStream

## Project Overview
CamoStream 是一个 Go 语言网络流量伪装工具，将真实流量封装为视频流（RTP/RTCP）流量，用于授权的内部安全测试。

## Tech Stack
- **Language**: Go 1.24.3, zero external dependencies (stdlib only)
- **Architecture**: Single-file `main.go` (1562 lines)
- **Build**: `go build -o camostream main.go`

## Key Features
- UDP/TCP dual protocol, Client/Server/Selftest roles
- RTP-ish (12B RTP header) + shim payload wrapping (UDP)
- Token bucket bitrate shaping
- Decoy injection: shim-decoy + RTCP SR/RR + RTP keepalive + STUN Binding
- AES-GCM optional encryption
- PCAP debug capture with size cap
- expvar metrics on /debug/vars

## Protocol Format
- **Shim Header**: 20 bytes (magic 0x5C10ADED, version, mode, flags, session_id, timestamp, length)
- **RTP-ish**: 12B RTP header + Shim + Payload (UDP only)
- **Flags**: bit0=decoy, bit1=encrypted

## Ports Convention
- Server listen: 39001, metrics: 9100
- Client listen: 37001, metrics: 9101
- Forward target: configurable (e.g., 4141 for TCP, 18081 for UDP)

## Build & Run
```bash
go build -o camostream main.go
./server.sh   # TCP server
./client.sh   # TCP client
./server_udp.sh  # UDP server
./client_udp.sh  # UDP client
```

## Testing
```bash
cd tests/
./run_all_tests.sh
```
