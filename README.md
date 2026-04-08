# CamoStream

Network traffic obfuscation tool that disguises real UDP/TCP traffic as legitimate video streaming protocols. Supports multiple wire formats for different camouflage scenarios.

> For authorized internal security testing only.

## Wire Modes

| Mode | Disguise As | Protocol Stack |
|------|-------------|----------------|
| `rtpish` | Generic RTP video | RTP(12B) + Shim + Payload |
| `webrtc` | WebRTC video call | SRTP(24B) + Extensions + Auth Tag + Opus Audio + Compound RTCP + STUN |
| `ipcam` | Surveillance camera | H.264 FU-A over RTP + SPS/PPS + GOP I/P frames |
| `shim` | Raw tunnel (no disguise) | ShimHeader + Payload |

## Architecture

```
[App] --UDP--> [CamoStream Client :37001]
                    |
                    | encrypted + disguised tunnel
                    v
               [CamoStream Server :39001] --UDP--> [Real Backend :18081]
```

## Build

```bash
go build -o camostream .
```

Requires Go 1.24+, zero external dependencies (stdlib only).

## Quick Start

### WebRTC Mode (Recommended)

```bash
# Server side
./camostream -role=server -mode=udp -wire=webrtc \
  -listen=:39001 -forward=127.0.0.1:18081 \
  -bitrate-mbps=20 -fps=30 \
  -aes=0123456789abcdef0123456789abcdef \
  -decoy-rps=5 -rtcp-sr-rps=1 -stun-rps=0.2 \
  -metrics=:9100 -log=info

# Client side
./camostream -role=client -mode=udp -wire=webrtc \
  -listen=:37001 -server=<server-ip>:39001 \
  -bitrate-mbps=20 -fps=30 \
  -aes=0123456789abcdef0123456789abcdef \
  -decoy-rps=5 -rtcp-sr-rps=1 -stun-rps=0.2 \
  -metrics=:9101 -log=info
```

### IPCAM Mode (Surveillance Camera)

```bash
# Server
./camostream -role=server -mode=udp -wire=ipcam \
  -listen=:39001 -forward=127.0.0.1:18081 \
  -ipcam-fps=25 -ipcam-gop=50 -bitrate-mbps=4 \
  -aes=0123456789abcdef0123456789abcdef \
  -metrics=:9100

# Client
./camostream -role=client -mode=udp -wire=ipcam \
  -listen=:37001 -server=<server-ip>:39001 \
  -ipcam-fps=25 -ipcam-gop=50 -bitrate-mbps=4 \
  -aes=0123456789abcdef0123456789abcdef \
  -metrics=:9101
```

### TCP Mode

```bash
# Server
./camostream -role=server -mode=tcp -listen=:39001 -forward=127.0.0.1:4141 \
  -bitrate-mbps=20 -decoy-rps=10 -aes=0123456789abcdef0123456789abcdef

# Client
./camostream -role=client -mode=tcp -listen=:37001 -server=127.0.0.1:39001 \
  -bitrate-mbps=20 -decoy-rps=10 -aes=0123456789abcdef0123456789abcdef
```

## SpeedTest Demo

Built-in CRC32 integrity verification and throughput measurement:

```bash
# Start tunnel (webrtc mode)
./camostream -role=server -mode=udp -wire=webrtc -listen=:39001 -forward=127.0.0.1:18081 \
  -bitrate-mbps=50 -aes=0123456789abcdef0123456789abcdef -dtls=false -log=warn &
./camostream -role=client -mode=udp -wire=webrtc -listen=:37001 -server=127.0.0.1:39001 \
  -bitrate-mbps=50 -aes=0123456789abcdef0123456789abcdef -dtls=false -log=warn &

# Start receiver
go run demo/speedtest.go -mode=server -recv=:18081 &

# Run speedtest (200 pps, 1000 byte packets, 10 seconds)
go run demo/speedtest.go -mode=client -send=127.0.0.1:37001 -size=1000 -pps=200 -duration=10
```

Or run all wire modes:

```bash
bash demo/run_speedtest.sh
```

### SpeedTest Results (Local, WebRTC Mode)

```
Sent:      1997 packets, 1.60 Mbps
Received:  818 packets through tunnel
CRC32 OK:  818   FAIL: 0   (100% integrity)
OOO: 0  DUP: 0
```

## Security Features

### Encryption
- **AES-GCM** encrypts the entire shim header + payload together
- Magic bytes (`0x5C10ADED`) never appear on the wire when encryption is enabled
- Without AES: magic is XOR-masked with session-derived key to prevent static fingerprinting

### WebRTC Camouflage
- 24-byte SRTP headers with `0xBEDE` extensions (abs-send-time, transport-cc)
- 10-byte SRTP authentication tag on every packet
- Opus audio stream at 50 pps (PT=111) with separate SSRC
- Compound RTCP (SR + SDES with CNAME) per RFC 3550
- STUN Binding Request/Response with FINGERPRINT attribute
- STUN consent freshness every 5 seconds
- DTLS 1.2 handshake simulation at session start (optional)

### Decoy System
- **Shim decoys**: encrypted fake frames injected at configurable RPS
- **RTCP SR/RR**: realistic sender/receiver reports
- **RTP keepalive**: comfort noise (PT=13) packets
- **STUN Binding**: ICE connectivity checks with proper responses
- Decoys sent with 2-8ms random delay to avoid burst timing fingerprint

## DPI Resistance

Tested with automated 7-dimension analysis:

| Dimension | Score | Description |
|-----------|-------|-------------|
| Protocol Conformance | 100/100 | All packets classify as RTP/RTCP/STUN |
| Packet Size Distribution | 69/100 | Bimodal (audio small + video large) |
| Timing Analysis | 69/100 | Consistent with video call FPS |
| Entropy | 53/100 | High entropy from AES-GCM |
| RTP Consistency | 100/100 | Perfect sequence/timestamp progression |
| Decoy Coverage | 40/100 | Multiple decoy types present |
| **Overall** | **73.8/100** | **Grade C - Passes basic DPI** |

## CLI Reference

```
-wire       shim|rtpish|webrtc|ipcam    Wire format (UDP only)
-role       server|client|selftest      Role
-mode       udp|tcp                     Transport mode
-listen     :port                       Listen address
-server     host:port                   Server address (client mode)
-forward    host:port                   Forward target (server mode)
-aes        hex-key                     AES-GCM 128/192/256 bit key
-bitrate-mbps  N                        Bitrate cap in Mbps
-fps        N                           Frames per second
-decoy-rps  N                           Shim decoy frames per second
-rtcp-sr-rps N                          RTCP SR decoys per second
-rtcp-rr-rps N                          RTCP RR decoys per second
-stun-rps   N                           STUN decoys per second
-dtls       bool                        DTLS handshake (webrtc, default true)
-audio-rps  N                           Audio packets/sec (webrtc, default 50)
-ipcam-fps  N                           Camera FPS (ipcam, default 25)
-ipcam-gop  N                           GOP size (ipcam, default 50)
-pcap       path                        PCAP output file
-pcap-max-mb N                          Max PCAP size in MB
-metrics    :port                       Metrics HTTP endpoint
-log        debug|info|warn|error       Log level
```

## Metrics

Available at `http://host:port/debug/vars`:

```
bytes_up, bytes_down, frames_up, frames_down,
decoy_dropped, sessions_active, shim_decoy_sent,
rtcp_sr_sent, rtcp_rr_sent, rtp_keepalive_sent,
stun_sent, dtls_handshake_sent, audio_packets_sent
```

## Project Structure

```
├── main.go           Core framework, UDP/TCP client/server, CLI
├── crypto.go         sealFrame/openFrame (full shim+payload encryption)
├── dtls.go           DTLS 1.2 handshake simulation
├── wire.go           Unified encode/decode path for all wire formats
├── wire_webrtc.go    WebRTC: SRTP, audio ticker, compound RTCP, STUN
├── wire_ipcam.go     IPCAM: H.264 FU-A, GOP state, SPS/PPS
├── demo/             SpeedTest demo with CRC32 verification
├── sim/              UDP echo server for testing
└── tests/            E2E tests, PCAP analysis, Docker environment
```

## Disclaimer

This tool is designed for authorized internal security testing only. Traffic obfuscation capabilities must be used in compliance with applicable laws and organizational policies.
