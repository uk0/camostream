# CamoStream

Network traffic obfuscation tool that disguises real UDP/TCP traffic as legitimate video streaming protocols. Zero external dependencies, single binary, multiple camouflage strategies.

> For authorized internal security testing only.

## Features

- **4 种伪装模式**: WebRTC 视频通话 / 监控摄像头 / 通用 RTP / 原始隧道
- **全帧加密**: AES-GCM 整体加密 shim 头 + 载荷，消除协议指纹
- **多维诱饵注入**: shim-decoy / RTCP SR+SDES / RTCP RR / RTP keepalive / STUN Binding
- **协议仿真**: DTLS 1.2 握手、SRTP auth tag、H.264 FU-A 分片、GOP I/P 帧
- **码率整形**: Token Bucket 令牌桶限速
- **PCAP 调试**: 带大小上限的抓包输出
- **expvar 指标**: 实时流量/诱饵/会话统计

## Wire Modes

### `webrtc` — WebRTC 视频通话伪装（推荐）

将流量伪装为一个完整的 WebRTC 1:1 视频通话会话。

**协议栈仿真**:
- DTLS 1.2 握手（ClientHello / ServerHello / ChangeCipherSpec / Finished）
- SRTP 24 字节头：V=2, X=1, 含 `0xBEDE` 一字节扩展
  - abs-send-time (id=3, 3 字节, NTP 6.18 定点)
  - transport-cc (id=5, 2 字节, 跨流共享递增计数器)
- 10 字节 SRTP HMAC-SHA1-80 认证标签
- Opus 音频流 (PT=111, 独立 SSRC, 50 pps / 20ms 间隔)
- 视频流 (PT=96, 动态载荷类型)
- Compound RTCP: SR(28B) + SDES(CNAME) + SRTCP index + auth tag (RFC 3550)
- STUN Binding Request/Response 含 FINGERPRINT (CRC32 XOR 0x5354554E)
- ICE consent freshness 每 5 秒

**线上包格式**:
```
[SRTP Header 24B][Nonce 12B][AES-GCM(ShimHeader 20B + Payload)][Auth Tag 10B]
```

### `ipcam` — 监控摄像头伪装

模拟 Hikvision / Dahua 风格的 H.264 IP 摄像头 RTP 视频流。

**协议栈仿真**:
- H.264 over RTP (RFC 6184)
- FU-A 分片 (NAL type 28): IDR indicator 0x7C / non-IDR 0x5C
- STAP-A (NAL type 24): SPS (High profile, Level 4.0) + PPS 周期发送
- GOP 状态机: I 帧间隔可配 (默认 50 帧 = 2 秒 @25fps)
- I 帧 burst ~120KB / P 帧 ~15KB，VBR 波动 ±30%
- 90kHz 时钟, 时间戳增量 = 90000 / fps

**线上包格式**:
```
[RTP Header 12B][FU-A Indicator 1B][FU Header 1B][Nonce 12B][AES-GCM(Shim + Payload)]
```

### `rtpish` — 通用 RTP 伪装

基础 RTP 封装，适用于一般场景。

```
[RTP Header 12B][Nonce 12B][AES-GCM(ShimHeader 20B + Payload)]
```

### `shim` — 原始隧道（无伪装）

仅 shim 头 + 载荷，无 RTP 包装。用于 TCP 模式或调试。

## Architecture

```
                    Encrypted + Disguised Tunnel
                    ┌──────────────────────┐
[User App] ──UDP──▶ │  CamoStream Client   │ ════════════════▶ │  CamoStream Server   │ ──UDP──▶ [Backend]
  :any              │  :37001              │  looks like       │  :39001              │          :18081
                    │  encode + encrypt    │  video stream     │  decrypt + decode    │
                    └──────────────────────┘                   └──────────────────────┘
```

## Build

```bash
go build -o camostream .
```

Go 1.24+, 零外部依赖（纯标准库）。

## Quick Start

### WebRTC Mode

```bash
# Server
./camostream -role=server -mode=udp -wire=webrtc \
  -listen=:39001 -forward=127.0.0.1:18081 \
  -bitrate-mbps=20 -fps=30 \
  -aes=0123456789abcdef0123456789abcdef \
  -decoy-rps=5 -rtcp-sr-rps=1 -stun-rps=0.2 \
  -metrics=:9100 -log=info

# Client
./camostream -role=client -mode=udp -wire=webrtc \
  -listen=:37001 -server=<server-ip>:39001 \
  -bitrate-mbps=20 -fps=30 \
  -aes=0123456789abcdef0123456789abcdef \
  -decoy-rps=5 -rtcp-sr-rps=1 -stun-rps=0.2 \
  -metrics=:9101 -log=info
```

### IPCAM Mode

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
./camostream -role=server -mode=tcp -listen=:39001 -forward=127.0.0.1:4141 \
  -bitrate-mbps=20 -decoy-rps=10 -aes=0123456789abcdef0123456789abcdef
./camostream -role=client -mode=tcp -listen=:37001 -server=127.0.0.1:39001 \
  -bitrate-mbps=20 -decoy-rps=10 -aes=0123456789abcdef0123456789abcdef
```

## SpeedTest & Data Integrity Verification

内置 CRC32 完整性校验 + 吞吐量测量的 demo:

```bash
# 启动隧道
./camostream -role=server -mode=udp -wire=webrtc -listen=:39001 -forward=127.0.0.1:18081 \
  -bitrate-mbps=50 -aes=0123456789abcdef0123456789abcdef -dtls=false -log=warn &
./camostream -role=client -mode=udp -wire=webrtc -listen=:37001 -server=127.0.0.1:39001 \
  -bitrate-mbps=50 -aes=0123456789abcdef0123456789abcdef -dtls=false -log=warn &

# 接收端
go run demo/speedtest.go -mode=server -recv=:18081 &

# 发送端 (200 pps, 1000 字节, 10 秒)
go run demo/speedtest.go -mode=client -send=127.0.0.1:37001 -size=1000 -pps=200 -duration=10
```

一键测试所有 wire 模式: `bash demo/run_speedtest.sh`

**SpeedTest 结果 (WebRTC + AES-GCM, 本地回环)**:

```
Sent:        1997 packets, 1.60 Mbps
Received:    818 packets (through encrypted tunnel)
CRC32 OK:    818        FAIL: 0         Integrity: 100%
Out-of-Order: 0         Duplicates: 0
```

每个包携带: `[4B seq][4B CRC32][8B timestamp][payload]`，接收端逐包校验 CRC32。

## Security Mechanisms

### Encryption: Full-Frame AES-GCM

```
传统方式 (已弃用):  [RTP][Magic 0x5C10ADED][Shim Header][AES-GCM(Payload)]
                    ↑ DPI 一条规则即可指纹识别

当前方式:           [RTP][Nonce 12B][AES-GCM(Magic + Shim Header + Payload)]
                    ↑ 整体加密, 无可识别特征
```

- 加密范围覆盖 shim 头（含 magic/version/flags/session）+ 用户载荷
- 未启用 AES 时: magic 与 session ID 派生的掩码 XOR，防止静态指纹

### Anti-DPI Timing

```
旧模式:  [Real Frame][Decoy][RTCP][STUN]  ← 微秒级突发, 可被统计检测
                t=0       t=0    t=0   t=0

新模式:  [Real Frame]...[Decoy]........[Audio]........[RTCP]
                t=0       t=+4ms        t=+20ms       t=+1s
```

- 诱饵帧延迟 2-8ms 随机间隔发送
- 音频 ticker 每 20ms 发一个 Opus 包 (±2ms 抖动)
- STUN consent 每 5s (±1s) 发送
- RTCP 按 RPS 速率均匀分布

### Decoy Types

| 类型 | 格式 | 触发方式 | 用途 |
|------|------|----------|------|
| Shim Decoy | 与真实帧相同格式 | RPS 或百分比 | 混淆真实帧识别 |
| RTCP SR+SDES | RFC 3550 compound | RPS 调度 | 模拟媒体会话报告 |
| RTCP RR | Receiver Report | RPS 调度 | 模拟接收端反馈 |
| RTP Keepalive | PT=13 (CN) | RPS 调度 | 模拟静音检测 |
| STUN Binding | 含 FINGERPRINT | RPS 调度 | 模拟 ICE 连通性 |

## DPI Resistance Analysis

使用 `tests/scripts/analyze_pcap.py` 进行 7 维度自动化分析:

| 维度 | 权重 | 评分 | 说明 |
|------|------|------|------|
| 协议一致性 | 25% | 100/100 | 100% 包被 Wireshark 识别为 RTP/RTCP/STUN |
| 包大小分布 | 20% | 69/100 | 双峰分布 (音频 ~160B + 视频 ~880B), CV=0.93 |
| 时序分析 | 15% | 69/100 | 均值 IAT 13ms, 中位数 18ms, 符合 30fps 视频 |
| 载荷熵值 | 20% | 53/100 | AES-GCM 加密载荷高熵 |
| RTP 序列一致性 | 10% | 100/100 | 3 个 SSRC 流, 序列号 100% 递增 |
| 诱饵覆盖率 | 10% | 40/100 | RTCP + STUN 双类型覆盖 |
| **总分** | **100%** | **73.8/100** | **通过基础 DPI 检测** |

运行分析:
```bash
python3 tests/scripts/analyze_pcap.py <pcap-file> --mode udp --output report.json
```

## CLI Reference

### 核心参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-wire` | `rtpish` | 伪装模式: `shim` / `rtpish` / `webrtc` / `ipcam` |
| `-role` | `server` | 角色: `server` / `client` / `selftest` |
| `-mode` | `udp` | 传输: `udp` / `tcp` |
| `-listen` | `:9001` | 监听地址 |
| `-server` | `127.0.0.1:9001` | 服务端地址 (client 模式) |
| `-forward` | `127.0.0.1:18081` | 转发目标 (server 模式) |
| `-aes` | (空) | AES-GCM 密钥, 16/24/32 字节 hex 编码 |

### 流量控制

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-bitrate-mbps` | `20` | 码率上限 (Mbps) |
| `-fps` | `60` | 帧率 |
| `-jitter` | `30` | 抖动百分比 (0-100) |
| `-decoy-rps` | `0` | Shim 诱饵帧/秒 |
| `-rtcp-sr-rps` | `0` | RTCP SR 报告/秒 |
| `-rtcp-rr-rps` | `0` | RTCP RR 报告/秒 |
| `-rtpkeep-rps` | `0` | RTP keepalive/秒 |
| `-stun-rps` | `0` | STUN Binding/秒 |

### WebRTC 专用

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-dtls` | `true` | 会话启动时模拟 DTLS 握手 |
| `-audio-rps` | `50` | Opus 音频包/秒 (20ms 间隔) |
| `-stun-interval` | `5` | STUN consent freshness 间隔 (秒) |

### IPCAM 专用

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-ipcam-fps` | `25` | 摄像头帧率 |
| `-ipcam-gop` | `50` | GOP 大小 (帧数, 50 = 2 秒 @25fps) |

### 调试

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-pcap` | (空) | PCAP 输出路径 |
| `-pcap-max-mb` | `50` | PCAP 大小上限 (MB) |
| `-metrics` | `:9100` | Metrics HTTP 端口 (`/debug/vars`) |
| `-log` | `info` | 日志级别: `debug` / `info` / `warn` / `error` |
| `-showdrop` | `false` | 日志中显示诱饵丢弃信息 |

## Metrics

`http://host:port/debug/vars` 返回 JSON:

| 指标 | 说明 |
|------|------|
| `bytes_up` / `bytes_down` | 上/下行字节数 |
| `frames_up` / `frames_down` | 上/下行帧数 |
| `decoy_dropped` | 丢弃的诱饵帧数 |
| `shim_decoy_sent` | 发送的 shim 诱饵数 |
| `rtcp_sr_sent` / `rtcp_rr_sent` | RTCP 报告发送数 |
| `rtp_keepalive_sent` | RTP keepalive 发送数 |
| `stun_sent` | STUN 请求发送数 |
| `dtls_handshake_sent` | DTLS 握手完成数 |
| `audio_packets_sent` | 音频包发送数 |
| `sessions_active` | 活跃会话数 |

## Testing

```bash
# 本地 E2E 测试 (无 Docker)
bash tests/scripts/test_e2e.sh

# PCAP 深度分析
python3 tests/scripts/analyze_pcap.py <pcap> --mode udp

# Docker Compose 集成测试
cd tests && docker compose up --build --abort-on-container-exit

# 全套测试
bash tests/run_all_tests.sh
```

## Project Structure

```
camostream/
├── main.go              核心框架: UDP/TCP client/server, CLI, metrics, PCAP
├── crypto.go            加密: sealFrame/openFrame, AES-GCM 全帧加密, magic XOR 掩码
├── dtls.go              DTLS 1.2 仿真: ClientHello/ServerHello/CCS/Finished
├── wire.go              统一编解码: encodeUDPFrame/decodeUDPFrame, 所有 wire 模式入口
├── wire_webrtc.go       WebRTC: SRTP 头, 音频 ticker, compound RTCP, STUN consent
├── wire_ipcam.go        IPCAM: H.264 FU-A/STAP-A, GOP 状态机, 帧大小仿真
├── demo/
│   ├── speedtest.go     UDP 吞吐测试 + CRC32 完整性校验
│   └── run_speedtest.sh 一键测试所有 wire 模式
├── sim/
│   └── udp_server.go    简易 UDP echo 服务器
└── tests/
    ├── docker-compose.yml    Docker 多容器测试环境
    ├── Dockerfile            多阶段构建 (golang + alpine + tshark)
    ├── scripts/
    │   ├── test_e2e.sh       本地 E2E 测试 (TCP/UDP/加密/诱饵/PCAP/Metrics)
    │   ├── analyze_pcap.py   7 维度 DPI 抵抗评分 (协议/大小/时序/熵/RTP/诱饵)
    │   └── test_traffic_stealth.sh   tshark 协议层次分析
    └── backend/
        └── server.py         HTTP echo 后端
```

## Disclaimer

This tool is designed for authorized internal security testing only. Features involving traffic disguise and obfuscation must be used in strict compliance with applicable laws and organizational policies.
