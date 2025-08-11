### CamoStreamPro

>我也不知道有什么用

#### build

```bash
go build -o camostream main.go
```

#### tcp 

```bash

./camostream -role=client -mode=tcp -listen=:37001 -server=127.0.0.1:39001 \
  -bitrate-mbps=20 -decoy-rps=10 \
  -pcap=tcp_client.pcap -pcap-max-mb=50 -metrics=:9101 -log=info
  
  
./camostream -role=server -mode=tcp -listen=:39001 -forward=127.0.0.1:4141 \
  -bitrate-mbps=20 -decoy-rps=10 \
  -pcap=tcp_server.pcap -pcap-max-mb=50 -metrics=:9100 -log=info

```








#### udp

```bash
./camostream -role=server -mode=udp -listen=:39001 -forward=127.0.0.1:18081 \
  -wire=rtpish -fps=60 -bitrate-mbps=20 \
  -decoy-rps=12 \
  -rtcp-sr-rps=2 -rtcp-rr-rps=3 -rtpkeep-rps=4 -stun-rps=1 \
  -pcap=udp_server.pcap -pcap-max-mb=100 -metrics=:9100 -log=info
  
  
./camostream -role=client -mode=udp -listen=:37001 -server=127.0.0.1:39001 \
  -wire=rtpish -fps=60 -bitrate-mbps=20 \
  -decoy-rps=12 \
  -rtcp-sr-rps=2 -rtcp-rr-rps=3 -rtpkeep-rps=4 -stun-rps=1 \
  -pcap=udp_client.pcap -pcap-max-mb=100 -metrics=:9101 -log=info
  
```




#### feat

*	✅ UDP/TCP 双协议、Client/Server 双角色
*	✅ UDP：RTP-ish（12B RTP 头）+ shim 载荷、60/120fps、GOP 峰谷、抖动
*	✅ 码率整形（令牌桶）
*	✅ 诱饵插播（shim‑decoy）+ AES‑GCM 可选
*	✅ 额外伪报文（UDP 无 shim）：RTCP SR、RTCP RR、纯 RTP keepalive、STUN Binding
*	✅ 自测模式（UDP Echo + Client/Server + 负载）
*	✅ PCAP（UDP RAW）与指标（/debug/vars）


#### 增强

*	UDP 方向新增无 shim 的额外伪报文（中间盒可见，但业务端不感知）：
*	RTCP SR（PT=200）：包含 sender SSRC、NTP 时间戳、RTP 时间戳、包/字节计数。
*	RTCP RR（PT=201）：简单接收者报告，无 report block。
*	纯 RTP keepalive：PT=13（CN 习惯），小 payload/可零 payload。
*	STUN Binding Request：标准 20B 报文，含 Magic Cookie 和 Transaction ID。
这些报文不带 shim，因此服务端在解析 RTP-ish+shim 失败时直接 continue 丢弃；同样客户端也会丢弃，从而只起到“流量伪装/背景噪声”作用。
*	仍保持诱饵为“插播”（不替代真实帧）：
*	TCP：真实帧 → （可选）插播 shim‑decoy。
*	UDP：真实帧（RTP-ish+shim 或 shim）→ （可选）插播 shim‑decoy → （可选）插播 RTCP/RTP/STUN 等额外无壳伪报文。
*	新增 CLI 控制这类伪报文注入概率（UDP only）：
*	-rtcp-sr-pct：插播 RTCP SR 的概率（默认 4）
*	-rtcp-rr-pct：插播 RTCP RR 的概率（默认 6）
*	-rtpkeep-pct：插播纯 RTP keepalive 的概率（默认 5）
*	-stun-pct：插播 STUN Binding 的概率（默认 3）


>备注：-wire=rtpish 仅对 UDP 生效；TCP 会打印一个 WARN 并忽略




#### 指标

*	http://127.0.0.1:9100/debug/vars（server）
*	http://127.0.0.1:9101/debug/vars（client）
*	关注：bytes_*、frames_*、decoy_dropped、shim_decoy_sent、rtcp_sr_sent、rtcp_rr_sent、rtp_keepalive_sent、stun_sent


#### Warn

仅用于授权的内部安全测试。涉及伪装/混淆的功能，请严格遵循公司及法律合规要求。
TCP 的 PCAP 是伪造的网络层帧，用于 debug 观察我们应用层写入/读到的 shim 帧，不代表内核真实的 TCP 会话（没有三次握手、窗口/ACK 真实演进），但校验和正确，可在 Wireshark 中查看和过滤。