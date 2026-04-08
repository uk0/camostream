// main.go
// camostream with shim-decoy RPS scheduling and TCP PCAP (size-capped) debug capture.
// UDP/TCP, RTP-ish masking (UDP only), fps profiles, bitrate shaping, decoy insertion,
// AES-GCM optional, selftest, and PCAP (LINKTYPE_RAW, IPv4/UDP|TCP).
// For internal security testing only.

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"expvar"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

/* ============ Metrics ============ */

var (
	metricBytesUp      = expvar.NewInt("bytes_up")
	metricBytesDown    = expvar.NewInt("bytes_down")
	metricFramesUp     = expvar.NewInt("frames_up")
	metricFramesDown   = expvar.NewInt("frames_down")
	metricDecoyDropped = expvar.NewInt("decoy_dropped")
	metricSessions     = expvar.NewInt("sessions_active")

	metricRTCPsrSent   = expvar.NewInt("rtcp_sr_sent")
	metricRTCPrrSent   = expvar.NewInt("rtcp_rr_sent")
	metricRTPkeepSent  = expvar.NewInt("rtp_keepalive_sent")
	metricSTUNSent     = expvar.NewInt("stun_sent")
	metricShimDecoySent = expvar.NewInt("shim_decoy_sent")
	metricDTLSSent      = expvar.NewInt("dtls_handshake_sent")
	metricAudioSent     = expvar.NewInt("audio_packets_sent")
)

/* ============ CLI / Config ============ */

type Role string
type Mode string
type Wire string

const (
	RoleServer Role = "server"
	RoleClient Role = "client"
	RoleSelf   Role = "selftest"

	ModeUDP Mode = "udp"
	ModeTCP Mode = "tcp"

	WireShim   Wire = "shim"   // ShimHeader + Payload
	WireRTPish Wire = "rtpish" // RTP(12) + Shim + Payload (UDP only)
	WireWebRTC Wire = "webrtc" // DTLS+SRTP(24)+Shim+Payload+AuthTag (UDP only)
	WireIPCam  Wire = "ipcam"  // H.264/RTP surveillance camera (UDP only)
)

type Config struct {
	Role        Role
	Mode        Mode
	Listen      string
	ServerAddr  string
	ForwardAddr string
	Wire        Wire
	FPS         int
	GOPMs       int
	BitrateMbps int

	// shim-decoy controls (both TCP/UDP):
	DecoyPct int     // legacy percentage
	DecoyRps float64 // per-second rate (sliding window); overrides DecoyPct when >0

	// Extra decoys (UDP only):
	// Either use per-second rate (recommended), or fallback to percentage if rps == 0.
	RTCPSrPct   int     // legacy percentage for RTCP SR
	RTCPRrPct   int     // legacy percentage for RTCP RR
	RTPKeepPct  int     // legacy percentage for pure RTP keepalive
	STUNPct     int     // legacy percentage for STUN Binding
	RTCPSrRps   float64 // per-second rate (sliding window) for RTCP SR
	RTCPRrRps   float64 // per-second rate for RTCP RR
	RTPKeepRps  float64 // per-second rate for pure RTP keepalive
	STUNRps     float64 // per-second rate for STUN Binding

	AESKeyHex   string
	PaceMs      int
	JitterPct   int
	FrameMin    int
	FrameMax    int
	UDPRcvBuf   int
	UDPSndBuf   int
	SessID      uint32
	MetricsAddr string
	PcapPath    string
	PcapMaxMB   int    // Max PCAP size in MB (0 = unlimited)
	SelfDur     time.Duration
	LogLevel    string
	LogDrop     bool

	// WebRTC mode options
	EnableDTLS  bool // simulate DTLS handshake at session start
	AudioRps    int  // audio packets per second (default 50 for Opus 20ms)
	STUNInterval int // STUN consent freshness interval in seconds (default 5)

	// IPCAM mode options
	IPCAMFPS    int // surveillance camera FPS (default 25)
	IPCAMGop    int // GOP size in frames (default 50 = 2 seconds)
}

func defaultConfig() *Config {
	return &Config{
		Role:        RoleServer,
		Mode:        ModeUDP,
		Listen:      ":9001",
		ServerAddr:  "127.0.0.1:9001",
		ForwardAddr: "127.0.0.1:18081",
		Wire:        WireRTPish,
		FPS:         60,
		GOPMs:       2000,
		BitrateMbps: 20,

		// shim decoy
		DecoyPct: 10,
		DecoyRps: 0,

		// legacy percentages (only used if the corresponding RPS is 0)
		RTCPSrPct:  0,
		RTCPRrPct:  0,
		RTPKeepPct: 0,
		STUNPct:    0,

		// RPS default off (0). Set >0 to enable rate scheduling.
		RTCPSrRps:  0,
		RTCPRrRps:  0,
		RTPKeepRps: 0,
		STUNRps:    0,

		PaceMs:      16,   // TCP: base rhythm
		JitterPct:   30,   // 0~100
		FrameMin:    800,  // TCP split
		FrameMax:    1400, // TCP split
		UDPRcvBuf:   1 << 20,
		UDPSndBuf:   1 << 20,
		SessID:      0,
		MetricsAddr: ":9100",
		PcapPath:    "",
		PcapMaxMB:   50,
		SelfDur:     15 * time.Second,
		LogLevel:    "info",
		LogDrop:     false,

		EnableDTLS:   true,
		AudioRps:     50,
		STUNInterval: 5,
		IPCAMFPS:     25,
		IPCAMGop:     50,
	}
}

func parseFlags() *Config {
	cfg := defaultConfig()
	flag.StringVar((*string)(&cfg.Role), "role", string(cfg.Role), "server|client|selftest")
	flag.StringVar((*string)(&cfg.Mode), "mode", string(cfg.Mode), "udp|tcp")
	flag.StringVar(&cfg.Listen, "listen", cfg.Listen, "listen addr")
	flag.StringVar(&cfg.ServerAddr, "server", cfg.ServerAddr, "server addr (client)")
	flag.StringVar(&cfg.ForwardAddr, "forward", cfg.ForwardAddr, "forward addr (server)")
	flag.StringVar((*string)(&cfg.Wire), "wire", string(cfg.Wire), "shim|rtpish|webrtc|ipcam (udp)")
	flag.IntVar(&cfg.FPS, "fps", cfg.FPS, "60|120")
	flag.IntVar(&cfg.GOPMs, "gop", cfg.GOPMs, "keyframe interval ms")
	flag.IntVar(&cfg.BitrateMbps, "bitrate-mbps", cfg.BitrateMbps, "20|40 etc.")

	// shim decoy
	flag.IntVar(&cfg.DecoyPct, "decoy", cfg.DecoyPct, "shim-decoy percent 0-100 (ignored if -decoy-rps>0)")
	flag.Float64Var(&cfg.DecoyRps, "decoy-rps", cfg.DecoyRps, "shim-decoy frames per second (overrides -decoy)")

	// Extra decoys legacy percentages (UDP only; used only if corresponding RPS==0)
	flag.IntVar(&cfg.RTCPSrPct, "rtcp-sr-pct", cfg.RTCPSrPct, "insert RTCP SR decoy percent 0-100 (UDP only; ignored if -rtcp-sr-rps>0)")
	flag.IntVar(&cfg.RTCPRrPct, "rtcp-rr-pct", cfg.RTCPRrPct, "insert RTCP RR decoy percent 0-100 (UDP only; ignored if -rtcp-rr-rps>0)")
	flag.IntVar(&cfg.RTPKeepPct, "rtpkeep-pct", cfg.RTPKeepPct, "insert pure RTP keepalive decoy percent 0-100 (UDP only; ignored if -rtpkeep-rps>0)")
	flag.IntVar(&cfg.STUNPct, "stun-pct", cfg.STUNPct, "insert STUN Binding decoy percent 0-100 (UDP only; ignored if -stun-rps>0)")

	// Extra decoys per-second rates (UDP only; sliding window scheduling)
	flag.Float64Var(&cfg.RTCPSrRps, "rtcp-sr-rps", cfg.RTCPSrRps, "RTCP SR decoys per second (UDP only; overrides -rtcp-sr-pct)")
	flag.Float64Var(&cfg.RTCPRrRps, "rtcp-rr-rps", cfg.RTCPRrRps, "RTCP RR decoys per second (UDP only; overrides -rtcp-rr-pct)")
	flag.Float64Var(&cfg.RTPKeepRps, "rtpkeep-rps", cfg.RTPKeepRps, "pure RTP keepalive decoys per second (UDP only; overrides -rtpkeep-pct)")
	flag.Float64Var(&cfg.STUNRps, "stun-rps", cfg.STUNRps, "STUN Binding decoys per second (UDP only; overrides -stun-pct)")

	flag.StringVar(&cfg.AESKeyHex, "aes", cfg.AESKeyHex, "AES-GCM key hex (optional)")
	flag.IntVar(&cfg.PaceMs, "pace", cfg.PaceMs, "base pace ms (TCP)")
	flag.IntVar(&cfg.JitterPct, "jitter", cfg.JitterPct, "jitter percent")
	flag.IntVar(&cfg.FrameMin, "fmin", cfg.FrameMin, "tcp frame min")
	flag.IntVar(&cfg.FrameMax, "fmax", cfg.FrameMax, "tcp frame max")
	flag.IntVar(&cfg.UDPRcvBuf, "udp-rbuf", cfg.UDPRcvBuf, "udp read buffer")
	flag.IntVar(&cfg.UDPSndBuf, "udp-wbuf", cfg.UDPSndBuf, "udp write buffer")

	// sess flag (uint <-» uint32)
	sessFlag := uint(cfg.SessID)
	flag.UintVar(&sessFlag, "sess", sessFlag, "udp session id (0=random)")

	flag.StringVar(&cfg.MetricsAddr, "metrics", cfg.MetricsAddr, "metrics http addr")
	flag.StringVar(&cfg.PcapPath, "pcap", cfg.PcapPath, "pcap output path (IPv4/UDP RAW + TCP)")
	flag.IntVar(&cfg.PcapMaxMB, "pcap-max-mb", cfg.PcapMaxMB, "max PCAP size in MB (0=unlimited)")
	flag.DurationVar(&cfg.SelfDur, "duration", cfg.SelfDur, "selftest duration")
	flag.StringVar(&cfg.LogLevel, "log", cfg.LogLevel, "debug|info|warn|error")
	flag.BoolVar(&cfg.LogDrop, "showdrop", cfg.LogDrop, "log when dropping decoy")

	// WebRTC mode options
	flag.BoolVar(&cfg.EnableDTLS, "dtls", cfg.EnableDTLS, "simulate DTLS handshake (webrtc mode)")
	flag.IntVar(&cfg.AudioRps, "audio-rps", cfg.AudioRps, "audio packets per second (webrtc mode, default 50)")
	flag.IntVar(&cfg.STUNInterval, "stun-interval", cfg.STUNInterval, "STUN consent interval seconds (webrtc mode)")

	// IPCAM mode options
	flag.IntVar(&cfg.IPCAMFPS, "ipcam-fps", cfg.IPCAMFPS, "surveillance camera FPS (ipcam mode, default 25)")
	flag.IntVar(&cfg.IPCAMGop, "ipcam-gop", cfg.IPCAMGop, "GOP size in frames (ipcam mode, default 50)")

	flag.Parse()

	cfg.SessID = uint32(sessFlag)
	if cfg.Mode == ModeTCP && cfg.Wire != WireShim {
		fmt.Printf("[WARN] wire=%s is only effective in UDP mode, falling back to shim for TCP.\n", cfg.Wire)
	}
	return cfg
}

/* ============ Logging ============ */

type LogLevel int

const (
	LDebug LogLevel = iota
	LInfo
	LWarn
	LError
)

var gLogLevel = LInfo

func setLog(s string) {
	switch strings.ToLower(s) {
	case "debug":
		gLogLevel = LDebug
	case "info":
		gLogLevel = LInfo
	case "warn":
		gLogLevel = LWarn
	case "error":
		gLogLevel = LError
	}
}
func logf(lv LogLevel, f string, a ...any) {
	if lv < gLogLevel {
		return
	}
	ts := time.Now().Format("15:04:05.000")
	p := [...]string{"DEBU", "INFO", "WARN", "ERRO"}[lv]
	fmt.Printf("%s [%s] %s\n", ts, p, fmt.Sprintf(f, a...))
}
func must(err error) {
	if err != nil {
		logf(LError, "fatal: %v", err)
		os.Exit(2)
	}
}

/* ============ Random/Timing ============ */

var grnd *rand.Rand

func init() {
	seed := time.Now().UnixNano()
	var b [8]byte
	if _, err := cryptoRand.Read(b[:]); err == nil {
		seed = int64(binary.BigEndian.Uint64(b[:]))
	}
	grnd = rand.New(rand.NewSource(seed))
}
func randRange(min, max int) int {
	if max <= min {
		return min
	}
	return min + grnd.Intn(max-min+1)
}
func jitterSleep(paceMs, jitterPct int) {
	if paceMs <= 0 {
		return
	}
	j := float64(paceMs) * float64(jitterPct) / 100
	delta := grnd.Float64()*2*j - j
	d := time.Duration(math.Max(0, float64(paceMs)+delta)) * time.Millisecond
	time.Sleep(d)
}

/* ============ Token Bucket (bitrate shaping) ============ */

type tokenBucket struct {
	rate  int64
	burst int64
	tok   int64
	last  time.Time
	mu    sync.Mutex
}

func newTB(mbps int, burst int) *tokenBucket {
	if mbps <= 0 {
		return nil
	}
	return &tokenBucket{
		rate:  int64(mbps) * 1024 * 1024 / 8, // bytes/sec
		burst: int64(burst),
		last:  time.Now(),
	}
}
func (tb *tokenBucket) wait(n int) {
	if tb == nil {
		return
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	now := time.Now()
	el := now.Sub(tb.last).Seconds()
	tb.tok += int64(float64(tb.rate) * el)
	if tb.tok > tb.burst { tb.tok = tb.burst }
	tb.last = now
	need := int64(n)
	for tb.tok < need {
		def := float64(need-tb.tok) / float64(tb.rate)
		sleep := time.Duration(def*1000.0)*time.Millisecond + time.Millisecond
		tb.mu.Unlock()
		time.Sleep(sleep)
		tb.mu.Lock()
		now = time.Now()
		el = now.Sub(tb.last).Seconds()
		tb.tok += int64(float64(tb.rate) * el)
		if tb.tok > tb.burst { tb.tok = tb.burst }
		tb.last = now
	}
	tb.tok -= need
}

/* ============ Per-second sliding-window scheduler for decoys ============ */

type rateLimiter struct {
	rps    float64
	burst  float64
	tokens float64
	last   time.Time
	mu     sync.Mutex
}

func newRL(rps float64) *rateLimiter {
	if rps <= 0 {
		return nil
	}
	burst := rps*1.5 + 1.0 // small burst to smooth boundary effects
	return &rateLimiter{rps: rps, burst: burst, tokens: burst, last: time.Now()}
}

// take up to max tokens (integer). returns how many allowed right now.
func (rl *rateLimiter) takeMax(max int) int {
	if rl == nil {
		return 0
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	el := now.Sub(rl.last).Seconds()
	rl.tokens += el * rl.rps
	if rl.tokens > rl.burst {
		rl.tokens = rl.burst
	}
	rl.last = now
	n := int(math.Floor(rl.tokens))
	if n <= 0 {
		return 0
	}
	if n > max {
		n = max
	}
	rl.tokens -= float64(n)
	return n
}

type decoyRL struct {
	sr   *rateLimiter
	rr   *rateLimiter
	keep *rateLimiter
	stun *rateLimiter
}

func newDecoyRL(cfg *Config, up bool) *decoyRL {
	// Split given total RPS 50/50 into up and down directions.
	f := 0.5
	return &decoyRL{
		sr:   newRL(cfg.RTCPSrRps * f),
		rr:   newRL(cfg.RTCPRrRps * f),
		keep: newRL(cfg.RTPKeepRps * f),
		stun: newRL(cfg.STUNRps * f),
	}
}

/* ============ Shim & RTP-ish headers ============ */

const (
	magicConst uint32 = 0x5C10ADED
	version    uint8  = 1

	modeTCP uint8 = 1
	modeUDP uint8 = 2

	flagDecoy uint8 = 1 << 0
	flagEnc   uint8 = 1 << 1
)

type shimHeader struct {
	Magic     uint32
	Version   uint8
	Mode      uint8
	Flags     uint8
	Reserved  uint8
	SessionID uint32
	TsMs      uint32
	Len       uint32
}

const shimLen = 20

func (h shimHeader) Marshal() []byte {
	b := make([]byte, shimLen)
	binary.BigEndian.PutUint32(b[0:4], h.Magic)
	b[4] = h.Version
	b[5] = h.Mode
	b[6] = h.Flags
	b[7] = h.Reserved
	binary.BigEndian.PutUint32(b[8:12], h.SessionID)
	binary.BigEndian.PutUint32(b[12:16], h.TsMs)
	binary.BigEndian.PutUint32(b[16:20], h.Len)
	return b
}

func parseShimFull(b []byte) (shimHeader, []byte, error) {
	if len(b) < shimLen {
		return shimHeader{}, nil, io.ErrUnexpectedEOF
	}
	h := shimHeader{
		Magic:     binary.BigEndian.Uint32(b[0:4]),
		Version:   b[4],
		Mode:      b[5],
		Flags:     b[6],
		Reserved:  b[7],
		SessionID: binary.BigEndian.Uint32(b[8:12]),
		TsMs:      binary.BigEndian.Uint32(b[12:16]),
		Len:       binary.BigEndian.Uint32(b[16:20]),
	}
	if h.Magic != magicConst || h.Version != version {
		return shimHeader{}, nil, errors.New("bad shim")
	}
	if int(h.Len) > len(b[shimLen:]) {
		return shimHeader{}, nil, errors.New("bad len")
	}
	return h, b[shimLen : shimLen+int(h.Len)], nil
}

// 仅解析头部（TCP 流模式）
func parseShimHeader(hb []byte) (shimHeader, error) {
	if len(hb) < shimLen {
		return shimHeader{}, io.ErrUnexpectedEOF
	}
	h := shimHeader{
		Magic:     binary.BigEndian.Uint32(hb[0:4]),
		Version:   hb[4],
		Mode:      hb[5],
		Flags:     hb[6],
		Reserved:  hb[7],
		SessionID: binary.BigEndian.Uint32(hb[8:12]),
		TsMs:      binary.BigEndian.Uint32(hb[12:16]),
		Len:       binary.BigEndian.Uint32(hb[16:20]),
	}
	if h.Magic != magicConst || h.Version != version {
		return shimHeader{}, errors.New("bad shim header")
	}
	return h, nil
}

// RTP-ish (UDP only)
type rtpState struct{ seq uint16; ssrc uint32 }

func buildRTPHeader(seq uint16, ts uint32, pt uint8, marker bool, ssrc uint32) []byte {
	b := make([]byte, 12)
	b[0] = 0x80 // V=2
	b[1] = pt
	if marker {
		b[1] |= 0x80
	}
	binary.BigEndian.PutUint16(b[2:4], seq)
	binary.BigEndian.PutUint32(b[4:8], ts)
	binary.BigEndian.PutUint32(b[8:12], ssrc)
	return b
}
func stripRTP(b []byte) (pt uint8, marker bool, rest []byte, err error) {
	if len(b) < 12 {
		return 0, false, nil, io.ErrUnexpectedEOF
	}
	if (b[0]>>6)&0x3 != 2 {
		return 0, false, nil, errors.New("rtp ver")
	}
	marker = (b[1] & 0x80) != 0
	pt = b[1] & 0x7F
	return pt, marker, b[12:], nil
}

/* ============ AES-GCM (optional) ============ */

type aeadBox struct{ aead cipher.AEAD }

func newAEAD(hexKey string) (*aeadBox, error) {
	if strings.TrimSpace(hexKey) == "" {
		return nil, nil
	}
	kb, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	switch len(kb) {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("aes key must be 16/24/32 bytes")
	}
	block, err := aes.NewCipher(kb)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &aeadBox{aead: a}, nil
}
func (b *aeadBox) seal(p []byte) (out []byte, nonce []byte, err error) {
	if b == nil {
		return p, nil, nil
	}
	nonce = make([]byte, b.aead.NonceSize())
	if _, err = cryptoRand.Read(nonce); err != nil {
		return nil, nil, err
	}
	c := b.aead.Seal(nil, nonce, p, nil)
	return c, nonce, nil
}
func (b *aeadBox) open(nonce, c []byte) ([]byte, error) {
	if b == nil {
		return c, nil
	}
	return b.aead.Open(nil, nonce, c, nil)
}

/* ============ PCAP Writer (IPv4 RAW, LINKTYPE_RAW=101) ============ */

type pcapWriter struct {
	f         *os.File
	mu        sync.Mutex
	ipID      uint16
	limitBytes int64
	written   int64

	tcpSeq map[string]uint32
}

func newPCAP(path string, maxBytes int64) (*pcapWriter, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	gh := make([]byte, 24)
	binary.BigEndian.PutUint32(gh[0:4], 0xa1b2c3d4)
	binary.BigEndian.PutUint16(gh[4:6], 2)
	binary.BigEndian.PutUint16(gh[6:8], 4)
	binary.BigEndian.PutUint32(gh[16:20], 0xffff)
	binary.BigEndian.PutUint32(gh[20:24], 101) // LINKTYPE_RAW
	if _, err := f.Write(gh); err != nil {
		f.Close()
		return nil, err
	}
	return &pcapWriter{
		f: f, ipID: uint16(rand.Intn(65535)),
		limitBytes: maxBytes, written: 24, // include global header
		tcpSeq: make(map[string]uint32),
	}, nil
}
func (w *pcapWriter) Close() { if w != nil && w.f != nil { _ = w.f.Close() } }

func (w *pcapWriter) canWrite(n int) bool {
	if w == nil {
		return false
	}
	if w.limitBytes <= 0 {
		return true
	}
	return w.written+int64(n) <= w.limitBytes
}
func (w *pcapWriter) writeRecord(frame []byte) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.canWrite(16+len(frame)) {
		return
	}
	now := time.Now()
	pkth := make([]byte, 16)
	binary.BigEndian.PutUint32(pkth[0:4], uint32(now.Unix()))
	binary.BigEndian.PutUint32(pkth[4:8], uint32(now.Nanosecond()/1000))
	binary.BigEndian.PutUint32(pkth[8:12], uint32(len(frame)))
	binary.BigEndian.PutUint32(pkth[12:16], uint32(len(frame)))
	_, _ = w.f.Write(pkth)
	_, _ = w.f.Write(frame)
	w.written += int64(16 + len(frame))
}

func (w *pcapWriter) ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (w *pcapWriter) udpFrame(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, payload []byte) []byte {
	s4 := srcIP.To4()
	d4 := dstIP.To4()
	if s4 == nil || d4 == nil { return nil }
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	udp[6] = 0; udp[7] = 0

	ip := make([]byte, 20)
	ip[0] = (4 << 4) | 5
	ip[1] = 0
	total := 20 + 8 + len(payload)
	binary.BigEndian.PutUint16(ip[2:4], uint16(total))
	w.ipID++
	binary.BigEndian.PutUint16(ip[4:6], w.ipID)
	binary.BigEndian.PutUint16(ip[6:8], 0)
	ip[8] = 64
	ip[9] = 17 // UDP
	copy(ip[12:16], s4)
	copy(ip[16:20], d4)
	cs := w.ipChecksum(ip)
	binary.BigEndian.PutUint16(ip[10:12], cs)

	frame := append(ip, udp...)
	frame = append(frame, payload...)
	return frame
}
func (w *pcapWriter) WriteUDP(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, payload []byte) {
	if w == nil {
		return
	}
	frame := w.udpFrame(srcIP, srcPort, dstIP, dstPort, payload)
	if frame == nil { return }
	w.writeRecord(frame)
}

func key4(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int) string {
	return fmt.Sprintf("%s:%d>%s:%d", srcIP.String(), srcPort, dstIP.String(), dstPort)
}

func checksumTCP(srcIP, dstIP net.IP, tcpHdr, payload []byte) uint16 {
	// pseudo header + tcp header + payload
	s4 := srcIP.To4(); d4 := dstIP.To4()
	var sum uint32
	// pseudo
	sum += uint32(binary.BigEndian.Uint16(s4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(s4[2:4]))
	sum += uint32(binary.BigEndian.Uint16(d4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(d4[2:4]))
	sum += uint32(6) // protocol
	tcpLen := len(tcpHdr) + len(payload)
	sum += uint32(tcpLen)

	// tcp header
	for i := 0; i < len(tcpHdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpHdr[i : i+2]))
	}
	// payload
	for i := 0; i+1 < len(payload); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
	}
	if len(payload)%2 == 1 {
		sum += uint32(uint16(payload[len(payload)-1]) << 8)
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (w *pcapWriter) tcpFrame(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, payload []byte) []byte {
	s4 := srcIP.To4(); d4 := dstIP.To4()
	if s4 == nil || d4 == nil { return nil }

	// maintain a fake seq space per 4-tuple for debug
	w.mu.Lock()
	key := key4(s4, srcPort, d4, dstPort)
	seq := w.tcpSeq[key]
	if seq == 0 {
		seq = uint32(rand.Int31())
	}
	w.tcpSeq[key] = seq + uint32(len(payload))
	w.mu.Unlock()

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcp[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], 0) // ack=0 (we're not modeling handshake)
	tcp[12] = (5 << 4)                      // data offset=5 (20B)
	tcp[13] = 0x08                          // PSH (no ACK to avoid bogus ack=0+ACK)
	binary.BigEndian.PutUint16(tcp[14:16], 65535) // window
	binary.BigEndian.PutUint16(tcp[16:18], 0)     // checksum placeholder
	binary.BigEndian.PutUint16(tcp[18:20], 0)     // urgent

	// IPv4 header
	ip := make([]byte, 20)
	ip[0] = (4 << 4) | 5
	ip[1] = 0
	total := 20 + 20 + len(payload)
	binary.BigEndian.PutUint16(ip[2:4], uint16(total))
	w.ipID++
	binary.BigEndian.PutUint16(ip[4:6], w.ipID)
	binary.BigEndian.PutUint16(ip[6:8], 0)
	ip[8] = 64
	ip[9] = 6 // TCP
	copy(ip[12:16], s4)
	copy(ip[16:20], d4)

	// TCP checksum (needs pseudo header)
	csTCP := checksumTCP(s4, d4, tcp, payload)
	binary.BigEndian.PutUint16(tcp[16:18], csTCP)

	// IP checksum
	csIP := w.ipChecksum(ip)
	binary.BigEndian.PutUint16(ip[10:12], csIP)

	frame := append(ip, tcp...)
	frame = append(frame, payload...)
	return frame
}
func (w *pcapWriter) WriteTCP(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, payload []byte) {
	if w == nil {
		return
	}
	frame := w.tcpFrame(srcIP, srcPort, dstIP, dstPort, payload)
	if frame == nil { return }
	w.writeRecord(frame)
}

/* ============ Common runtime & helpers ============ */

type runtimeCtx struct {
	cfg       *Config
	tb        *tokenBucket
	ae        *aeadBox
	pc        *pcapWriter
	dropLog   bool

	// Extra decoys
	upRL     *decoyRL
	downRL   *decoyRL

	// Shim decoy RPS
	shimUpRL   *rateLimiter
	shimDownRL *rateLimiter
}

func runMetrics(addr string) {
	if addr == "" { return }
	go func() { _ = http.ListenAndServe(addr, nil) }()
}

func ip4OrLoopback(ip net.IP) net.IP {
	v4 := ip.To4()
	if v4 == nil || v4.IsUnspecified() {
		return net.ParseIP("127.0.0.1")
	}
	return v4
}
func max(a, b int) int { if a > b { return a } ; return b }

/* ============ Extra Decoys (UDP only): RTCP SR/RR, RTP keepalive, STUN ============ */

const ntpEpochOffset = 2208988800 // seconds between 1900 and 1970

func buildRTCP_SR(ssrc uint32, rtpTs uint32, pktCount uint32, octCount uint32) []byte {
	// RTCP SR (PT=200), RC=0, length=6 (7 words total: 28 bytes)
	b := make([]byte, 4+24)
	b[0] = 0x80 // V=2, P=0, RC=0
	b[1] = 200  // SR
	binary.BigEndian.PutUint16(b[2:4], 6)
	binary.BigEndian.PutUint32(b[4:8], ssrc)
	now := time.Now()
	sec := uint32(uint64(now.Unix()) + ntpEpochOffset)
	frac := uint32(uint64(now.Nanosecond()) * (1<<32) / 1_000_000_000)
	binary.BigEndian.PutUint32(b[8:12], sec)
	binary.BigEndian.PutUint32(b[12:16], frac)
	binary.BigEndian.PutUint32(b[16:20], rtpTs)
	binary.BigEndian.PutUint32(b[20:24], pktCount)
	binary.BigEndian.PutUint32(b[24:28], octCount)
	return b
}
func buildRTCP_RR(ssrc uint32) []byte {
	// RTCP RR (PT=201), RC=0, length=1 (2 words total: 8 bytes)
	b := make([]byte, 4+4)
	b[0] = 0x80 // V=2, RC=0
	b[1] = 201  // RR
	binary.BigEndian.PutUint16(b[2:4], 1)
	binary.BigEndian.PutUint32(b[4:8], ssrc)
	return b
}
func buildRTPKeepalive(seq uint16, ts uint32, pt uint8, ssrc uint32, payloadLen int) []byte {
	h := buildRTPHeader(seq, ts, pt, false, ssrc)
	if payloadLen < 0 { payloadLen = 0 }
	if payloadLen > 1400 { payloadLen = 1400 }
	if payloadLen == 0 {
		return h
	}
	p := make([]byte, payloadLen)
	_, _ = cryptoRand.Read(p)
	return append(h, p...)
}
func buildSTUNBindingRequest() []byte {
	b := make([]byte, 20)
	// Type: Binding Request 0x0001
	binary.BigEndian.PutUint16(b[0:2], 0x0001)
	// Length: 0 (no attributes)
	binary.BigEndian.PutUint16(b[2:4], 0)
	// Magic cookie
	binary.BigEndian.PutUint32(b[4:8], 0x2112A442)
	// Transaction ID
	_, _ = cryptoRand.Read(b[8:20])
	return b
}

func sendExtraDecoysUDP(conn *net.UDPConn, src *net.UDPAddr, dst *net.UDPAddr, rt *runtimeCtx,
	ssrc uint32, seq *uint16, ts *uint32, step int, upDirection bool) {

	srcIP := ip4OrLoopback(src.IP)
	dstIP := ip4OrLoopback(dst.IP)

	// Choose per-direction rate limiters
	var rl *decoyRL
	if upDirection { rl = rt.upRL } else { rl = rt.downRL }

	const maxBurstPerTick = 3 // avoid huge bursts on long silent gaps

	// --- RTCP SR ---
	if rl != nil && rl.sr != nil {
		n := rl.sr.takeMax(maxBurstPerTick)
		for i := 0; i < n; i++ {
			pktCount := uint32(metricFramesUp.Value())
			octCount := uint32(metricBytesUp.Value())
			sr := buildRTCP_SR(ssrc, *ts, pktCount, octCount)
			rt.tb.wait(len(sr) + 28)
			_, _ = conn.WriteToUDP(sr, dst)
			rt.pc.WriteUDP(srcIP, src.Port, dstIP, dst.Port, sr)
			metricRTCPsrSent.Add(1)
			if rt.dropLog { logf(LDebug, "[extra][rps] RTCP SR %dB (%s)", len(sr), dirStr(upDirection)) }
		}
	} else if rt.cfg.RTCPSrPct > 0 && grnd.Intn(100) < rt.cfg.RTCPSrPct {
		// fallback: percentage
		pktCount := uint32(metricFramesUp.Value())
		octCount := uint32(metricBytesUp.Value())
		sr := buildRTCP_SR(ssrc, *ts, pktCount, octCount)
		rt.tb.wait(len(sr) + 28)
		_, _ = conn.WriteToUDP(sr, dst)
		rt.pc.WriteUDP(srcIP, src.Port, dstIP, dst.Port, sr)
		metricRTCPsrSent.Add(1)
		if rt.dropLog { logf(LDebug, "[extra][pct] RTCP SR %dB (%s)", len(sr), dirStr(upDirection)) }
	}

	// --- RTCP RR ---
	if rl != nil && rl.rr != nil {
		n := rl.rr.takeMax(maxBurstPerTick)
		for i := 0; i < n; i++ {
			rr := buildRTCP_RR(ssrc)
			rt.tb.wait(len(rr) + 28)
			_, _ = conn.WriteToUDP(rr, dst)
			rt.pc.WriteUDP(srcIP, src.Port, dstIP, dst.Port, rr)
			metricRTCPrrSent.Add(1)
			if rt.dropLog { logf(LDebug, "[extra][rps] RTCP RR %dB (%s)", len(rr), dirStr(upDirection)) }
		}
	} else if rt.cfg.RTCPRrPct > 0 && grnd.Intn(100) < rt.cfg.RTCPRrPct {
		rr := buildRTCP_RR(ssrc)
		rt.tb.wait(len(rr) + 28)
		_, _ = conn.WriteToUDP(rr, dst)
		rt.pc.WriteUDP(srcIP, src.Port, dstIP, dst.Port, rr)
		metricRTCPrrSent.Add(1)
		if rt.dropLog { logf(LDebug, "[extra][pct] RTCP RR %dB (%s)", len(rr), dirStr(upDirection)) }
	}

	// --- pure RTP keepalive ---
	if rl != nil && rl.keep != nil {
		n := rl.keep.takeMax(maxBurstPerTick)
		for i := 0; i < n; i++ {
			*seq = *seq + 1
			*ts = *ts + uint32(step)
			rtp := buildRTPKeepalive(*seq, *ts, 13, ssrc, randRange(0, 60))
			rt.tb.wait(len(rtp) + 28)
			_, _ = conn.WriteToUDP(rtp, dst)
			rt.pc.WriteUDP(srcIP, src.Port, dstIP, dst.Port, rtp)
			metricRTPkeepSent.Add(1)
			if rt.dropLog { logf(LDebug, "[extra][rps] RTP keepalive %dB (%s)", len(rtp), dirStr(upDirection)) }
		}
	} else if rt.cfg.RTPKeepPct > 0 && grnd.Intn(100) < rt.cfg.RTPKeepPct {
		*seq = *seq + 1
		*ts = *ts + uint32(step)
		rtp := buildRTPKeepalive(*seq, *ts, 13, ssrc, randRange(0, 60))
		rt.tb.wait(len(rtp) + 28)
		_, _ = conn.WriteToUDP(rtp, dst)
		rt.pc.WriteUDP(srcIP, src.Port, dstIP, dst.Port, rtp)
		metricRTPkeepSent.Add(1)
		if rt.dropLog { logf(LDebug, "[extra][pct] RTP keepalive %dB (%s)", len(rtp), dirStr(upDirection)) }
	}

	// --- STUN Binding ---
	if rl != nil && rl.stun != nil {
		n := rl.stun.takeMax(maxBurstPerTick)
		for i := 0; i < n; i++ {
			stun := buildSTUNBindingRequest()
			rt.tb.wait(len(stun) + 28)
			_, _ = conn.WriteToUDP(stun, dst)
			rt.pc.WriteUDP(srcIP, src.Port, dstIP, dst.Port, stun)
			metricSTUNSent.Add(1)
			if rt.dropLog { logf(LDebug, "[extra][rps] STUN binding %dB (%s)", len(stun), dirStr(upDirection)) }
		}
	} else if rt.cfg.STUNPct > 0 && grnd.Intn(100) < rt.cfg.STUNPct {
		stun := buildSTUNBindingRequest()
		rt.tb.wait(len(stun) + 28)
		_, _ = conn.WriteToUDP(stun, dst)
		rt.pc.WriteUDP(srcIP, src.Port, dstIP, dst.Port, stun)
		metricSTUNSent.Add(1)
		if rt.dropLog { logf(LDebug, "[extra][pct] STUN binding %dB (%s)", len(stun), dirStr(upDirection)) }
	}
}
func dirStr(up bool) string {
	if up { return "up" }
	return "down"
}

/* ============ UDP Client/Server ============ */

func runUDPClient(ctx context.Context, rt *runtimeCtx) error {
	laddr, err := net.ResolveUDPAddr("udp", rt.cfg.Listen)
	if err != nil { return err }
	uc, err := net.ListenUDP("udp", laddr)
	if err != nil { return err }
	defer uc.Close()
	if rt.cfg.UDPRcvBuf > 0 { _ = uc.SetReadBuffer(rt.cfg.UDPRcvBuf) }
	if rt.cfg.UDPSndBuf > 0 { _ = uc.SetWriteBuffer(rt.cfg.UDPSndBuf) }
	saddr, err := net.ResolveUDPAddr("udp", rt.cfg.ServerAddr)
	if err != nil { return err }

	sess := rt.cfg.SessID
	if sess == 0 { sess = grnd.Uint32() }
	logf(LInfo, "[client][udp] %s -> server %s (sess=%d, wire=%s, %dfps, %dMbps)",
		rt.cfg.Listen, rt.cfg.ServerAddr, sess, rt.cfg.Wire, rt.cfg.FPS, rt.cfg.BitrateMbps)

	var appPeerMu sync.RWMutex
	var appPeer *net.UDPAddr

	// RTP 累加
	var rtp = rtpState{seq: uint16(grnd.Uint32()), ssrc: grnd.Uint32()}
	var rtpTs uint32
	step := 90000 / max(1, rt.cfg.FPS)

	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil { return }

			// 来自 server：解壳 -> 发给应用
			if from.IP.Equal(saddr.IP) && from.Port == saddr.Port {
				raw := append([]byte(nil), buf[:n]...)
				src := ip4OrLoopback(from.IP)
				dst := ip4OrLoopback(uc.LocalAddr().(*net.UDPAddr).IP)
				rt.pc.WriteUDP(src, from.Port, dst, uc.LocalAddr().(*net.UDPAddr).Port, raw)

				// Skip DTLS/STUN control packets (not data)
				if isDTLSRange(raw[0]) || isSTUNPacket(raw) { continue }

				h, payload, e2 := decodeUDPFrame(rt.cfg, rt.ae, raw, sess)
				if e2 != nil { continue }
				if (h.Flags & flagDecoy) != 0 {
					metricDecoyDropped.Add(1)
					if rt.dropLog { logf(LDebug, "[client] drop decoy %dB", len(payload)) }
					continue
				}
				appPeerMu.RLock(); dstPeer := appPeer; appPeerMu.RUnlock()
				if dstPeer != nil {
					_, _ = uc.WriteToUDP(payload, dstPeer)
					metricFramesDown.Add(1); metricBytesDown.Add(int64(len(payload)))
				}
				continue
			}

			// 来自应用：加壳 -> 先发真实帧，再插播 shim 诱饵（RPS 优先）→ 插播额外伪报文
			appPeerMu.Lock(); appPeer = from; appPeerMu.Unlock()
			p := append([]byte(nil), buf[:n]...)

			// a) 真实帧
			var twccSeq uint32
			frame := encodeUDPFrame(rt.cfg, rt.ae, &rtp, &rtpTs, step, sess, p, false, &twccSeq)
			rt.tb.wait(len(frame) + 28)
			_, _ = uc.WriteToUDP(frame, saddr)
			metricFramesUp.Add(1); metricBytesUp.Add(int64(n))
			srcIP := ip4OrLoopback(uc.LocalAddr().(*net.UDPAddr).IP)
			dstIP := ip4OrLoopback(saddr.IP)
			rt.pc.WriteUDP(srcIP, uc.LocalAddr().(*net.UDPAddr).Port, dstIP, saddr.Port, frame)

			// b) shim 诱饵
			sendDecoy := false
			if rt.shimUpRL != nil && rt.shimUpRL.takeMax(1) > 0 { sendDecoy = true
			} else if rt.cfg.DecoyRps <= 0 && grnd.Intn(100) < rt.cfg.DecoyPct { sendDecoy = true }
			if sendDecoy {
				djunk := make([]byte, len(p))
				_, _ = cryptoRand.Read(djunk)
				df := encodeUDPFrame(rt.cfg, rt.ae, &rtp, &rtpTs, step, sess, djunk, true, &twccSeq)
				rt.tb.wait(len(df) + 28)
				_, _ = uc.WriteToUDP(df, saddr)
				metricFramesUp.Add(1); metricShimDecoySent.Add(1)
				rt.pc.WriteUDP(srcIP, uc.LocalAddr().(*net.UDPAddr).Port, dstIP, saddr.Port, df)
			}

			// c) 额外伪报文（无 shim；RTCP / pure RTP / STUN）
			sendExtraDecoysUDP(uc, uc.LocalAddr().(*net.UDPAddr), saddr, rt, rtp.ssrc, &rtp.seq, &rtpTs, step, true)

			// 节奏（fps）
			base := 1000 / max(1, rt.cfg.FPS)
			jitterSleep(base, rt.cfg.JitterPct)
		}
	}()

	<-ctx.Done()
	return nil
}

type udpSess struct {
	client *net.UDPAddr
	target *net.UDPConn
	last   int64
}

func runUDPServer(ctx context.Context, rt *runtimeCtx) error {
	laddr, err := net.ResolveUDPAddr("udp", rt.cfg.Listen); if err != nil { return err }
	ln, err := net.ListenUDP("udp", laddr); if err != nil { return err }
	defer ln.Close()
	if rt.cfg.UDPRcvBuf > 0 { _ = ln.SetReadBuffer(rt.cfg.UDPRcvBuf) }
	if rt.cfg.UDPSndBuf > 0 { _ = ln.SetWriteBuffer(rt.cfg.UDPSndBuf) }
	fwd, err := net.ResolveUDPAddr("udp", rt.cfg.ForwardAddr); if err != nil { return err }
	logf(LInfo, "[server][udp] %s -> %s (wire=%s, %dfps, %dMbps)",
		rt.cfg.Listen, rt.cfg.ForwardAddr, rt.cfg.Wire, rt.cfg.FPS, rt.cfg.BitrateMbps)

	type key struct{ ip string; port int; sess uint32 }
	var mu sync.Mutex
	smap := map[key]*udpSess{}

	// session GC
	go func() {
		t := time.NewTicker(60 * time.Second)
		for {
			select {
			case <-t.C:
				now := time.Now().Unix()
				mu.Lock()
				for k, s := range smap {
					if now-atomic.LoadInt64(&s.last) > 300 {
						if s.target != nil { s.target.Close() }
						delete(smap, k)
						metricSessions.Add(-1)
					}
				}
				mu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()

	buf := make([]byte, 64<<10)
	for {
		n, caddr, err := ln.ReadFromUDP(buf)
		if err != nil {
			select { case <-ctx.Done(): return nil ; default: return err }
		}
		raw := append([]byte(nil), buf[:n]...)
		src := ip4OrLoopback(caddr.IP)
		dst := ip4OrLoopback(ln.LocalAddr().(*net.UDPAddr).IP)
		rt.pc.WriteUDP(src, caddr.Port, dst, ln.LocalAddr().(*net.UDPAddr).Port, raw)

		// Skip DTLS/STUN control packets
		if len(raw) > 0 && (isDTLSRange(raw[0]) || isSTUNPacket(raw)) { continue }

		h, p, e2 := decodeUDPFrame(rt.cfg, rt.ae, raw, 0)
		if e2 != nil { continue }
		k := key{ip: caddr.IP.String(), port: caddr.Port, sess: h.SessionID}

		if (h.Flags & flagDecoy) != 0 {
			metricDecoyDropped.Add(1)
			if rt.dropLog { logf(LDebug, "[server] drop shim-decoy %dB", len(p)) }
			continue
		}

		mu.Lock()
		sess := smap[k]
		if sess == nil {
			tconn, err := net.DialUDP("udp", nil, fwd)
			if err != nil { mu.Unlock(); continue }
			sess = &udpSess{client: caddr, target: tconn, last: time.Now().Unix()}
			smap[k] = sess; metricSessions.Add(1)

			// 回程：目标 -> client（真实帧 + shim诱饵 + 额外伪报文）
			go func(k key, s *udpSess) {
				b := make([]byte, 64<<10)
				// RTP 构造（用于 RTP-ish + keepalive）
				var rtp = rtpState{seq: uint16(grnd.Uint32()), ssrc: grnd.Uint32()}
				var rtpTs uint32
				step := 90000 / max(1, rt.cfg.FPS)

				for {
					n2, _, e2 := s.target.ReadFromUDP(b)
					if e2 != nil { return }
					pp := append([]byte(nil), b[:n2]...)

					// a) 真实帧
					var twccSeq uint32
					pkt := encodeUDPFrame(rt.cfg, rt.ae, &rtp, &rtpTs, step, k.sess, pp, false, &twccSeq)
					rt.tb.wait(len(pkt) + 28)
					_, _ = ln.WriteToUDP(pkt, s.client)
					metricFramesDown.Add(1); metricBytesDown.Add(int64(n2))
					src2 := ip4OrLoopback(ln.LocalAddr().(*net.UDPAddr).IP)
					dst2 := ip4OrLoopback(s.client.IP)
					rt.pc.WriteUDP(src2, ln.LocalAddr().(*net.UDPAddr).Port, dst2, s.client.Port, pkt)

					// b) shim 诱饵
					sendDecoy := false
					if rt.shimDownRL != nil && rt.shimDownRL.takeMax(1) > 0 { sendDecoy = true
					} else if rt.cfg.DecoyRps <= 0 && grnd.Intn(100) < rt.cfg.DecoyPct { sendDecoy = true }
					if sendDecoy {
						djunk := make([]byte, len(pp))
						_, _ = cryptoRand.Read(djunk)
						df := encodeUDPFrame(rt.cfg, rt.ae, &rtp, &rtpTs, step, k.sess, djunk, true, &twccSeq)
						rt.tb.wait(len(df) + 28)
						_, _ = ln.WriteToUDP(df, s.client)
						metricFramesDown.Add(1); metricShimDecoySent.Add(1)
						rt.pc.WriteUDP(src2, ln.LocalAddr().(*net.UDPAddr).Port, dst2, s.client.Port, df)
					}

					// c) 额外伪报文（无 shim；RTCP / pure RTP / STUN），发往 client
					sendExtraDecoysUDP(ln, ln.LocalAddr().(*net.UDPAddr), s.client, rt, rtp.ssrc, &rtp.seq, &rtpTs, step, false)

					// 节奏（fps）
					base := 1000 / max(1, rt.cfg.FPS)
					jitterSleep(base, rt.cfg.JitterPct)
				}
			}(k, sess)
		}
		atomic.StoreInt64(&sess.last, time.Now().Unix())
		mu.Unlock()

		// 发往真实目标（原始负载）
		rt.tb.wait(len(p) + 28)
		_, _ = sess.target.Write(p)
		metricFramesUp.Add(1); metricBytesUp.Add(int64(len(p)))
	}
}

/* ============ TCP Client/Server ============ */

// Client：应用<->(加/解壳)<->Server
func runTCPClient(ctx context.Context, rt *runtimeCtx) error {
	ln, err := net.Listen("tcp", rt.cfg.Listen); if err != nil { return err }
	defer ln.Close()
	logf(LInfo, "[client][tcp] %s -> server %s", rt.cfg.Listen, rt.cfg.ServerAddr)
	for {
		ac, err := ln.Accept()
		if err != nil { select { case <-ctx.Done(): return nil ; default: return err } }
		go func(app net.Conn) {
			defer app.Close()
			s, err := net.Dial("tcp", rt.cfg.ServerAddr); if err != nil { return }
			defer s.Close()
			// app->server: 加壳（写入 s，记录 TCP PCAP）
			go tcpUp(app, s, rt)
			// server->app: 解壳（从 s 读网络帧，记录 TCP PCAP）
			tcpDown(s, app, rt)
		}(ac)
	}
}

// Server：client<-(加/解壳)->target（注意方向）
func runTCPServer(ctx context.Context, rt *runtimeCtx) error {
	ln, err := net.Listen("tcp", rt.cfg.Listen); if err != nil { return err }
	defer ln.Close()
	logf(LInfo, "[server][tcp] %s -> %s", rt.cfg.Listen, rt.cfg.ForwardAddr)
	for {
		c, err := ln.Accept()
		if err != nil { select { case <-ctx.Done(): return nil ; default: return err } }
		go func(cli net.Conn) {
			defer cli.Close()
			dst, err := net.Dial("tcp", rt.cfg.ForwardAddr)
			if err != nil { logf(LError, "dial forward: %v", err); return }
			defer dst.Close()

			// 从 client 读带壳 -> 解壳 -> 写给目标（记录来自 cli 的网络帧）
			go tcpDown(cli, dst, rt)
			// 从目标读原始 -> 加壳 -> 回 client（记录写给 cli 的网络帧）
			tcpUp(dst, cli, rt)
		}(c)
	}
}

// tcpUp：从 r 读“原始数据”，分片+抖动+（可选）加密，封成带壳帧写给 w（网络 conn）
// 诱饵为“插播”（RPS 优先），不影响真实流
func tcpUp(r net.Conn, w net.Conn, rt *runtimeCtx) {
	buf := make([]byte, 64<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			p := append([]byte(nil), buf[:n]...)
			parts := splitTCP(p, rt.cfg.FrameMin, rt.cfg.FrameMax)
			for _, ck := range parts {
				// a) 真实帧
				realFlags := uint8(0)
				realPayload := ck
				if rt.ae != nil {
					if c, nonce, e := rt.ae.seal(realPayload); e == nil {
						realPayload = append(nonce, c...)
						realFlags |= flagEnc
					}
				}
				h := shimHeader{Magic: magicConst, Version: version, Mode: modeTCP, Flags: realFlags,
					SessionID: grnd.Uint32(), TsMs: uint32(time.Now().UnixMilli()), Len: uint32(len(realPayload))}
				frame := append(h.Marshal(), realPayload...)
				rt.tb.wait(len(frame))
				if _, err := w.Write(frame); err != nil { return }
				metricFramesUp.Add(1); metricBytesUp.Add(int64(len(ck)))

				// TCP PCAP（网络方向：w.Local->w.Remote）
				if rt.pc != nil {
					if la, ok1 := w.LocalAddr().(*net.TCPAddr); ok1 {
						if ra, ok2 := w.RemoteAddr().(*net.TCPAddr); ok2 {
							rt.pc.WriteTCP(ip4OrLoopback(la.IP), la.Port, ip4OrLoopback(ra.IP), ra.Port, frame)
						}
					}
				}

				jitterSleep(rt.cfg.PaceMs, rt.cfg.JitterPct)

				// b) shim 诱饵插播（RPS 优先，否则百分比）
				sendDecoy := false
				if rt.shimUpRL != nil && rt.shimUpRL.takeMax(1) > 0 { sendDecoy = true
				} else if rt.cfg.DecoyRps <= 0 && grnd.Intn(100) < rt.cfg.DecoyPct { sendDecoy = true }
				if sendDecoy {
					djunk := make([]byte, len(ck))
					_, _ = cryptoRand.Read(djunk)
					decFlags := uint8(flagDecoy)
					decPayload := djunk
					if rt.ae != nil {
						if c, nonce, e := rt.ae.seal(decPayload); e == nil {
							decPayload = append(nonce, c...)
							decFlags |= flagEnc
						}
					}
					hd := shimHeader{Magic: magicConst, Version: version, Mode: modeTCP, Flags: decFlags,
						SessionID: grnd.Uint32(), TsMs: uint32(time.Now().UnixMilli()), Len: uint32(len(decPayload))}
					f2 := append(hd.Marshal(), decPayload...)
					rt.tb.wait(len(f2))
					if _, err := w.Write(f2); err != nil { return }
					metricFramesUp.Add(1); metricShimDecoySent.Add(1)

					// PCAP 记录诱饵
					if rt.pc != nil {
						if la, ok1 := w.LocalAddr().(*net.TCPAddr); ok1 {
							if ra, ok2 := w.RemoteAddr().(*net.TCPAddr); ok2 {
								rt.pc.WriteTCP(ip4OrLoopback(la.IP), la.Port, ip4OrLoopback(ra.IP), ra.Port, f2)
							}
						}
					}
				}
			}
		}
		if err != nil { return }
	}
}

// tcpDown：从 r（网络 conn）读“带壳帧”，解壳后写给 w（应用或另一侧网络）
// 同时用 r 的 5元组记录“入向”PCAP（debug）
func tcpDown(r net.Conn, w net.Conn, rt *runtimeCtx) {
	for {
		hb := make([]byte, shimLen)
		if _, err := io.ReadFull(r, hb); err != nil { return }
		h, err := parseShimHeader(hb)
		if err != nil { return }
		payload := make([]byte, h.Len)
		if _, err := io.ReadFull(r, payload); err != nil { return }

		// PCAP 记录“网络入向”帧（按 r.Local->r.Remote）
		if rt.pc != nil {
			if la, ok1 := r.LocalAddr().(*net.TCPAddr); ok1 {
				if ra, ok2 := r.RemoteAddr().(*net.TCPAddr); ok2 {
					frame := append(append([]byte{}, hb...), payload...)
					rt.pc.WriteTCP(ip4OrLoopback(la.IP), la.Port, ip4OrLoopback(ra.IP), ra.Port, frame)
				}
			}
		}

		if (h.Flags & flagDecoy) != 0 {
			metricDecoyDropped.Add(1)
			if rt.dropLog { logf(LDebug, "drop shim-decoy %dB", len(payload)) }
			continue
		}
		if (h.Flags & flagEnc) != 0 && rt.ae != nil {
			ns := rt.ae.aead.NonceSize()
			if len(payload) >= ns {
				if plain, e := rt.ae.open(payload[:ns], payload[ns:]); e == nil {
					payload = plain
				}
			}
		}
		if _, err := w.Write(payload); err != nil { return }
		metricFramesDown.Add(1); metricBytesDown.Add(int64(len(payload)))
	}
}

func splitTCP(buf []byte, min, max int) [][]byte {
	if min <= 0 { min = 800 }
	if max < min { max = min }
	var out [][]byte
	for len(buf) > 0 {
		n := randRange(min, max)
		if n > len(buf) { n = len(buf) }
		out = append(out, append([]byte(nil), buf[:n]...))
		buf = buf[n:]
	}
	return out
}

/* ============ Self-test (UDP) ============ */

func runSelfTest(cfg *Config) {
	setLog(cfg.LogLevel)
	tb := newTB(cfg.BitrateMbps, 512*1024)
	ae, _ := newAEAD(cfg.AESKeyHex)
	pc, _ := newPCAP(cfg.PcapPath, int64(cfg.PcapMaxMB)*1024*1024)

	// build runtime with decoy RL
	upRL := newDecoyRL(cfg, true)
	downRL := newDecoyRL(cfg, false)
	shimUp := newRL(cfg.DecoyRps * 0.5)
	shimDown := newRL(cfg.DecoyRps * 0.5)

	rt := &runtimeCtx{
		cfg: cfg, tb: tb, ae: ae, pc: pc, dropLog: cfg.LogDrop,
		upRL: upRL, downRL: downRL,
		shimUpRL: shimUp, shimDownRL: shimDown,
	}
	defer func() { if pc != nil { pc.Close() } }()

	// 内置 UDP Echo 目标（在 forward 上）
	go func() {
		addr, _ := net.ResolveUDPAddr("udp", cfg.ForwardAddr)
		ln, err := net.ListenUDP("udp", addr)
		if err != nil { logf(LError, "echo bind: %v", err); return }
		defer ln.Close()
		buf := make([]byte, 64<<10)
		for {
			n, from, err := ln.ReadFromUDP(buf); if err != nil { return }
			_, _ = ln.WriteToUDP(buf[:n], from)
		}
	}()

	// Server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = runUDPServer(ctx, rt) }()

	// Client
	ccfg := *cfg
	ccfg.Role = RoleClient
	ccfg.Listen = ":7001"
	rtC := &runtimeCtx{
		cfg: &ccfg, tb: tb, ae: ae, pc: pc, dropLog: cfg.LogDrop,
		upRL: upRL, downRL: downRL,
		shimUpRL: shimUp, shimDownRL: shimDown,
	}
	go func() { _ = runUDPClient(ctx, rtC) }()

	// 负载发生器（应用 -> client.listen）
	go func() {
		dst, _ := net.ResolveUDPAddr("udp", ccfg.Listen)
		c, err := net.DialUDP("udp", nil, dst); if err != nil { return }
		defer c.Close()
		fps := max(1, cfg.FPS)
		avgBytesPerSec := cfg.BitrateMbps * 1024 * 1024 / 8
		avgPerFrame := avgBytesPerSec / fps
		ticker := time.NewTicker(time.Second / time.Duration(fps))
		defer ticker.Stop()
		lastKey := time.Now()
		for {
			select {
			case <-ticker.C:
				var size int
				isKey := time.Since(lastKey) >= time.Duration(cfg.GOPMs)*time.Millisecond
				if isKey {
					lastKey = time.Now()
					size = int(float64(avgPerFrame)*2.5) + randRange(2000, 6000)
				} else {
					size = int(float64(avgPerFrame)*0.6) + randRange(300, 1500)
				}
				if size < 200 { size = 200 }
				payload := make([]byte, size)
				_, _ = cryptoRand.Read(payload)
				_, _ = c.Write(payload)
			case <-ctx.Done():
				return
			}
		}
	}()

	logf(LInfo, "[selftest] running %v ...", cfg.SelfDur)
	time.Sleep(cfg.SelfDur)
	cancel()
	logf(LInfo, "[selftest] done. pcap=%s  metrics on %s (/debug/vars)", cfg.PcapPath, cfg.MetricsAddr)
}

/* ============ main ============ */

func main() {
	cfg := parseFlags()
	setLog(cfg.LogLevel)
	runMetrics(cfg.MetricsAddr)

	switch cfg.Role {
	case RoleSelf:
		runSelfTest(cfg)
		return
	}

	tb := newTB(cfg.BitrateMbps, 512*1024)
	ae, err := newAEAD(cfg.AESKeyHex); must(err)
	pc, err := newPCAP(cfg.PcapPath, int64(cfg.PcapMaxMB)*1024*1024); must(err)

	// build runtime with decoy RL
	upRL := newDecoyRL(cfg, true)
	downRL := newDecoyRL(cfg, false)
	shimUp := newRL(cfg.DecoyRps * 0.5)
	shimDown := newRL(cfg.DecoyRps * 0.5)

	rt := &runtimeCtx{
		cfg: cfg, tb: tb, ae: ae, pc: pc, dropLog: cfg.LogDrop,
		upRL: upRL, downRL: downRL,
		shimUpRL: shimUp, shimDownRL: shimDown,
	}
	defer func() { if pc != nil { pc.Close() } }()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	switch cfg.Role {
	case RoleClient:
		switch cfg.Mode {
		case ModeUDP: must(runUDPClient(ctx, rt))
		case ModeTCP: must(runTCPClient(ctx, rt))
		default: must(fmt.Errorf("unknown mode"))
		}
	case RoleServer:
		switch cfg.Mode {
		case ModeUDP: must(runUDPServer(ctx, rt))
		case ModeTCP: must(runTCPServer(ctx, rt))
		default: must(fmt.Errorf("unknown mode"))
		}
	default:
		must(fmt.Errorf("unknown role"))
	}
}
