package main

import (
	cryptoRand "crypto/rand"
	"encoding/binary"
	"errors"
	"math/rand"
	"time"
)

/* ============ IPCAM Wire Format: H.264 over RTP (RFC 6184) ============ */
// Simulates surveillance camera (Hikvision/Dahua style) streaming to NVR/VMS.
// Single video stream, PT=96, FU-A fragmentation, STAP-A for SPS/PPS.

const (
	ipcamPT       uint8  = 96   // dynamic payload type for H.264
	ipcamClockHz  uint32 = 90000
	ipcamMTU             = 1400 // max RTP payload per fragment
	ipcamRTPHdrSz        = 12
)

// H.264 NAL unit types
const (
	nalNonIDR uint8 = 1  // P-frame slice
	nalIDR    uint8 = 5  // I-frame (IDR)
	nalSPS    uint8 = 7
	nalPPS    uint8 = 8
	nalSTAPA  uint8 = 24 // STAP-A aggregation
	nalFUA    uint8 = 28 // FU-A fragmentation
)

/* ---------- GOP State Machine ---------- */

type gopState struct {
	frameNum int    // frame within GOP (0 = I-frame)
	gopSize  int    // frames per GOP (default 50 for 25fps * 2s)
	fps      int    // typically 25
	ssrc     uint32
	seq      uint16
	ts       uint32
	tsStep   uint32 // 90000/fps = 3600 for 25fps
	pktCount uint32
	octCount uint32
}

func newGopState(fps int, ssrc uint32) *gopState {
	if fps <= 0 {
		fps = 25
	}
	return &gopState{
		frameNum: 0,
		gopSize:  fps * 2, // I-frame every 2 seconds
		fps:      fps,
		ssrc:     ssrc,
		seq:      uint16(rand.Intn(0xFFFF)),
		ts:       uint32(rand.Intn(0xFFFFFF)),
		tsStep:   ipcamClockHz / uint32(fps),
	}
}

/* ---------- RTP Header builder (IPCAM, no extensions) ---------- */

func buildIPCAMRTPHeader(seq uint16, ts uint32, marker bool, ssrc uint32) []byte {
	b := make([]byte, ipcamRTPHdrSz)
	b[0] = 0x80 // V=2, P=0, X=0, CC=0
	b[1] = ipcamPT
	if marker {
		b[1] |= 0x80
	}
	binary.BigEndian.PutUint16(b[2:4], seq)
	binary.BigEndian.PutUint32(b[4:8], ts)
	binary.BigEndian.PutUint32(b[8:12], ssrc)
	return b
}

/* ---------- SPS/PPS STAP-A Packet ---------- */

func buildSTAPA_SPS_PPS() []byte {
	// Fake SPS: High profile, Level 4.0, 1080p indicators (26 bytes)
	sps := make([]byte, 26)
	sps[0] = 0x67 // SPS NAL header (forbidden=0, NRI=3, Type=7)
	sps[1] = 0x64 // profile_idc = High (100)
	sps[2] = 0x00 // constraint flags
	sps[3] = 0x28 // level_idc = 4.0
	_, _ = cryptoRand.Read(sps[4:]) // plausible bitstream tail

	// Fake PPS: 4 bytes
	pps := []byte{0x68, 0xEE, 0x3C, 0x80}

	// STAP-A: indicator(1) + spsLen(2) + sps + ppsLen(2) + pps
	payload := make([]byte, 0, 1+2+len(sps)+2+len(pps))
	payload = append(payload, 0x78) // F=0, NRI=11, Type=24 (STAP-A)
	payload = append(payload, byte(len(sps)>>8), byte(len(sps)))
	payload = append(payload, sps...)
	payload = append(payload, byte(len(pps)>>8), byte(len(pps)))
	payload = append(payload, pps...)
	return payload
}

/* ---------- FU-A Fragmentation ---------- */

func (g *gopState) buildFUAFragments(nalType uint8, totalSize int) [][]byte {
	if totalSize < 1 {
		totalSize = 1
	}

	// FU indicator: forbidden(0) | NRI(2bits) | Type=28(FU-A)
	var fuIndicator uint8
	switch nalType {
	case nalIDR:
		fuIndicator = 0x7C // NRI=11, Type=28
	default:
		fuIndicator = 0x5C // NRI=10, Type=28
	}

	// Generate fake NAL payload (random bytes simulating H.264 bitstream)
	nalPayload := make([]byte, totalSize)
	_, _ = cryptoRand.Read(nalPayload)

	maxFrag := ipcamMTU - 2 // 2 bytes for FU indicator + FU header
	var packets [][]byte
	off := 0

	for off < len(nalPayload) {
		end := off + maxFrag
		if end > len(nalPayload) {
			end = len(nalPayload)
		}
		isFirst := off == 0
		isLast := end == len(nalPayload)

		// FU header: S(1) | E(1) | R(0) | Type(5)
		var fuHeader uint8
		fuHeader = nalType & 0x1F
		if isFirst {
			fuHeader |= 0x80 // S=1
		}
		if isLast {
			fuHeader |= 0x40 // E=1
		}

		// RTP header (marker=1 on last fragment of frame)
		rtp := buildIPCAMRTPHeader(g.seq, g.ts, isLast, g.ssrc)
		g.seq++

		// Assemble: RTP header + FU indicator + FU header + payload fragment
		pkt := make([]byte, 0, ipcamRTPHdrSz+2+end-off)
		pkt = append(pkt, rtp...)
		pkt = append(pkt, fuIndicator, fuHeader)
		pkt = append(pkt, nalPayload[off:end]...)

		packets = append(packets, pkt)
		g.pktCount++
		g.octCount += uint32(len(pkt) - ipcamRTPHdrSz)

		off = end
	}
	return packets
}

/* ---------- Frame Size Simulation ---------- */

func ipcamFrameSize(isIFrame bool, bitrateMbps int, fps int) int {
	if fps <= 0 {
		fps = 25
	}
	if bitrateMbps <= 0 {
		bitrateMbps = 4
	}
	bytesPerSec := bitrateMbps * 1024 * 1024 / 8

	if isIFrame {
		// I-frame ~8x average P-frame
		base := bytesPerSec / fps * 8
		if base < 40960 {
			base = 40960
		}
		return base
	}

	// P-frame: average bitrate portion with ±30% VBR
	base := float64(bytesPerSec) / float64(fps) * 0.8
	jitter := base * 0.3 * (rand.Float64()*2 - 1) // ±30%

	// Occasional motion spike (10% chance, 1.5x)
	if rand.Intn(10) == 0 {
		base *= 1.5
	}

	size := int(base + jitter)
	if size < 200 {
		size = 200
	}
	return size
}

/* ---------- Generate One Video Frame ---------- */

func (g *gopState) generateFrame(isIFrame bool) [][]byte {
	var packets [][]byte

	if isIFrame {
		// SPS+PPS as STAP-A before IDR
		stapa := buildSTAPA_SPS_PPS()
		rtp := buildIPCAMRTPHeader(g.seq, g.ts, false, g.ssrc)
		g.seq++
		g.pktCount++
		g.octCount += uint32(len(stapa))
		pkt := append(rtp, stapa...)
		packets = append(packets, pkt)

		// IDR slice fragments
		idrSize := ipcamFrameSize(true, 4, g.fps)
		packets = append(packets, g.buildFUAFragments(nalIDR, idrSize)...)
	} else {
		// Non-IDR (P-frame) fragments
		pSize := ipcamFrameSize(false, 4, g.fps)
		packets = append(packets, g.buildFUAFragments(nalNonIDR, pSize)...)
	}

	// Advance timestamp for next frame
	g.ts += g.tsStep

	return packets
}

/* ---------- Wrap Shim Inside FU-A Payload ---------- */

func (g *gopState) wrapPayloadAsIPCAM(shimFrame []byte) [][]byte {
	isIFrame := g.frameNum == 0

	// Determine target frame size for camouflage
	var targetSize int
	if isIFrame {
		targetSize = ipcamFrameSize(true, 4, g.fps)
	} else {
		targetSize = ipcamFrameSize(false, 4, g.fps)
	}
	// Ensure target is large enough for the shim + 4-byte length prefix
	minSize := len(shimFrame) + 4
	if targetSize < minSize {
		targetSize = minSize
	}

	// Build padded NAL body: [shimLen(4)] [shimFrame] [random padding...]
	nalBody := make([]byte, targetSize)
	binary.BigEndian.PutUint32(nalBody[0:4], uint32(len(shimFrame)))
	copy(nalBody[4:4+len(shimFrame)], shimFrame)
	_, _ = cryptoRand.Read(nalBody[4+len(shimFrame):])

	// Choose NAL type based on GOP position
	var nalType uint8
	if isIFrame {
		nalType = nalIDR
	} else {
		nalType = nalNonIDR
	}

	// FU indicator
	var fuIndicator uint8
	if nalType == nalIDR {
		fuIndicator = 0x7C
	} else {
		fuIndicator = 0x5C
	}

	var packets [][]byte

	// If I-frame, prepend SPS/PPS STAP-A
	if isIFrame {
		stapa := buildSTAPA_SPS_PPS()
		rtp := buildIPCAMRTPHeader(g.seq, g.ts, false, g.ssrc)
		g.seq++
		g.pktCount++
		g.octCount += uint32(len(stapa))
		packets = append(packets, append(rtp, stapa...))
	}

	// Fragment the padded NAL body as FU-A
	maxFrag := ipcamMTU - 2
	off := 0
	for off < len(nalBody) {
		end := off + maxFrag
		if end > len(nalBody) {
			end = len(nalBody)
		}
		isFirst := off == 0
		isLast := end == len(nalBody)

		var fuHeader uint8
		fuHeader = nalType & 0x1F
		if isFirst {
			fuHeader |= 0x80
		}
		if isLast {
			fuHeader |= 0x40
		}

		rtp := buildIPCAMRTPHeader(g.seq, g.ts, isLast, g.ssrc)
		g.seq++

		pkt := make([]byte, 0, ipcamRTPHdrSz+2+end-off)
		pkt = append(pkt, rtp...)
		pkt = append(pkt, fuIndicator, fuHeader)
		pkt = append(pkt, nalBody[off:end]...)

		packets = append(packets, pkt)
		g.pktCount++
		g.octCount += uint32(len(pkt) - ipcamRTPHdrSz)

		off = end
	}

	// Advance GOP state
	g.ts += g.tsStep
	g.frameNum = (g.frameNum + 1) % g.gopSize

	return packets
}

/* ---------- Extract Shim from IPCAM Packets ---------- */

func extractPayloadFromIPCAM(packets [][]byte) ([]byte, error) {
	if len(packets) == 0 {
		return nil, errors.New("ipcam: no packets")
	}

	// Find FU-A fragments (skip STAP-A if present)
	var fuPackets [][]byte
	for _, pkt := range packets {
		if len(pkt) < ipcamRTPHdrSz+2 {
			continue
		}
		fuIndicator := pkt[ipcamRTPHdrSz]
		nalType := fuIndicator & 0x1F
		if nalType == nalFUA {
			fuPackets = append(fuPackets, pkt)
		}
	}

	if len(fuPackets) == 0 {
		return nil, errors.New("ipcam: no FU-A fragments found")
	}

	// Reassemble FU-A payload (strip RTP header + FU indicator + FU header)
	var assembled []byte
	for _, pkt := range fuPackets {
		if len(pkt) < ipcamRTPHdrSz+2 {
			continue
		}
		payload := pkt[ipcamRTPHdrSz+2:]
		assembled = append(assembled, payload...)
	}

	// Extract shim: first 4 bytes = length, then that many bytes of shim data
	if len(assembled) < 4 {
		return nil, errors.New("ipcam: reassembled too short")
	}
	shimLen := binary.BigEndian.Uint32(assembled[0:4])
	if shimLen == 0 || int(shimLen) > len(assembled)-4 {
		return nil, errors.New("ipcam: invalid shim length")
	}
	return assembled[4 : 4+shimLen], nil
}

/* ---------- RTCP SR for IPCAM ---------- */

func (g *gopState) buildIPCAMRTCPSR() []byte {
	// Standard RTCP SR: V=2, P=0, RC=0, PT=200, length=6 (28 bytes)
	b := make([]byte, 28)
	b[0] = 0x80 // V=2, P=0, RC=0
	b[1] = 200  // SR
	binary.BigEndian.PutUint16(b[2:4], 6) // length in 32-bit words minus 1

	binary.BigEndian.PutUint32(b[4:8], g.ssrc)

	// NTP timestamp
	now := time.Now()
	sec := uint32(uint64(now.Unix()) + 2208988800) // NTP epoch offset
	frac := uint32(uint64(now.Nanosecond()) * (1 << 32) / 1_000_000_000)
	binary.BigEndian.PutUint32(b[8:12], sec)
	binary.BigEndian.PutUint32(b[12:16], frac)

	// RTP timestamp, packet count, octet count
	binary.BigEndian.PutUint32(b[16:20], g.ts)
	binary.BigEndian.PutUint32(b[20:24], g.pktCount)
	binary.BigEndian.PutUint32(b[24:28], g.octCount)
	return b
}

/* ---------- Packet Identification ---------- */

func isIPCAMRTP(b []byte) bool {
	if len(b) < ipcamRTPHdrSz {
		return false
	}
	// V=2
	if (b[0]>>6)&0x3 != 2 {
		return false
	}
	// PT=96 (ignore marker bit)
	pt := b[1] & 0x7F
	return pt == ipcamPT
}
