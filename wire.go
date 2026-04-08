package main

import (
	"encoding/binary"
	"errors"
	"sync/atomic"
	"time"
)

// encodeUDPFrame builds a complete wire frame for the configured wire format.
// Returns the ready-to-send bytes.
func encodeUDPFrame(cfg *Config, ae *aeadBox, rtp *rtpState, rtpTs *uint32,
	step int, sess uint32, payload []byte, isDecoy bool, twccSeq *uint32) []byte {

	// Build shim header
	flags := uint8(0)
	if isDecoy {
		flags |= flagDecoy
	}
	if ae != nil {
		flags |= flagEnc
	}
	hdr := shimHeader{
		Magic:     magicConst,
		Version:   version,
		Mode:      modeUDP,
		Flags:     flags,
		SessionID: sess,
		TsMs:      uint32(time.Now().UnixMilli()),
		Len:       uint32(len(payload)),
	}

	switch cfg.Wire {
	case WireWebRTC:
		// Encrypt shim header + payload together (eliminates magic fingerprint)
		sealed, err := sealFrame(ae, hdr, payload)
		if err != nil {
			// fallback: raw
			sealed = append(hdr.Marshal(), payload...)
		}
		// WebRTC RTP header (24 bytes) with extensions
		*rtpTs += uint32(step)
		absTime := webrtcAbsSendTime()
		twcc := uint16(0)
		if twccSeq != nil {
			twcc = uint16(atomic.AddUint32(twccSeq, 1))
		}
		rtpHdr := buildWebRTCRTPHeader(rtp.seq, *rtpTs, 96, !isDecoy, rtp.ssrc, absTime, twcc)
		rtp.seq++
		frame := append(rtpHdr, sealed...)
		return appendSRTPAuthTag(frame)

	case WireIPCam:
		// For IPCAM mode: encrypt shim + payload, then wrap in single RTP with H.264 FU-A first-frag indicator
		sealed, err := sealFrame(ae, hdr, payload)
		if err != nil {
			sealed = append(hdr.Marshal(), payload...)
		}
		*rtpTs += uint32(step)
		rtpHdr := buildRTPHeader(rtp.seq, *rtpTs, ipcamPT, true, rtp.ssrc)
		rtp.seq++
		// Prepend a FU-A indicator+header to look like H.264 fragment
		nalType := uint8(nalNonIDR) // default P-frame
		fuIndicator := byte(0x5C)   // F=0 NRI=10 Type=28(FU-A)
		fuHeader := byte(0x80 | nalType) // S=1 E=0 R=0 Type=1 (start+end for single)
		fuHeader |= 0x40                 // set E bit too (single fragment)
		h264Hdr := []byte{fuIndicator, fuHeader}
		frame := append(rtpHdr, h264Hdr...)
		frame = append(frame, sealed...)
		return frame

	case WireRTPish:
		// Legacy: encrypt only payload, shim header exposed (but XOR magic if no AES)
		sealed, err := sealFrame(ae, hdr, payload)
		if err != nil {
			sealed = append(hdr.Marshal(), payload...)
		}
		*rtpTs += uint32(step)
		rtpHdr := buildRTPHeader(rtp.seq, *rtpTs, 96, false, rtp.ssrc)
		rtp.seq++
		return append(rtpHdr, sealed...)

	default: // WireShim
		sealed, err := sealFrame(ae, hdr, payload)
		if err != nil {
			sealed = append(hdr.Marshal(), payload...)
		}
		return sealed
	}
}

// decodeUDPFrame strips wire framing and decrypts to recover shimHeader + payload.
func decodeUDPFrame(cfg *Config, ae *aeadBox, raw []byte, sessionHint uint32) (shimHeader, []byte, error) {
	switch cfg.Wire {
	case WireWebRTC:
		_, _, rest, err := stripWebRTCRTP(raw)
		if err != nil {
			return shimHeader{}, nil, err
		}
		return openFrame(ae, rest, sessionHint)

	case WireIPCam:
		// Strip RTP header (12 bytes) + FU-A header (2 bytes)
		if len(raw) < 14 {
			return shimHeader{}, nil, errors.New("ipcam frame too short")
		}
		if (raw[0]>>6)&0x3 != 2 {
			return shimHeader{}, nil, errors.New("rtp ver")
		}
		rest := raw[14:] // skip 12B RTP + 2B FU-A
		return openFrame(ae, rest, sessionHint)

	case WireRTPish:
		// Strip 12-byte RTP header
		if len(raw) < 12 {
			return shimHeader{}, nil, errors.New("rtpish too short")
		}
		if (raw[0]>>6)&0x3 != 2 {
			return shimHeader{}, nil, errors.New("rtp ver")
		}
		rest := raw[12:]
		return openFrame(ae, rest, sessionHint)

	default: // WireShim
		return openFrame(ae, raw, sessionHint)
	}
}

// webrtcAbsSendTime computes a 24-bit abs-send-time (6.18 fixed-point NTP fraction).
func webrtcAbsSendTime() uint32 {
	now := time.Now()
	sec := uint64(now.Unix()) + ntpEpochOffset
	frac := uint64(now.Nanosecond()) * (1 << 18) / 1_000_000_000
	return uint32(((sec & 0x3F) << 18) | (frac & 0x3FFFF))
}

// isDTLSRange checks if the first byte falls in the DTLS content type range (20-63).
func isDTLSRange(b byte) bool {
	return b >= 20 && b <= 63
}

// isSTUNPacket checks if the packet looks like STUN (magic cookie at offset 4).
func isSTUNPacket(data []byte) bool {
	if len(data) < 20 {
		return false
	}
	cookie := binary.BigEndian.Uint32(data[4:8])
	return cookie == 0x2112A442
}
