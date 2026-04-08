package main

import (
	"context"
	cryptoRand "crypto/rand"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"math/rand"
	"net"
	"sync/atomic"
	"time"
)

func buildWebRTCRTPHeader(seq uint16, ts uint32, pt uint8, marker bool, ssrc uint32, absTime uint32, twccSeq uint16) []byte {
	b := make([]byte, 24)
	b[0] = 0x90 // V=2, X=1
	b[1] = pt
	if marker {
		b[1] |= 0x80
	}
	binary.BigEndian.PutUint16(b[2:4], seq)
	binary.BigEndian.PutUint32(b[4:8], ts)
	binary.BigEndian.PutUint32(b[8:12], ssrc)
	binary.BigEndian.PutUint16(b[12:14], 0xBEDE)
	binary.BigEndian.PutUint16(b[14:16], 0x0002)
	b[16] = 0x32 // id=3, len=2 (abs-send-time)
	b[17] = byte(absTime >> 16)
	b[18] = byte(absTime >> 8)
	b[19] = byte(absTime)
	b[20] = 0x51 // id=5, len=1 (transport-cc)
	binary.BigEndian.PutUint16(b[21:23], twccSeq)
	b[23] = 0x00 // padding
	return b
}

func appendSRTPAuthTag(packet []byte) []byte {
	tag := make([]byte, 10)
	_, _ = cryptoRand.Read(tag)
	return append(packet, tag...)
}

func stripWebRTCRTP(b []byte) (pt uint8, marker bool, rest []byte, err error) {
	if len(b) < 24+10 {
		return 0, false, nil, io.ErrUnexpectedEOF
	}
	if (b[0]>>6)&0x3 != 2 {
		return 0, false, nil, errors.New("rtp ver")
	}
	marker = (b[1] & 0x80) != 0
	pt = b[1] & 0x7F
	rest = b[24 : len(b)-10]
	return pt, marker, rest, nil
}

type audioState struct {
	seq     uint16
	ts      uint32
	ssrc    uint32
	twccSeq *uint32
}

func (a *audioState) buildAudioPacket() []byte {
	twcc := uint16(atomic.AddUint32(a.twccSeq, 1))
	now := time.Now()
	sec := uint32(uint64(now.Unix()) + ntpEpochOffset)
	frac := uint32(uint64(now.Nanosecond()) * (1 << 18) / 1_000_000_000)
	absTime := (sec << 18) | frac

	h := buildWebRTCRTPHeader(a.seq, a.ts, 111, true, a.ssrc, absTime, twcc)
	a.seq++
	a.ts += 960

	payloadLen := 80 + rand.Intn(41) // 80-120
	payload := make([]byte, payloadLen)
	_, _ = cryptoRand.Read(payload)

	pkt := append(h, payload...)
	return appendSRTPAuthTag(pkt)
}

func buildCompoundRTCP(ssrc uint32, rtpTs uint32, pktCount uint32, octCount uint32) []byte {
	now := time.Now()
	sec := uint32(uint64(now.Unix()) + ntpEpochOffset)
	frac := uint32(uint64(now.Nanosecond()) * (1 << 32) / 1_000_000_000)

	// SR: 28 bytes
	sr := make([]byte, 28)
	sr[0] = 0x80 // V=2, P=0, RC=0
	sr[1] = 200  // SR
	binary.BigEndian.PutUint16(sr[2:4], 6)
	binary.BigEndian.PutUint32(sr[4:8], ssrc)
	binary.BigEndian.PutUint32(sr[8:12], sec)
	binary.BigEndian.PutUint32(sr[12:16], frac)
	binary.BigEndian.PutUint32(sr[16:20], rtpTs)
	binary.BigEndian.PutUint32(sr[20:24], pktCount)
	binary.BigEndian.PutUint32(sr[24:28], octCount)

	// SDES: CNAME = "{hex-ssrc}@webrtc.local"
	cname := []byte(hexSSRC(ssrc) + "@webrtc.local")
	// SDES header(4) + SSRC(4) + CNAME item(2+len) + END(1) + padding
	sdesPayload := make([]byte, 0, 4+len(cname)+3)
	sdesPayload = append(sdesPayload, byte(ssrc>>24), byte(ssrc>>16), byte(ssrc>>8), byte(ssrc))
	sdesPayload = append(sdesPayload, 1, byte(len(cname)))
	sdesPayload = append(sdesPayload, cname...)
	sdesPayload = append(sdesPayload, 0x00) // END
	for len(sdesPayload)%4 != 0 {
		sdesPayload = append(sdesPayload, 0x00)
	}

	sdesHdr := make([]byte, 4)
	sdesHdr[0] = 0x81 // V=2, SC=1
	sdesHdr[1] = 202  // SDES
	binary.BigEndian.PutUint16(sdesHdr[2:4], uint16(len(sdesPayload)/4))

	compound := append(sr, sdesHdr...)
	compound = append(compound, sdesPayload...)

	// SRTCP index (E-flag set, index=0)
	idx := make([]byte, 4)
	idx[0] = 0x80 // E-flag
	compound = append(compound, idx...)

	return appendSRTPAuthTag(compound)
}

func hexSSRC(ssrc uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ssrc)
	const hex = "0123456789abcdef"
	out := make([]byte, 8)
	for i := 0; i < 4; i++ {
		out[i*2] = hex[b[i]>>4]
		out[i*2+1] = hex[b[i]&0x0f]
	}
	return string(out)
}

func stunCRC32(data []byte) uint32 {
	return crc32.ChecksumIEEE(data) ^ 0x5354554E
}

func buildSTUNBindingRequestFull() []byte {
	b := make([]byte, 28)
	binary.BigEndian.PutUint16(b[0:2], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(b[2:4], 8)       // length: FINGERPRINT attr (8 bytes)
	binary.BigEndian.PutUint32(b[4:8], 0x2112A442)
	_, _ = cryptoRand.Read(b[8:20])

	// FINGERPRINT attribute
	binary.BigEndian.PutUint16(b[20:22], 0x8028) // type
	binary.BigEndian.PutUint16(b[22:24], 4)       // length
	fp := stunCRC32(b[:20])
	binary.BigEndian.PutUint32(b[24:28], fp)
	return b
}

func buildSTUNBindingResponse(transactionID []byte) []byte {
	b := make([]byte, 44)
	binary.BigEndian.PutUint16(b[0:2], 0x0101) // Binding Success Response
	binary.BigEndian.PutUint16(b[2:4], 24)      // length: XOR-MAPPED-ADDRESS(12) + FINGERPRINT(8)
	binary.BigEndian.PutUint32(b[4:8], 0x2112A442)
	copy(b[8:20], transactionID)

	// XOR-MAPPED-ADDRESS
	binary.BigEndian.PutUint16(b[20:22], 0x0020) // type
	binary.BigEndian.PutUint16(b[22:24], 8)       // length
	b[24] = 0x00                                   // reserved
	b[25] = 0x01                                   // IPv4
	binary.BigEndian.PutUint16(b[26:28], 0x2112^0xD903) // XOR'd port
	binary.BigEndian.PutUint32(b[28:32], 0x2112A442^0xC0A80101) // XOR'd 192.168.1.1

	// FINGERPRINT
	binary.BigEndian.PutUint16(b[32:34], 0x8028)
	binary.BigEndian.PutUint16(b[34:36], 4)
	fp := stunCRC32(b[:32])
	binary.BigEndian.PutUint32(b[36:40], fp)

	// pad remaining
	return b[:40]
}

func runAudioTicker(ctx context.Context, conn *net.UDPConn, peer *net.UDPAddr, audio *audioState, tb *tokenBucket, pcap *pcapWriter) {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	srcIP := ip4OrLoopback(localAddr.IP)
	dstIP := ip4OrLoopback(peer.IP)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			jitter := time.Duration(rand.Intn(4000)-2000) * time.Microsecond
			time.Sleep(jitter)

			pkt := audio.buildAudioPacket()
			tb.wait(len(pkt) + 28)
			_, _ = conn.WriteToUDP(pkt, peer)
			pcap.WriteUDP(srcIP, localAddr.Port, dstIP, peer.Port, pkt)
		}
	}
}

func runSTUNConsent(ctx context.Context, conn *net.UDPConn, peer *net.UDPAddr, pcap *pcapWriter) {
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	srcIP := ip4OrLoopback(localAddr.IP)
	dstIP := ip4OrLoopback(peer.IP)

	for {
		jitter := time.Duration(rand.Intn(2000)-1000) * time.Millisecond
		wait := 5*time.Second + jitter

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
			req := buildSTUNBindingRequestFull()
			_, _ = conn.WriteToUDP(req, peer)
			pcap.WriteUDP(srcIP, localAddr.Port, dstIP, peer.Port, req)
		}
	}
}
