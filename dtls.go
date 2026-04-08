package main

import (
	cryptoRand "crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// DTLS record header offsets and constants
const (
	dtlsContentHandshake      = 22
	dtlsContentChangeCipher   = 20
	dtlsContentAppData        = 23
	dtlsVersion12             = 0xFEFD // DTLS 1.2
	dtlsRecordHeaderLen       = 13
	dtlsHandshakeHeaderLen    = 12
	dtlsHandshakeTimeout      = 2 * time.Second
)

// Handshake types
const (
	dtlsHSClientHello = 1
	dtlsHSServerHello = 2
)

// putDTLSRecordHeader writes a DTLS record header into dst (must be >= 13 bytes).
func putDTLSRecordHeader(dst []byte, contentType uint8, epoch uint16, seq uint64, payloadLen int) {
	dst[0] = contentType
	binary.BigEndian.PutUint16(dst[1:3], dtlsVersion12)
	binary.BigEndian.PutUint16(dst[3:5], epoch)
	// 48-bit sequence number
	dst[5] = byte(seq >> 40)
	dst[6] = byte(seq >> 32)
	dst[7] = byte(seq >> 24)
	dst[8] = byte(seq >> 16)
	dst[9] = byte(seq >> 8)
	dst[10] = byte(seq)
	binary.BigEndian.PutUint16(dst[11:13], uint16(payloadLen))
}

// putHandshakeHeader writes a DTLS handshake message header.
func putHandshakeHeader(dst []byte, hsType uint8, length int, msgSeq uint16, fragOff, fragLen int) {
	dst[0] = hsType
	// 24-bit length
	dst[1] = byte(length >> 16)
	dst[2] = byte(length >> 8)
	dst[3] = byte(length)
	binary.BigEndian.PutUint16(dst[4:6], msgSeq)
	// 24-bit fragment offset
	dst[6] = byte(fragOff >> 16)
	dst[7] = byte(fragOff >> 8)
	dst[8] = byte(fragOff)
	// 24-bit fragment length
	dst[9] = byte(fragLen >> 16)
	dst[10] = byte(fragLen >> 8)
	dst[11] = byte(fragLen)
}

// buildDTLSClientHello constructs a realistic DTLS 1.2 ClientHello (~250 bytes).
func buildDTLSClientHello(random []byte) []byte {
	// Body: version(2) + random(32) + sessionID(1+32) + cookie(1+0) +
	//       cipherSuites(2+N*2) + compressionMethods(1+1) + extensions
	var body []byte

	// client version
	body = append(body, 0xFE, 0xFD)

	// random (32 bytes); pad/truncate caller input
	r := make([]byte, 32)
	copy(r, random)
	body = append(body, r...)

	// session id: 32-byte random
	sid := make([]byte, 32)
	cryptoRand.Read(sid)
	body = append(body, 32)
	body = append(body, sid...)

	// cookie: empty
	body = append(body, 0)

	// cipher suites
	suites := []uint16{
		0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
		0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
		0x00FF, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
	}
	binary.BigEndian.AppendUint16(nil, 0) // placeholder
	sLen := len(suites) * 2
	body = append(body, byte(sLen>>8), byte(sLen))
	for _, s := range suites {
		body = append(body, byte(s>>8), byte(s))
	}

	// compression methods: null only
	body = append(body, 1, 0)

	// extensions
	var exts []byte

	// use_srtp extension (type 0x000E)
	srtpProfiles := []uint16{0x0001} // SRTP_AES128_CM_HMAC_SHA1_80
	srtpBody := make([]byte, 2+len(srtpProfiles)*2+1)
	binary.BigEndian.PutUint16(srtpBody[0:2], uint16(len(srtpProfiles)*2))
	for i, p := range srtpProfiles {
		binary.BigEndian.PutUint16(srtpBody[2+i*2:4+i*2], p)
	}
	srtpBody[len(srtpBody)-1] = 0 // mki length
	exts = appendExtension(exts, 0x000E, srtpBody)

	// supported_groups (type 0x000A): x25519, secp256r1, secp384r1
	groups := []uint16{0x001D, 0x0017, 0x0018}
	gBody := make([]byte, 2+len(groups)*2)
	binary.BigEndian.PutUint16(gBody[0:2], uint16(len(groups)*2))
	for i, g := range groups {
		binary.BigEndian.PutUint16(gBody[2+i*2:4+i*2], g)
	}
	exts = appendExtension(exts, 0x000A, gBody)

	// ec_point_formats (type 0x000B)
	exts = appendExtension(exts, 0x000B, []byte{1, 0}) // uncompressed

	// signature_algorithms (type 0x000D)
	sigAlgs := []uint16{0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601}
	saBody := make([]byte, 2+len(sigAlgs)*2)
	binary.BigEndian.PutUint16(saBody[0:2], uint16(len(sigAlgs)*2))
	for i, sa := range sigAlgs {
		binary.BigEndian.PutUint16(saBody[2+i*2:4+i*2], sa)
	}
	exts = appendExtension(exts, 0x000D, saBody)

	// extensions length prefix
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	// wrap in handshake header + record header
	hsPayload := make([]byte, dtlsHandshakeHeaderLen+len(body))
	putHandshakeHeader(hsPayload, dtlsHSClientHello, len(body), 0, 0, len(body))
	copy(hsPayload[dtlsHandshakeHeaderLen:], body)

	pkt := make([]byte, dtlsRecordHeaderLen+len(hsPayload))
	putDTLSRecordHeader(pkt, dtlsContentHandshake, 0, 0, len(hsPayload))
	copy(pkt[dtlsRecordHeaderLen:], hsPayload)
	return pkt
}

// buildDTLSServerHello constructs a DTLS 1.2 ServerHello (~120 bytes).
func buildDTLSServerHello(random []byte) []byte {
	var body []byte

	// server version
	body = append(body, 0xFE, 0xFD)

	// random (32 bytes)
	r := make([]byte, 32)
	copy(r, random)
	body = append(body, r...)

	// session id (32 bytes, echo a random one)
	sid := make([]byte, 32)
	cryptoRand.Read(sid)
	body = append(body, 32)
	body = append(body, sid...)

	// selected cipher suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	body = append(body, 0xC0, 0x2B)

	// compression method: null
	body = append(body, 0)

	// extensions: use_srtp
	var exts []byte
	srtpBody := []byte{0x00, 0x02, 0x00, 0x01, 0x00} // profile=0x0001, mki=0
	exts = appendExtension(exts, 0x000E, srtpBody)

	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	hsPayload := make([]byte, dtlsHandshakeHeaderLen+len(body))
	putHandshakeHeader(hsPayload, dtlsHSServerHello, len(body), 1, 0, len(body))
	copy(hsPayload[dtlsHandshakeHeaderLen:], body)

	pkt := make([]byte, dtlsRecordHeaderLen+len(hsPayload))
	putDTLSRecordHeader(pkt, dtlsContentHandshake, 0, 1, len(hsPayload))
	copy(pkt[dtlsRecordHeaderLen:], hsPayload)
	return pkt
}

// buildDTLSChangeCipherSpec builds a DTLS ChangeCipherSpec record (14 bytes total).
func buildDTLSChangeCipherSpec() []byte {
	pkt := make([]byte, dtlsRecordHeaderLen+1)
	putDTLSRecordHeader(pkt, dtlsContentChangeCipher, 0, 2, 1)
	pkt[dtlsRecordHeaderLen] = 0x01
	return pkt
}

// buildDTLSFinished builds a fake encrypted Finished record (~50-60 bytes).
func buildDTLSFinished(random []byte) []byte {
	// simulate encrypted payload (40-60 bytes random data)
	pLen := 40 + int(random[0]%21) // 40..60
	payload := make([]byte, pLen)
	cryptoRand.Read(payload)

	pkt := make([]byte, dtlsRecordHeaderLen+pLen)
	putDTLSRecordHeader(pkt, dtlsContentAppData, 1, 0, pLen)
	copy(pkt[dtlsRecordHeaderLen:], payload)
	return pkt
}

// isDTLSPacket checks if the first byte indicates a DTLS record (content types 20-63).
func isDTLSPacket(data []byte) bool {
	if len(data) < 1 {
		return false
	}
	return data[0] >= 20 && data[0] <= 63
}

// appendExtension appends a TLS extension (type + length-prefixed data).
func appendExtension(buf []byte, extType uint16, data []byte) []byte {
	buf = append(buf, byte(extType>>8), byte(extType))
	buf = append(buf, byte(len(data)>>8), byte(len(data)))
	buf = append(buf, data...)
	return buf
}

// performDTLSHandshake runs a fake DTLS 1.2 handshake over the given UDP connection.
// isServer: true for the responder side, false for the initiator.
// pcap: optional pcap writer (may be nil).
func performDTLSHandshake(conn *net.UDPConn, peer *net.UDPAddr, isServer bool, pcap *pcapWriter) error {
	rnd := make([]byte, 32)
	cryptoRand.Read(rnd)

	if !isServer {
		return dtlsClientHandshake(conn, peer, rnd, pcap)
	}
	return dtlsServerHandshake(conn, peer, rnd, pcap)
}

func dtlsClientHandshake(conn *net.UDPConn, peer *net.UDPAddr, rnd []byte, pcap *pcapWriter) error {
	// 1. Send ClientHello
	ch := buildDTLSClientHello(rnd)
	if _, err := conn.WriteToUDP(ch, peer); err != nil {
		return fmt.Errorf("dtls: send ClientHello: %w", err)
	}
	dtlsWritePcap(pcap, conn.LocalAddr(), peer, ch)
	logf(LDebug, "dtls: sent ClientHello (%d bytes)", len(ch))

	// 2. Wait for ServerHello
	conn.SetReadDeadline(time.Now().Add(dtlsHandshakeTimeout))
	buf := make([]byte, 2048)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return fmt.Errorf("dtls: wait ServerHello: %w", err)
		}
		if from.String() != peer.String() {
			continue
		}
		data := buf[:n]
		dtlsWritePcap(pcap, from, conn.LocalAddr(), data)
		if len(data) >= dtlsRecordHeaderLen && data[0] == dtlsContentHandshake {
			logf(LDebug, "dtls: recv ServerHello (%d bytes)", n)
			break
		}
	}

	// 3. Wait for server ChangeCipherSpec
	conn.SetReadDeadline(time.Now().Add(dtlsHandshakeTimeout))
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return fmt.Errorf("dtls: wait ChangeCipherSpec: %w", err)
		}
		if from.String() != peer.String() {
			continue
		}
		data := buf[:n]
		dtlsWritePcap(pcap, from, conn.LocalAddr(), data)
		if len(data) >= dtlsRecordHeaderLen && data[0] == dtlsContentChangeCipher {
			logf(LDebug, "dtls: recv ChangeCipherSpec (%d bytes)", n)
			break
		}
	}

	// 4. Wait for server Finished
	conn.SetReadDeadline(time.Now().Add(dtlsHandshakeTimeout))
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return fmt.Errorf("dtls: wait server Finished: %w", err)
		}
		if from.String() != peer.String() {
			continue
		}
		data := buf[:n]
		dtlsWritePcap(pcap, from, conn.LocalAddr(), data)
		if len(data) >= dtlsRecordHeaderLen && data[0] == dtlsContentAppData {
			logf(LDebug, "dtls: recv server Finished (%d bytes)", n)
			break
		}
	}

	// 5. Send client ChangeCipherSpec + Finished
	ccs := buildDTLSChangeCipherSpec()
	if _, err := conn.WriteToUDP(ccs, peer); err != nil {
		return fmt.Errorf("dtls: send ChangeCipherSpec: %w", err)
	}
	dtlsWritePcap(pcap, conn.LocalAddr(), peer, ccs)
	logf(LDebug, "dtls: sent ChangeCipherSpec (%d bytes)", len(ccs))

	fin := buildDTLSFinished(rnd)
	if _, err := conn.WriteToUDP(fin, peer); err != nil {
		return fmt.Errorf("dtls: send Finished: %w", err)
	}
	dtlsWritePcap(pcap, conn.LocalAddr(), peer, fin)
	logf(LDebug, "dtls: sent Finished (%d bytes)", len(fin))

	conn.SetReadDeadline(time.Time{})
	return nil
}

func dtlsServerHandshake(conn *net.UDPConn, peer *net.UDPAddr, rnd []byte, pcap *pcapWriter) error {
	buf := make([]byte, 2048)

	// 1. Wait for ClientHello
	conn.SetReadDeadline(time.Now().Add(dtlsHandshakeTimeout))
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return fmt.Errorf("dtls: wait ClientHello: %w", err)
		}
		if from.String() != peer.String() {
			continue
		}
		data := buf[:n]
		dtlsWritePcap(pcap, from, conn.LocalAddr(), data)
		if len(data) >= dtlsRecordHeaderLen && data[0] == dtlsContentHandshake {
			logf(LDebug, "dtls: recv ClientHello (%d bytes)", n)
			break
		}
	}

	// 2. Send ServerHello
	sh := buildDTLSServerHello(rnd)
	if _, err := conn.WriteToUDP(sh, peer); err != nil {
		return fmt.Errorf("dtls: send ServerHello: %w", err)
	}
	dtlsWritePcap(pcap, conn.LocalAddr(), peer, sh)
	logf(LDebug, "dtls: sent ServerHello (%d bytes)", len(sh))

	// 3. Send ChangeCipherSpec + Finished
	ccs := buildDTLSChangeCipherSpec()
	if _, err := conn.WriteToUDP(ccs, peer); err != nil {
		return fmt.Errorf("dtls: send ChangeCipherSpec: %w", err)
	}
	dtlsWritePcap(pcap, conn.LocalAddr(), peer, ccs)
	logf(LDebug, "dtls: sent ChangeCipherSpec (%d bytes)", len(ccs))

	fin := buildDTLSFinished(rnd)
	if _, err := conn.WriteToUDP(fin, peer); err != nil {
		return fmt.Errorf("dtls: send Finished: %w", err)
	}
	dtlsWritePcap(pcap, conn.LocalAddr(), peer, fin)
	logf(LDebug, "dtls: sent Finished (%d bytes)", len(fin))

	// 4. Wait for client ChangeCipherSpec + Finished
	conn.SetReadDeadline(time.Now().Add(dtlsHandshakeTimeout))
	got := 0
	for got < 2 {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return fmt.Errorf("dtls: wait client finish: %w", err)
		}
		if from.String() != peer.String() {
			continue
		}
		data := buf[:n]
		dtlsWritePcap(pcap, from, conn.LocalAddr(), data)
		if len(data) >= dtlsRecordHeaderLen {
			if data[0] == dtlsContentChangeCipher || data[0] == dtlsContentAppData {
				got++
				logf(LDebug, "dtls: recv client handshake pkt type=%d (%d bytes)", data[0], n)
			}
		}
	}

	conn.SetReadDeadline(time.Time{})
	return nil
}

// dtlsWritePcap records a DTLS packet to pcap if the writer is available.
func dtlsWritePcap(pcap *pcapWriter, src, dst net.Addr, data []byte) {
	if pcap == nil {
		return
	}
	srcU, okS := src.(*net.UDPAddr)
	dstU, okD := dst.(*net.UDPAddr)
	if !okS || !okD {
		return
	}
	pcap.WriteUDP(srcU.IP, srcU.Port, dstU.IP, dstU.Port, data)
}
