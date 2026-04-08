package main

import (
	"crypto/aes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

type aeadBox2 struct{ aead cipher.AEAD }

func newAEAD2(hexKey string) (*aeadBox2, error) {
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
	return &aeadBox2{aead: a}, nil
}

func (b *aeadBox2) seal(p []byte) (out []byte, nonce []byte, err error) {
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

func (b *aeadBox2) open(nonce, c []byte) ([]byte, error) {
	if b == nil {
		return c, nil
	}
	return b.aead.Open(nil, nonce, c, nil)
}

const nonceLen = 12

// magicMask derives a 4-byte XOR mask from the session ID so the magic constant
// never appears as a fixed pattern on the wire when encryption is disabled.
func magicMask(sessionID uint32) uint32 {
	// simple deterministic mixing: multiply by a large odd prime, rotate
	m := sessionID * 0x9E3779B9
	m ^= m >> 16
	m *= 0x45D9F3B
	m ^= m >> 16
	return m
}

// sealFrame encrypts (or obfuscates) the shim header + payload into a wire frame.
//
// When ae != nil (AES-GCM enabled):
//
//	output = nonce(12) || AEAD(shimHeader || payload)
//
// When ae == nil (no encryption):
//
//	output = shimHeader(magic XORed with session mask) || payload
func sealFrame(ae *aeadBox, hdr shimHeader, payload []byte) ([]byte, error) {
	inner := make([]byte, shimLen+len(payload))
	copy(inner, hdr.Marshal())
	copy(inner[shimLen:], payload)

	if ae != nil {
		nonce := make([]byte, nonceLen)
		if _, err := cryptoRand.Read(nonce); err != nil {
			return nil, err
		}
		ct := ae.aead.Seal(nil, nonce, inner, nil)
		out := make([]byte, nonceLen+len(ct))
		copy(out, nonce)
		copy(out[nonceLen:], ct)
		return out, nil
	}

	// No encryption: XOR the magic so it is not a static fingerprint.
	mask := magicMask(hdr.SessionID)
	binary.BigEndian.PutUint32(inner[0:4], hdr.Magic^mask)
	return inner, nil
}

// openFrame decrypts (or de-obfuscates) a wire frame back into shimHeader + payload.
//
// When ae != nil:
//
//	expects data = nonce(12) || ciphertext
//
// When ae == nil:
//
//	expects data = shimHeader(magic XORed) || payload
func openFrame(ae *aeadBox, data []byte, sessionHint uint32) (shimHeader, []byte, error) {
	if ae != nil {
		if len(data) < nonceLen {
			return shimHeader{}, nil, io.ErrUnexpectedEOF
		}
		nonce := data[:nonceLen]
		ct := data[nonceLen:]
		plain, err := ae.aead.Open(nil, nonce, ct, nil)
		if err != nil {
			return shimHeader{}, nil, fmt.Errorf("aead open: %w", err)
		}
		return parseShimFull(plain)
	}

	// No encryption: un-XOR the magic first.
	if len(data) < shimLen {
		return shimHeader{}, nil, io.ErrUnexpectedEOF
	}
	// work on a copy so we don't mutate the caller's buffer
	buf := make([]byte, len(data))
	copy(buf, data)
	mask := magicMask(sessionHint)
	raw := binary.BigEndian.Uint32(buf[0:4])
	binary.BigEndian.PutUint32(buf[0:4], raw^mask)
	return parseShimFull(buf)
}
