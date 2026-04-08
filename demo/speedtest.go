// demo/speedtest.go
// UDP throughput & integrity test through CamoStream tunnel.
//
// Architecture:
//   [speedtest sender] --UDP--> [:37001 CamoStream Client] ==tunnel==>
//       [:39001 CamoStream Server] --UDP--> [:18081 speedtest receiver]
//
// Usage:
//   1. Start CamoStream server + client (any wire mode)
//   2. go run demo/speedtest.go -mode=server   (listens on :18081)
//   3. go run demo/speedtest.go -mode=client   (sends to :37001)
//
// The client sends numbered packets with CRC32 checksums.
// The server verifies each packet and reports stats.

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"hash/crc32"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

// Packet layout:
//   [0:4]   sequence number (uint32 BE)
//   [4:8]   CRC32 of payload portion (uint32 BE)
//   [8:16]  send timestamp nanoseconds (int64 BE)
//   [16:]   random payload

const headerSize = 16

func main() {
	mode := flag.String("mode", "client", "client|server|both")
	sendAddr := flag.String("send", "127.0.0.1:37001", "send to (CamoStream client listen)")
	recvAddr := flag.String("recv", ":18081", "listen on (CamoStream server forwards here)")
	pktSize := flag.Int("size", 1000, "packet payload size in bytes")
	duration := flag.Int("duration", 10, "test duration in seconds")
	pps := flag.Int("pps", 100, "packets per second")
	flag.Parse()

	switch *mode {
	case "server":
		runServer(*recvAddr)
	case "client":
		runClient(*sendAddr, *pktSize, *duration, *pps)
	case "both":
		go runServer(*recvAddr)
		time.Sleep(500 * time.Millisecond)
		runClient(*sendAddr, *pktSize, *duration, *pps)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode: %s\n", *mode)
		os.Exit(1)
	}
}

func runClient(addr string, pktSize, durSec, pps int) {
	dst, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve %s: %v\n", addr, err)
		os.Exit(1)
	}
	conn, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	if pktSize < headerSize+1 {
		pktSize = headerSize + 1
	}

	fmt.Printf("╔══════════════════════════════════════════════════╗\n")
	fmt.Printf("║       CamoStream UDP SpeedTest - Client         ║\n")
	fmt.Printf("╠══════════════════════════════════════════════════╣\n")
	fmt.Printf("║  Target:    %-36s  ║\n", addr)
	fmt.Printf("║  Pkt Size:  %-4d bytes                            ║\n", pktSize)
	fmt.Printf("║  PPS:       %-4d                                  ║\n", pps)
	fmt.Printf("║  Duration:  %-2d seconds                            ║\n", durSec)
	fmt.Printf("║  Expected:  %-6.2f Mbps                           ║\n", float64(pktSize*pps*8)/1e6)
	fmt.Printf("╚══════════════════════════════════════════════════╝\n\n")

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	buf := make([]byte, pktSize)
	interval := time.Second / time.Duration(pps)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	deadline := time.After(time.Duration(durSec) * time.Second)
	var seq uint32
	var totalBytes int64
	start := time.Now()

	for {
		select {
		case <-deadline:
			elapsed := time.Since(start).Seconds()
			mbps := float64(totalBytes*8) / elapsed / 1e6
			fmt.Printf("\n[Client] Sent %d packets, %d bytes in %.1fs\n", seq, totalBytes, elapsed)
			fmt.Printf("[Client] Throughput: %.2f Mbps\n", mbps)
			return
		case <-ticker.C:
			// Fill random payload
			rng.Read(buf[headerSize:])
			// Header: seq + CRC + timestamp
			binary.BigEndian.PutUint32(buf[0:4], seq)
			csum := crc32.ChecksumIEEE(buf[headerSize:])
			binary.BigEndian.PutUint32(buf[4:8], csum)
			binary.BigEndian.PutUint64(buf[8:16], uint64(time.Now().UnixNano()))

			n, err := conn.Write(buf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[Client] write error: %v\n", err)
				continue
			}
			totalBytes += int64(n)
			seq++

			if seq%uint32(pps) == 0 {
				elapsed := time.Since(start).Seconds()
				mbps := float64(totalBytes*8) / elapsed / 1e6
				fmt.Printf("[Client] %ds: sent %d pkts, %.2f Mbps\n", int(elapsed), seq, mbps)
			}
		}
	}
}

func runServer(addr string) {
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve %s: %v\n", addr, err)
		os.Exit(1)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("╔══════════════════════════════════════════════════╗\n")
	fmt.Printf("║       CamoStream UDP SpeedTest - Server         ║\n")
	fmt.Printf("╠══════════════════════════════════════════════════╣\n")
	fmt.Printf("║  Listening: %-36s  ║\n", addr)
	fmt.Printf("╚══════════════════════════════════════════════════╝\n\n")

	var (
		totalPkts   uint64
		totalBytes  uint64
		crcOK       uint64
		crcFail     uint64
		outOfOrder  uint64
		duplicate   uint64
		latencySum  int64
		latencyMin  int64 = 1<<62
		latencyMax  int64
		expectedSeq uint32
		started     bool
		startTime   time.Time
	)

	// Echo response back (so CamoStream server->client path also works)
	buf := make([]byte, 64*1024)

	// Stats printer
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if !started {
					continue
				}
				elapsed := time.Since(startTime).Seconds()
				p := atomic.LoadUint64(&totalPkts)
				b := atomic.LoadUint64(&totalBytes)
				ok := atomic.LoadUint64(&crcOK)
				fail := atomic.LoadUint64(&crcFail)
				ooo := atomic.LoadUint64(&outOfOrder)
				dup := atomic.LoadUint64(&duplicate)
				mbps := float64(b*8) / elapsed / 1e6
				fmt.Printf("[Server] %.0fs: %d pkts, %.2f Mbps | CRC OK:%d FAIL:%d | OOO:%d DUP:%d\n",
					elapsed, p, mbps, ok, fail, ooo, dup)
			case <-sig:
				printFinalReport(startTime, totalPkts, totalBytes, crcOK, crcFail,
					outOfOrder, duplicate, latencySum, latencyMin, latencyMax)
				os.Exit(0)
			}
		}
	}()

	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if n < headerSize {
			continue
		}

		if !started {
			started = true
			startTime = time.Now()
			fmt.Printf("[Server] First packet from %s\n", from)
		}

		atomic.AddUint64(&totalPkts, 1)
		atomic.AddUint64(&totalBytes, uint64(n))

		// Parse header
		seq := binary.BigEndian.Uint32(buf[0:4])
		expectedCRC := binary.BigEndian.Uint32(buf[4:8])
		sendTS := int64(binary.BigEndian.Uint64(buf[8:16]))

		// CRC verification
		actualCRC := crc32.ChecksumIEEE(buf[headerSize:n])
		if actualCRC == expectedCRC {
			atomic.AddUint64(&crcOK, 1)
		} else {
			atomic.AddUint64(&crcFail, 1)
		}

		// Sequence check
		if seq == expectedSeq {
			expectedSeq++
		} else if seq < expectedSeq {
			atomic.AddUint64(&duplicate, 1)
		} else {
			atomic.AddUint64(&outOfOrder, 1)
			expectedSeq = seq + 1
		}

		// Latency
		lat := time.Now().UnixNano() - sendTS
		atomic.AddInt64(&latencySum, lat)
		if lat < atomic.LoadInt64(&latencyMin) {
			atomic.StoreInt64(&latencyMin, lat)
		}
		if lat > atomic.LoadInt64(&latencyMax) {
			atomic.StoreInt64(&latencyMax, lat)
		}

		// Echo back (trimmed to small ack)
		ack := buf[:headerSize]
		conn.WriteToUDP(ack, from)
	}
}

func printFinalReport(start time.Time, pkts, bytes, ok, fail, ooo, dup uint64,
	latSum, latMin, latMax int64) {
	elapsed := time.Since(start).Seconds()
	if elapsed < 0.001 {
		elapsed = 0.001
	}
	mbps := float64(bytes*8) / elapsed / 1e6
	avgLat := float64(0)
	if pkts > 0 {
		avgLat = float64(latSum) / float64(pkts) / 1e6
	}

	fmt.Printf("\n")
	fmt.Printf("╔══════════════════════════════════════════════════╗\n")
	fmt.Printf("║            SpeedTest Final Report                ║\n")
	fmt.Printf("╠══════════════════════════════════════════════════╣\n")
	fmt.Printf("║  Duration:     %8.1f s                         ║\n", elapsed)
	fmt.Printf("║  Packets:      %8d                            ║\n", pkts)
	fmt.Printf("║  Bytes:        %8d                            ║\n", bytes)
	fmt.Printf("║  Throughput:   %8.2f Mbps                      ║\n", mbps)
	fmt.Printf("╠══════════════════════════════════════════════════╣\n")
	fmt.Printf("║  CRC32 OK:     %8d                            ║\n", ok)
	fmt.Printf("║  CRC32 FAIL:   %8d                            ║\n", fail)
	fmt.Printf("║  Integrity:    %7.1f%%                            ║\n", float64(ok)/float64(max64(pkts,1))*100)
	fmt.Printf("╠══════════════════════════════════════════════════╣\n")
	fmt.Printf("║  Out-of-Order: %8d                            ║\n", ooo)
	fmt.Printf("║  Duplicates:   %8d                            ║\n", dup)
	fmt.Printf("║  Avg Latency:  %7.2f ms                         ║\n", avgLat)
	fmt.Printf("║  Min Latency:  %7.2f ms                         ║\n", float64(latMin)/1e6)
	fmt.Printf("║  Max Latency:  %7.2f ms                         ║\n", float64(latMax)/1e6)
	fmt.Printf("╚══════════════════════════════════════════════════╝\n")
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
