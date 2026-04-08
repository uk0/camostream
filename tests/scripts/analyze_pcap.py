#!/usr/bin/env python3
"""
CamoStream PCAP Analysis Script
================================
Evaluates how well CamoStream disguises real traffic as video streaming (RTP/RTCP).

Performs 7 analysis dimensions:
  1. Protocol Distribution
  2. Packet Size Distribution
  3. Timing Analysis
  4. Entropy Analysis
  5. RTP Consistency Check
  6. Decoy Effectiveness
  7. DPI Resistance Score (composite)

Usage:
    python analyze_pcap.py <pcap_file> [--mode tcp|udp] [--output report.json]

Exit codes:
    0 - overall stealth score >= 70
    1 - overall stealth score < 70
"""

import argparse
import json
import math
import struct
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from scapy.all import rdpcap, UDP, TCP, IP, Raw

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CAMOSTREAM_MAGIC = 0x5C10ADED
STUN_MAGIC_COOKIE = 0x2112A442

# RTP payload types considered valid for CamoStream
VALID_RTP_PTS = set(range(0, 128))  # 0-127 are valid per RFC 3551
# CamoStream uses PT=96 (dynamic) for data and PT=13 for keepalive
CAMOSTREAM_PTS = {96, 13}
# RTCP payload types
RTCP_SR_PT = 200
RTCP_RR_PT = 201

# Expected video clock rate (Hz)
VIDEO_CLOCK_RATE = 90_000
# Target FPS
TARGET_FPS = 60
TARGET_INTERVAL_MS = 1000.0 / TARGET_FPS  # ~16.67ms

# Scoring weights
WEIGHTS = {
    "protocol_conformance": 0.25,
    "size_distribution": 0.20,
    "timing": 0.15,
    "entropy": 0.20,
    "rtp_consistency": 0.10,
    "decoy_coverage": 0.10,
}


# ---------------------------------------------------------------------------
# Packet Classification Helpers
# ---------------------------------------------------------------------------

def _parse_rtp_header(data: bytes):
    """
    Parse a minimal 12-byte RTP header.
    Returns dict with version, padding, extension, cc, marker, pt, seq, ts, ssrc
    or None if data is too short or version != 2.
    """
    if len(data) < 12:
        return None
    b0, b1 = data[0], data[1]
    version = (b0 >> 6) & 0x03
    if version != 2:
        return None
    padding = (b0 >> 5) & 0x01
    extension = (b0 >> 4) & 0x01
    cc = b0 & 0x0F
    marker = (b1 >> 7) & 0x01
    pt = b1 & 0x7F
    seq = struct.unpack("!H", data[2:4])[0]
    ts = struct.unpack("!I", data[4:8])[0]
    ssrc = struct.unpack("!I", data[8:12])[0]
    return {
        "version": version,
        "padding": padding,
        "extension": extension,
        "cc": cc,
        "marker": marker,
        "pt": pt,
        "seq": seq,
        "timestamp": ts,
        "ssrc": ssrc,
    }


def _is_stun(data: bytes) -> bool:
    """Check if payload looks like a STUN Binding message (magic cookie at offset 4)."""
    if len(data) < 20:
        return False
    # STUN message: first 2 bytes = type, next 2 = length, bytes 4-8 = magic cookie
    cookie = struct.unpack("!I", data[4:8])[0]
    return cookie == STUN_MAGIC_COOKIE


def _is_rtcp(data: bytes):
    """
    Check if payload looks like RTCP (SR or RR).
    Returns the RTCP PT (200 or 201) or None.
    """
    if len(data) < 8:
        return None
    b0, b1 = data[0], data[1]
    version = (b0 >> 6) & 0x03
    if version != 2:
        return None
    pt = b1
    if pt in (RTCP_SR_PT, RTCP_RR_PT):
        return pt
    return None


def _parse_shim_header(data: bytes, offset: int = 12):
    """
    Parse the 20-byte CamoStream shim header starting at offset (after RTP header).
    Returns dict or None.
    """
    if len(data) < offset + 20:
        return None
    segment = data[offset:offset + 20]
    magic = struct.unpack("!I", segment[0:4])[0]
    if magic != CAMOSTREAM_MAGIC:
        return None
    ver = segment[4]
    mode = segment[5]
    flags = struct.unpack("!H", segment[6:8])[0]
    session_id = struct.unpack("!I", segment[8:12])[0]
    timestamp = struct.unpack("!I", segment[12:16])[0]
    length = struct.unpack("!I", segment[16:20])[0]
    return {
        "magic": magic,
        "version": ver,
        "mode": mode,
        "flags": flags,
        "session_id": session_id,
        "timestamp": timestamp,
        "length": length,
        "is_decoy": bool(flags & 0x01),
        "is_encrypted": bool(flags & 0x02),
    }


def classify_packet(pkt):
    """
    Classify a scapy packet into one of:
      'rtp', 'rtcp_sr', 'rtcp_rr', 'rtp_keepalive', 'stun',
      'other_udp', 'tcp', 'other'
    Also returns parsed header info dict (may be None).
    """
    if pkt.haslayer(TCP):
        return "tcp", None

    if not pkt.haslayer(UDP):
        return "other", None

    payload = bytes(pkt[UDP].payload)
    if not payload:
        return "other_udp", None

    # Check STUN first (distinct magic cookie)
    if _is_stun(payload):
        return "stun", {"type": "stun"}

    # Check RTCP
    rtcp_pt = _is_rtcp(payload)
    if rtcp_pt == RTCP_SR_PT:
        return "rtcp_sr", {"rtcp_pt": rtcp_pt}
    if rtcp_pt == RTCP_RR_PT:
        return "rtcp_rr", {"rtcp_pt": rtcp_pt}

    # Check RTP
    rtp = _parse_rtp_header(payload)
    if rtp is not None:
        if rtp["pt"] == 13:
            return "rtp_keepalive", rtp
        if rtp["pt"] in VALID_RTP_PTS:
            shim = _parse_shim_header(payload, 12)
            info = {**rtp}
            if shim:
                info["shim"] = shim
            return "rtp", info

    return "other_udp", None


# ---------------------------------------------------------------------------
# Analysis Functions
# ---------------------------------------------------------------------------

def analyze_protocol_distribution(classifications):
    """
    Section 1: Protocol distribution analysis.
    Returns (report_dict, score 0-100).
    """
    counts = Counter(classifications)
    total = len(classifications)
    if total == 0:
        return {"error": "no packets"}, 0

    udp_types = {"rtp", "rtcp_sr", "rtcp_rr", "rtp_keepalive", "stun", "other_udp"}
    total_udp = sum(counts.get(t, 0) for t in udp_types)
    classifiable = sum(counts.get(t, 0) for t in udp_types - {"other_udp"})
    pct_classifiable = (classifiable / total_udp * 100) if total_udp > 0 else 0

    dist = {}
    for t in sorted(counts.keys()):
        dist[t] = {"count": counts[t], "pct": round(counts[t] / total * 100, 2)}

    passed = pct_classifiable > 80
    # Score: linear mapping from 50% -> 0 to 100% -> 100
    score = max(0, min(100, (pct_classifiable - 50) * 2))

    return {
        "total_packets": total,
        "total_udp": total_udp,
        "classifiable_as_rtp_rtcp_stun": classifiable,
        "pct_classifiable": round(pct_classifiable, 2),
        "distribution": dist,
        "pass": passed,
    }, score


def analyze_size_distribution(packet_sizes):
    """
    Section 2: Packet size distribution.
    Checks bimodality and coefficient of variation.
    Returns (report_dict, score 0-100).
    """
    if not packet_sizes:
        return {"error": "no packets"}, 0

    sizes = np.array(packet_sizes, dtype=float)
    mean_size = float(np.mean(sizes))
    std_size = float(np.std(sizes))
    cv = std_size / mean_size if mean_size > 0 else 0

    # Build histogram bins
    bins = [0, 100, 200, 400, 600, 800, 1000, 1200, 1400, 1600]
    hist, edges = np.histogram(sizes, bins=bins)
    histogram = {}
    for i in range(len(hist)):
        label = f"{int(edges[i])}-{int(edges[i+1])}"
        histogram[label] = int(hist[i])

    # WebRTC-like bimodality check: expect packets in both <200 and >800 ranges
    small_count = int(np.sum(sizes < 200))
    large_count = int(np.sum(sizes > 800))
    has_bimodal = small_count > 0 and large_count > 0
    bimodal_ratio = min(small_count, large_count) / max(small_count, large_count, 1)

    passed = cv > 0.3

    # Score: CV contribution + bimodality bonus
    cv_score = min(60, cv * 100)
    bimodal_score = 40 * bimodal_ratio if has_bimodal else 0
    score = min(100, cv_score + bimodal_score)

    return {
        "count": len(packet_sizes),
        "mean": round(mean_size, 2),
        "std": round(std_size, 2),
        "min": int(np.min(sizes)),
        "max": int(np.max(sizes)),
        "coefficient_of_variation": round(cv, 4),
        "histogram": histogram,
        "small_packets_lt200": small_count,
        "large_packets_gt800": large_count,
        "bimodal_detected": has_bimodal,
        "pass": passed,
    }, score


def analyze_timing(timestamps_sec):
    """
    Section 3: Inter-packet timing analysis.
    Returns (report_dict, score 0-100).
    """
    if len(timestamps_sec) < 2:
        return {"error": "insufficient packets for timing analysis"}, 0

    ts = np.array(timestamps_sec, dtype=float)
    deltas_ms = np.diff(ts) * 1000.0  # convert to ms
    deltas_ms = deltas_ms[deltas_ms > 0]  # filter zero-deltas

    if len(deltas_ms) == 0:
        return {"error": "no positive inter-arrival times"}, 0

    mean_iat = float(np.mean(deltas_ms))
    std_iat = float(np.std(deltas_ms))
    median_iat = float(np.median(deltas_ms))
    jitter = float(np.mean(np.abs(np.diff(deltas_ms))))  # RFC 3550 style jitter approx

    # Pass: mean inter-arrival in 10-25ms for 60fps with jitter
    in_range = 10 <= mean_iat <= 25
    passed = in_range

    # Score: distance from ideal 16.67ms
    ideal = TARGET_INTERVAL_MS
    deviation = abs(mean_iat - ideal) / ideal
    timing_score = max(0, 100 - deviation * 200)

    # Bonus for having reasonable jitter (not perfectly periodic, not chaotic)
    # Jitter between 0.5ms and 5ms is ideal for looking like real video
    if 0.5 <= jitter <= 5.0:
        jitter_bonus = 20
    elif jitter < 0.5:
        jitter_bonus = 5  # too regular, might look suspicious
    else:
        jitter_bonus = max(0, 20 - (jitter - 5.0) * 2)

    score = min(100, timing_score * 0.7 + jitter_bonus + 10)

    # Percentile distribution
    percentiles = {}
    for p in [5, 25, 50, 75, 95]:
        percentiles[f"p{p}"] = round(float(np.percentile(deltas_ms, p)), 3)

    return {
        "packet_count": len(timestamps_sec),
        "mean_iat_ms": round(mean_iat, 3),
        "std_iat_ms": round(std_iat, 3),
        "median_iat_ms": round(median_iat, 3),
        "jitter_ms": round(jitter, 3),
        "percentiles": percentiles,
        "target_fps": TARGET_FPS,
        "target_interval_ms": TARGET_INTERVAL_MS,
        "pass": passed,
    }, max(0, min(100, score))


def analyze_entropy(payloads):
    """
    Section 4: Shannon entropy of packet payloads.
    Returns (report_dict, score 0-100).
    """
    if not payloads:
        return {"error": "no payloads to analyze"}, 0

    entropies = []
    for payload in payloads:
        if len(payload) < 16:
            continue
        # Calculate Shannon entropy
        byte_counts = Counter(payload)
        total = len(payload)
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        entropies.append(entropy)

    if not entropies:
        return {"error": "no payloads with sufficient length"}, 0

    ent_arr = np.array(entropies)
    avg_entropy = float(np.mean(ent_arr))
    min_entropy = float(np.min(ent_arr))
    max_entropy = float(np.max(ent_arr))
    std_entropy = float(np.std(ent_arr))

    # Count packets with high entropy (>7.5 = near-random)
    high_entropy_count = int(np.sum(ent_arr > 7.5))
    high_entropy_pct = high_entropy_count / len(ent_arr) * 100

    passed = avg_entropy > 7.0

    # Score: linear from 5.0 -> 0 to 8.0 -> 100
    score = max(0, min(100, (avg_entropy - 5.0) / 3.0 * 100))

    return {
        "samples_analyzed": len(entropies),
        "avg_entropy_bits": round(avg_entropy, 4),
        "min_entropy_bits": round(min_entropy, 4),
        "max_entropy_bits": round(max_entropy, 4),
        "std_entropy_bits": round(std_entropy, 4),
        "high_entropy_gt7_5_pct": round(high_entropy_pct, 2),
        "max_possible_entropy": 8.0,
        "pass": passed,
    }, score


def analyze_rtp_consistency(rtp_packets):
    """
    Section 5: RTP sequence number, SSRC, and timestamp consistency.
    rtp_packets: list of (classification, info_dict) where classification is 'rtp'.
    Returns (report_dict, score 0-100).
    """
    if not rtp_packets:
        return {"error": "no RTP packets found"}, 0

    # Group by SSRC
    ssrc_streams = defaultdict(list)
    for info in rtp_packets:
        ssrc_streams[info["ssrc"]].append(info)

    total_checks = 0
    sequential_ok = 0
    ts_progression_ok = 0
    ssrc_report = {}

    for ssrc, pkts in ssrc_streams.items():
        stream_seq_ok = 0
        stream_ts_ok = 0
        stream_total = 0

        for i in range(1, len(pkts)):
            prev_seq = pkts[i - 1]["seq"]
            curr_seq = pkts[i]["seq"]
            expected_seq = (prev_seq + 1) & 0xFFFF

            prev_ts = pkts[i - 1]["timestamp"]
            curr_ts = pkts[i]["timestamp"]

            stream_total += 1
            total_checks += 1

            if curr_seq == expected_seq:
                stream_seq_ok += 1
                sequential_ok += 1

            # Timestamp should increase (with wraparound tolerance)
            ts_diff = (curr_ts - prev_ts) & 0xFFFFFFFF
            # For 60fps at 90kHz, expect ~1500 ticks per frame
            # Allow wide range: 100 to 10000 ticks
            if 0 < ts_diff < 900000:  # up to ~10 seconds worth
                stream_ts_ok += 1
                ts_progression_ok += 1

        ssrc_hex = f"0x{ssrc:08X}"
        ssrc_report[ssrc_hex] = {
            "packet_count": len(pkts),
            "seq_checks": stream_total,
            "seq_ok": stream_seq_ok,
            "seq_consistency_pct": round(stream_seq_ok / max(stream_total, 1) * 100, 2),
            "ts_ok": stream_ts_ok,
            "ts_consistency_pct": round(stream_ts_ok / max(stream_total, 1) * 100, 2),
        }

    seq_pct = sequential_ok / max(total_checks, 1) * 100
    ts_pct = ts_progression_ok / max(total_checks, 1) * 100

    passed = seq_pct > 90

    # Score: weighted combination of seq and ts consistency
    score = seq_pct * 0.6 + ts_pct * 0.4

    return {
        "unique_ssrc_count": len(ssrc_streams),
        "total_rtp_packets": len(rtp_packets),
        "total_seq_checks": total_checks,
        "sequential_consistency_pct": round(seq_pct, 2),
        "timestamp_progression_pct": round(ts_pct, 2),
        "streams": ssrc_report,
        "pass": passed,
    }, min(100, max(0, score))


def analyze_decoy_effectiveness(classifications, rtp_infos):
    """
    Section 6: Decoy type coverage and well-formedness.
    Returns (report_dict, score 0-100).
    """
    counts = Counter(classifications)

    decoy_types = {
        "rtcp_sr": counts.get("rtcp_sr", 0),
        "rtcp_rr": counts.get("rtcp_rr", 0),
        "rtp_keepalive": counts.get("rtp_keepalive", 0),
        "stun": counts.get("stun", 0),
    }

    # Also count shim-level decoys from RTP packets
    shim_decoy_count = 0
    for info in rtp_infos:
        shim = info.get("shim")
        if shim and shim.get("is_decoy"):
            shim_decoy_count += 1
    decoy_types["shim_decoy"] = shim_decoy_count

    total_decoys = sum(decoy_types.values())
    types_present = sum(1 for v in decoy_types.values() if v > 0)
    total_expected_types = len(decoy_types)

    passed = types_present == total_expected_types

    # Score: coverage percentage * quality factor
    coverage_pct = types_present / total_expected_types * 100
    # Bonus for having a decent number of each type
    balance_scores = []
    if total_decoys > 0:
        for t, c in decoy_types.items():
            ratio = c / total_decoys
            # Ideal: roughly even distribution, but some variation is fine
            balance_scores.append(min(1.0, ratio * total_expected_types * 2))
    balance = np.mean(balance_scores) * 100 if balance_scores else 0

    score = coverage_pct * 0.7 + balance * 0.3

    return {
        "decoy_counts": decoy_types,
        "total_decoys": total_decoys,
        "types_present": types_present,
        "types_expected": total_expected_types,
        "pass": passed,
    }, min(100, max(0, score))


def compute_dpi_score(section_scores):
    """
    Section 7: Combine all metrics into a single DPI resistance score.
    Returns (report_dict, overall_score).
    """
    weighted_score = 0.0
    breakdown = {}

    for key, weight in WEIGHTS.items():
        raw = section_scores.get(key, 0)
        contribution = raw * weight
        weighted_score += contribution
        breakdown[key] = {
            "raw_score": round(raw, 2),
            "weight": weight,
            "weighted": round(contribution, 2),
        }

    overall = round(weighted_score, 2)

    # Grade
    if overall >= 90:
        grade = "A"
        verdict = "Excellent - traffic is highly convincing as video streaming"
    elif overall >= 80:
        grade = "B"
        verdict = "Good - traffic passes casual inspection"
    elif overall >= 70:
        grade = "C"
        verdict = "Acceptable - traffic has some anomalies but may pass basic DPI"
    elif overall >= 50:
        grade = "D"
        verdict = "Poor - traffic has detectable anomalies"
    else:
        grade = "F"
        verdict = "Failing - traffic is easily distinguishable from video streaming"

    return {
        "overall_score": overall,
        "grade": grade,
        "verdict": verdict,
        "breakdown": breakdown,
    }, overall


# ---------------------------------------------------------------------------
# Main Analysis Pipeline
# ---------------------------------------------------------------------------

def analyze_pcap(pcap_path: str, mode: str = "udp"):
    """
    Run all analysis sections on the given PCAP file.
    Returns the full report dict and the overall score.
    """
    print(f"[*] Loading PCAP: {pcap_path}")
    packets = rdpcap(pcap_path)
    print(f"[*] Loaded {len(packets)} packets")

    # Classify all packets
    classifications = []
    rtp_infos = []
    packet_sizes = []
    timestamps_sec = []
    payloads = []

    for pkt in packets:
        cls, info = classify_packet(pkt)
        classifications.append(cls)

        # Collect sizes
        pkt_len = len(pkt)
        packet_sizes.append(pkt_len)

        # Collect timestamps
        if hasattr(pkt, "time"):
            timestamps_sec.append(float(pkt.time))

        # Collect RTP info
        if cls == "rtp" and info:
            rtp_infos.append(info)

        # Collect payloads for entropy analysis
        if pkt.haslayer(UDP) and pkt[UDP].payload:
            raw_payload = bytes(pkt[UDP].payload)
            if len(raw_payload) > 12:  # skip tiny packets
                # For entropy, analyze the payload after RTP header (12B) + shim (20B)
                payload_offset = 32 if len(raw_payload) > 32 else 12
                payloads.append(raw_payload[payload_offset:])
        elif pkt.haslayer(TCP) and pkt.haslayer(Raw):
            raw_payload = bytes(pkt[Raw].load)
            if len(raw_payload) > 20:
                payloads.append(raw_payload[20:])  # skip shim for TCP mode

    # Filter by mode if needed
    if mode == "tcp":
        print("[*] Mode: TCP - analyzing TCP stream characteristics")
    else:
        print("[*] Mode: UDP - analyzing RTP/RTCP/STUN characteristics")

    # Run all analysis sections
    print("[*] Running protocol distribution analysis...")
    proto_report, proto_score = analyze_protocol_distribution(classifications)

    print("[*] Running packet size distribution analysis...")
    size_report, size_score = analyze_size_distribution(packet_sizes)

    print("[*] Running timing analysis...")
    timing_report, timing_score = analyze_timing(timestamps_sec)

    print("[*] Running entropy analysis...")
    entropy_report, entropy_score = analyze_entropy(payloads)

    print("[*] Running RTP consistency check...")
    rtp_report, rtp_score = analyze_rtp_consistency(rtp_infos)

    print("[*] Running decoy effectiveness analysis...")
    decoy_report, decoy_score = analyze_decoy_effectiveness(classifications, rtp_infos)

    # Compute composite DPI score
    section_scores = {
        "protocol_conformance": proto_score,
        "size_distribution": size_score,
        "timing": timing_score,
        "entropy": entropy_score,
        "rtp_consistency": rtp_score,
        "decoy_coverage": decoy_score,
    }

    print("[*] Computing DPI resistance score...")
    dpi_report, overall_score = compute_dpi_score(section_scores)

    report = {
        "metadata": {
            "pcap_file": pcap_path,
            "mode": mode,
            "total_packets": len(packets),
            "analysis_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "1_protocol_distribution": proto_report,
        "2_size_distribution": size_report,
        "3_timing_analysis": timing_report,
        "4_entropy_analysis": entropy_report,
        "5_rtp_consistency": rtp_report,
        "6_decoy_effectiveness": decoy_report,
        "7_dpi_resistance_score": dpi_report,
    }

    return report, overall_score


def print_summary(report, overall_score):
    """Print a human-readable summary of the analysis."""
    sep = "=" * 72

    print(f"\n{sep}")
    print("  CamoStream Traffic Analysis Report")
    print(sep)

    meta = report["metadata"]
    print(f"  File:     {meta['pcap_file']}")
    print(f"  Mode:     {meta['mode']}")
    print(f"  Packets:  {meta['total_packets']}")
    print(f"  Time:     {meta['analysis_timestamp']}")
    print(sep)

    # Section 1: Protocol Distribution
    s1 = report["1_protocol_distribution"]
    print("\n  [1] Protocol Distribution")
    print(f"      Total UDP packets:  {s1.get('total_udp', 'N/A')}")
    print(f"      Classifiable:       {s1.get('pct_classifiable', 'N/A')}%")
    dist = s1.get("distribution", {})
    for proto, info in dist.items():
        print(f"        {proto:20s} {info['count']:6d}  ({info['pct']:.1f}%)")
    _print_pass(s1.get("pass", False), ">80% classifiable as RTP/RTCP/STUN")

    # Section 2: Size Distribution
    s2 = report["2_size_distribution"]
    print("\n  [2] Packet Size Distribution")
    print(f"      Mean:  {s2.get('mean', 'N/A')}B   Std: {s2.get('std', 'N/A')}B")
    print(f"      Range: {s2.get('min', 'N/A')}B - {s2.get('max', 'N/A')}B")
    print(f"      CV:    {s2.get('coefficient_of_variation', 'N/A')}")
    print(f"      Small (<200B): {s2.get('small_packets_lt200', 'N/A')}  "
          f"Large (>800B): {s2.get('large_packets_gt800', 'N/A')}")
    _print_pass(s2.get("pass", False), "CV > 0.3")

    # Section 3: Timing
    s3 = report["3_timing_analysis"]
    print("\n  [3] Timing Analysis")
    print(f"      Mean IAT:   {s3.get('mean_iat_ms', 'N/A')} ms")
    print(f"      Median IAT: {s3.get('median_iat_ms', 'N/A')} ms")
    print(f"      Jitter:     {s3.get('jitter_ms', 'N/A')} ms")
    _print_pass(s3.get("pass", False), "mean IAT in 10-25ms range")

    # Section 4: Entropy
    s4 = report["4_entropy_analysis"]
    print("\n  [4] Entropy Analysis")
    print(f"      Avg entropy:  {s4.get('avg_entropy_bits', 'N/A')} bits/byte")
    print(f"      High (>7.5):  {s4.get('high_entropy_gt7_5_pct', 'N/A')}%")
    _print_pass(s4.get("pass", False), "avg entropy > 7.0 bits/byte")

    # Section 5: RTP Consistency
    s5 = report["5_rtp_consistency"]
    print("\n  [5] RTP Consistency")
    print(f"      SSRC streams:      {s5.get('unique_ssrc_count', 'N/A')}")
    print(f"      Seq consistency:   {s5.get('sequential_consistency_pct', 'N/A')}%")
    print(f"      TS progression:    {s5.get('timestamp_progression_pct', 'N/A')}%")
    _print_pass(s5.get("pass", False), ">90% sequential consistency")

    # Section 6: Decoy Effectiveness
    s6 = report["6_decoy_effectiveness"]
    print("\n  [6] Decoy Effectiveness")
    dc = s6.get("decoy_counts", {})
    for dtype, count in dc.items():
        print(f"        {dtype:20s} {count:6d}")
    print(f"      Types present: {s6.get('types_present', 0)}/{s6.get('types_expected', 5)}")
    _print_pass(s6.get("pass", False), "all decoy types present")

    # Section 7: DPI Score
    s7 = report["7_dpi_resistance_score"]
    print(f"\n{sep}")
    print(f"  [7] DPI Resistance Score")
    print(f"{sep}")
    bd = s7.get("breakdown", {})
    for metric, info in bd.items():
        bar_len = int(info["raw_score"] / 5)
        bar = "#" * bar_len + "." * (20 - bar_len)
        print(f"      {metric:25s} [{bar}] {info['raw_score']:5.1f} x {info['weight']:.2f} = {info['weighted']:5.1f}")

    print(f"\n      OVERALL SCORE: {s7['overall_score']:.1f} / 100  (Grade: {s7['grade']})")
    print(f"      {s7['verdict']}")
    print(sep)

    if overall_score >= 70:
        print("\n  RESULT: PASS")
    else:
        print("\n  RESULT: FAIL")
    print()


def _print_pass(passed, criteria):
    """Print pass/fail indicator."""
    status = "PASS" if passed else "FAIL"
    marker = "[+]" if passed else "[-]"
    print(f"      {marker} {status}: {criteria}")


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="CamoStream PCAP Traffic Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("pcap", help="Path to the PCAP file to analyze")
    parser.add_argument(
        "--mode",
        choices=["tcp", "udp"],
        default="udp",
        help="Transport mode (default: udp)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Path to save JSON report (default: stdout summary only)",
    )

    args = parser.parse_args()

    pcap_path = str(Path(args.pcap).resolve())
    if not Path(pcap_path).exists():
        print(f"[!] Error: PCAP file not found: {pcap_path}", file=sys.stderr)
        sys.exit(2)

    report, overall_score = analyze_pcap(pcap_path, mode=args.mode)

    # Print human-readable summary
    print_summary(report, overall_score)

    # Save JSON report if requested
    if args.output:
        output_path = str(Path(args.output).resolve())
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] JSON report saved to: {output_path}")

    # Exit code based on score
    if overall_score >= 70:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
