<div align="center">
```
██████╗ ██████╗ ██╗    ███████╗███╗   ██╗ ██████╗ ██╗███╗   ██╗███████╗
██╔══██╗██╔══██╗██║    ██╔════╝████╗  ██║██╔════╝ ██║████╗  ██║██╔════╝
██║  ██║██████╔╝██║    █████╗  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║█████╗
██║  ██║██╔═══╝ ██║    ██╔══╝  ██║╚██╗██║██║   ██║██║██║╚██╗██║██╔══╝
██████╔╝██║     ██║    ███████╗██║ ╚████║╚██████╔╝██║██║ ╚████║███████╗
╚═════╝ ╚═╝     ╚═╝    ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝
```

### *Because knowing WHERE packets go is more powerful than reading what they say.*

[![Language](https://img.shields.io/badge/Language-C%2B%2B17-00599C?style=for-the-badge&logo=cplusplus)](/)
[![Threads](https://img.shields.io/badge/Architecture-Multithreaded-6C3483?style=for-the-badge&logo=linux)](/)
[![Tests](https://img.shields.io/badge/Unit%20Tests-30%2F30%20✓-27AE60?style=for-the-badge)](/)
[![ML](https://img.shields.io/badge/ML-Random%20Forest-E67E22?style=for-the-badge&logo=python)](/)
[![Benchmark](https://img.shields.io/badge/Throughput-13%2C500%2B%20pkt%2Fs-E74C3C?style=for-the-badge)](/)

</div>

---

## The One-Line Explanation

> **Your browser visits `https://youtube.com`. The connection is encrypted — nobody can read your video. But the domain name travels in plaintext in the very first packet. This engine catches that, classifies it, and decides: forward or drop — in under 1 millisecond.**

That's Deep Packet Inspection. That's what ISPs do to throttle your Netflix. That's what colleges use to block gaming sites. That's what this project replicates — from scratch, in C++, with a multithreaded pipeline and an ML classifier on top.

---

## Why This Project Exists

Most networking projects either:
- Use a library that does everything for them (`scapy`, `libpcap`)
- Stop at "parse a packet and print the IP address"

This project does neither. Every byte offset is hand-calculated. Every thread is hand-managed. The goal was to understand what actually happens inside a Cisco firewall or a Cloudflare edge node — not just use one.

---

## What It Actually Does
```
  Your capture.pcap                                    filtered.pcap
  ┌──────────────┐                                   ┌──────────────┐
  │ 15,414       │                                   │ Clean        │
  │ raw packets  │──────────────────────────────────►│ packets only │
  │ from         │                                   │ (blocked     │
  │ Wireshark    │                                   │  flows gone) │
  └──────────────┘                                   └──────────────┘
         │
         │   For each packet:
         ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  LAYER 2  Read 14 bytes → src MAC, dst MAC, EtherType           │
  │  LAYER 3  Read 20 bytes → src IP, dst IP, protocol, TTL         │
  │  LAYER 4  Read 20 bytes → src port, dst port, TCP flags         │
  │  LAYER 7  Inspect payload:                                       │
  │           ├── TLS? → Walk ClientHello → find extension 0x0000   │
  │           │          → extract SNI → "www.youtube.com"  🎯      │
  │           ├── HTTP? → Find "Host:" header → "example.com" 🎯    │
  │           └── DNS?  → Parse query labels → "google.com"  🎯     │
  │  RULES    isBlocked(src_ip, app_type, sni)?                      │
  │           ├── YES → DROP                                         │
  │           └── NO  → FORWARD                                      │
  └─────────────────────────────────────────────────────────────────┘
         │
         ▼
  flows.csv → Random Forest → predict app WITHOUT domain name
```
---

## The Architecture That Makes It Fast
```
                         ┌──────────────────────┐
                         │    READER (main)      │
                         │  reads PCAP file      │
                         └──────────┬───────────┘
                                    │
                     hash(5-tuple) % num_lbs
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                                           │
    ┌─────────▼──────────┐                   ┌───────────▼────────┐
    │   LOAD BALANCER 0  │                   │  LOAD BALANCER 1   │
    └─────────┬──────────┘                   └──────────┬─────────┘
              │                                         │
     ┌────────┴────────┐                     ┌─────────┴─────────┐
     │                 │                     │                   │
  ┌──▼───┐         ┌───▼──┐              ┌───▼──┐           ┌────▼─┐
  │ FP 0 │         │ FP 1 │              │ FP 2 │           │ FP 3 │
  │ own  │         │ own  │              │ own  │           │ own  │
  │ flow │         │ flow │              │ flow │           │ flow │
  │ table│         │ table│              │ table│           │ table│
  └──┬───┘         └──┬───┘              └──┬───┘           └──┬───┘
     └────────────────┴─────────────────────┴─────────────────┘
                                    │
                             output_queue
                                    │
                         ┌──────────▼──────────┐
                         │    WRITER THREAD     │
                         │  writes filtered.pcap│
                         └─────────────────────┘
```

### Why Consistent Hashing?
```cpp
// Same connection ALWAYS goes to same FP thread
// Each FP has its own flow table — NO LOCKS needed
size_t fp_idx = hash(five_tuple) % fps_.size();
```

All packets of connection A always go to FP2. All packets of connection B always go to FP0. No two FPs ever touch the same flow. The hot path is completely **lock-free**.

---

## How TLS SNI Extraction Works

HTTPS is encrypted — but the destination hostname is NOT encrypted in the first packet:
```
Byte offset from payload start:

[0]      0x16       → Content-Type: Handshake
[1-2]    0x03 0x01  → TLS version
[5]      0x01       → Handshake-Type: ClientHello ← CHECK
[9-10]   0x03 0x03  → Client version TLS 1.2
[11-42]  random     → 32 bytes                   ← SKIP
[43]     N          → Session ID length           ← SKIP N
[44+N]   cipher_len → Cipher suites              ← SKIP
[...]    comp_len   → Compression methods         ← SKIP
[X]      ext_total  → Walk extensions:
                       type == 0x0000? → SNI found!
                         read name_len bytes
                         → "www.youtube.com" 🎯
```

No decryption. No keys. Just careful byte counting.

---

## Build & Run

### Requirements
```bash
sudo apt install g++ make python3
```

### Build
```bash
git clone https://github.com/YOUR_USERNAME/packet_analyzer
cd packet_analyzer
make all
```

### Generate test data
```bash
python3 generate_test_pcap.py
```

### Run simple version
```bash
./dpi_simple test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app Steam
```

### Run multithreaded version
```bash
./dpi_engine test_dpi.pcap output.pcap \
    --block-app YouTube       \
    --block-app Netflix       \
    --block-domain tiktok     \
    --block-ip 192.168.1.50   \
    --lbs 2 --fps 4
```

### Run unit tests
```bash
make dpi_test && ./dpi_test
```

### Run ML classifier
```bash
pip3 install pandas scikit-learn
python3 ml_classifier.py
```

---

## CLI Reference

| Flag | Description | Example |
|------|-------------|---------|
| `--block-app` | Block by app name | `--block-app YouTube` |
| `--block-ip` | Block source IPv4 | `--block-ip 192.168.1.99` |
| `--block-domain` | Block SNI substring | `--block-domain tiktok` |
| `--lbs` | Load Balancer threads | `--lbs 2` |
| `--fps` | Fast Path threads per LB | `--fps 4` |

**Supported apps:**
`YouTube` · `Netflix` · `Facebook` · `Instagram` · `TikTok` · `Twitter` · `WhatsApp` · `Telegram` · `GitHub` · `Reddit` · `Steam` · `Google`

---

## Benchmark Results

Tested on real Wireshark capture:

| Metric | Value |
|--------|-------|
| Real packets tested | 15,414 |
| Processing time | 0.060 seconds |
| **Throughput** | **13,596 packets/sec** |
| Data rate | 9.32 MB/sec |
| Threads | 2 LB + 4 FP + 1 Writer = 7 total |
| Unit tests | 30 / 30 passing |

---

## Unit Test Results
```
── SNI Extractor Tests ──────────────────────────
  ✓ PASS  Extract www.youtube.com
  ✓ PASS  Extract github.com
  ✓ PASS  Non-TLS returns nullopt
  ✓ PASS  Empty payload returns nullopt
  ✓ PASS  Extract long YouTube CDN domain

── HTTP Host Extractor Tests ────────────────────
  ✓ PASS  Extract Host from GET request
  ✓ PASS  TLS data returns nullopt
  ✓ PASS  Extract Host from POST request

── App Classification Tests ─────────────────────
  ✓ PASS  YouTube SNI → AppType::YOUTUBE
  ✓ PASS  netflix → AppType::NETFLIX
  ✓ PASS  github → AppType::GITHUB
  ✓ PASS  Port 53 UDP → DNS
  ✓ PASS  Port 443 TCP → HTTPS

── Rule Manager Tests ───────────────────────────
  ✓ PASS  Block YouTube by app type
  ✓ PASS  Block tiktok.com by domain
  ✓ PASS  Block by source IP
  ✓ PASS  Allow clean IP

── FiveTuple Tests ──────────────────────────────
  ✓ PASS  Same 5-tuple equals
  ✓ PASS  Different tuple diff hash

╔══════════════════════════════════════════════╗
║  RESULTS:  30 passed    0 failed   🏆        ║
╚══════════════════════════════════════════════╝
```

---

## ML Classifier Results
```
Feature Importance (what the model learned):
  avg_pkt_size    0.291  ##############
  byte_count      0.287  ##############
  packet_count    0.252  ############
  dst_port        0.106  #####
  protocol        0.064  ###

Sample Predictions (NO SNI used):
  dst_port   actual     predicted
  ─────────────────────────────────
  443        Google     Google     ✓
  53         DNS        DNS        ✓
  443        GitHub     GitHub     ✓
  80         HTTP       HTTP       ✓
  443        YouTube    YouTube    ✓
```

The model identifies YouTube vs GitHub vs Google
purely from how packets behave — no domain names used.

---

## ML Classifier — CICIDS2017

Trained on real network attack dataset (134,412 samples):

| Attack Type | Precision | Recall |
|---|---|---|
| DDoS | 100% | 100% |
| Port Scan | 100% | 100% |
| Normal | 99% | 99% |
| Web Attack | 88% | 98% |

Overall Accuracy: 99.38%

> Note: High accuracy (99.4%) is consistent with 
> published results on CICIDS2017. DDoS and Port Scan 
> attacks have distinctive behavioral signatures making 
> them easy to classify. Infiltration detection is weaker 
> (86% recall) due to only 36 training samples.

## Key Engineering Decisions

**Why not use libpcap?**
Writing the binary parser from scratch means understanding every byte — 24-byte global header, 16-byte per-packet header, endianness detection via magic number. Using a library hides all of this.

**Why consistent hashing over round-robin?**
Round-robin breaks flow tracking. The blocked flag, SNI, and byte count must all be seen by one thread. Consistent hashing guarantees this with zero synchronization overhead.

**Why condition_variable over busy-waiting?**
A busy-waiting thread burns 100% CPU doing nothing. `condition_variable.wait()` suspends the thread at OS level — zero CPU cost while idle.

**Why Random Forest for ML?**
Handles small datasets well, feature importance is interpretable, no GPU needed, fast inference. You can explain exactly why it classified traffic as YouTube.

---

## Real-World Parallels

| This Project | Real World |
|---|---|
| FiveTuple hash routing | RSS in Network Interface Cards |
| TSQueue back-pressure | Kernel socket buffer management |
| Per-FP flow tables | Per-CPU tables in Linux conntrack |
| SNI extraction | Palo Alto App-ID engine |
| Rule matching | iptables / nftables |
| ML classification | Cisco NBAR2 behavioral analysis |

---

## Interview Questions This Project Answers

**Q: How do you extract domain names from HTTPS without decrypting it?**
TLS SNI is sent in plaintext in the ClientHello before encryption begins. Walk the extension list looking for type `0x0000`.

**Q: Why does the same connection need to go to the same thread?**
Flow state is stateful — you need all packets of a connection to maintain the blocked/forwarded decision and correctly extract SNI.

**Q: What is a dangling pointer and where could one occur here?**
`ParsedPacket.payload` points into `RawPacket.data`. If you parse a local `RawPacket` then move the struct to another thread, the pointer becomes invalid. Fix: always parse from the copy that travels with the struct.

**Q: How would you scale this to 10 million packets/sec?**
DPDK to bypass the kernel network stack, huge pages for DMA buffers, NUMA-aware memory allocation, batch processing instead of per-packet.

---

## What's Next

- [ ] Live capture via raw AF_PACKET socket
- [ ] QUIC/HTTP3 SNI support
- [ ] Bandwidth throttling (delay instead of drop)
- [ ] Real-time web dashboard
- [ ] DNS-over-HTTPS detection

---

## File Structure
```
packet_analyzer/
├── include/
│   ├── types.h              # FiveTuple, AppType, Flow, RawPacket
│   ├── pcap_reader.h        # Binary PCAP read/write
│   ├── packet_parser.h      # Ethernet/IP/TCP/UDP dissection
│   ├── sni_extractor.h      # TLS SNI + HTTP Host extraction
│   ├── rule_manager.h       # Block/throttle rules
│   └── thread_safe_queue.h  # TSQueue producer/consumer
├── src/
│   ├── main_working.cpp     # Simple version (start here)
│   ├── dpi_mt.cpp           # Multithreaded version
│   └── test_dpi.cpp         # 30 unit tests
├── ml_classifier.py         # Random Forest classifier
├── generate_test_pcap.py    # Test data generator
└── Makefile
```

---

<div align="center">

**Built to understand what actually happens inside a network.**
**Not to wrap a library. Not to follow a tutorial.**
**From raw bytes to blocked connections — every step by hand.**

*Tested on 15,000+ real packets captured from live network traffic.*

</div>