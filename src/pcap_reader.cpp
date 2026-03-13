#include "pcap_reader.h"
#include <cstring>
#include <iostream>

static const uint32_t MAGIC_LE = 0xa1b2c3d4;
static const uint32_t MAGIC_BE = 0xd4c3b2a1;

uint32_t PcapReader::_swap32(uint32_t v) const {
    if (!swap_bytes_) return v;
    return ((v & 0xFF) << 24) | (((v>>8) & 0xFF) << 16) |
           (((v>>16)& 0xFF) << 8) | ((v>>24) & 0xFF);
}

uint16_t PcapReader::_swap16(uint16_t v) const {
    if (!swap_bytes_) return v;
    return (uint16_t)(((v & 0xFF) << 8) | ((v >> 8) & 0xFF));
}

bool PcapReader::open(const std::string& filename) {
    file_.open(filename, std::ios::binary);
    if (!file_.is_open()) {
        std::cerr << "[PcapReader] Cannot open: " << filename << "\n";
        return false;
    }
    struct { uint32_t magic, v1, v2, tz, sig, snap, net; } gh;
    file_.read((char*)&gh, 24);
    if (file_.gcount() != 24) return false;

    if (gh.magic == MAGIC_LE)      swap_bytes_ = false;
    else if (gh.magic == MAGIC_BE) swap_bytes_ = true;
    else {
        std::cerr << "[PcapReader] Invalid magic\n";
        return false;
    }
    return true;
}

bool PcapReader::readNextPacket(RawPacket& pkt) {
    struct { uint32_t ts_sec, ts_usec, incl_len, orig_len; } hdr;
    file_.read((char*)&hdr, 16);
    if (file_.gcount() != 16) return false;

    pkt.ts_sec   = _swap32(hdr.ts_sec);
    pkt.ts_usec  = _swap32(hdr.ts_usec);
    pkt.incl_len = _swap32(hdr.incl_len);
    pkt.orig_len = _swap32(hdr.orig_len);

    if (pkt.incl_len > 65535) return false;
    file_.read((char*)pkt.data, pkt.incl_len);
    return (size_t)file_.gcount() == pkt.incl_len;
}

void PcapReader::close() { file_.close(); }

bool PcapWriter::open(const std::string& filename) {
    file_.open(filename, std::ios::binary | std::ios::trunc);
    if (!file_.is_open()) return false;
    struct { uint32_t magic; uint16_t vmaj, vmin;
             int32_t tz; uint32_t sig, snap, net; }
    gh = { 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1 };
    file_.write((char*)&gh, sizeof(gh));
    return true;
}

bool PcapWriter::writePacket(const RawPacket& pkt) {
    struct { uint32_t ts_sec, ts_usec, incl_len, orig_len; }
    hdr = { pkt.ts_sec, pkt.ts_usec, pkt.incl_len, pkt.orig_len };
    file_.write((char*)&hdr, 16);
    file_.write((char*)pkt.data, pkt.incl_len);
    return file_.good();
}

void PcapWriter::close() { file_.close(); }