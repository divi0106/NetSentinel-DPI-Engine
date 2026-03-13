#pragma once
#include "types.h"
#include <fstream>
#include <string>

class PcapReader {
public:
    bool open(const std::string& filename);
    bool readNextPacket(RawPacket& pkt);
    void close();
    bool isOpen() const { return file_.is_open(); }

private:
    std::ifstream file_;
    bool          swap_bytes_ = false;
    uint32_t _swap32(uint32_t v) const;
    uint16_t _swap16(uint16_t v) const;
};

class PcapWriter {
public:
    bool open(const std::string& filename);
    bool writePacket(const RawPacket& pkt);
    void close();

private:
    std::ofstream file_;
};