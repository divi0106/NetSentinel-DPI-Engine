#pragma once
#include <cstdint>
#include <string>
#include <functional>

struct FiveTuple {
    uint32_t src_ip   = 0;
    uint32_t dst_ip   = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t  protocol = 0;

    bool operator==(const FiveTuple& o) const {
        return src_ip == o.src_ip && dst_ip == o.dst_ip &&
               src_port == o.src_port && dst_port == o.dst_port &&
               protocol == o.protocol;
    }
};

namespace std {
    template<> struct hash<FiveTuple> {
        size_t operator()(const FiveTuple& t) const noexcept {
            size_t h = 0;
            auto mix = [&](size_t v){ h ^= v + 0x9e3779b9 + (h<<6) + (h>>2); };
            mix(hash<uint32_t>{}(t.src_ip));
            mix(hash<uint32_t>{}(t.dst_ip));
            mix(hash<uint32_t>{}(t.src_port));
            mix(hash<uint32_t>{}(t.dst_port));
            mix(hash<uint8_t> {}(t.protocol));
            return h;
        }
    };
}

enum class AppType {
    UNKNOWN = 0,
    HTTP, HTTPS, DNS,
    GOOGLE, YOUTUBE, FACEBOOK,
    TWITTER, INSTAGRAM, TIKTOK,
    NETFLIX, STEAM, GITHUB,
    REDDIT, WHATSAPP, TELEGRAM,
    SSH, FTP, SMTP
};

const char* appTypeName(AppType t);
AppType     sniToAppType(const std::string& sni);
AppType     portToAppType(uint16_t port, uint8_t proto);

struct Flow {
    FiveTuple   tuple;
    AppType     app_type     = AppType::UNKNOWN;
    std::string sni;
    std::string http_host;
    bool        blocked      = false;
    uint64_t    packet_count = 0;
    uint64_t    byte_count   = 0;
};

struct RawPacket {
    uint32_t ts_sec   = 0;
    uint32_t ts_usec  = 0;
    uint32_t incl_len = 0;
    uint32_t orig_len = 0;
    uint8_t  data[65536];
};

struct ParsedPacket {
    bool      has_eth    = false;
    uint16_t  eth_type   = 0;
    bool      has_ip     = false;
    uint32_t  src_ip     = 0;
    uint32_t  dst_ip     = 0;
    uint8_t   ip_proto   = 0;
    uint8_t   ttl        = 0;
    bool      has_tcp    = false;
    bool      has_udp    = false;
    uint16_t  src_port   = 0;
    uint16_t  dst_port   = 0;
    uint8_t   tcp_flags  = 0;
    const uint8_t* payload     = nullptr;
    size_t         payload_len = 0;

    FiveTuple toTuple() const {
        FiveTuple t;
        t.src_ip   = src_ip;
        t.dst_ip   = dst_ip;
        t.src_port = src_port;
        t.dst_port = dst_port;
        t.protocol = ip_proto;
        return t;
    }
};