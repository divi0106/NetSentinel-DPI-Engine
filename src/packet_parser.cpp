#include "packet_parser.h"
#include <cstring>

static inline uint16_t r16(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}
static inline uint32_t r32(const uint8_t* p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|
           ((uint32_t)p[2]<<8 )|(uint32_t)p[3];
}

bool PacketParser::parse(const RawPacket& raw, ParsedPacket& out) {
    out = ParsedPacket{};
    const uint8_t* data = raw.data;
    size_t         len  = raw.incl_len;

    if (len < 14) return false;
    uint16_t eth_type = r16(data + 12);

    size_t ip_offset = 14;
    if (eth_type == 0x8100) {
        if (len < 18) return false;
        eth_type  = r16(data + 16);
        ip_offset = 18;
    }

    out.has_eth  = true;
    out.eth_type = eth_type;

    if (eth_type != 0x0800) return true;

    if (len < ip_offset + 20) return false;
    const uint8_t* ip = data + ip_offset;

    uint8_t  ihl      = (ip[0] & 0x0F) * 4;
    uint16_t frag_off = r16(ip + 6) & 0x1FFF;
    if (ihl < 20 || len < ip_offset + ihl) return false;

    out.has_ip   = true;
    out.ttl      = ip[8];
    out.ip_proto = ip[9];
    out.src_ip   = r32(ip + 12);
    out.dst_ip   = r32(ip + 16);

    if (frag_off != 0) return true;

    const uint8_t* transport = ip + ihl;
    size_t trans_len = (len > ip_offset + ihl)
                       ? len - ip_offset - ihl : 0;

    if (out.ip_proto == 6) {
        if (trans_len < 20) return true;
        uint8_t doff = (transport[12] >> 4) * 4;
        if (doff < 20 || trans_len < doff) return true;

        out.has_tcp   = true;
        out.src_port  = r16(transport);
        out.dst_port  = r16(transport + 2);
        out.tcp_flags = transport[13];

        out.payload     = transport + doff;
        out.payload_len = trans_len - doff;
    }
    else if (out.ip_proto == 17) {
        if (trans_len < 8) return true;

        out.has_udp  = true;
        out.src_port = r16(transport);
        out.dst_port = r16(transport + 2);

        out.payload     = transport + 8;
        out.payload_len = trans_len - 8;
    }

    return true;
}