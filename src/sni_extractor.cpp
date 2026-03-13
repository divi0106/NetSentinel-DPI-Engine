#include "sni_extractor.h"
#include <cstring>

static inline uint16_t r16be(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

std::optional<std::string> SNIExtractor::extract(
    const uint8_t* p, size_t len)
{
    if (len < 9) return std::nullopt;
    if (p[0] != 0x16) return std::nullopt;
    if (p[1] != 0x03) return std::nullopt;
    if (p[5] != 0x01) return std::nullopt;

    size_t pos = 9;
    pos += 2;   // skip client version
    pos += 32;  // skip random

    if (pos >= len) return std::nullopt;
    uint8_t sid_len = p[pos++];
    pos += sid_len;
    if (pos + 2 > len) return std::nullopt;

    uint16_t cs_len = r16be(p + pos); pos += 2;
    pos += cs_len;
    if (pos + 1 > len) return std::nullopt;

    uint8_t cm_len = p[pos++];
    pos += cm_len;
    if (pos + 2 > len) return std::nullopt;

    uint16_t ext_total = r16be(p + pos); pos += 2;
    size_t   ext_end   = pos + ext_total;
    if (ext_end > len) ext_end = len;

    while (pos + 4 <= ext_end) {
        uint16_t ext_type = r16be(p + pos);
        uint16_t ext_len  = r16be(p + pos + 2);
        pos += 4;

        if (ext_type == 0x0000 && pos + 5 <= ext_end) {
            uint16_t name_len = r16be(p + pos + 3);
            if (pos + 5 + name_len <= ext_end) {
                return std::string((char*)(p + pos + 5), name_len);
            }
        }
        pos += ext_len;
    }
    return std::nullopt;
}

static const char* HTTP_METHODS[] = {
    "GET ", "POST", "PUT ", "HEAD",
    "DELE", "OPTI", "PATC", nullptr
};

std::optional<std::string> HTTPHostExtractor::extract(
    const uint8_t* p, size_t len)
{
    if (len < 4) return std::nullopt;

    bool is_http = false;
    for (int i = 0; HTTP_METHODS[i]; ++i) {
        if (memcmp(p, HTTP_METHODS[i], 4) == 0) {
            is_http = true;
            break;
        }
    }
    if (!is_http) return std::nullopt;

    const char* txt = (const char*)p;
    for (size_t i = 0; i + 6 < len; ++i) {
        if ((txt[i]   == 'H' || txt[i]   == 'h') &&
            (txt[i+1] == 'o' || txt[i+1] == 'O') &&
            (txt[i+2] == 's' || txt[i+2] == 'S') &&
            (txt[i+3] == 't' || txt[i+3] == 'T') &&
             txt[i+4] == ':' && txt[i+5] == ' ')
        {
            size_t start = i + 6;
            size_t end   = start;
            while (end < len &&
                   txt[end] != '\r' &&
                   txt[end] != '\n') ++end;
            if (end > start)
                return std::string(txt + start, end - start);
        }
    }
    return std::nullopt;
}