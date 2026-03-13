#pragma once
#include "types.h"

class PacketParser {
public:
    static bool parse(const RawPacket& raw, ParsedPacket& out);
};