#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <optional>

class SNIExtractor {
public:
    static std::optional<std::string> extract(
        const uint8_t* payload, size_t length);
};

class HTTPHostExtractor {
public:
    static std::optional<std::string> extract(
        const uint8_t* payload, size_t length);
};