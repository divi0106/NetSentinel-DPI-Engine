#include "types.h"
#include <algorithm>
#include <cctype>

const char* appTypeName(AppType t) {
    switch (t) {
        case AppType::UNKNOWN:   return "Unknown";
        case AppType::HTTP:      return "HTTP";
        case AppType::HTTPS:     return "HTTPS";
        case AppType::DNS:       return "DNS";
        case AppType::GOOGLE:    return "Google";
        case AppType::YOUTUBE:   return "YouTube";
        case AppType::FACEBOOK:  return "Facebook";
        case AppType::TWITTER:   return "Twitter";
        case AppType::INSTAGRAM: return "Instagram";
        case AppType::TIKTOK:    return "TikTok";
        case AppType::NETFLIX:   return "Netflix";
        case AppType::STEAM:     return "Steam";
        case AppType::GITHUB:    return "GitHub";
        case AppType::REDDIT:    return "Reddit";
        case AppType::WHATSAPP:  return "WhatsApp";
        case AppType::TELEGRAM:  return "Telegram";
        case AppType::SSH:       return "SSH";
        case AppType::FTP:       return "FTP";
        case AppType::SMTP:      return "SMTP";
        default:                 return "Other";
    }
}

static std::string toLower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return r;
}

AppType sniToAppType(const std::string& raw_sni) {
    std::string s = toLower(raw_sni);

    if (s.find("youtube") != std::string::npos ||
        s.find("googlevideo") != std::string::npos)  return AppType::YOUTUBE;

    if (s.find("netflix") != std::string::npos)      return AppType::NETFLIX;

    if (s.find("facebook") != std::string::npos ||
        s.find("fbcdn") != std::string::npos)        return AppType::FACEBOOK;

    if (s.find("instagram") != std::string::npos)    return AppType::INSTAGRAM;

    if (s.find("tiktok") != std::string::npos ||
        s.find("musically") != std::string::npos)    return AppType::TIKTOK;

    if (s.find("twitter") != std::string::npos ||
        s.find("twimg") != std::string::npos)        return AppType::TWITTER;

    if (s.find("whatsapp") != std::string::npos)     return AppType::WHATSAPP;
    if (s.find("telegram") != std::string::npos)     return AppType::TELEGRAM;
    if (s.find("github") != std::string::npos)       return AppType::GITHUB;
    if (s.find("reddit") != std::string::npos)       return AppType::REDDIT;

    if (s.find("steampowered") != std::string::npos ||
        s.find("steamcommunity") != std::string::npos) return AppType::STEAM;

    if (s.find("google") != std::string::npos ||
        s.find("gstatic") != std::string::npos)      return AppType::GOOGLE;

    return AppType::HTTPS;
}

AppType portToAppType(uint16_t port, uint8_t proto) {
    if (proto == 17 && port == 53)  return AppType::DNS;
    if (proto == 6  && port == 22)  return AppType::SSH;
    if (proto == 6  && port == 21)  return AppType::FTP;
    if (proto == 6  && port == 25)  return AppType::SMTP;
    if (proto == 6  && (port == 80 || port == 8080)) return AppType::HTTP;
    if (proto == 6  && (port == 443|| port == 8443)) return AppType::HTTPS;
    return AppType::UNKNOWN;
}