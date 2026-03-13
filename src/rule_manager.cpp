#include "rule_manager.h"
#include <algorithm>
#include <cctype>
#include <arpa/inet.h>

static std::string toLower(std::string s) {
    for (auto& c : s)
        c = (char)std::tolower((unsigned char)c);
    return s;
}

bool RuleManager::isBlocked(uint32_t src_ip, AppType app,
                             const std::string& sni) const
{
    if (blocked_ips_.count(src_ip)) return true;
    if (blocked_apps_.count(app))   return true;

    std::string low = toLower(sni);
    for (const auto& dom : blocked_domains_) {
        if (low.find(toLower(dom)) != std::string::npos)
            return true;
    }
    return false;
}

AppType RuleManager::parseAppName(const std::string& name) {
    std::string n = toLower(name);
    if (n == "youtube")   return AppType::YOUTUBE;
    if (n == "netflix")   return AppType::NETFLIX;
    if (n == "facebook")  return AppType::FACEBOOK;
    if (n == "instagram") return AppType::INSTAGRAM;
    if (n == "tiktok")    return AppType::TIKTOK;
    if (n == "twitter")   return AppType::TWITTER;
    if (n == "whatsapp")  return AppType::WHATSAPP;
    if (n == "telegram")  return AppType::TELEGRAM;
    if (n == "github")    return AppType::GITHUB;
    if (n == "reddit")    return AppType::REDDIT;
    if (n == "steam")     return AppType::STEAM;
    if (n == "google")    return AppType::GOOGLE;
    if (n == "http")      return AppType::HTTP;
    if (n == "https")     return AppType::HTTPS;
    if (n == "dns")       return AppType::DNS;
    return AppType::UNKNOWN;
}

uint32_t RuleManager::parseIPv4(const std::string& s) {
    struct in_addr addr;
    if (inet_aton(s.c_str(), &addr) == 0) return 0;
    return ntohl(addr.s_addr);
}