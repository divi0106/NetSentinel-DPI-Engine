#pragma once
#include "types.h"
#include <unordered_set>
#include <vector>
#include <string>

class RuleManager {
public:
    void blockApp(AppType t)               { blocked_apps_.insert(t); }
    void blockIP (uint32_t ip)             { blocked_ips_.insert(ip); }
    void blockDomain(const std::string& d) { blocked_domains_.push_back(d); }

    bool isBlocked(uint32_t src_ip, AppType app,
                   const std::string& sni) const;

    static AppType  parseAppName(const std::string& name);
    static uint32_t parseIPv4(const std::string& s);

    bool hasRules() const {
        return !blocked_apps_.empty() ||
               !blocked_ips_.empty()  ||
               !blocked_domains_.empty();
    }

private:
    std::unordered_set<AppType>   blocked_apps_;
    std::unordered_set<uint32_t>  blocked_ips_;
    std::vector<std::string>      blocked_domains_;
};