#include "types.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "rule_manager.h"

#include <iostream>
#include <iomanip>
#include <unordered_map>
#include <map>
#include <vector>
#include <algorithm>
#include <string>

static void printUsage(const char* prog) {
    std::cerr
        << "Usage: " << prog
        << " <input.pcap> <output.pcap> [options]\n"
        << "Options:\n"
        << "  --block-app NAME\n"
        << "  --block-ip  IP\n"
        << "  --block-domain D\n";
}

int main(int argc, char** argv) {
    if (argc < 3) { printUsage(argv[0]); return 1; }

    std::string input_path  = argv[1];
    std::string output_path = argv[2];
    RuleManager rules;

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--block-app" && i+1 < argc) {
            AppType t = RuleManager::parseAppName(argv[++i]);
            if (t != AppType::UNKNOWN) {
                std::cout << "[Rules] Blocked app: "
                          << appTypeName(t) << "\n";
                rules.blockApp(t);
            }
        } else if (arg == "--block-ip" && i+1 < argc) {
            uint32_t ip = RuleManager::parseIPv4(argv[++i]);
            std::cout << "[Rules] Blocked IP: " << argv[i] << "\n";
            rules.blockIP(ip);
        } else if (arg == "--block-domain" && i+1 < argc) {
            std::cout << "[Rules] Blocked domain: "
                      << argv[i+1] << "\n";
            rules.blockDomain(argv[++i]);
        }
    }

    PcapReader reader;
    PcapWriter writer;
    if (!reader.open(input_path))  return 1;
    if (!writer.open(output_path)) return 1;

    std::unordered_map<FiveTuple, Flow> flows;
    std::map<AppType, uint64_t>         app_counts;
    std::map<std::string, AppType>      sni_map;

    uint64_t total = 0, forwarded = 0, dropped = 0;
    uint64_t tcp_pkts = 0, udp_pkts = 0, total_bytes = 0;

    RawPacket    raw;
    ParsedPacket parsed;

    while (reader.readNextPacket(raw)) {
        total++;
        total_bytes += raw.incl_len;

        if (!PacketParser::parse(raw, parsed) || !parsed.has_ip) {
            writer.writePacket(raw);
            forwarded++;
            continue;
        }

        FiveTuple tuple = parsed.toTuple();
        if (parsed.has_tcp) tcp_pkts++;
        if (parsed.has_udp) udp_pkts++;

        Flow& flow = flows[tuple];
        flow.packet_count++;
        flow.byte_count += raw.incl_len;

        if (parsed.payload && parsed.payload_len > 0) {
            if (flow.sni.empty() &&
                (tuple.dst_port == 443 ||
                 tuple.dst_port == 8443))
            {
                auto sni = SNIExtractor::extract(
                    parsed.payload, parsed.payload_len);
                if (sni) {
                    flow.sni      = *sni;
                    flow.app_type = sniToAppType(*sni);
                    sni_map[*sni] = flow.app_type;
                }
            }

            if (flow.http_host.empty() &&
                (tuple.dst_port == 80 ||
                 tuple.dst_port == 8080))
            {
                auto host = HTTPHostExtractor::extract(
                    parsed.payload, parsed.payload_len);
                if (host) {
                    flow.http_host = *host;
                    flow.app_type  = AppType::HTTP;
                    if (flow.sni.empty()) flow.sni = *host;
                    sni_map[*host] = AppType::HTTP;
                }
            }

            if (flow.app_type == AppType::UNKNOWN)
                flow.app_type = portToAppType(
                    tuple.dst_port, parsed.ip_proto);
        }

        if (!flow.blocked)
            flow.blocked = rules.isBlocked(
                tuple.src_ip, flow.app_type, flow.sni);

        app_counts[flow.app_type]++;

        if (flow.blocked) {
            dropped++;
        } else {
            forwarded++;
            writer.writePacket(raw);
        }
    }

    reader.close();
    writer.close();

    uint64_t processed = forwarded + dropped;
    if (processed == 0) processed = 1;

    std::cout
        << "\n╔══════════════════════════════════════════════╗\n"
        << "║     DPI ENGINE v1.0 (Single-threaded)        ║\n"
        << "╠══════════════════════════════════════════════╣\n"
        << "║ Total Packets:   " << std::setw(8) << total
        << "                  ║\n"
        << "║ Total Bytes:     " << std::setw(8) << total_bytes
        << "                  ║\n"
        << "║ TCP Packets:     " << std::setw(8) << tcp_pkts
        << "                  ║\n"
        << "║ UDP Packets:     " << std::setw(8) << udp_pkts
        << "                  ║\n"
        << "╠══════════════════════════════════════════════╣\n"
        << "║ Forwarded:       " << std::setw(8) << forwarded
        << "                  ║\n"
        << "║ Dropped:         " << std::setw(8) << dropped
        << "                  ║\n"
        << "╠══════════════════════════════════════════════╣\n"
        << "║           APPLICATION BREAKDOWN              ║\n"
        << "╠══════════════════════════════════════════════╣\n";

    std::vector<std::pair<AppType,uint64_t>> sorted(
        app_counts.begin(), app_counts.end());
    std::sort(sorted.begin(), sorted.end(),
        [](const auto& a, const auto& b){
            return a.second > b.second;
        });

    for (auto& [app, cnt] : sorted) {
        double pct = 100.0 * cnt / processed;
        bool   blk = rules.isBlocked(0, app, "");
        int    bar = (int)(pct / 5.0);
        std::string bar_str(bar, '#');
        std::cout << "║ " << std::left << std::setw(12)
                  << appTypeName(app)
                  << std::right << std::setw(5) << cnt
                  << " " << std::setw(5)
                  << std::fixed << std::setprecision(1) << pct
                  << "% " << std::setw(10) << std::left
                  << bar_str
                  << (blk ? " BLOCKED" : "        ")
                  << " ║\n";
    }

    std::cout
        << "╚══════════════════════════════════════════════╝\n";

    if (!sni_map.empty()) {
        std::cout << "\n[Detected Domains/SNIs]\n";
        for (auto& [sni, app] : sni_map)
            std::cout << "  - " << sni
                      << " -> " << appTypeName(app) << "\n";
    }

    std::cout << "\n[Output] Written to: " << output_path << "\n"
              << "[Output] Forwarded : " << forwarded << "\n"
              << "[Output] Dropped   : " << dropped   << "\n\n";

    return 0;
}