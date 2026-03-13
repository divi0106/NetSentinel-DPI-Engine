#include "types.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "rule_manager.h"
#include "thread_safe_queue.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <thread>
#include <vector>
#include <unordered_map>
#include <atomic>
#include <string>
#include <sstream>
#include <algorithm>
#include <map>
#include <chrono>

struct Packet {
    RawPacket    raw;
    ParsedPacket parsed;
    FiveTuple    tuple;
    bool         valid = false;
};

using PacketQueue = TSQueue<Packet>;

struct Stats {
    std::atomic<uint64_t> forwarded  {0};
    std::atomic<uint64_t> dropped    {0};
    std::atomic<uint64_t> tcp_pkts   {0};
    std::atomic<uint64_t> udp_pkts   {0};
    std::atomic<uint64_t> total_bytes{0};
};

struct FPStats {
    uint64_t processed = 0;
    std::map<AppType, uint64_t>    app_counts;
    std::map<std::string, AppType> sni_map;
};

static void classifyFlow(const Packet& pkt, Flow& flow,
                         const RuleManager& rules)
{
    if (!pkt.parsed.payload || pkt.parsed.payload_len == 0)
        return;

    if (flow.sni.empty() &&
        (pkt.tuple.dst_port == 443 ||
         pkt.tuple.dst_port == 8443))
    {
        auto sni = SNIExtractor::extract(
            pkt.parsed.payload, pkt.parsed.payload_len);
        if (sni) {
            flow.sni      = *sni;
            flow.app_type = sniToAppType(*sni);
        }
    }

    if (flow.http_host.empty() &&
        (pkt.tuple.dst_port == 80 ||
         pkt.tuple.dst_port == 8080))
    {
        auto host = HTTPHostExtractor::extract(
            pkt.parsed.payload, pkt.parsed.payload_len);
        if (host) {
            flow.http_host = *host;
            flow.app_type  = AppType::HTTP;
            if (flow.sni.empty()) flow.sni = *host;
        }
    }

    if (flow.app_type == AppType::UNKNOWN)
        flow.app_type = portToAppType(
            pkt.tuple.dst_port, pkt.parsed.ip_proto);

    if (!flow.blocked)
        flow.blocked = rules.isBlocked(
            pkt.tuple.src_ip, flow.app_type, flow.sni);
}

// ── Fast Path Thread ─────────────────────────────────────────
class FastPath {
public:
    FastPath(int id, PacketQueue* out_q,
             const RuleManager* rules, Stats* stats)
        : id_(id), out_q_(out_q),
          rules_(rules), stats_(stats) {}

    void run() {
        while (true) {
            auto opt = in_q_.pop();
            if (!opt) break;
            Packet pkt = std::move(*opt);

            fp_stats_.processed++;
            stats_->total_bytes += pkt.raw.incl_len;

            Flow& flow = flows_[pkt.tuple];
            flow.packet_count++;
            flow.byte_count += pkt.raw.incl_len;

            classifyFlow(pkt, flow, *rules_);

            fp_stats_.app_counts[flow.app_type]++;
            if (!flow.sni.empty())
                fp_stats_.sni_map[flow.sni] = flow.app_type;

            if (flow.blocked) {
                stats_->dropped++;
            } else {
                stats_->forwarded++;
                out_q_->push(std::move(pkt));
            }
        }
    }

    PacketQueue&   queue()   { return in_q_; }
    const FPStats& fpStats() { return fp_stats_; }
    int            id() const { return id_; }

    // Public so main() can export flow features
    std::unordered_map<FiveTuple, Flow> flows_;

private:
    int                id_;
    PacketQueue        in_q_{2048};
    PacketQueue*       out_q_;
    const RuleManager* rules_;
    Stats*             stats_;
    FPStats            fp_stats_;
};

// ── Load Balancer Thread ─────────────────────────────────────
class LoadBalancer {
public:
    LoadBalancer(int id, std::vector<FastPath*> fps)
        : id_(id), fps_(std::move(fps)) {}

    void run() {
        while (true) {
            auto opt = in_q_.pop();
            if (!opt) break;
            Packet pkt = std::move(*opt);
            dispatched_++;
            size_t idx =
                std::hash<FiveTuple>{}(pkt.tuple) % fps_.size();
            fps_[idx]->queue().push(std::move(pkt));
        }
        for (auto* fp : fps_)
            fp->queue().setDone();
    }

    PacketQueue& queue()      { return in_q_; }
    uint64_t     dispatched() { return dispatched_; }
    int          id() const   { return id_; }

private:
    int                    id_;
    PacketQueue            in_q_{4096};
    std::vector<FastPath*> fps_;
    uint64_t               dispatched_ = 0;
};

// ── Main ─────────────────────────────────────────────────────
static void printUsage(const char* prog) {
    std::cerr
        << "Usage: " << prog
        << " <input.pcap> <output.pcap> [options]\n"
        << "  --lbs N          Load balancer threads (default 2)\n"
        << "  --fps N          Fast path threads per LB (default 2)\n"
        << "  --block-app NAME\n"
        << "  --block-ip  IP\n"
        << "  --block-domain D\n";
}

int main(int argc, char** argv) {
    if (argc < 3) { printUsage(argv[0]); return 1; }

    std::string input_path  = argv[1];
    std::string output_path = argv[2];
    int num_lbs    = 2;
    int fps_per_lb = 2;
    RuleManager rules;

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--lbs" && i+1 < argc)
            num_lbs = std::stoi(argv[++i]);
        else if (arg == "--fps" && i+1 < argc)
            fps_per_lb = std::stoi(argv[++i]);
        else if (arg == "--block-app" && i+1 < argc) {
            AppType t = RuleManager::parseAppName(argv[++i]);
            if (t != AppType::UNKNOWN) {
                std::cout << "[Rules] Blocked app: "
                          << appTypeName(t) << "\n";
                rules.blockApp(t);
            }
        } else if (arg == "--block-ip" && i+1 < argc) {
            uint32_t ip = RuleManager::parseIPv4(argv[++i]);
            std::cout << "[Rules] Blocked IP: "
                      << argv[i] << "\n";
            rules.blockIP(ip);
        } else if (arg == "--block-domain" && i+1 < argc) {
            std::cout << "[Rules] Blocked domain: "
                      << argv[i+1] << "\n";
            rules.blockDomain(argv[++i]);
        }
    }

    int total_fps = num_lbs * fps_per_lb;

    std::cout
        << "\n╔══════════════════════════════════════════════╗\n"
        << "║     DPI ENGINE v2.0 (Multi-threaded)         ║\n"
        << "╠══════════════════════════════════════════════╣\n"
        << "║ LBs: " << std::setw(2) << num_lbs
        << "  FPs/LB: " << std::setw(2) << fps_per_lb
        << "  Total FPs: " << std::setw(2) << total_fps
        << "             ║\n"
        << "╚══════════════════════════════════════════════╝\n\n";

    Stats       stats;
    PacketQueue output_queue(8192);

    // Create FPs
    std::vector<std::unique_ptr<FastPath>> all_fps;
    for (int i = 0; i < total_fps; ++i)
        all_fps.emplace_back(std::make_unique<FastPath>(
            i, &output_queue, &rules, &stats));

    // Create LBs
    std::vector<std::unique_ptr<LoadBalancer>> lbs;
    for (int li = 0; li < num_lbs; ++li) {
        std::vector<FastPath*> fp_slice;
        for (int fi = 0; fi < fps_per_lb; ++fi)
            fp_slice.push_back(
                all_fps[li * fps_per_lb + fi].get());
        lbs.emplace_back(std::make_unique<LoadBalancer>(
            li, std::move(fp_slice)));
    }

    // Writer thread
    std::vector<std::thread> threads;
    std::thread writer_thread([&]{
        PcapWriter writer;
        if (!writer.open(output_path)) return;
        while (true) {
            auto opt = output_queue.pop();
            if (!opt) break;
            writer.writePacket(opt->raw);
        }
        writer.close();
    });

    // FP threads
    for (auto& fp : all_fps)
        threads.emplace_back([&fp]{ fp->run(); });

    // LB threads
    for (auto& lb : lbs)
        threads.emplace_back([&lb]{ lb->run(); });

    // ── START TIMER ───────────────────────────────────────
    auto t_start = std::chrono::high_resolution_clock::now();

    // Reader (main thread)
    PcapReader reader;
    if (!reader.open(input_path)) return 1;

    std::cout << "[Reader] Processing packets...\n";
    uint64_t read_count = 0;
    RawPacket raw;

    while (reader.readNextPacket(raw)) {
        Packet pkt;
        pkt.raw = raw;
        if (PacketParser::parse(pkt.raw, pkt.parsed)
            && pkt.parsed.has_ip)
        {
            pkt.tuple = pkt.parsed.toTuple();
            pkt.valid = true;
            if (pkt.parsed.has_tcp) stats.tcp_pkts++;
            if (pkt.parsed.has_udp) stats.udp_pkts++;
            size_t lb_idx =
                std::hash<FiveTuple>{}(pkt.tuple) % num_lbs;
            lbs[lb_idx]->queue().push(std::move(pkt));
        }
        read_count++;
    }
    reader.close();
    std::cout << "[Reader] Done: " << read_count
              << " packets\n";

    for (auto& lb : lbs) lb->queue().setDone();
    for (auto& t : threads) t.join();
    output_queue.setDone();
    writer_thread.join();

    // ── STOP TIMER ────────────────────────────────────────
    auto t_end = std::chrono::high_resolution_clock::now();
    double seconds = std::chrono::duration<double>(
        t_end - t_start).count();
    uint64_t total_processed =
        stats.forwarded + stats.dropped;
    double pps  = total_processed / seconds;
    double mbps = (stats.total_bytes / seconds) / 1e6;

    // Merge FP stats
    std::map<AppType, uint64_t>    app_totals;
    std::map<std::string, AppType> all_snis;
    for (auto& fp : all_fps) {
        for (auto& [app, cnt] : fp->fpStats().app_counts)
            app_totals[app] += cnt;
        for (auto& [sni, app] : fp->fpStats().sni_map)
            all_snis[sni] = app;
    }

    uint64_t grand = stats.forwarded + stats.dropped;
    if (grand == 0) grand = 1;

    // ── Print Report ──────────────────────────────────────
    std::cout
        << "\n╔══════════════════════════════════════════════╗\n"
        << "║           PROCESSING REPORT                  ║\n"
        << "╠══════════════════════════════════════════════╣\n"
        << "║ Total Packets:   " << std::setw(8)
        << grand                 << "                  ║\n"
        << "║ Total Bytes:     " << std::setw(8)
        << stats.total_bytes.load() << "                  ║\n"
        << "║ TCP Packets:     " << std::setw(8)
        << stats.tcp_pkts.load()   << "                  ║\n"
        << "║ UDP Packets:     " << std::setw(8)
        << stats.udp_pkts.load()   << "                  ║\n"
        << "╠══════════════════════════════════════════════╣\n"
        << "║ Forwarded:       " << std::setw(8)
        << stats.forwarded.load()  << "                  ║\n"
        << "║ Dropped:         " << std::setw(8)
        << stats.dropped.load()    << "                  ║\n"
        << "╠══════════════════════════════════════════════╣\n"
        << "║ THREAD STATS                                 ║\n";

    for (auto& lb : lbs)
        std::cout << "║   LB" << lb->id()
                  << " dispatched: " << std::setw(8)
                  << lb->dispatched() << "              ║\n";
    for (auto& fp : all_fps)
        std::cout << "║   FP" << fp->id()
                  << " processed:  " << std::setw(8)
                  << fp->fpStats().processed << "              ║\n";

    std::cout
        << "╠══════════════════════════════════════════════╣\n"
        << "║         APPLICATION BREAKDOWN                ║\n"
        << "╠══════════════════════════════════════════════╣\n";

    std::vector<std::pair<AppType,uint64_t>> sorted(
        app_totals.begin(), app_totals.end());
    std::sort(sorted.begin(), sorted.end(),
        [](const auto& a, const auto& b){
            return a.second > b.second;
        });

    for (auto& [app, cnt] : sorted) {
        double pct = 100.0 * cnt / grand;
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

    if (!all_snis.empty()) {
        std::cout << "\n[Detected SNIs]\n";
        for (auto& [sni, app] : all_snis)
            std::cout << "  - " << sni
                      << " -> " << appTypeName(app) << "\n";
    }

    std::cout
        << "\n[Output] Written to: " << output_path << "\n"
        << "[Output] Forwarded : " << stats.forwarded << "\n"
        << "[Output] Dropped   : " << stats.dropped   << "\n";

    // ── Benchmark Results ─────────────────────────────────
    std::cout
        << "\n╔══════════════════════════════════════════════╗\n"
        << "║           BENCHMARK RESULTS                  ║\n"
        << "╠══════════════════════════════════════════════╣\n"
        << "║ Time elapsed:  " << std::setw(9)
        << std::fixed << std::setprecision(3)
        << seconds << " seconds            ║\n"
        << "║ Throughput:    " << std::setw(9)
        << (uint64_t)pps << " packets/sec        ║\n"
        << "║ Data rate:     " << std::setw(9)
        << std::fixed << std::setprecision(2)
        << mbps     << " MB/sec             ║\n"
        << "╚══════════════════════════════════════════════╝\n\n";

    // ── Export Flow Features for ML ───────────────────────
    std::ofstream csv("flows.csv");
    csv << "dst_port,protocol,packet_count,"
        << "byte_count,avg_pkt_size,app_type\n";

    for (auto& fp : all_fps) {
        for (auto& [tuple, flow] : fp->flows_) {
            if (flow.app_type == AppType::UNKNOWN) continue;
            double avg = flow.packet_count > 0
                ? (double)flow.byte_count / flow.packet_count
                : 0;
            csv << tuple.dst_port       << ","
                << (int)tuple.protocol  << ","
                << flow.packet_count    << ","
                << flow.byte_count      << ","
                << avg                  << ","
                << appTypeName(flow.app_type) << "\n";
        }
    }
    csv.close();
    std::cout << "[ML] Flow features exported → flows.csv\n\n";

    return 0;
}