#include "types.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "rule_manager.h"
#include "pcap_reader.h"

#include <iostream>
#include <cassert>
#include <cstring>

// ── Test colors ───────────────────────────────────────────────
#define GREEN "\033[92m"
#define RED   "\033[91m"
#define RESET "\033[0m"

int passed = 0;
int failed = 0;

void test(const std::string& name, bool result) {
    if (result) {
        std::cout << GREEN << "  ✓ PASS" << RESET
                  << "  " << name << "\n";
        passed++;
    } else {
        std::cout << RED << "  ✗ FAIL" << RESET
                  << "  " << name << "\n";
        failed++;
    }
}

// ── Build a fake TLS ClientHello with SNI ─────────────────────
static std::vector<uint8_t> makeTLSClientHello(
    const std::string& sni)
{
    std::vector<uint8_t> sni_bytes(sni.begin(), sni.end());
    uint16_t sni_len  = sni_bytes.size();

    // SNI extension data
    std::vector<uint8_t> ext_data = {
        0x00, (uint8_t)(sni_len + 3),  // list length
        0x00,                           // type: hostname
        (uint8_t)(sni_len >> 8),
        (uint8_t)(sni_len & 0xFF),
    };
    ext_data.insert(ext_data.end(),
                    sni_bytes.begin(), sni_bytes.end());

    // Extension header (type=0x0000, SNI)
    std::vector<uint8_t> ext = {
        0x00, 0x00,
        (uint8_t)(ext_data.size() >> 8),
        (uint8_t)(ext_data.size() & 0xFF),
    };
    ext.insert(ext.end(), ext_data.begin(), ext_data.end());

    // Extensions block
    std::vector<uint8_t> exts_block = {
        (uint8_t)(ext.size() >> 8),
        (uint8_t)(ext.size() & 0xFF),
    };
    exts_block.insert(exts_block.end(),
                      ext.begin(), ext.end());

    // ClientHello body
    std::vector<uint8_t> ch;
    ch.push_back(0x03); ch.push_back(0x03); // version
    for (int i = 0; i < 32; i++) ch.push_back(0x00); // random
    ch.push_back(0x00); // session id len
    ch.push_back(0x00); ch.push_back(0x02); // cipher suites len
    ch.push_back(0xc0); ch.push_back(0x2c); // cipher suite
    ch.push_back(0x01); ch.push_back(0x00); // compression
    ch.insert(ch.end(), exts_block.begin(), exts_block.end());

    // Handshake header
    uint32_t ch_len = ch.size();
    std::vector<uint8_t> hs = {
        0x01,
        (uint8_t)(ch_len >> 16),
        (uint8_t)(ch_len >> 8),
        (uint8_t)(ch_len & 0xFF),
    };
    hs.insert(hs.end(), ch.begin(), ch.end());

    // TLS record
    uint16_t hs_len = hs.size();
    std::vector<uint8_t> record = {
        0x16, 0x03, 0x01,
        (uint8_t)(hs_len >> 8),
        (uint8_t)(hs_len & 0xFF),
    };
    record.insert(record.end(), hs.begin(), hs.end());
    return record;
}

// ── Build fake HTTP request ───────────────────────────────────
static std::vector<uint8_t> makeHTTPRequest(
    const std::string& host)
{
    std::string req = "GET / HTTP/1.1\r\nHost: "
                    + host + "\r\n\r\n";
    return std::vector<uint8_t>(req.begin(), req.end());
}

// ════════════════════════════════════════════════════════════
// TEST SUITES
// ════════════════════════════════════════════════════════════

void test_sni_extractor() {
    std::cout << "\n── SNI Extractor Tests ──\n";

    // Test 1: Extract YouTube SNI
    auto pkt = makeTLSClientHello("www.youtube.com");
    auto result = SNIExtractor::extract(
        pkt.data(), pkt.size());
    test("Extract www.youtube.com",
         result.has_value() && *result == "www.youtube.com");

    // Test 2: Extract GitHub SNI
    auto pkt2 = makeTLSClientHello("github.com");
    auto result2 = SNIExtractor::extract(
        pkt2.data(), pkt2.size());
    test("Extract github.com",
         result2.has_value() && *result2 == "github.com");

    // Test 3: Non-TLS data returns nullopt
    std::vector<uint8_t> garbage = {
        0x00,0x01,0x02,0x03,0x04};
    auto result3 = SNIExtractor::extract(
        garbage.data(), garbage.size());
    test("Non-TLS returns nullopt", !result3.has_value());

    // Test 4: Empty payload returns nullopt
    auto result4 = SNIExtractor::extract(nullptr, 0);
    test("Empty payload returns nullopt",
         !result4.has_value());

    // Test 5: Long domain name
    auto pkt5 = makeTLSClientHello(
        "r3---sn-youtube.googlevideo.com");
    auto result5 = SNIExtractor::extract(
        pkt5.data(), pkt5.size());
    test("Extract long YouTube CDN domain",
         result5.has_value() &&
         *result5 == "r3---sn-youtube.googlevideo.com");
}

void test_http_extractor() {
    std::cout << "\n── HTTP Host Extractor Tests ──\n";

    // Test 1: Extract host from GET request
    auto pkt = makeHTTPRequest("www.example.com");
    auto result = HTTPHostExtractor::extract(
        pkt.data(), pkt.size());
    test("Extract Host from GET request",
         result.has_value() &&
         *result == "www.example.com");

    // Test 2: Non-HTTP returns nullopt
    auto tls = makeTLSClientHello("test.com");
    auto result2 = HTTPHostExtractor::extract(
        tls.data(), tls.size());
    test("TLS data returns nullopt", !result2.has_value());

    // Test 3: POST request
    std::string post =
        "POST /login HTTP/1.1\r\nHost: api.bank.com\r\n\r\n";
    std::vector<uint8_t> pkt3(post.begin(), post.end());
    auto result3 = HTTPHostExtractor::extract(
        pkt3.data(), pkt3.size());
    test("Extract Host from POST request",
         result3.has_value() &&
         *result3 == "api.bank.com");
}

void test_app_classification() {
    std::cout << "\n── App Classification Tests ──\n";

    test("YouTube SNI → AppType::YOUTUBE",
         sniToAppType("www.youtube.com") ==
         AppType::YOUTUBE);

    test("googlevideo → AppType::YOUTUBE",
         sniToAppType("r3.googlevideo.com") ==
         AppType::YOUTUBE);

    test("netflix → AppType::NETFLIX",
         sniToAppType("www.netflix.com") ==
         AppType::NETFLIX);

    test("facebook → AppType::FACEBOOK",
         sniToAppType("www.facebook.com") ==
         AppType::FACEBOOK);

    test("github → AppType::GITHUB",
         sniToAppType("github.com") ==
         AppType::GITHUB);

    test("tiktok → AppType::TIKTOK",
         sniToAppType("www.tiktok.com") ==
         AppType::TIKTOK);

    test("Port 53 UDP → DNS",
         portToAppType(53, 17) == AppType::DNS);

    test("Port 443 TCP → HTTPS",
         portToAppType(443, 6) == AppType::HTTPS);

    test("Port 80 TCP → HTTP",
         portToAppType(80, 6) == AppType::HTTP);

    test("Port 22 TCP → SSH",
         portToAppType(22, 6) == AppType::SSH);
}

void test_rule_manager() {
    std::cout << "\n── Rule Manager Tests ──\n";

    RuleManager rules;

    // Test 1: Block by app type
    rules.blockApp(AppType::YOUTUBE);
    test("Block YouTube by app type",
         rules.isBlocked(0, AppType::YOUTUBE, ""));

    // Test 2: Allow non-blocked app
    test("Allow GitHub (not blocked)",
         !rules.isBlocked(0, AppType::GITHUB, ""));

    // Test 3: Block by domain
    rules.blockDomain("tiktok");
    test("Block tiktok.com by domain",
         rules.isBlocked(0, AppType::UNKNOWN,
                         "www.tiktok.com"));

    // Test 4: Block by IP
    uint32_t bad_ip = RuleManager::parseIPv4("192.168.1.99");
    rules.blockIP(bad_ip);
    test("Block by source IP",
         rules.isBlocked(bad_ip, AppType::UNKNOWN, ""));

    // Test 5: Clean IP not blocked
    uint32_t good_ip =
        RuleManager::parseIPv4("192.168.1.1");
    test("Allow clean IP",
         !rules.isBlocked(good_ip, AppType::GITHUB, ""));

    // Test 6: Parse app names
    test("Parse 'youtube' → YOUTUBE",
         RuleManager::parseAppName("youtube") ==
         AppType::YOUTUBE);
    test("Parse 'Netflix' → NETFLIX",
         RuleManager::parseAppName("Netflix") ==
         AppType::NETFLIX);
    test("Parse unknown → UNKNOWN",
         RuleManager::parseAppName("xyz123") ==
         AppType::UNKNOWN);
}

void test_five_tuple() {
    std::cout << "\n── FiveTuple Tests ──\n";

    FiveTuple a, b, c;
    a.src_ip = 1; a.dst_ip = 2;
    a.src_port = 100; a.dst_port = 443; a.protocol = 6;

    b.src_ip = 1; b.dst_ip = 2;
    b.src_port = 100; b.dst_port = 443; b.protocol = 6;

    c.src_ip = 1; c.dst_ip = 3;
    c.src_port = 100; c.dst_port = 443; c.protocol = 6;

    test("Same 5-tuple equals",       a == b);
    test("Different 5-tuple differs", !(a == c));

    // Test hash
    std::hash<FiveTuple> hasher;
    test("Same tuple same hash",      hasher(a) == hasher(b));
    test("Different tuple diff hash", hasher(a) != hasher(c));
}

// ════════════════════════════════════════════════════════════
int main() {
    std::cout
        << "╔══════════════════════════════════════════════╗\n"
        << "║         DPI ENGINE — UNIT TESTS              ║\n"
        << "╚══════════════════════════════════════════════╝\n";

    test_sni_extractor();
    test_http_extractor();
    test_app_classification();
    test_rule_manager();
    test_five_tuple();

    std::cout
        << "\n╔══════════════════════════════════════════════╗\n"
        << "║ RESULTS:  "
        << GREEN << passed << " passed" << RESET
        << "   "
        << (failed > 0 ? RED : "")
        << failed << " failed"
        << (failed > 0 ? RESET : "")
        << "                    ║\n"
        << "╚══════════════════════════════════════════════╝\n\n";

    return failed > 0 ? 1 : 0;
}