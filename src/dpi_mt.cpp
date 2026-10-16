// Multi-threaded DPI Engine
// Architecture: Reader (file or libpcap) -> LB threads -> FP threads -> Output
// Policy per packet: malware signatures, block rules, content categories, rate limits

#include <iostream>
#include <fstream>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <optional>
#include <map>
#include <csignal>
#include <cctype>
#include <cstdlib>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"
#include "content_filter.h"
#include "ja3.h"
#include "p2p_detector.h"
#include "packet_source.h"
#include "signature_engine.h"
#include "token_bucket.h"

using namespace PacketAnalyzer;
using namespace DPI;

// =============================================================================
// Thread-Safe Queue
// =============================================================================
template<typename T>
class TSQueue {
public:
    TSQueue(size_t max_size = 10000) : max_size_(max_size), shutdown_(false) {}
    
    void push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] { return queue_.size() < max_size_ || shutdown_; });
        if (shutdown_) return;
        queue_.push(std::move(item));
        not_empty_.notify_one();
    }
    
    std::optional<T> pop(int timeout_ms = 100) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!not_empty_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                  [this] { return !queue_.empty() || shutdown_; })) {
            return std::nullopt;
        }
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        not_full_.notify_one();
        return item;
    }
    
    void shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    
    bool is_shutdown() const { return shutdown_; }

private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    size_t max_size_;
    std::atomic<bool> shutdown_;
};

// =============================================================================
// Packet Job - Contains all packet data (self-contained, no pointers)
// =============================================================================
struct Packet {
    uint32_t id;
    uint32_t ts_sec;
    uint32_t ts_usec;
    FiveTuple tuple;
    std::vector<uint8_t> data;
    uint8_t tcp_flags;
    size_t payload_offset;
    size_t payload_length;
};

// =============================================================================
// Flow Entry
// =============================================================================
struct FlowEntry {
    FiveTuple tuple;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool blocked = false;
    bool classified = false;

    // Why the flow was blocked: kind is "rule", "signature" or "category".
    std::string block_kind;
    std::string block_detail;

    // Each check below runs once per flow, as soon as the data it needs is available.
    std::string category;
    bool ip_checked = false;
    bool domain_checked = false;
    bool ja3_checked = false;
    bool category_checked = false;

    TokenBucket bucket;  // rate limit state when the flow's app is throttled
    uint64_t last_ts_us = 0;  // packet time of the latest packet, used to expire idle flows
};

// =============================================================================
// Policy: everything the fast paths consult but never modify while running
// =============================================================================
struct Policy {
    SignatureEngine signatures;
    ContentFilter categories;
    bool show_ja3 = false;
};

// =============================================================================
// Blocking Rules
// =============================================================================
class Rules {
public:
    void blockIP(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ips_.insert(parseIP(ip));
        std::cout << "[Rules] Blocked IP: " << ip << "\n";
    }

    bool blockApp(const std::string& app) {
        std::lock_guard<std::mutex> lock(mutex_);
        AppType type;
        if (!findApp(app, &type)) {
            std::cerr << "[Rules] Unknown app: " << app << "\n";
            return false;
        }
        blocked_apps_.insert(type);
        std::cout << "[Rules] Blocked app: " << appTypeToString(type) << "\n";
        return true;
    }

    void blockDomain(const std::string& domain) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_domains_.push_back(domain);
        std::cout << "[Rules] Blocked domain: " << domain << "\n";
    }

    void blockCategory(const std::string& category) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_categories_.insert(lowerCase(category));
        std::cout << "[Rules] Blocked category: " << category << "\n";
    }

    // Limit every flow of this app to `bytes_per_sec` (each flow gets its own budget).
    bool throttleApp(const std::string& app, double bytes_per_sec) {
        std::lock_guard<std::mutex> lock(mutex_);
        AppType type;
        if (!findApp(app, &type)) {
            std::cerr << "[Rules] Unknown app: " << app << "\n";
            return false;
        }
        throttles_[type] = bytes_per_sec;
        has_throttles_ = true;
        std::cout << "[Rules] Throttled app: " << appTypeToString(type) << " to "
                  << static_cast<long>(bytes_per_sec / 1024) << " KB/s per flow\n";
        return true;
    }

    // Empty when traffic is allowed, otherwise a short description of the rule that matched.
    std::string blockReason(uint32_t src_ip, AppType app, const std::string& sni) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (blocked_ips_.count(src_ip)) return "ip";
        if (blocked_apps_.count(app)) return std::string("app ") + appTypeToString(app);
        for (const auto& dom : blocked_domains_) {
            if (sni.find(dom) != std::string::npos) return "domain " + dom;
        }
        return "";
    }

    bool isCategoryBlocked(const std::string& category) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return blocked_categories_.count(lowerCase(category)) > 0;
    }

    // Bytes per second for this app, or 0 when it is not throttled.
    double throttleRate(AppType app) const {
        if (!has_throttles_) return 0;  // common case: no lock
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = throttles_.find(app);
        return it == throttles_.end() ? 0 : it->second;
    }

private:
    static std::string lowerCase(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
        return s;
    }

    static bool findApp(const std::string& name, AppType* out) {
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            AppType t = static_cast<AppType>(i);
            if (lowerCase(appTypeToString(t)) == lowerCase(name)) {
                *out = t;
                return true;
            }
        }
        return false;
    }

    static uint32_t parseIP(const std::string& ip) {
        uint32_t result = 0;
        int octet = 0, shift = 0;
        for (char c : ip) {
            if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
            else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
        }
        return result | (octet << shift);
    }

    mutable std::mutex mutex_;
    std::unordered_set<uint32_t> blocked_ips_;
    std::unordered_set<AppType> blocked_apps_;
    std::vector<std::string> blocked_domains_;
    std::unordered_set<std::string> blocked_categories_;
    std::unordered_map<AppType, double> throttles_;
    std::atomic<bool> has_throttles_{false};
};

// =============================================================================
// Statistics (thread-safe)
// =============================================================================
struct Stats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded{0};
    std::atomic<uint64_t> dropped{0};  // every drop below is also counted here
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};

    // Why packets were dropped
    std::atomic<uint64_t> dropped_rule{0};
    std::atomic<uint64_t> dropped_signature{0};
    std::atomic<uint64_t> dropped_category{0};
    std::atomic<uint64_t> throttled{0};

    // Per-app stats (protected by mutex)
    std::mutex app_mutex;
    std::unordered_map<AppType, uint64_t> app_counts;
    std::unordered_map<std::string, AppType> detected_snis;
    std::map<std::string, uint64_t> detections;        // "signature: payload EICAR" -> flows
    std::map<std::string, uint64_t> category_packets;  // category -> packets seen
    std::map<std::string, std::string> tls_fingerprints;  // server name -> JA3 hash

    void recordApp(AppType app, const std::string& sni) {
        std::lock_guard<std::mutex> lock(app_mutex);
        app_counts[app]++;
        if (!sni.empty()) {
            detected_snis[sni] = app;
        }
    }

    void recordDetection(const std::string& what) {
        std::lock_guard<std::mutex> lock(app_mutex);
        detections[what]++;
    }

    void recordCategory(const std::string& category) {
        std::lock_guard<std::mutex> lock(app_mutex);
        category_packets[category]++;
    }

    void recordJa3(const std::string& sni, const std::string& hash) {
        std::lock_guard<std::mutex> lock(app_mutex);
        tls_fingerprints[sni.empty() ? "(no server name)" : sni] = hash;
    }

    void recordBlockedPacket(const std::string& kind) {
        dropped++;
        if (kind == "signature") dropped_signature++;
        else if (kind == "category") dropped_category++;
        else dropped_rule++;
    }
};

// =============================================================================
// Fast Path Processor (one per FP thread)
// =============================================================================
class FastPath {
public:
    FastPath(int id, Rules* rules, const Policy* policy, Stats* stats, TSQueue<Packet>* output_queue)
        : id_(id), rules_(rules), policy_(policy), stats_(stats), output_queue_(output_queue) {}

    void start() {
        running_ = true;
        thread_ = std::thread(&FastPath::run, this);
    }

    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }

    TSQueue<Packet>& queue() { return input_queue_; }

    uint64_t processed() const { return processed_; }

private:
    int id_;
    Rules* rules_;
    const Policy* policy_;
    Stats* stats_;
    TSQueue<Packet>* output_queue_;
    TSQueue<Packet> input_queue_;
    std::unordered_map<FiveTuple, FlowEntry, FiveTupleHash> flows_;

    // A long-running capture must not remember every flow forever. Flows silent for five minutes are
    // forgotten: lazily when their 5-tuple returns, and by a sweep once a minute (of packet time).
    static constexpr uint64_t kSweepIntervalSec = 60;
    static constexpr uint64_t kIdleTimeoutSec = 300;
    uint64_t last_sweep_sec_ = 0;

    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> processed_{0};

    void run() {
        while (running_) {
            auto pkt_opt = input_queue_.pop(100);
            if (!pkt_opt) continue;

            processed_++;
            Packet& pkt = *pkt_opt;
            const uint64_t ts_sec = pkt.ts_sec;
            const uint64_t ts_us = ts_sec * 1000000ULL + pkt.ts_usec;

            // Get or create flow
            FlowEntry& flow = flows_[pkt.tuple];
            if (flow.packets > 0 && ts_us > flow.last_ts_us + kIdleTimeoutSec * 1000000ULL) {
                flow = FlowEntry{};  // silent for too long: a returning 5-tuple starts a new flow
            }
            if (flow.packets == 0) {
                flow.tuple = pkt.tuple;
            }
            flow.last_ts_us = std::max(flow.last_ts_us, ts_us);
            flow.packets++;
            flow.bytes += pkt.data.size();

            // Try to classify if not done yet
            if (!flow.classified) {
                classifyFlow(pkt, flow);
            }

            // Policy, in order of severity: threats, then admin rules, then content categories.
            if (!flow.blocked) inspectSignatures(pkt, flow);
            if (!flow.blocked) {
                std::string why = rules_->blockReason(pkt.tuple.src_ip, flow.app_type, flow.sni);
                if (!why.empty()) blockFlow(flow, "rule", why);
            }
            if (!flow.blocked) applyContentFilter(flow);

            // Record stats
            stats_->recordApp(flow.app_type, flow.sni);
            if (!flow.category.empty()) stats_->recordCategory(flow.category);

            // Forward, drop or throttle
            if (flow.blocked) {
                stats_->recordBlockedPacket(flow.block_kind);
            } else if (overRateLimit(pkt, flow)) {
                stats_->dropped++;
                stats_->throttled++;
            } else {
                stats_->forwarded++;
                output_queue_->push(std::move(pkt));
            }

            sweepIdleFlows(ts_sec);
        }
    }

    void sweepIdleFlows(uint64_t now_sec) {
        if (last_sweep_sec_ == 0) last_sweep_sec_ = now_sec;
        if (now_sec < last_sweep_sec_ + kSweepIntervalSec) return;
        last_sweep_sec_ = now_sec;
        const uint64_t now_us = now_sec * 1000000ULL;
        for (auto it = flows_.begin(); it != flows_.end();) {
            if (now_us > it->second.last_ts_us + kIdleTimeoutSec * 1000000ULL) it = flows_.erase(it);
            else ++it;
        }
    }

    void blockFlow(FlowEntry& flow, const std::string& kind, const std::string& detail) {
        flow.blocked = true;
        flow.block_kind = kind;
        flow.block_detail = detail;
        if (kind != "rule") stats_->recordDetection(kind + ": " + detail);
    }

    // Malware signatures: server IP, server name, TLS fingerprint, then payload bytes.
    void inspectSignatures(const Packet& pkt, FlowEntry& flow) {
        const SignatureEngine& sigs = policy_->signatures;
        const bool want_ja3 = policy_->show_ja3 || !sigs.empty();
        if (sigs.empty() && !want_ja3) return;

        if (!sigs.empty() && !flow.ip_checked) {
            flow.ip_checked = true;
            auto m = sigs.matchIp(pkt.tuple.src_ip);
            if (!m) m = sigs.matchIp(pkt.tuple.dst_ip);
            if (m) return blockFlow(flow, "signature", m->kind + " " + m->name);
        }
        if (!sigs.empty() && !flow.sni.empty() && !flow.domain_checked) {
            flow.domain_checked = true;
            if (auto m = sigs.matchDomain(flow.sni)) return blockFlow(flow, "signature", m->kind + " " + m->name);
        }
        if (pkt.payload_length == 0) return;
        const uint8_t* payload = pkt.data.data() + pkt.payload_offset;

        if (want_ja3 && !flow.ja3_checked && pkt.payload_length > 5 && payload[0] == 0x16) {
            flow.ja3_checked = true;
            if (auto ja3 = computeJa3(payload, pkt.payload_length)) {
                if (policy_->show_ja3) stats_->recordJa3(flow.sni, ja3->hash);
                if (auto m = sigs.matchJa3(ja3->hash)) return blockFlow(flow, "signature", m->kind + " " + m->name);
            }
        }
        if (sigs.hasPayloadSignatures()) {
            if (auto m = sigs.matchPayload(payload, pkt.payload_length))
                return blockFlow(flow, "signature", m->kind + " " + m->name);
        }
    }

    // Content filtering: put the flow's domain into a category, block it if that category is blocked.
    void applyContentFilter(FlowEntry& flow) {
        if (flow.sni.empty()) return;
        if (!flow.category_checked) {
            flow.category_checked = true;
            flow.category = policy_->categories.categoryOf(flow.sni);
        }
        if (!flow.category.empty() && rules_->isCategoryBlocked(flow.category))
            blockFlow(flow, "category", flow.category);
    }

    // Per-flow rate limit for throttled apps. Time comes from the packet timestamps.
    bool overRateLimit(const Packet& pkt, FlowEntry& flow) {
        double rate = rules_->throttleRate(flow.app_type);
        if (rate <= 0) return false;
        uint64_t ts_us = static_cast<uint64_t>(pkt.ts_sec) * 1000000ULL + pkt.ts_usec;
        return !flow.bucket.allow(rate, pkt.data.size(), ts_us);
    }

    void classifyFlow(Packet& pkt, FlowEntry& flow) {
        // Peer-to-peer has no server name, so recognise it from the payload on any port.
        if (pkt.payload_length >= 20) {
            const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
            if (isBitTorrent(payload, pkt.payload_length, pkt.tuple.protocol)) {
                flow.app_type = AppType::BITTORRENT;
                flow.classified = true;
                return;
            }
        }

        // Try SNI extraction for HTTPS
        if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
            const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
            auto sni = SNIExtractor::extract(payload, pkt.payload_length);
            if (sni) {
                flow.sni = *sni;
                flow.app_type = sniToAppType(*sni);
                flow.classified = true;
                return;
            }
        }

        // Try HTTP Host extraction
        if (pkt.tuple.dst_port == 80 && pkt.payload_length > 10) {
            const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
            auto host = HTTPHostExtractor::extract(payload, pkt.payload_length);
            if (host) {
                flow.sni = *host;
                flow.app_type = sniToAppType(*host);
                flow.classified = true;
                return;
            }
        }

        // DNS
        if (pkt.tuple.dst_port == 53 || pkt.tuple.src_port == 53) {
            flow.app_type = AppType::DNS;
            flow.classified = true;
            return;
        }

        // Port-based fallback (but don't mark as classified - might get SNI later)
        if (pkt.tuple.dst_port == 443) {
            flow.app_type = AppType::HTTPS;
        } else if (pkt.tuple.dst_port == 80) {
            flow.app_type = AppType::HTTP;
        }
    }
};

// =============================================================================
// Load Balancer (one per LB thread)
// =============================================================================
class LoadBalancer {
public:
    LoadBalancer(int id, std::vector<FastPath*> fps, size_t num_lbs)
        : id_(id), fps_(std::move(fps)), num_fps_(fps_.size()), num_lbs_(num_lbs) {}
    
    void start() {
        running_ = true;
        thread_ = std::thread(&LoadBalancer::run, this);
    }
    
    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }
    
    TSQueue<Packet>& queue() { return input_queue_; }
    
    uint64_t dispatched() const { return dispatched_; }

private:
    int id_;
    std::vector<FastPath*> fps_;
    size_t num_fps_;
    size_t num_lbs_;
    TSQueue<Packet> input_queue_;
    
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> dispatched_{0};
    
    void run() {
        while (running_) {
            auto pkt_opt = input_queue_.pop(100);
            if (!pkt_opt) continue;
            
            // Hash to select FP. The reader already used (hash % num_lbs_) to pick this LB,
            // so use the next "digit" of the same hash. Reusing hash % N here would only ever
            // reach the FPs whose index matches this LB's hash residue.
            FiveTupleHash hasher;
            size_t fp_idx = (hasher(pkt_opt->tuple) / num_lbs_) % num_fps_;
            
            fps_[fp_idx]->queue().push(std::move(*pkt_opt));
            dispatched_++;
        }
    }
};

// =============================================================================
// DPI Engine
// =============================================================================
class DPIEngine {
public:
    struct Config {
        int num_lbs = 2;
        int fps_per_lb = 2;
    };

    DPIEngine(const Config& cfg) : config_(cfg) {
        int total_fps = cfg.num_lbs * cfg.fps_per_lb;

        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║              DPI ENGINE v2.1 (Multi-threaded)                 ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Load Balancers: " << std::setw(2) << cfg.num_lbs
                  << "    FPs per LB: " << std::setw(2) << cfg.fps_per_lb
                  << "    Total FPs: " << std::setw(2) << total_fps << "     ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

        // Create FP threads
        for (int i = 0; i < total_fps; i++) {
            fps_.push_back(std::make_unique<FastPath>(i, &rules_, &policy_, &stats_, &output_queue_));
        }

        // Create LB threads, each managing a subset of FPs
        for (int lb = 0; lb < cfg.num_lbs; lb++) {
            std::vector<FastPath*> lb_fps;
            int start = lb * cfg.fps_per_lb;
            for (int i = 0; i < cfg.fps_per_lb; i++) {
                lb_fps.push_back(fps_[start + i].get());
            }
            lbs_.push_back(std::make_unique<LoadBalancer>(lb, std::move(lb_fps), cfg.num_lbs));
        }
    }

    void blockIP(const std::string& ip) { rules_.blockIP(ip); }
    bool blockApp(const std::string& app) { return rules_.blockApp(app); }
    void blockDomain(const std::string& dom) { rules_.blockDomain(dom); }
    void blockCategory(const std::string& category) { rules_.blockCategory(category); }
    bool throttleApp(const std::string& app, double bytes_per_sec) { return rules_.throttleApp(app, bytes_per_sec); }

    bool hasCategory(const std::string& category) const { return policy_.categories.hasCategory(category); }
    std::vector<std::string> categories() const { return policy_.categories.categories(); }
    void showJa3(bool on) { policy_.show_ja3 = on; }

    bool loadSignatures(const std::string& path, std::string* err) {
        if (!policy_.signatures.loadFile(path, err)) return false;
        policy_.signatures.finalize();
        std::cout << "[Signatures] Loaded " << policy_.signatures.size() << " signatures from " << path << "\n";
        return true;
    }

    bool loadCategories(const std::string& path, std::string* err) {
        if (!policy_.categories.loadFile(path, err)) return false;
        std::cout << "[Categories] Loaded domain lists from " << path << "\n";
        return true;
    }

    bool process(PacketSource& source, const std::string& output_file) {
        // Open output
        std::ofstream output(output_file, std::ios::binary);
        if (!output.is_open()) {
            std::cerr << "Cannot open output file\n";
            return false;
        }

        // Write PCAP header
        const auto& hdr = source.globalHeader();
        output.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));

        // Start all threads
        for (auto& fp : fps_) fp->start();
        for (auto& lb : lbs_) lb->start();

        // Start output writer thread
        std::atomic<bool> output_running{true};
        std::thread output_thread([&]() {
            while (output_running || output_queue_.size() > 0) {
                auto pkt_opt = output_queue_.pop(50);
                if (!pkt_opt) continue;

                PcapPacketHeader phdr;
                phdr.ts_sec = pkt_opt->ts_sec;
                phdr.ts_usec = pkt_opt->ts_usec;
                phdr.incl_len = pkt_opt->data.size();
                phdr.orig_len = pkt_opt->data.size();

                output.write(reinterpret_cast<const char*>(&phdr), sizeof(phdr));
                output.write(reinterpret_cast<const char*>(pkt_opt->data.data()), pkt_opt->data.size());
            }
        });

        // Read and dispatch packets
        std::cout << "[Reader] Processing packets (" << source.describe() << ")...\n";
        RawPacket raw;
        ParsedPacket parsed;
        uint32_t pkt_id = 0;

        while (source.readNextPacket(raw)) {
            if (!PacketParser::parse(raw, parsed)) continue;
            if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;

            // Create packet
            Packet pkt;
            pkt.id = pkt_id++;
            pkt.ts_sec = raw.header.ts_sec;
            pkt.ts_usec = raw.header.ts_usec;
            pkt.tcp_flags = parsed.tcp_flags;
            pkt.data = std::move(raw.data);

            // Parse 5-tuple
            auto parseIP = [](const std::string& ip) -> uint32_t {
                uint32_t result = 0;
                int octet = 0, shift = 0;
                for (char c : ip) {
                    if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
                    else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
                }
                return result | (octet << shift);
            };

            pkt.tuple.src_ip = parseIP(parsed.src_ip);
            pkt.tuple.dst_ip = parseIP(parsed.dest_ip);
            pkt.tuple.src_port = parsed.src_port;
            pkt.tuple.dst_port = parsed.dest_port;
            pkt.tuple.protocol = parsed.protocol;

            // Calculate payload offset
            pkt.payload_offset = 14;  // Ethernet
            if (pkt.data.size() > 14) {
                uint8_t ip_ihl = pkt.data[14] & 0x0F;
                pkt.payload_offset += ip_ihl * 4;

                if (parsed.has_tcp && pkt.payload_offset + 12 < pkt.data.size()) {
                    uint8_t tcp_off = (pkt.data[pkt.payload_offset + 12] >> 4) & 0x0F;
                    pkt.payload_offset += tcp_off * 4;
                } else if (parsed.has_udp) {
                    pkt.payload_offset += 8;
                }

                if (pkt.payload_offset < pkt.data.size()) {
                    pkt.payload_length = pkt.data.size() - pkt.payload_offset;
                } else {
                    pkt.payload_length = 0;
                }
            }

            // Update stats
            stats_.total_packets++;
            stats_.total_bytes += pkt.data.size();
            if (parsed.has_tcp) stats_.tcp_packets++;
            else if (parsed.has_udp) stats_.udp_packets++;

            // Dispatch to LB (hash-based)
            FiveTupleHash hasher;
            size_t lb_idx = hasher(pkt.tuple) % lbs_.size();
            lbs_[lb_idx]->queue().push(std::move(pkt));
        }

        std::cout << "[Reader] Done reading " << pkt_id << " packets\n";

        // Wait until every dispatched packet has been forwarded or dropped (give up after 10 s).
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (stats_.forwarded + stats_.dropped < stats_.total_packets &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        // Stop all threads
        for (auto& lb : lbs_) lb->stop();
        for (auto& fp : fps_) fp->stop();

        output_running = false;
        output_queue_.shutdown();
        output_thread.join();

        output.close();

        // Print report
        printReport();

        return true;
    }

private:
    Config config_;
    Rules rules_;
    Policy policy_;
    Stats stats_;
    TSQueue<Packet> output_queue_;
    std::vector<std::unique_ptr<FastPath>> fps_;
    std::vector<std::unique_ptr<LoadBalancer>> lbs_;

    void printReport() {
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                      PROCESSING REPORT                        ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Total Packets:      " << std::setw(12) << stats_.total_packets.load() << "                           ║\n";
        std::cout << "║ Total Bytes:        " << std::setw(12) << stats_.total_bytes.load() << "                           ║\n";
        std::cout << "║ TCP Packets:        " << std::setw(12) << stats_.tcp_packets.load() << "                           ║\n";
        std::cout << "║ UDP Packets:        " << std::setw(12) << stats_.udp_packets.load() << "                           ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Forwarded:          " << std::setw(12) << stats_.forwarded.load() << "                           ║\n";
        std::cout << "║ Dropped:            " << std::setw(12) << stats_.dropped.load() << "                           ║\n";
        std::cout << "║   by rule:          " << std::setw(12) << stats_.dropped_rule.load() << "                           ║\n";
        std::cout << "║   by signature:     " << std::setw(12) << stats_.dropped_signature.load() << "                           ║\n";
        std::cout << "║   by category:      " << std::setw(12) << stats_.dropped_category.load() << "                           ║\n";
        std::cout << "║   by throttle:      " << std::setw(12) << stats_.throttled.load() << "                           ║\n";

        // Thread stats
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ THREAD STATISTICS                                             ║\n";
        for (size_t i = 0; i < lbs_.size(); i++) {
            std::cout << "║   LB" << i << " dispatched:   " << std::setw(12) << lbs_[i]->dispatched() << "                           ║\n";
        }
        for (size_t i = 0; i < fps_.size(); i++) {
            std::cout << "║   FP" << i << " processed:    " << std::setw(12) << fps_[i]->processed() << "                           ║\n";
        }

        // App distribution
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║                   APPLICATION BREAKDOWN                       ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";

        std::lock_guard<std::mutex> lock(stats_.app_mutex);

        std::vector<std::pair<AppType, uint64_t>> sorted_apps(
            stats_.app_counts.begin(), stats_.app_counts.end());
        std::sort(sorted_apps.begin(), sorted_apps.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });

        uint64_t total = stats_.total_packets.load();
        for (const auto& [app, count] : sorted_apps) {
            double pct = total > 0 ? (100.0 * count / total) : 0;
            int bar = static_cast<int>(pct / 5);
            std::string bar_str(bar, '#');

            std::cout << "║ " << std::setw(15) << std::left << appTypeToString(app)
                      << std::setw(8) << std::right << count
                      << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "% "
                      << std::setw(20) << std::left << bar_str << "  ║\n";
        }

        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";

        // Detected SNIs
        if (!stats_.detected_snis.empty()) {
            std::cout << "\n[Detected Domains/SNIs]\n";
            for (const auto& [sni, app] : stats_.detected_snis) {
                std::cout << "  - " << sni << " -> " << appTypeToString(app) << "\n";
            }
        }

        // Threats and blocked categories (flows)
        if (!stats_.detections.empty()) {
            std::cout << "\n[Detections]\n";
            for (const auto& [what, flows] : stats_.detections) {
                std::cout << "  - " << what << " (" << flows << (flows == 1 ? " flow)" : " flows)") << "\n";
            }
        }

        if (!stats_.category_packets.empty()) {
            std::cout << "\n[Content Categories Seen]\n";
            for (const auto& [category, packets] : stats_.category_packets) {
                std::cout << "  - " << category << ": " << packets << " packets\n";
            }
        }

        if (!stats_.tls_fingerprints.empty()) {
            std::cout << "\n[TLS Fingerprints (JA3)]\n";
            for (const auto& [sni, hash] : stats_.tls_fingerprints) {
                std::cout << "  - " << hash << "  " << sni << "\n";
            }
        }
    }
};

// =============================================================================
// Main
// =============================================================================
static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

// "256KB/s", "2MB/s", "900B/s" or a plain number (KB/s) -> bytes per second
static bool parseRate(const std::string& text, double* bytes_per_sec) {
    size_t i = 0;
    while (i < text.size() && (std::isdigit(static_cast<unsigned char>(text[i])) || text[i] == '.')) i++;
    if (i == 0) return false;
    double value;
    try {
        value = std::stod(text.substr(0, i));
    } catch (...) {
        return false;
    }
    std::string unit = toLower(text.substr(i));
    double multiplier = 1024;
    if (unit.empty() || unit == "kb/s") multiplier = 1024;
    else if (unit == "mb/s") multiplier = 1024 * 1024;
    else if (unit == "b/s") multiplier = 1;
    else return false;
    *bytes_per_sec = value * multiplier;
    return *bytes_per_sec > 0;
}

void printUsage(const char* prog) {
    std::cout << R"(
DPI Engine v2.1 - Multi-threaded Deep Packet Inspection
========================================================

Usage: )" << prog << R"( <input.pcap> <output.pcap> [options]
       )" << prog << R"( --iface <name> <output.pcap> [options]      (live capture, needs a libpcap build)

Rules:
  --block-ip <ip>              Block source IP
  --block-app <app>            Block application (YouTube, Facebook, BitTorrent, ...)
  --block-domain <dom>         Block domain (substring match)
  --block-category <name>      Block a content category (ads, social, streaming, gaming, torrents, or your own)
  --categories <file>          Add domain lists: one `category: domain, domain` per line
  --signatures <file>          Load malware signatures (payload, domain, ip, ja3); matches are blocked
  --throttle-app <app> <rate>  Limit each flow of an app, e.g. --throttle-app BitTorrent 64KB/s
  --throttle-p2p <rate>        Shorthand for --throttle-app BitTorrent <rate>
  --show-ja3                   List the JA3 TLS fingerprint of every TLS connection

Threads:
  --lbs <n>                    Number of load balancer threads (default: 2)
  --fps <n>                    FP threads per LB (default: 2)

Live capture (build with `make dpi_engine_live`):
  --iface <name>               Capture from this interface instead of reading a file
  --list-ifaces                Show the interfaces libpcap can capture from
  --bpf "<filter>"             Only capture matching packets, e.g. "tcp port 443"
  --count <n>                  Stop after n packets
  --duration <seconds>         Stop after this long (Ctrl-C also stops cleanly)
  --libpcap-file <pcap>        Read a file through libpcap (tests the live code path without root)

Example:
  )" << prog << R"( capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
  )" << prog << R"( capture.pcap out.pcap --signatures rules/signatures.txt --throttle-p2p 32KB/s
)";
}

#ifdef HAVE_PCAP
static void onSigint(int) { requestLiveStop(); }
#endif

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    DPIEngine::Config cfg;
    std::vector<std::string> positional;
    std::vector<std::string> block_ips, block_apps, block_domains, block_categories;
    std::vector<std::string> signature_files, category_files;
    std::vector<std::pair<std::string, std::string>> throttles;  // app, rate text
    bool show_ja3 = false;
    bool want_live = false;
    bool list_ifaces = false;
    std::string iface, bpf, libpcap_file;
    uint64_t live_count = 0;
    double live_seconds = 0;

    auto fail = [&](const std::string& message) {
        std::cerr << "Error: " << message << "\n\nRun without arguments for usage.\n";
        return 2;
    };

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        auto value = [&](const char* what) -> const char* {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " needs " << what << "\n";
                std::exit(2);
            }
            return argv[++i];
        };
        try {
            if (arg == "--block-ip") block_ips.push_back(value("an IP address"));
            else if (arg == "--block-app") block_apps.push_back(value("an app name"));
            else if (arg == "--block-domain") block_domains.push_back(value("a domain"));
            else if (arg == "--block-category") block_categories.push_back(value("a category"));
            else if (arg == "--categories") category_files.push_back(value("a file"));
            else if (arg == "--signatures") signature_files.push_back(value("a file"));
            else if (arg == "--throttle-app") {
                std::string app = value("an app name");
                throttles.emplace_back(app, value("a rate such as 64KB/s"));
            }
            else if (arg == "--throttle-p2p") throttles.emplace_back("BitTorrent", value("a rate such as 64KB/s"));
            else if (arg == "--show-ja3") show_ja3 = true;
            else if (arg == "--lbs") cfg.num_lbs = std::stoi(value("a number"));
            else if (arg == "--fps") cfg.fps_per_lb = std::stoi(value("a number"));
            else if (arg == "--iface") { iface = value("an interface name"); want_live = true; }
            else if (arg == "--libpcap-file") { libpcap_file = value("a file"); want_live = true; }
            else if (arg == "--bpf") bpf = value("a filter expression");
            else if (arg == "--count") live_count = std::stoull(value("a number"));
            else if (arg == "--duration") live_seconds = std::stod(value("seconds"));
            else if (arg == "--list-ifaces") list_ifaces = true;
            else if (arg == "--help" || arg == "-h") { printUsage(argv[0]); return 0; }
            else if (arg.rfind("--", 0) == 0) return fail("unknown option " + arg);
            else positional.push_back(arg);
        } catch (const std::exception&) {
            return fail("bad number for " + arg);
        }
    }

    if (cfg.num_lbs < 1 || cfg.fps_per_lb < 1) return fail("--lbs and --fps must be at least 1");

#ifdef HAVE_PCAP
    if (list_ifaces) {
        std::string err;
        auto names = listInterfaces(&err);
        if (!err.empty()) { std::cerr << "Error: " << err << "\n"; return 1; }
        for (const auto& n : names) std::cout << n << "\n";
        return 0;
    }
#else
    if (list_ifaces || want_live || !bpf.empty() || live_count || live_seconds > 0)
        return fail("this build has no libpcap support; rebuild with `make dpi_engine_live`");
#endif

    const size_t needed = want_live ? 1 : 2;
    if (positional.size() != needed) {
        return fail(want_live ? "live capture needs one output file: --iface <name> <output.pcap>"
                              : "expected <input.pcap> <output.pcap>");
    }
    const std::string output = positional.back();

    DPIEngine engine(cfg);

    for (const auto& file : signature_files) {
        std::string err;
        if (!engine.loadSignatures(file, &err)) return fail(err);
    }
    for (const auto& file : category_files) {
        std::string err;
        if (!engine.loadCategories(file, &err)) return fail(err);
    }
    engine.showJa3(show_ja3);

    for (const auto& ip : block_ips) engine.blockIP(ip);
    for (const auto& app : block_apps) {
        if (!engine.blockApp(app)) return 2;
    }
    for (const auto& dom : block_domains) engine.blockDomain(dom);
    for (const auto& category : block_categories) {
        if (!engine.hasCategory(category)) {
            std::string known;
            for (const auto& c : engine.categories()) known += (known.empty() ? "" : ", ") + c;
            return fail("unknown category `" + category + "` (known: " + known + ")");
        }
        engine.blockCategory(category);
    }
    for (const auto& [app, rate_text] : throttles) {
        double rate;
        if (!parseRate(rate_text, &rate)) return fail("bad rate `" + rate_text + "` (use e.g. 64KB/s, 2MB/s, 900B/s)");
        if (!engine.throttleApp(app, rate)) return 2;
    }

    std::unique_ptr<PacketSource> source;
#ifdef HAVE_PCAP
    LiveSource* live = nullptr;
    if (want_live) {
        LiveOptions opts;
        opts.iface = iface;
        opts.offline_file = libpcap_file;
        opts.bpf_filter = bpf;
        opts.max_packets = live_count;
        opts.max_seconds = live_seconds;
        auto s = std::make_unique<LiveSource>();
        std::string err;
        if (!s->open(opts, &err)) {
            std::cerr << "Error: " << err << "\n";
            return 1;
        }
        std::signal(SIGINT, onSigint);
        live = s.get();
        source = std::move(s);
        if (libpcap_file.empty()) std::cout << "[Capture] Listening on " << iface << " (Ctrl-C to stop)\n";
    }
#endif
    if (!source) {
        auto f = std::make_unique<FileSource>();
        if (!f->open(positional[0])) return 1;
        source = std::move(f);
    }

    if (!engine.process(*source, output)) {
        return 1;
    }

#ifdef HAVE_PCAP
    if (live) {
        uint64_t received = 0, dropped = 0;
        if (live->kernelStats(&received, &dropped))
            std::cout << "\n[Capture] libpcap received " << received << " packets, kernel dropped " << dropped << "\n";
        if (!live->lastError().empty()) std::cerr << "[Capture] stopped by error: " << live->lastError() << "\n";
    }
#endif
    source->close();

    std::cout << "\nOutput written to: " << output << "\n";
    return 0;
}
