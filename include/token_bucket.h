#ifndef DPI_TOKEN_BUCKET_H
#define DPI_TOKEN_BUCKET_H

// Per-flow rate limiter. Time comes from the packet timestamps (pcap or live capture), so a
// replayed capture is throttled exactly as it would have been when it was recorded.

#include <algorithm>
#include <cstdint>

namespace DPI {

class TokenBucket {
public:
    // Returns true if a packet of `bytes` may pass at time `ts_us` under `rate_bytes_per_sec`.
    bool allow(double rate_bytes_per_sec, size_t bytes, uint64_t ts_us) {
        const double capacity = std::max(rate_bytes_per_sec, 1500.0);  // burst: one second, at least one full packet
        if (!started_) {
            started_ = true;
            tokens_ = capacity;
            last_us_ = ts_us;
        } else if (ts_us > last_us_) {
            tokens_ = std::min(capacity, tokens_ + rate_bytes_per_sec * static_cast<double>(ts_us - last_us_) / 1e6);
            last_us_ = ts_us;
        }
        if (tokens_ >= static_cast<double>(bytes)) {
            tokens_ -= static_cast<double>(bytes);
            return true;
        }
        return false;
    }

private:
    bool started_ = false;
    double tokens_ = 0;
    uint64_t last_us_ = 0;
};

}  // namespace DPI

#endif  // DPI_TOKEN_BUCKET_H
