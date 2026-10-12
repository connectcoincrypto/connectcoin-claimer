// Offline bookkeeping-only benchmark. No network or claim activity.
#include <claimer/performance_window.hpp>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <vector>

using namespace claimer;
// Historical benchmark reference only; these constants do not configure production.
struct PreviousEma {
    double valid{0.1}, seconds{0.02};
    void Record(bool success, double elapsed) { valid = 0.999 * valid + 0.001 * success; seconds = 0.999 * seconds + 0.001 * elapsed; }
    double Rate() const { return std::clamp(valid / seconds, std::numeric_limits<double>::denorm_min(), std::numeric_limits<double>::max()); }
};
int main() {
    constexpr size_t count = 2880000, endpoints = 32;
    double checksum = 0;
    std::cout << std::setprecision(9) << "Offline endpoint bookkeeping, 32 score lookups per observation; not end-to-end TLS throughput.\n";
    for (int round = 0; round < 3; ++round) {
        std::array<PreviousEma, endpoints> old;
        auto start = std::chrono::steady_clock::now();
        for (size_t i = 0; i < count; ++i) {
            old[i % endpoints].Record(i % 17 != 0, 0.005 + (i % 37) * 0.003);
            for (const auto& score : old) checksum += score.Rate();
        }
        const double ema_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
        EndpointPerformanceCache cache;
        std::array<std::shared_ptr<EndpointPerformanceScore>, endpoints> scores;
        for (auto& score : scores) score = std::make_shared<EndpointPerformanceScore>();
        start = std::chrono::steady_clock::now();
        for (size_t i = 0; i < count; ++i) {
            const double now = i / 800.0;
            cache.Record(scores[i % endpoints], i % 17 != 0, 0.005 + (i % 37) * 0.003, now);
            for (const auto& score : scores) checksum += cache.Rate(score, now);
        }
        const double window_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
        std::cout << "round=" << round + 1 << " observations=" << count << " ema_ms=" << ema_ms << " window_ms=" << window_ms
                  << " wall_equivalent_one_core_percent_at_800=" << window_ms / count * 80 << '\n';
    }
    EndpointPerformanceCache bounded;
    std::vector<std::shared_ptr<EndpointPerformanceScore>> owners;
    for (size_t i = 0; i < 16384; ++i) {
        auto score = std::make_shared<EndpointPerformanceScore>();
        bounded.Record(score, true, 0.1, 0); owners.push_back(std::move(score));
    }
    if (bounded.Size() != 8192) return 1;
    std::cout << "retained_histories=" << bounded.Size() << " bytes_per_window=" << sizeof(MinutePerformanceWindow)
              << " retained_window_bytes=" << bounded.Size() * sizeof(MinutePerformanceWindow)
              << " bytes_per_score=" << sizeof(EndpointPerformanceScore) << " checksum=" << checksum << '\n';
    return 0;
}
