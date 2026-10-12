// Copyright (c) 2026 The ConnectCoin developers. MIT license.
#pragma once
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <limits>
#include <iterator>
#include <list>
#include <memory>
#include <stdexcept>

namespace claimer {
struct PerformanceTotals {
    uint64_t attempts{}, valid{};
    double seconds{};
};

inline constexpr double PERFORMANCE_BASE_VALID = 5.0;
inline constexpr double PERFORMANCE_BASE_SECONDS = 1.0;

// Apply the prior once to the window totals, never to each sample or bucket.
// Adding one to a finite nonnegative duration cannot overflow a double: at
// that magnitude its representable spacing is already much larger than one.
inline double SmoothedPerformanceRate(const PerformanceTotals& totals) {
    const auto rate = (PERFORMANCE_BASE_VALID + static_cast<double>(totals.valid)) /
                      (PERFORMANCE_BASE_SECONDS + totals.seconds);
    return std::clamp(rate, std::numeric_limits<double>::denorm_min(), std::numeric_limits<double>::max());
}

// Completion-time buckets: the current minute and the preceding 59 minutes.
// Ordinary samples/readers touch one bucket; elapsed empty minutes are removed
// once, and a gap of an hour clears a fixed-size array, never per-connection data.
class MinutePerformanceWindow {
    std::array<PerformanceTotals, 60> buckets_{};
    PerformanceTotals totals_{};
    int64_t minute_{-1}, observed_minute_{-1};
public:
    static int64_t Minute(double seconds) {
        if (!std::isfinite(seconds) || seconds < 0 || seconds / 60 >= static_cast<double>(INT64_MAX))
            throw std::invalid_argument("Invalid monotonic performance timestamp");
        return static_cast<int64_t>(std::floor(seconds / 60));
    }
    PerformanceTotals ReadMinute(int64_t minute) {
        if (minute < 0) throw std::invalid_argument("Invalid performance minute");
        minute = std::max(minute, minute_); // A test clock regression cannot resurrect expired samples.
        if (minute_ < 0 || minute - minute_ >= 60) {
            buckets_.fill({}); totals_ = {}; minute_ = minute;
        } else if (minute > minute_) {
            while (minute_ < minute) {
                auto& expired = buckets_[static_cast<size_t>(++minute_ % 60)];
                expired = {};
            }
            // Re-sum only when the minute changes (at most 60 buckets), rather
            // than repeatedly subtracting large expired floating-point totals
            // and losing the smaller observations which remain in the window.
            totals_ = {};
            long double seconds = 0;
            for (const auto& bucket : buckets_) {
                totals_.attempts += bucket.attempts; totals_.valid += bucket.valid;
                seconds += bucket.seconds;
            }
            totals_.seconds = static_cast<double>(seconds);
        }
        return totals_;
    }
    PerformanceTotals Read(double now) { return ReadMinute(Minute(now)); }
    bool RecordMinute(bool valid, double seconds, int64_t minute) {
        if (!std::isfinite(seconds) || seconds < 0) return false;
        ReadMinute(minute);
        if (totals_.attempts == UINT64_MAX || !std::isfinite(totals_.seconds + seconds)) return false;
        auto& bucket = buckets_[static_cast<size_t>(minute_ % 60)];
        ++bucket.attempts; bucket.valid += valid ? 1 : 0; bucket.seconds += seconds;
        ++totals_.attempts; totals_.valid += valid ? 1 : 0; totals_.seconds += seconds;
        observed_minute_ = minute_;
        return true;
    }
    bool Record(bool valid, double seconds, double now) { return RecordMinute(valid, seconds, Minute(now)); }
    int64_t ObservedMinute() const { return observed_minute_; }
};

struct EndpointPerformanceScore;
using PerformanceScoreList = std::list<std::shared_ptr<EndpointPerformanceScore>>;
struct EndpointPerformanceScore {
    double credit{};
private:
    friend class EndpointPerformanceCache;
    std::unique_ptr<MinutePerformanceWindow> window_;
    PerformanceScoreList::iterator position_;
};

// DNS entries and running jobs own scores independently of their histories.
// Keep at most 8192 lazy windows (~12 MiB), not 4096 domains * 32 IPs * 7 masks.
// Eviction/expiration retains rotation credit and restores the same 5/1 prior
// as a fresh history. Claim counters and bounty budgets are entirely separate.
class EndpointPerformanceCache {
    const size_t maximum_;
    PerformanceScoreList recent_;
    int64_t minute_{-1};
    void Remove(const std::shared_ptr<EndpointPerformanceScore>& score) {
        // The caller may be referencing the list node that erase invalidates.
        auto retained = score;
        recent_.erase(retained->position_); retained->window_.reset();
    }
    int64_t Advance(double now) {
        minute_ = std::max(minute_, MinutePerformanceWindow::Minute(now));
        // Ordered by last conclusive sample. Each stale history is freed once;
        // no scan of the DNS table or the cache on the ordinary connection path.
        while (!recent_.empty() && minute_ - recent_.front()->window_->ObservedMinute() >= 60)
            Remove(recent_.front());
        return minute_;
    }
public:
    explicit EndpointPerformanceCache(size_t maximum = 8192) : maximum_(maximum) {
        if (!maximum) throw std::invalid_argument("Performance cache requires a positive bound");
    }
    EndpointPerformanceCache(const EndpointPerformanceCache&) = delete;
    EndpointPerformanceCache& operator=(const EndpointPerformanceCache&) = delete;
    ~EndpointPerformanceCache() {
        // Scores may outlive their history cache through an in-flight owner.
        // Do not leave a window carrying an iterator into a destroyed list.
        for (const auto& score : recent_) score->window_.reset();
    }
    size_t Size() const { return recent_.size(); }
    double Rate(const std::shared_ptr<EndpointPerformanceScore>& score, double now) {
        const auto minute = Advance(now);
        return SmoothedPerformanceRate(score->window_ ? score->window_->ReadMinute(minute) : PerformanceTotals{});
    }
    bool Record(const std::shared_ptr<EndpointPerformanceScore>& score, bool valid, double seconds, double now) {
        if (!std::isfinite(seconds) || seconds < 0) return false;
        const auto minute = Advance(now);
        if (!score->window_) {
            if (recent_.size() == maximum_) Remove(recent_.front());
            auto window = std::make_unique<MinutePerformanceWindow>();
            recent_.push_back(score); score->position_ = std::prev(recent_.end());
            score->window_ = std::move(window);
        }
        if (!score->window_->RecordMinute(valid, seconds, minute)) return false;
        recent_.splice(recent_.end(), recent_, score->position_);
        return true;
    }
};
} // namespace claimer
