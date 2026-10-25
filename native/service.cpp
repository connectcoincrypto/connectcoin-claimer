// Copyright (c) 2026 The ConnectCoin developers. MIT license.
#include <claimer/service.hpp>
#include <claimer/performance_window.hpp>
#include <mbedtls/version.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <deque>
#include <exception>
#include <limits>
#include <list>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <unordered_map>

namespace claimer {
namespace {
using Clock = std::chrono::steady_clock;
constexpr uint64_t MAX_ID = (uint64_t{1} << 53) - 1;
constexpr uint64_t MAX_CONNECTION_LIMIT = 2147483647;
constexpr size_t MAX_DNS = 4096, MAX_BUDGETS = 1024, MAX_ENDPOINTS = 32;
constexpr size_t MAX_UNREACHABLE_ENDPOINTS = 4096;
constexpr double REACHABILITY_RECHECK_SECONDS = 60;
double Now() { return std::chrono::duration<double>(Clock::now().time_since_epoch()).count(); }
void Require(bool value, const char* message) { if (!value) throw std::invalid_argument(message); }
void UniqueKeys(const UniValue& value, unsigned depth = 0) {
    Require(depth <= 64, "JSON nesting limit exceeded");
    if (value.isObject()) {
        const auto& keys = value.getKeys();
        // Ordinary protocol objects have at most seven fields. Compare views
        // on the stack, without allocating tree nodes/copying every key. Large
        // malformed objects retain O(n log n), not quadratic, duplicate checks.
        std::array<std::string_view, 16> small;
        std::vector<std::string_view> large;
        if (keys.size() > small.size()) large.resize(keys.size());
        std::span<std::string_view> sorted = keys.size() <= small.size()
            ? std::span<std::string_view>(small).first(keys.size()) : std::span<std::string_view>(large);
        std::ranges::copy(keys, sorted.begin());
        std::ranges::sort(sorted);
        Require(std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end(), "Duplicate JSON field");
    }
    if (value.isObject() || value.isArray()) for (const auto& child : value.getValues()) UniqueKeys(child, depth + 1);
}
uint64_t Decimal(const std::string& text, uint64_t maximum) {
    Require(!text.empty() && text.size() <= 20 && (text.size() == 1 || text[0] != '0'), "Invalid protocol decimal");
    uint64_t value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    Require(error == std::errc{} && end == text.data() + text.size() && value <= maximum, "Invalid protocol decimal");
    return value;
}
struct BudgetExhausted : std::exception {};
struct EndpointExcluded : std::exception {};
struct OutputFailure : std::runtime_error { OutputFailure() : std::runtime_error("Helper output failed") {} };
using Score = EndpointPerformanceScore;
struct Budget {
    std::string target;
    uint64_t stop_count{}, successes{}, users{}, touched{};
    std::optional<PreparedContext> prepared_context;
};
struct DnsEntry {
    struct Item { Endpoint endpoint; std::map<uint8_t, std::shared_ptr<Score>> scores; };
    std::vector<Item> endpoints;
    std::map<uint8_t, size_t> next;
    double expires{};
    uint64_t touched{};
};
struct Job {
    uint64_t id{};
    bool attempt{}, running{}, started{}, captured{}, target_miss{};
    Context context;
    std::optional<PreparedContext> prepared_context;
    std::optional<Endpoint> endpoint;
    std::string domain, bounty;
    CaptureControl control;
    // Service cancellation must wake a paced socket before Cancel waits for
    // that socket's mutex. Every result/proof check observes the same flag.
    std::atomic<bool> cancel_requested{};
    std::condition_variable connection_condition;
    double seconds{}, started_at{};
    std::optional<uint64_t> successes;
    bool Cancelled() const { return cancel_requested.load(std::memory_order_acquire) || control.Cancelled(); }
};
} // namespace

std::optional<UniValue> ProtocolFrameReader::Next(size_t maximum) {
    Require(maximum <= 160 * 1024, "Protocol frame limit exceeds supported maximum");
    if (buffer_.size() < maximum + 1) buffer_.resize(maximum + 1);
    // One stream sentry per frame, rather than per byte. Unlike read(n), this
    // returns as soon as the newline arrives even while a pipe remains open.
    // gcount includes the consumed delimiter, which is part of our size limit.
    input_.getline(buffer_.data(), static_cast<std::streamsize>(maximum + 1), '\n');
    const auto count = input_.gcount();
    Require(!input_.bad(), "Protocol input failed");
    if (input_.eof()) {
        if (count == 0) return std::nullopt;
        throw std::invalid_argument("Incomplete protocol frame");
    }
    Require(!input_.fail() && count > 0 && static_cast<size_t>(count) <= maximum,
            "Protocol frame exceeds size limit");
    UniValue value;
    Require(value.read(std::string_view(buffer_.data(), static_cast<size_t>(count) - 1)), "Invalid protocol JSON");
    UniqueKeys(value);
    return value;
}
std::optional<UniValue> ReadFrame(std::istream& input, size_t maximum) {
    return ProtocolFrameReader(input).Next(maximum);
}
void ExactKeys(const UniValue& value, std::initializer_list<std::string_view> expected) {
    Require(value.isObject() && value.size() == expected.size(), "Invalid protocol command fields");
    for (const auto key : expected) Require(value.exists(std::string(key)), "Invalid protocol command fields");
}
uint64_t ProtocolInteger(const UniValue& value, uint64_t minimum, uint64_t maximum) {
    Require(value.isNum(), "Invalid protocol integer");
    const auto result = value.getInt<uint64_t>();
    Require(result >= minimum && result <= maximum, "Invalid protocol integer");
    return result;
}
std::string PublicDomain(const UniValue& value) {
    Require(value.isStr(), "Public DNS domain required");
    const auto domain = value.get_str();
    Require(IsCanonicalDomain(domain) && domain.find('.') != std::string::npos && !domain.ends_with(".localhost") && !domain.ends_with(".local") && !domain.ends_with(".internal"), "Public DNS domain required");
    return domain;
}
namespace {
Context ParseContextFields(const UniValue& value) {
    ExactKeys(value, {"domain", "txid", "input_index", "connection_work_target", "root_certificates_version", "signature_algorithms_mask", "validation_time"});
    Context result;
    result.domain = PublicDomain(value["domain"]);
    result.txid = value["txid"].get_str();
    result.input_index = static_cast<uint32_t>(ProtocolInteger(value["input_index"], 0, 0xffffffff));
    result.connection_work_target = value["connection_work_target"].get_str();
    result.root_certificates_version = static_cast<uint32_t>(ProtocolInteger(value["root_certificates_version"], 1, 1));
    result.signature_algorithms_mask = static_cast<uint8_t>(ProtocolInteger(value["signature_algorithms_mask"], 1, 7));
    result.validation_time = static_cast<int64_t>(ProtocolInteger(value["validation_time"], 1, 253402300799));
    return result;
}
} // namespace
Context ParseContext(const UniValue& value) {
    auto result = ParseContextFields(value);
    ValidateContext(result);
    return result;
}
UniValue PublicContext(const Context& context) {
    UniValue result(UniValue::VOBJ);
    result.pushKV("domain", context.domain); result.pushKV("txid", context.txid);
    result.pushKV("input_index", context.input_index); result.pushKV("connection_work_target", context.connection_work_target);
    result.pushKV("root_certificates_version", context.root_certificates_version);
    result.pushKV("signature_algorithms_mask", static_cast<unsigned>(context.signature_algorithms_mask));
    result.pushKV("validation_time", context.validation_time);
    return result;
}
UniValue ReadyFrame() {
    UniValue result(UniValue::VOBJ), security(UniValue::VOBJ);
    security.pushKV("provider", "mbedtls"); security.pushKV("mbedtlsVersion", MBEDTLS_VERSION_STRING); security.pushKV("rsaPublicExponentMaxBits", 64);
    security.pushKV("admissionGate", 1);
    result.pushKV("type", "ready"); result.pushKV("protocol", 4); result.pushKV("roots", 1); result.pushKV("security", security);
    return result;
}
namespace {
using BudgetFactor = std::array<uint32_t, 9>;
BudgetFactor ParseBudgetFactor(std::string_view target) {
    const auto bytes = Unhex(target);
    Require(bytes.size() == 32, "Invalid connection target");
    BudgetFactor factor{};
    for (size_t i = 0; i < bytes.size(); ++i) factor[i / 4] |= uint32_t(bytes[31 - i]) << ((i % 4) * 8);
    uint64_t carry = 1;
    for (auto& word : factor) { carry += word; word = static_cast<uint32_t>(carry); carry >>= 32; }
    return factor;
}
bool BudgetProductExceeds(const BudgetFactor& factor, uint64_t successes) {
    const std::array<uint32_t, 2> multiplier{static_cast<uint32_t>(successes), static_cast<uint32_t>(successes >> 32)};
    std::array<uint32_t, 11> product{};
    for (size_t i = 0; i < factor.size(); ++i) {
        uint64_t carry = 0;
        for (size_t j = 0; j < multiplier.size(); ++j) {
            const uint64_t part = uint64_t(factor[i]) * multiplier[j] + product[i + j] + carry;
            product[i + j] = static_cast<uint32_t>(part); carry = part >> 32;
        }
        for (size_t k = i + 2; carry && k < product.size(); ++k) {
            carry += product[k]; product[k] = static_cast<uint32_t>(carry); carry >>= 32;
        }
    }
    // Compare the full product with 2^257; equality is permitted.
    for (size_t i = product.size(); i-- > 0;) {
        const uint32_t limit = i == 8 ? 2 : 0;
        if (product[i] != limit) return product[i] > limit;
    }
    return false;
}
} // namespace
bool ConnectionBudgetExhausted(std::string_view target, uint64_t successes) {
    if (successes == UINT64_MAX) return true;
    return BudgetProductExceeds(ParseBudgetFactor(target), successes);
}
uint64_t ConnectionBudgetStopCount(std::string_view target) {
    const auto factor = ParseBudgetFactor(target);
    // Find the first blocked count, once per cached bounty. The lower bound is
    // always allowed and UINT64_MAX is always blocked by saturation. Using the
    // full product preserves > (not >=) at the exact 2^257 boundary, including
    // targets whose mathematical stop is beyond the representable counter.
    uint64_t allowed = 0, blocked = UINT64_MAX;
    while (blocked - allowed > 1) {
        const uint64_t middle = allowed + (blocked - allowed) / 2;
        if (BudgetProductExceeds(factor, middle)) blocked = middle;
        else allowed = middle;
    }
    return blocked;
}
double AdvanceConnectionDeadline(double previous, double now, uint32_t rate, bool idle) {
    if (idle) previous = std::max(previous, now);
    return std::max(previous + 1.0 / rate, now - 1.0);
}

struct ClaimsService::Impl {
    Emit output;
    ServiceDependencies deps;
    uint32_t rate{}, concurrency{};
    size_t pending_limit{};
    std::mutex mutex, output_mutex;
    std::condition_variable tls_condition, dns_condition;
    std::unordered_map<uint64_t, std::shared_ptr<Job>> jobs;
    std::deque<std::shared_ptr<Job>> tls_pending, dns_pending;
    std::list<std::shared_ptr<Job>> connection_pending;
    std::unordered_map<std::string, Budget> budgets;
    std::unordered_map<std::string, DnsEntry> dns;
    EndpointPerformanceCache performance;
    std::unordered_map<std::string, double> unavailable_endpoints;
    std::unordered_map<int, double> unavailable_families;
    std::vector<std::thread> workers;
    size_t tls_workers{}, dns_workers{}, active_tls{}, active_dns{};
    uint64_t last_id{}, touched{}, admission_revision{};
    double next_connection{};
    bool idle{true}, closed{}, native_pipeline{}, admission_allowed{true};
    std::atomic<bool> failed{}, failure_reported{};

    Impl(const UniValue& options, Emit emit, ServiceDependencies dependencies) : output(std::move(emit)), deps(std::move(dependencies)) {
        ExactKeys(options, {"connectionsPerSecond", "concurrency"});
        rate = static_cast<uint32_t>(ProtocolInteger(options["connectionsPerSecond"], 1, MAX_CONNECTION_LIMIT));
        concurrency = static_cast<uint32_t>(ProtocolInteger(options["concurrency"], 1, MAX_CONNECTION_LIMIT));
        pending_limit = std::max<size_t>(512, static_cast<size_t>(concurrency) + 2);
        // Custom capture/verification dependencies retain their exact boundary
        // contract. Production carries an owned, already-parsed capture from
        // the network worker to cryptographic verification without reparsing it.
        native_pipeline = !deps.capture && !deps.verify;
        if (!deps.resolve) deps.resolve = [](const std::string& domain) { return ResolveEndpoints(domain); };
        if (!deps.capture) deps.capture = [](const Context& context, const Endpoint& endpoint, CaptureControl& control, const std::function<void()>& started) { return Capture(context, endpoint, control, started); };
        if (!deps.verify) deps.verify = [](const Bytes& proof, const Context& context) { return VerifyProof(proof, context); };
        if (!deps.reachability_time) deps.reachability_time = Now;
        if (!deps.performance_time) deps.performance_time = Now;
        if (!deps.dns_time) deps.dns_time = Now;
    }
    void EmitFrame(const UniValue& value) {
        const auto text = value.write();
        Require(text.size() <= 160 * 1024, "Helper response exceeds 160 KiB");
        std::lock_guard lock(output_mutex);
        try { output(text); } catch (...) {
            // Stop socket admission before a failing gate owner hands off.
            // Fatal performs cancellation after the socket stack has unwound.
            failed.store(true, std::memory_order_release);
            throw OutputFailure();
        }
    }
    UniValue Fields(const std::shared_ptr<Job>& job) {
        uint64_t count;
        // A completed capture owns an immutable per-job snapshot. Only jobs
        // without one (e.g. a queued cancellation) need the shared budget lock.
        if (job->successes) count = *job->successes;
        else { std::lock_guard lock(mutex); count = budgets.at(job->bounty).successes; }
        UniValue fields(UniValue::VOBJ);
        fields.pushKV("id", job->id); fields.pushKV("context", PublicContext(job->context));
        fields.pushKV("started", job->started); fields.pushKV("captured", job->captured);
        if (job->target_miss) fields.pushKV("targetMiss", true);
        fields.pushKV("seconds", job->seconds); fields.pushKV("cancelled", job->Cancelled());
        fields.pushKV("successfulConnections", std::to_string(count));
        return fields;
    }
    void RetireLocked(const std::shared_ptr<Job>& job) {
        const auto found = jobs.find(job->id);
        if (found == jobs.end() || found->second != job) return;
        jobs.erase(found);
        if (job->running) {
            if (job->attempt) --active_tls; else --active_dns;
        } else std::erase(job->attempt ? tls_pending : dns_pending, job);
        if (job->attempt) --budgets.at(job->bounty).users;
    }
    void EmitTerminal(const std::shared_ptr<Job>& job, const UniValue& frame) {
        // A controller can replace this request as soon as it reads the frame,
        // even while output() is still returning on this worker. Release every
        // admission reservation before making that acknowledgement visible.
        { std::lock_guard lock(mutex); RetireLocked(job); }
        EmitFrame(frame);
    }
    bool EndpointAvailableLocked(const Endpoint& endpoint) {
        const double now = deps.reachability_time();
        const auto family = unavailable_families.find(endpoint.family);
        if (family != unavailable_families.end() && family->second > now) return false;
        const auto address = unavailable_endpoints.find(endpoint.Key());
        return address == unavailable_endpoints.end() || address->second <= now;
    }
    bool HasEndpointLocked(const DnsEntry& entry) {
        return std::any_of(entry.endpoints.begin(), entry.endpoints.end(),
                           [&](const auto& item) { return EndpointAvailableLocked(item.endpoint); });
    }
    void ExcludeEndpointLocked(const Endpoint& endpoint, bool family_unsupported) {
        const double now = deps.reachability_time();
        if (family_unsupported) {
            // Production resolves only AF_INET/AF_INET6. Still bound injected or
            // future families rather than allowing an unbounded negative cache.
            if (!unavailable_families.contains(endpoint.family) && unavailable_families.size() >= 2) {
                const auto oldest = std::min_element(unavailable_families.begin(), unavailable_families.end(),
                    [](const auto& a, const auto& b) { return a.second < b.second; });
                unavailable_families.erase(oldest);
            }
            unavailable_families[endpoint.family] = now + REACHABILITY_RECHECK_SECONDS;
        } else {
            if (!unavailable_endpoints.contains(endpoint.Key()) && unavailable_endpoints.size() >= MAX_UNREACHABLE_ENDPOINTS) {
                const auto oldest = std::min_element(unavailable_endpoints.begin(), unavailable_endpoints.end(),
                    [](const auto& a, const auto& b) { return a.second < b.second; });
                unavailable_endpoints.erase(oldest);
            }
            unavailable_endpoints[endpoint.Key()] = now + REACHABILITY_RECHECK_SECONDS;
        }
        for (const auto& waiting : connection_pending) {
            if (waiting->endpoint && (family_unsupported ? waiting->endpoint->family == endpoint.family : *waiting->endpoint == endpoint))
                waiting->connection_condition.notify_one();
        }
    }
    void BudgetChangedLocked(const std::string& bounty, const Budget& budget) {
        if (budget.successes < budget.stop_count) return;
        for (const auto& waiting : connection_pending)
            if (waiting->bounty == bounty) waiting->connection_condition.notify_one();
    }
    void RequestCancelLocked(const std::shared_ptr<Job>& job) {
        job->cancel_requested.store(true, std::memory_order_release);
        job->connection_condition.notify_one();
    }
    void BeforeStartLocked(const std::shared_ptr<Job>& job) {
        if (closed || failed.load(std::memory_order_acquire) || job->Cancelled()) throw CaptureCancelled();
        // A different worker may have discovered an impossible route after
        // this job selected its address. Do not spend a TCP turn or extend the
        // exclusion deadline merely because a queued job observes the cache.
        if (job->endpoint && !EndpointAvailableLocked(*job->endpoint)) throw EndpointExcluded();
        const auto& budget = budgets.at(job->bounty);
        if (budget.successes >= budget.stop_count) throw BudgetExhausted();
    }
    void BeforeStart(const std::shared_ptr<Job>& job) { std::lock_guard lock(mutex); BeforeStartLocked(job); }
    void Connecting(const std::shared_ptr<Job>& job) {
        std::unique_lock lock(mutex);
        const auto position = connection_pending.insert(connection_pending.end(), job);
        const auto release = [&] {
            if (!lock.owns_lock()) lock.lock();
            const bool head = position == connection_pending.begin();
            connection_pending.erase(position);
            if (head && !connection_pending.empty()) connection_pending.front()->connection_condition.notify_one();
        };
        try {
            for (;;) {
                BeforeStartLocked(job);
                if (!admission_allowed || position != connection_pending.begin()) {
                    job->connection_condition.wait(lock);
                    continue;
                }
                if (next_connection <= Now()) break;
                // Only the head owns a deadline. Handoffs wake one successor;
                // cancellations/exclusions/budget changes wake affected jobs.
                const auto deadline = Clock::time_point(std::chrono::ceil<Clock::duration>(std::chrono::duration<double>(next_connection)));
                job->connection_condition.wait_until(lock, deadline);
            }
            job->started = true; job->started_at = Now();
            // Keep the queue reservation across the acknowledgement, but never
            // hold the scheduler mutex while writing to the controller.
            lock.unlock();
            UniValue frame(UniValue::VOBJ); frame.pushKV("type", "started"); frame.pushKV("id", job->id); EmitFrame(frame);
            lock.lock();
            // The acknowledgement can block while another capture exhausts
            // this budget or excludes its endpoint. Recheck every admission
            // condition before spending a pacing turn and returning to TCP.
            BeforeStartLocked(job);
            // A pause may arrive while the started ACK is blocked on output.
            // Preserve that one ACK but do not begin TCP or invent a sample.
            // The socket/control stack unwinds before Attempt calls Cancel.
            if (!admission_allowed) { RequestCancelLocked(job); throw CaptureCancelled(); }
            const auto now = Now(); next_connection = AdvanceConnectionDeadline(next_connection, now, rate, idle);
            idle = false; job->started_at = now;
        } catch (...) {
            release();
            throw;
        }
        release();
    }
    std::pair<Endpoint, std::shared_ptr<Score>> SelectEndpoint(const std::shared_ptr<Job>& job) {
        std::lock_guard lock(mutex);
        const auto found = dns.find(job->domain);
        Require(found != dns.end() && found->second.expires > deps.dns_time() && !found->second.endpoints.empty(), "Public DNS resolution required");
        auto& cached = found->second;
        const auto mask = job->context.signature_algorithms_mask;
        // Resolution bounds this set at 32; avoid three heap allocations on
        // every attempt while preserving the same iteration and credit order.
        Require(cached.endpoints.size() <= MAX_ENDPOINTS, "Too many cached endpoints");
        std::array<Score*, MAX_ENDPOINTS> scores{};
        std::array<double, MAX_ENDPOINTS> rates{};
        std::array<size_t, MAX_ENDPOINTS> eligible{};
        size_t count = 0;
        const auto performance_now = deps.performance_time();
        for (size_t index = 0; index < cached.endpoints.size(); ++index) {
            auto& item = cached.endpoints[index];
            if (!EndpointAvailableLocked(item.endpoint)) continue;
            auto& score = item.scores[mask]; if (!score) score = std::make_shared<Score>();
            scores[count] = score.get(); rates[count] = performance.Rate(score, performance_now);
            eligible[count++] = index;
        }
        if (!count) throw EndpointExcluded();
        const auto maximum = *std::max_element(rates.begin(), rates.begin() + count);
        double total = 0; for (size_t i = 0; i < count; ++i) { rates[i] /= maximum; total += rates[i]; }
        for (size_t i = 0; i < count; ++i) scores[i]->credit += 0.01 / count + 0.99 * rates[i] / total;
        const size_t cursor = cached.next[mask] % count;
        size_t selected = cursor;
        for (size_t offset = 1; offset < count; ++offset) {
            const auto candidate = (cursor + offset) % count;
            if (scores[candidate]->credit > scores[selected]->credit) selected = candidate;
        }
        scores[selected]->credit -= 1; cached.next[mask] = (selected + 1) % count; cached.touched = ++touched;
        job->endpoint = cached.endpoints[eligible[selected]].endpoint;
        return {*job->endpoint, cached.endpoints[eligible[selected]].scores.at(mask)};
    }
    void Resolve(const std::shared_ptr<Job>& job) {
        bool ok = false, cached = false;
        if (!job->Cancelled()) {
            { std::lock_guard lock(mutex);
                const auto found = dns.find(job->domain);
                if (found != dns.end() && found->second.expires > deps.dns_time()) {
                    cached = true; ok = HasEndpointLocked(found->second); found->second.touched = ++touched;
                }
            }
            if (!cached) {
                std::vector<Endpoint> endpoints;
                try { endpoints = deps.resolve(job->domain); if (endpoints.size() > MAX_ENDPOINTS) endpoints.resize(MAX_ENDPOINTS); } catch (...) {}
                std::lock_guard lock(mutex);
                DnsEntry next;
                const auto previous = dns.find(job->domain);
                if (previous != dns.end()) next.next = previous->second.next;
                for (const auto& endpoint : endpoints) {
                    DnsEntry::Item item{endpoint, {}};
                    if (previous != dns.end()) for (const auto& old : previous->second.endpoints) if (old.endpoint == endpoint) { item.scores = old.scores; break; }
                    next.endpoints.push_back(std::move(item));
                }
                // Keep DNS separate from local reachability. If every address
                // is excluded, resolve=false engages the controller's existing
                // two-second retry without repeated DNS or a hot attempt loop.
                next.expires = deps.dns_time() + (!endpoints.empty() ? 60.0 : 2.0); next.touched = ++touched;
                ok = HasEndpointLocked(next);
                dns[job->domain] = std::move(next);
                if (dns.size() > MAX_DNS) {
                    const auto oldest = std::min_element(dns.begin(), dns.end(), [](const auto& a, const auto& b) { return a.second.touched < b.second.touched; });
                    dns.erase(oldest);
                }
            }
        }
        const bool cancelled = job->Cancelled();
        UniValue frame(UniValue::VOBJ); frame.pushKV("type", "resolved"); frame.pushKV("id", job->id); frame.pushKV("ok", ok && !cancelled);
        if (!ok || cancelled) frame.pushKV("message", cancelled ? "Resolution cancelled" : "Public DNS resolution failed");
        EmitTerminal(job, frame);
    }
    void Attempt(const std::shared_ptr<Job>& job) {
        Bytes captured;
        std::optional<CapturedProof> native_capture;
        std::optional<std::string> proof;
        std::optional<bool> validated;
        bool validating = false, blocked = false, local_unavailable = false;
        std::string message;
        std::shared_ptr<Score> score;
        try {
            if (job->Cancelled()) throw CaptureCancelled();
            const auto selected = SelectEndpoint(job); score = selected.second;
            BeforeStart(job);
            std::exception_ptr capture_error;
            try {
                if (native_pipeline) native_capture.emplace(CapturePrepared(*job->prepared_context, selected.first, job->control, [&] { Connecting(job); }));
                else captured = deps.capture(job->context, selected.first, job->control, [&] { Connecting(job); });
                job->captured = true;
            }
            catch (const OutputFailure&) { throw; }
            catch (const CaptureTargetMiss&) { job->target_miss = true; }
            catch (const CaptureCancelled&) { capture_error = std::current_exception(); }
            // These gate exits can follow an already-visible started ACK but
            // precede the actual connect call. Preserve that protocol ACK and
            // its capture frame, without inventing a failed validation sample.
            catch (const BudgetExhausted&) { capture_error = std::current_exception(); }
            catch (const EndpointExcluded&) { capture_error = std::current_exception(); }
            catch (const LocalEndpointUnavailable& error) {
                if (!job->Cancelled()) {
                    std::lock_guard lock(mutex);
                    ExcludeEndpointLocked(selected.first, error.family_unsupported);
                    local_unavailable = true;
                    if (job->started) validated = false;
                }
                capture_error = std::current_exception();
            }
            catch (...) { if (job->started && !job->Cancelled()) validated = false; capture_error = std::current_exception(); }
            if (job->started) {
                const auto elapsed = Now() - job->started_at;
                { std::lock_guard lock(mutex);
                    job->seconds = std::nearbyint(std::max(0.0, elapsed) * 1000000.0) / 1000000.0;
                    auto& budget = budgets.at(job->bounty);
                    // Count each target-evaluable candidate once, including
                    // early misses, without claiming it was authenticated.
                    if ((job->captured || job->target_miss) && budget.successes != UINT64_MAX) ++budget.successes;
                    job->successes = budget.successes;
                    BudgetChangedLocked(job->bounty, budget);
                }
                auto frame = Fields(job); frame.pushKV("type", "capture"); EmitFrame(frame);
            }
            if (capture_error) std::rethrow_exception(capture_error);
            if (!job->Cancelled() && !job->target_miss) {
                validating = true;
                const auto verified = native_capture ? VerifyCaptured(*native_capture) : deps.verify(captured, job->context);
                validated = true;
                if (verified.meets_target && !job->Cancelled()) proof = Hex(native_capture ? native_capture->Encoded() : captured);
            }
        } catch (const OutputFailure&) { throw; }
        catch (const BudgetExhausted&) { blocked = true; }
        catch (const EndpointExcluded&) {
            local_unavailable = !job->Cancelled();
            message = "Local network endpoint is temporarily unavailable";
        }
        catch (const LocalEndpointUnavailable& error) {
            message = error.family_unsupported ? "Local IP family is unsupported" : "Local network route is unavailable";
        }
        catch (const CaptureCancelled&) {
            // Closing publishes the service flag before cancelling each job.
            // Connecting can observe that flag first. Its socket stack has
            // unwound here, so publishing this job's cancellation is safe and
            // ensures an inconclusive terminal observation is labelled so.
            job->control.Cancel(); message = "TLS capture cancelled";
        }
        catch (const CaptureTimeout&) { if (validating && !validated) validated = false; message = job->started ? "TLS connection timed out" : "Public DNS resolution is required"; }
        catch (...) { if (validating && !validated) validated = false; message = job->started ? "TLS capture or proof validation failed" : "Public DNS resolution is required"; }
        auto frame = Fields(job);
        if (frame["cancelled"].get_bool()) proof.reset();
        // An actual failed connect still counts as a failed attempt, but a
        // conclusive local route/family limitation says nothing about remote
        // certificate validity or endpoint quality. Keep those histories neutral.
        // Throughput scores estimate usable work candidates. Early target
        // misses are useful throughput observations, not valid-proof samples.
        if (!local_unavailable && score && (validated || job->target_miss) && std::isfinite(job->seconds) && job->seconds >= 0) {
            std::lock_guard lock(mutex);
            performance.Record(score, job->target_miss || *validated, job->seconds, deps.performance_time());
        }
        frame.pushKV("type", "attempt"); frame.pushKV("proof", proof ? UniValue(*proof) : UniValue()); frame.pushKV("verified", proof.has_value());
        frame.pushKV("validationPassed", validated ? UniValue(*validated) : UniValue());
        if (local_unavailable) frame.pushKV("localUnavailable", true);
        if (!message.empty()) frame.pushKV("message", message);
        if (blocked) frame.pushKV("blocked", "budget");
        EmitTerminal(job, frame);
    }
    void Fatal() noexcept {
        failed.store(true, std::memory_order_release);
        std::vector<std::shared_ptr<Job>> cancel;
        { std::lock_guard lock(mutex); closed = true; for (const auto& [id, job] : jobs) { RequestCancelLocked(job); cancel.push_back(job); } tls_condition.notify_all(); dns_condition.notify_all(); }
        // Admission failure may already have been published by EmitFrame.
        // Keep the single diagnostic acknowledgement independent of that flag.
        if (!failure_reported.exchange(true)) {
            try { UniValue error(UniValue::VOBJ); error.pushKV("type", "error"); error.pushKV("message", "Claims helper worker failed"); EmitFrame(error); } catch (...) {}
        }
        for (const auto& job : cancel) job->control.Cancel();
    }
    void Worker(bool attempts) noexcept {
        for (;;) {
            std::shared_ptr<Job> job;
            { std::unique_lock lock(mutex);
                auto& pending = attempts ? tls_pending : dns_pending;
                auto& available = attempts ? tls_condition : dns_condition;
                available.wait(lock, [&] { return closed || !pending.empty(); });
                if (closed) return;
                job = pending.front(); pending.pop_front(); job->running = true;
                if (attempts) ++active_tls; else ++active_dns;
            }
            try { if (attempts) Attempt(job); else Resolve(job); }
            catch (...) { Fatal(); }
            // Terminal output already retired successful requests. An earlier
            // exception still needs cleanup; the identity guard makes it once.
            { std::lock_guard lock(mutex); RetireLocked(job); }
        }
    }
    void Cancel(const std::shared_ptr<Job>& job) {
        // Connecting holds the socket mutex while it waits. Publish and wake
        // under the gate mutex before Cancel can block acquiring that socket.
        { std::lock_guard lock(mutex); RequestCancelLocked(job); }
        job->control.Cancel();
        bool queued = false;
        { std::lock_guard lock(mutex);
            const auto found = jobs.find(job->id);
            queued = found != jobs.end() && found->second == job && !job->running;
            if (queued) {
                // Retiring can make this budget evictable before Fields runs.
                // Keep the cancelled request's counter snapshot with the job.
                if (job->attempt) job->successes = budgets.at(job->bounty).successes;
                RetireLocked(job);
            }
        }
        if (!queued) return;
        if (job->attempt) {
            auto frame = Fields(job); frame.pushKV("type", "attempt"); frame.pushKV("proof", UniValue()); frame.pushKV("verified", false);
            frame.pushKV("validationPassed", UniValue()); frame.pushKV("message", "TLS capture cancelled");
            EmitFrame(frame);
        } else { UniValue frame(UniValue::VOBJ); frame.pushKV("type", "resolved"); frame.pushKV("id", job->id); frame.pushKV("ok", false); frame.pushKV("message", "Resolution cancelled"); EmitFrame(frame); }
    }
    void Command(const UniValue& command) {
        Require(command.isObject() && command["type"].isStr(), "Invalid protocol command");
        const auto kind = command["type"].get_str();
        if (kind == "admission") {
            ExactKeys(command, {"type", "id", "allowed"});
            const auto id = ProtocolInteger(command["id"], 1, MAX_ID);
            Require(command["allowed"].isBool(), "Invalid admission gate state");
            const bool allowed = command["allowed"].get_bool();
            {
                std::lock_guard lock(mutex);
                Require(!closed && !failed.load(std::memory_order_acquire), "Helper is shutting down");
                Require(id > last_id, "Request IDs must increase"); last_id = admission_revision = id;
                if (!allowed) {
                    admission_allowed = false;
                    for (const auto& waiting : connection_pending) waiting->connection_condition.notify_one();
                }
            }
            UniValue frame(UniValue::VOBJ); frame.pushKV("type", "admission"); frame.pushKV("id", id); frame.pushKV("allowed", allowed);
            EmitFrame(frame);
            if (allowed) {
                std::lock_guard lock(mutex);
                // Resume only after a successful ACK write; output failure
                // must not release queued sockets. A newer pause wins races.
                if (!closed && !failed.load(std::memory_order_acquire) && admission_revision == id) {
                    if (!admission_allowed) next_connection = std::max(next_connection, Now());
                    admission_allowed = true;
                    for (const auto& waiting : connection_pending) waiting->connection_condition.notify_one();
                }
            }
            return;
        }
        if (kind == "cancel") {
            ExactKeys(command, {"type", "id"}); const auto id = ProtocolInteger(command["id"], 1, MAX_ID);
            std::shared_ptr<Job> job;
            { std::lock_guard lock(mutex); if (const auto found = jobs.find(id); found != jobs.end()) job = found->second; }
            if (job) Cancel(job);
            return;
        }
        Require(kind == "resolve" || kind == "attempt", "Unknown protocol command");
        if (kind == "resolve") ExactKeys(command, {"type", "id", "domain"});
        else ExactKeys(command, {"type", "id", "context", "bountyId", "successfulConnections"});
        auto job = std::make_shared<Job>(); job->id = ProtocolInteger(command["id"], 1, MAX_ID); job->attempt = kind == "attempt";
        uint64_t successes = 0;
        if (!job->attempt) job->domain = PublicDomain(command["domain"]);
        else {
            job->context = native_pipeline ? ParseContextFields(command["context"]) : ParseContext(command["context"]);
            job->domain = job->context.domain;
            job->bounty = command["bountyId"].get_str();
            Require(job->bounty.size() >= 66 && job->bounty.size() <= 75 && job->bounty[64] == ':', "Invalid bounty outpoint");
            const auto hash = Unhex(std::string_view(job->bounty).substr(0, 64)); Require(hash.size() == 32, "Invalid bounty outpoint");
            Decimal(job->bounty.substr(65), 0xffffffff);
            successes = Decimal(command["successfulConnections"].get_str(), UINT64_MAX);
        }
        std::unique_lock lock(mutex);
        Require(!closed, "Helper is shutting down"); Require(job->id > last_id, "Request IDs must increase");
        Require(jobs.size() < pending_limit, "Helper pending request limit exceeded");
        if (job->attempt) {
            auto found = budgets.find(job->bounty);
            if (native_pipeline) {
                // A bounty can prepare a different claim transaction. Reuse
                // only exact validated static fields, never the bounty ID alone;
                // every job still owns its current validated median time.
                const PreparedContext* previous = found != budgets.end() && found->second.prepared_context
                    ? &*found->second.prepared_context : nullptr;
                if (previous && previous->MatchesStaticContext(job->context))
                    job->prepared_context = previous->WithValidationTime(job->context.validation_time);
                else job->prepared_context.emplace(job->context);
            }
            if (found == budgets.end()) {
                if (budgets.size() >= MAX_BUDGETS) {
                    auto oldest = budgets.end();
                    for (auto item = budgets.begin(); item != budgets.end(); ++item) if (!item->second.users && (oldest == budgets.end() || item->second.touched < oldest->second.touched)) oldest = item;
                    Require(oldest != budgets.end(), "Helper budget cache is full"); budgets.erase(oldest);
                }
                const auto& target = job->context.connection_work_target;
                found = budgets.emplace(job->bounty, Budget{target, ConnectionBudgetStopCount(target), successes, 0, 0}).first;
            }
            auto& budget = found->second;
            Require(budget.target == job->context.connection_work_target, "Bounty target changed within helper session");
            if (native_pipeline && (!budget.prepared_context || !budget.prepared_context->MatchesStaticContext(job->context)))
                budget.prepared_context = job->prepared_context;
            budget.successes = std::max(budget.successes, successes); ++budget.users; budget.touched = ++touched;
            BudgetChangedLocked(job->bounty, budget);
            if (std::none_of(jobs.begin(), jobs.end(), [](const auto& item) { return item.second->attempt && !item.second->Cancelled(); })) idle = true;
        }
        auto& pending = job->attempt ? tls_pending : dns_pending;
        last_id = job->id; jobs.emplace(job->id, job); pending.push_back(job);
        const size_t demand = pending.size() + (job->attempt ? active_tls : active_dns);
        auto& count = job->attempt ? tls_workers : dns_workers;
        const size_t limit = job->attempt ? concurrency : 2;
        try {
            if (count < limit && count < demand) { workers.emplace_back([this, attempts = job->attempt] { Worker(attempts); }); ++count; }
        } catch (...) { lock.unlock(); Fatal(); throw std::runtime_error("Claims helper could not create a connection worker"); }
        (job->attempt ? tls_condition : dns_condition).notify_one();
    }
    void Close() {
        std::vector<std::shared_ptr<Job>> cancel;
        { std::lock_guard lock(mutex); closed = true; for (const auto& [id, job] : jobs) { RequestCancelLocked(job); cancel.push_back(job); } tls_condition.notify_all(); dns_condition.notify_all(); }
        for (const auto& job : cancel) { try { Cancel(job); } catch (...) { failed = true; } }
        for (auto& worker : workers) if (worker.joinable()) worker.join();
    }
};

ClaimsService::ClaimsService(const UniValue& options, Emit emit, ServiceDependencies deps) : impl_(std::make_unique<Impl>(options, std::move(emit), std::move(deps))) {}
ClaimsService::~ClaimsService() { impl_->Close(); }
void ClaimsService::Command(const UniValue& command) { impl_->Command(command); }
void ClaimsService::Close() { impl_->Close(); }
bool ClaimsService::Failed() const { return impl_->failed.load(); }
int RunService(std::istream& input, Emit emit) {
    ProtocolFrameReader frames(input);
    const auto start = frames.Next(); Require(start.has_value(), "Protocol 4 start command required");
    ExactKeys(*start, {"type", "protocol", "options"});
    Require((*start)["type"].isStr() && (*start)["type"].get_str() == "start" && ProtocolInteger((*start)["protocol"], 4, 4) == 4, "Protocol 4 start command required");
    InitializeCrypto();
    ClaimsService service((*start)["options"], emit);
    emit(ReadyFrame().write());
    while (const auto command = frames.Next()) {
        if ((*command)["type"].isStr() && (*command)["type"].get_str() == "shutdown") { ExactKeys(*command, {"type"}); break; }
        service.Command(*command);
    }
    service.Close();
    return service.Failed() ? 1 : 0;
}
} // namespace claimer
