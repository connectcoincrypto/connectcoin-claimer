// Test-only stdin verifier. Never installed or linked into the production CLI.
#include <claimer/crypto.hpp>
#include <univalue.h>
#include <iostream>
#include <optional>
#include <string>
int main() {
    std::string line;
    std::optional<claimer::PreparedContext> reusable;
    while (std::getline(std::cin, line)) {
        UniValue out(UniValue::VOBJ);
        try {
            if (line.size() > 524288) throw std::runtime_error("fixture exceeds bound");
            UniValue request;
            if (!request.read(line)) throw std::runtime_error("invalid fixture JSON");
            if (request.exists("clear_cache") && request["clear_cache"].get_bool()) {
                claimer::ClearSignatureCacheForTesting();
                claimer::ClearCertificateCacheForTesting();
                reusable.reset();
            }
            const auto proof=claimer::Unhex(request["proof"].get_str());
            if (request["mode"].get_str()=="certificate") {
                claimer::ValidateCertificateMessage(proof);
            } else {
                const auto& c=request["context"];
                claimer::Context context{c["domain"].get_str(), c["txid"].get_str(), c["input_index"].getInt<uint32_t>(),
                    c["connection_work_target"].get_str(), c["root_certificates_version"].getInt<uint32_t>(),
                    c["signature_algorithms_mask"].getInt<uint8_t>(), c["validation_time"].getInt<int64_t>()};
                const std::string& pem=request["roots"].get_str();
                const std::span<const unsigned char> roots{reinterpret_cast<const unsigned char*>(pem.data()),pem.size()};
                const auto result = [&] {
                    if (request.exists("prepared") && request["prepared"].get_bool()) {
                        const bool hit = reusable && reusable->MatchesStaticContext(context);
                        out.pushKV("context_reused", hit);
                        auto prepared = hit ? reusable->WithValidationTime(context.validation_time) : claimer::PreparedContext(context);
                        reusable = prepared;
                        return claimer::VerifyCapturedForTesting(claimer::CapturedProof(proof, prepared), roots);
                    }
                    return claimer::VerifyProofForTesting(proof, context, roots);
                }();
                out.pushKV("work_hash",result.work_hash);
                out.pushKV("meets_target",result.meets_target);
                out.pushKV("scheme",result.signature_scheme);
            }
            out.pushKV("valid",true);
        } catch(const std::exception& e) { out.pushKV("valid",false); out.pushKV("error",e.what()); }
        const auto stats = claimer::SignatureCacheStatsForTesting();
        out.pushKV("cache_hits", static_cast<uint64_t>(stats.hits));
        out.pushKV("cache_misses", static_cast<uint64_t>(stats.misses));
        out.pushKV("cache_entries", static_cast<uint64_t>(stats.entries));
        out.pushKV("cache_bytes", static_cast<uint64_t>(stats.bytes));
        const auto metadata = claimer::CertificateCacheStatsForTesting();
        out.pushKV("metadata_hits", static_cast<uint64_t>(metadata.hits));
        out.pushKV("metadata_misses", static_cast<uint64_t>(metadata.misses));
        out.pushKV("metadata_builds", static_cast<uint64_t>(metadata.metadata_builds));
        out.pushKV("time_checks", static_cast<uint64_t>(metadata.time_checks));
        std::cout<<out.write()<<'\n'<<std::flush;
    }
}
