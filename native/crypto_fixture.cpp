// Test-only stdin verifier. Never installed or linked into the production CLI.
#include <claimer/crypto.hpp>
#include <univalue.h>
#include <iostream>
#include <string>
int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        UniValue out(UniValue::VOBJ);
        try {
            if (line.size() > 524288) throw std::runtime_error("fixture exceeds bound");
            UniValue request;
            if (!request.read(line)) throw std::runtime_error("invalid fixture JSON");
            const auto proof=claimer::Unhex(request["proof"].get_str());
            if (request["mode"].get_str()=="certificate") {
                claimer::ValidateCertificateMessage(proof);
            } else {
                const auto& c=request["context"];
                claimer::Context context{c["domain"].get_str(), c["txid"].get_str(), c["input_index"].getInt<uint32_t>(),
                    c["connection_work_target"].get_str(), c["root_certificates_version"].getInt<uint32_t>(),
                    c["signature_algorithms_mask"].getInt<uint8_t>(), c["validation_time"].getInt<int64_t>()};
                const std::string& pem=request["roots"].get_str();
                auto result=claimer::VerifyProofForTesting(proof,context,{reinterpret_cast<const unsigned char*>(pem.data()),pem.size()});
                out.pushKV("work_hash",result.work_hash);
                out.pushKV("meets_target",result.meets_target);
                out.pushKV("scheme",result.signature_scheme);
            }
            out.pushKV("valid",true);
        } catch(const std::exception& e) { out.pushKV("valid",false); out.pushKV("error",e.what()); }
        std::cout<<out.write()<<'\n'<<std::flush;
    }
}
