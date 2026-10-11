// Copyright (c) 2026 The ConnectCoin developers. MIT license.
#include <claimer/crypto.hpp>
#include <iostream>
#include <thread>
#include <stdexcept>
#include <atomic>
using namespace claimer;
void Require(bool v) { if (!v) throw std::runtime_error("native crypto test assertion failed"); }
template<class F> void Reject(F f) { bool failed=false; try { f(); } catch(const std::exception&) { failed=true; } Require(failed); }
int main() {
    try {
        Context c{"example.com", std::string(63,'0')+"1", 3, std::string(64,'f'), 1, 7, 1700000000};
        ValidateContext(c);
        Require(Hex(ClaimChallenge(c)) == "cd33d9054ba36d088e12d7a9f74b847b1f07082cc915416721ace1b010505758");
        Require(Hex(Unhex("001122aaff")) == "001122aaff");
        Reject([]{Unhex("AB");}); Reject([]{Unhex("a");}); Reject([]{Unhex("zz");});
        for (auto name : {"", "Example.com", "-x.com", "a..com", "x-.com", "a.com.", "a/com"}) Require(!IsCanonicalDomain(name));
        for (auto name : {"google.com", "xn--x.example", "a"}) Require(IsCanonicalDomain(name));
        for (auto name : {"localhost", "a.local", "a.localhost", "a.internal"}) { auto bad=c; bad.domain=name; Reject([&]{ValidateContext(bad);}); }
        auto bad=c; bad.validation_time=0; Reject([&]{ValidateContext(bad);});
        bad=c; bad.root_certificates_version=2; Reject([&]{ValidateContext(bad);});
        bad=c; bad.signature_algorithms_mask=8; Reject([&]{ValidateContext(bad);});
        bad=c; bad.txid[0]='A'; Reject([&]{ValidateContext(bad);});
        Reject([&]{ParseProof({},c);}); Reject([&]{ParseProof(Bytes{1},c);}); Reject([&]{ParseProof(Bytes{2,1,0,0,1},c);});
        Reject([&]{ValidateCertificateMessage(Bytes{11,0,0,4,0,0,0,0});});
        Reject([&]{ValidateCertificateMessage(Bytes{11,0,0,10,0,0,0,6,0,0,1,0,0,0});});
        std::atomic<bool> success{true};
        std::vector<std::thread> workers;
        for (int i=0;i<16;++i) workers.emplace_back([&]{try { for(int j=0;j<20;++j) { InitializeCrypto(); Hash random{}; RandomBytes(random); Require(random != Hash{}); Require(ClaimChallenge(c) != random); }}catch(...){success=false;}});
        for(auto& worker:workers) worker.join(); Require(success);
        std::cout << "native crypto regression tests passed\n";
        return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n';return 1; }
}
