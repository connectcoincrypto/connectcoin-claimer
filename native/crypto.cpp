// Copyright (c) 2026 The ConnectCoin developers.
// Distributed under the MIT software license. See vendor/CORE-LICENSE.
// Parser and certificate policy adapted from ConnectCoin Core p2c.cpp/p2c_x509.cpp.
#include <claimer/crypto.hpp>
#include <mbedtls/sha256.h>
#include <mbedtls/threading.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ecp.h>
#include <psa/crypto.h>
#include <mbedtls_rsa_pss.h>
#include <mbedtls_x509_root_first.h>
#include "roots.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <ranges>
#include <stdexcept>
#include <utility>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <sys/random.h>
#else
#include <unistd.h>
#endif
#if defined(MBEDTLS_HAVE_TIME) || defined(MBEDTLS_HAVE_TIME_DATE)
#error "P2C validation must use the explicit validation time, never the host clock"
#endif
#if !defined(MBEDTLS_THREADING_C) || !defined(MBEDTLS_THREADING_ALT)
#error "Concurrent PSA operations require the native mutex callbacks"
#endif

namespace claimer {
namespace {
constexpr size_t MAX_P2C_PROOF_SIZE{65536};
constexpr size_t MAX_P2C_CERTIFICATE_MESSAGE_SIZE{49152};
constexpr size_t MAX_P2C_CERTIFICATE_SIZE{16384};
constexpr size_t MAX_P2C_CERTIFICATES{8};


constexpr uint8_t TLS_HANDSHAKE_CLIENT_HELLO{1};
constexpr uint8_t TLS_HANDSHAKE_SERVER_HELLO{2};
constexpr uint8_t TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS{8};
constexpr uint8_t TLS_HANDSHAKE_CERTIFICATE{11};
constexpr uint8_t TLS_HANDSHAKE_CERTIFICATE_VERIFY{15};

constexpr uint16_t TLS_EXTENSION_SERVER_NAME{0};
constexpr uint16_t TLS_EXTENSION_COMPRESS_CERTIFICATE{27};
constexpr uint16_t TLS_EXTENSION_PRE_SHARED_KEY{41};
constexpr uint16_t TLS_EXTENSION_EARLY_DATA{42};
constexpr uint16_t TLS_EXTENSION_SUPPORTED_VERSIONS{43};
constexpr uint16_t TLS_EXTENSION_COOKIE{44};
constexpr uint16_t TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES{45};
constexpr uint16_t TLS_EXTENSION_KEY_SHARE{51};
constexpr uint16_t TLS_EXTENSION_SIGNATURE_ALGORITHMS{13};
constexpr uint16_t TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO{0xfe0d};

constexpr uint16_t TLS_VERSION_1_2{0x0303};
constexpr uint16_t TLS_VERSION_1_3{0x0304};
constexpr uint16_t TLS_AES_128_GCM_SHA256{0x1301};
constexpr uint16_t TLS_CHACHA20_POLY1305_SHA256{0x1303};

constexpr uint16_t TLS_ECDSA_SECP256R1_SHA256{0x0403};
constexpr uint16_t TLS_RSA_PSS_RSAE_SHA256{0x0804};
constexpr uint16_t TLS_RSA_PSS_PSS_SHA256{0x0809};
constexpr uint16_t TLS_GROUP_SECP256R1{0x0017};
constexpr uint16_t TLS_GROUP_X25519{0x001d};

constexpr size_t MAX_CLIENT_HELLO_SIZE{4096};
constexpr size_t MAX_SERVER_HELLO_SIZE{2048};
constexpr size_t MAX_ENCRYPTED_EXTENSIONS_SIZE{4096};
constexpr size_t MAX_CERTIFICATE_VERIFY_SIZE{8192};

constexpr std::array<unsigned char, 32> HELLO_RETRY_REQUEST_RANDOM{
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

class ByteReader
{
private:
    std::span<const unsigned char> m_bytes;
    size_t m_pos{0};

public:
    explicit ByteReader(std::span<const unsigned char> bytes) : m_bytes{bytes} {}

    size_t Position() const { return m_pos; }
    size_t Remaining() const { return m_bytes.size() - m_pos; }
    bool Empty() const { return m_pos == m_bytes.size(); }

    bool ReadU8(uint8_t& out)
    {
        if (Remaining() < 1) return false;
        out = m_bytes[m_pos++];
        return true;
    }

    bool ReadU16(uint16_t& out)
    {
        if (Remaining() < 2) return false;
        out = (uint16_t{m_bytes[m_pos]} << 8) | uint16_t{m_bytes[m_pos + 1]};
        m_pos += 2;
        return true;
    }

    bool ReadU24(uint32_t& out)
    {
        if (Remaining() < 3) return false;
        out = (uint32_t{m_bytes[m_pos]} << 16) |
              (uint32_t{m_bytes[m_pos + 1]} << 8) |
              uint32_t{m_bytes[m_pos + 2]};
        m_pos += 3;
        return true;
    }

    bool ReadBytes(size_t size, std::span<const unsigned char>& out)
    {
        if (Remaining() < size) return false;
        out = m_bytes.subspan(m_pos, size);
        m_pos += size;
        return true;
    }
};

struct TlsExtension
{
    uint16_t type;
    std::span<const unsigned char> data;
};

struct ClientHelloState
{
    std::vector<uint16_t> cipher_suites;
    std::vector<uint16_t> signature_algorithms;
    std::vector<uint16_t> key_share_groups;
    std::vector<unsigned char> legacy_session_id;
};

bool IsValidKeyShare(uint16_t group, std::span<const unsigned char> exchange)
{
    if (group == TLS_GROUP_X25519) return exchange.size() == 32;
    return group == TLS_GROUP_SECP256R1 && exchange.size() == 65 && exchange.front() == 0x04;
}

bool SetError(std::string& error, std::string message)
{
    error = std::move(message);
    return false;
}

bool ReadHandshake(ByteReader& proof, uint8_t expected_type, size_t maximum_size,
                   std::span<const unsigned char>& full, std::span<const unsigned char>& body,
                   std::string& error)
{
    const size_t start{proof.Position()};
    uint8_t type{0};
    uint32_t size{0};
    if (!proof.ReadU8(type) || !proof.ReadU24(size)) return SetError(error, "truncated TLS handshake header");
    if (type != expected_type) return SetError(error, "unexpected TLS handshake message order");
    if (size + 4 > maximum_size) return SetError(error, "TLS handshake message exceeds P2C limit");
    if (!proof.ReadBytes(size, body)) return SetError(error, "truncated TLS handshake message");
    full = std::span<const unsigned char>{body.data() - 4, size + 4};
    if (proof.Position() != start + full.size()) return SetError(error, "internal TLS parser offset mismatch");
    return true;
}

bool ReadExtensions(ByteReader& message, std::vector<TlsExtension>& extensions, std::string& error)
{
    uint16_t total_size{0};
    if (!message.ReadU16(total_size) || message.Remaining() != total_size) {
        return SetError(error, "invalid TLS extensions length");
    }
    std::span<const unsigned char> encoded;
    if (!message.ReadBytes(total_size, encoded)) return SetError(error, "truncated TLS extensions");
    ByteReader reader{encoded};
    while (!reader.Empty()) {
        uint16_t type{0};
        uint16_t size{0};
        std::span<const unsigned char> data;
        if (!reader.ReadU16(type) || !reader.ReadU16(size) || !reader.ReadBytes(size, data)) {
            return SetError(error, "truncated TLS extension");
        }
        if (std::ranges::any_of(extensions, [type](const auto& extension) { return extension.type == type; })) {
            return SetError(error, "duplicate TLS extension");
        }
        extensions.push_back({type, data});
    }
    return true;
}

const TlsExtension* FindExtension(const std::vector<TlsExtension>& extensions, uint16_t type)
{
    const auto it{std::ranges::find_if(extensions, [type](const auto& extension) { return extension.type == type; })};
    return it == extensions.end() ? nullptr : &*it;
}

bool ParseServerName(const TlsExtension& extension, std::string_view expected_domain, std::string& error)
{
    ByteReader reader{extension.data};
    uint16_t list_size{0};
    uint8_t name_type{0};
    uint16_t name_size{0};
    std::span<const unsigned char> name;
    if (!reader.ReadU16(list_size) || list_size != reader.Remaining() ||
        !reader.ReadU8(name_type) || name_type != 0 ||
        !reader.ReadU16(name_size) || !reader.ReadBytes(name_size, name) || !reader.Empty()) {
        return SetError(error, "P2C ClientHello must contain exactly one DNS server_name");
    }
    const std::string_view encoded_name{reinterpret_cast<const char*>(name.data()), name.size()};
    if (encoded_name != expected_domain) return SetError(error, "ClientHello server_name does not match P2C domain");
    return true;
}

bool ParseClientHello(std::span<const unsigned char> body, std::string_view expected_domain,
                      const Hash& expected_challenge, ClientHelloState& state, std::string& error)
{
    ByteReader reader{body};
    uint16_t legacy_version{0};
    std::span<const unsigned char> random;
    uint8_t session_id_size{0};
    std::span<const unsigned char> session_id;
    uint16_t cipher_suites_size{0};
    std::span<const unsigned char> cipher_suites;
    uint8_t compression_size{0};
    std::span<const unsigned char> compression;
    if (!reader.ReadU16(legacy_version) || legacy_version != TLS_VERSION_1_2 ||
        !reader.ReadBytes(32, random) ||
        !reader.ReadU8(session_id_size) || session_id_size > 32 || !reader.ReadBytes(session_id_size, session_id) ||
        !reader.ReadU16(cipher_suites_size) || cipher_suites_size < 2 || (cipher_suites_size % 2) != 0 ||
        !reader.ReadBytes(cipher_suites_size, cipher_suites) ||
        !reader.ReadU8(compression_size) || compression_size != 1 ||
        !reader.ReadBytes(compression_size, compression) || compression[0] != 0) {
        return SetError(error, "invalid canonical P2C ClientHello");
    }
    if (!std::equal(random.begin(), random.end(), expected_challenge.begin())) {
        return SetError(error, "ClientHello.random does not match P2C claim challenge");
    }
    state.legacy_session_id.assign(session_id.begin(), session_id.end());
    for (size_t i{0}; i < cipher_suites.size(); i += 2) {
        state.cipher_suites.push_back((uint16_t{cipher_suites[i]} << 8) | cipher_suites[i + 1]);
    }

    std::vector<TlsExtension> extensions;
    if (!ReadExtensions(reader, extensions, error) || !reader.Empty()) return false;
    const auto* server_name{FindExtension(extensions, TLS_EXTENSION_SERVER_NAME)};
    const auto* versions{FindExtension(extensions, TLS_EXTENSION_SUPPORTED_VERSIONS)};
    const auto* signatures{FindExtension(extensions, TLS_EXTENSION_SIGNATURE_ALGORITHMS)};
    const auto* key_share{FindExtension(extensions, TLS_EXTENSION_KEY_SHARE)};
    if (!server_name || !versions || !signatures || !key_share) {
        return SetError(error, "P2C ClientHello is missing a required TLS 1.3 extension");
    }
    if (!ParseServerName(*server_name, expected_domain, error)) return false;
    for (uint16_t forbidden : {TLS_EXTENSION_COMPRESS_CERTIFICATE, TLS_EXTENSION_PRE_SHARED_KEY,
                               TLS_EXTENSION_EARLY_DATA, TLS_EXTENSION_COOKIE,
                               TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES, TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO}) {
        if (FindExtension(extensions, forbidden)) return SetError(error, "forbidden P2C ClientHello extension");
    }

    ByteReader version_reader{versions->data};
    uint8_t version_size{0};
    std::span<const unsigned char> version_list;
    if (!version_reader.ReadU8(version_size) || version_size < 2 || (version_size % 2) != 0 ||
        !version_reader.ReadBytes(version_size, version_list) || !version_reader.Empty()) {
        return SetError(error, "invalid supported_versions extension");
    }
    bool offers_tls13{false};
    for (size_t i{0}; i < version_list.size(); i += 2) {
        offers_tls13 |= ((uint16_t{version_list[i]} << 8) | version_list[i + 1]) == TLS_VERSION_1_3;
    }
    if (!offers_tls13) return SetError(error, "ClientHello does not offer TLS 1.3");

    ByteReader signature_reader{signatures->data};
    uint16_t signature_size{0};
    std::span<const unsigned char> signature_list;
    if (!signature_reader.ReadU16(signature_size) || signature_size < 2 || (signature_size % 2) != 0 ||
        !signature_reader.ReadBytes(signature_size, signature_list) || !signature_reader.Empty()) {
        return SetError(error, "invalid signature_algorithms extension");
    }
    for (size_t i{0}; i < signature_list.size(); i += 2) {
        state.signature_algorithms.push_back((uint16_t{signature_list[i]} << 8) | signature_list[i + 1]);
    }

    ByteReader key_share_reader{key_share->data};
    uint16_t shares_size{0};
    std::span<const unsigned char> shares;
    if (!key_share_reader.ReadU16(shares_size) || shares_size == 0 ||
        !key_share_reader.ReadBytes(shares_size, shares) || !key_share_reader.Empty()) {
        return SetError(error, "invalid ClientHello key_share extension");
    }
    ByteReader shares_reader{shares};
    while (!shares_reader.Empty()) {
        uint16_t group{0};
        uint16_t exchange_size{0};
        std::span<const unsigned char> exchange;
        if (!shares_reader.ReadU16(group) || !shares_reader.ReadU16(exchange_size) || exchange_size == 0 ||
            !shares_reader.ReadBytes(exchange_size, exchange) || !IsValidKeyShare(group, exchange) ||
            std::ranges::find(state.key_share_groups, group) != state.key_share_groups.end()) {
            return SetError(error, "invalid ClientHello key share");
        }
        state.key_share_groups.push_back(group);
    }
    return true;
}

bool ParseServerHello(std::span<const unsigned char> body, const ClientHelloState& client, std::string& error)
{
    ByteReader reader{body};
    uint16_t legacy_version{0};
    std::span<const unsigned char> random;
    uint8_t session_id_size{0};
    std::span<const unsigned char> session_id;
    uint16_t cipher_suite{0};
    uint8_t compression{0};
    if (!reader.ReadU16(legacy_version) || legacy_version != TLS_VERSION_1_2 || !reader.ReadBytes(32, random) ||
        !reader.ReadU8(session_id_size) || session_id_size > 32 || !reader.ReadBytes(session_id_size, session_id) ||
        !reader.ReadU16(cipher_suite) || !reader.ReadU8(compression) || compression != 0) {
        return SetError(error, "invalid canonical P2C ServerHello");
    }
    if (std::ranges::equal(random, HELLO_RETRY_REQUEST_RANDOM)) return SetError(error, "HelloRetryRequest is forbidden in P2C v2");
    if (!std::ranges::equal(session_id, client.legacy_session_id)) return SetError(error, "ServerHello session id mismatch");
    if (cipher_suite != TLS_AES_128_GCM_SHA256 && cipher_suite != TLS_CHACHA20_POLY1305_SHA256) {
        return SetError(error, "P2C v2 requires a SHA-256 TLS 1.3 cipher suite");
    }
    if (std::ranges::find(client.cipher_suites, cipher_suite) == client.cipher_suites.end()) {
        return SetError(error, "ServerHello selected an unoffered cipher suite");
    }

    std::vector<TlsExtension> extensions;
    if (!ReadExtensions(reader, extensions, error) || !reader.Empty()) return false;
    if (extensions.size() != 2) return SetError(error, "P2C ServerHello must contain only supported_versions and key_share");
    const auto* versions{FindExtension(extensions, TLS_EXTENSION_SUPPORTED_VERSIONS)};
    const auto* key_share{FindExtension(extensions, TLS_EXTENSION_KEY_SHARE)};
    if (!versions || !key_share || versions->data.size() != 2 ||
        ((uint16_t{versions->data[0]} << 8) | versions->data[1]) != TLS_VERSION_1_3) {
        return SetError(error, "ServerHello did not select TLS 1.3");
    }
    ByteReader key_share_reader{key_share->data};
    uint16_t group{0};
    uint16_t exchange_size{0};
    std::span<const unsigned char> exchange;
    if (!key_share_reader.ReadU16(group) || !key_share_reader.ReadU16(exchange_size) || exchange_size == 0 ||
        !key_share_reader.ReadBytes(exchange_size, exchange) || !key_share_reader.Empty() ||
        !IsValidKeyShare(group, exchange) ||
        std::ranges::find(client.key_share_groups, group) == client.key_share_groups.end()) {
        return SetError(error, "invalid or unoffered ServerHello key share");
    }
    return true;
}

bool ParseEncryptedExtensions(std::span<const unsigned char> body, std::string& error)
{
    ByteReader reader{body};
    std::vector<TlsExtension> extensions;
    if (!ReadExtensions(reader, extensions, error) || !reader.Empty()) return false;
    if (FindExtension(extensions, TLS_EXTENSION_EARLY_DATA)) return SetError(error, "TLS early_data is forbidden in P2C v2");
    return true;
}

bool ParseCertificate(std::span<const unsigned char> body, ParsedProof& parsed, std::string& error)
{
    ByteReader reader{body};
    uint8_t context_size{0};
    std::span<const unsigned char> context;
    uint32_t list_size{0};
    std::span<const unsigned char> list;
    if (!reader.ReadU8(context_size) || context_size != 0 || !reader.ReadBytes(context_size, context) ||
        !reader.ReadU24(list_size) || list_size == 0 || list_size != reader.Remaining() ||
        !reader.ReadBytes(list_size, list) || !reader.Empty()) {
        return SetError(error, "invalid canonical P2C Certificate message");
    }

    ByteReader certificates{list};
    while (!certificates.Empty()) {
        uint32_t certificate_size{0};
        std::span<const unsigned char> certificate;
        uint16_t extensions_size{0};
        std::span<const unsigned char> extensions;
        if (!certificates.ReadU24(certificate_size) || certificate_size == 0 || certificate_size > MAX_P2C_CERTIFICATE_SIZE ||
            !certificates.ReadBytes(certificate_size, certificate) ||
            !certificates.ReadU16(extensions_size) || !certificates.ReadBytes(extensions_size, extensions)) {
            return SetError(error, "invalid certificate entry in P2C proof");
        }
        parsed.certificate_chain.push_back(certificate);
        if (parsed.certificate_chain.size() > MAX_P2C_CERTIFICATES) return SetError(error, "too many certificates in P2C proof");
    }
    return true;
}

bool IsSupportedCertificateVerifyScheme(uint16_t scheme)
{
    return scheme == TLS_ECDSA_SECP256R1_SHA256 ||
           scheme == TLS_RSA_PSS_RSAE_SHA256 ||
           scheme == TLS_RSA_PSS_PSS_SHA256;
}

bool ParseCertificateVerify(std::span<const unsigned char> body, const ClientHelloState& client,
                            ParsedProof& parsed, std::string& error)
{
    ByteReader reader{body};
    uint16_t signature_size{0};
    if (!reader.ReadU16(parsed.certificate_verify_scheme) ||
        !reader.ReadU16(signature_size) || signature_size == 0 ||
        !reader.ReadBytes(signature_size, parsed.certificate_verify_signature) || !reader.Empty()) {
        return SetError(error, "invalid P2C CertificateVerify message");
    }
    if (!IsSupportedCertificateVerifyScheme(parsed.certificate_verify_scheme)) {
        return SetError(error, "unsupported P2C CertificateVerify signature scheme");
    }
    if (std::ranges::find(client.signature_algorithms, parsed.certificate_verify_scheme) == client.signature_algorithms.end()) {
        return SetError(error, "CertificateVerify used an unoffered signature scheme");
    }
    return true;
}


[[noreturn]] void Fail(std::string_view message) { throw std::runtime_error(std::string(message)); }
class Sha256 {
    mbedtls_sha256_context context;
public:
    Sha256() {
        mbedtls_sha256_init(&context);
        if (mbedtls_sha256_starts(&context, 0) != 0) Fail("SHA-256 initialization failed");
    }
    ~Sha256() { mbedtls_sha256_free(&context); }
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;
    void Add(std::span<const unsigned char> value) {
        if (!value.empty() && mbedtls_sha256_update(&context, value.data(), value.size()) != 0) Fail("SHA-256 update failed");
    }
    Hash Finish() {
        Hash result{};
        if (mbedtls_sha256_finish(&context, result.data()) != 0) Fail("SHA-256 finalization failed");
        return result;
    }
};
std::span<const unsigned char> AsBytes(std::string_view s) {
    return {reinterpret_cast<const unsigned char*>(s.data()), s.size()};
}
Hash Digest(std::span<const unsigned char> value) { Sha256 h; h.Add(value); return h.Finish(); }
Sha256& Tag(Sha256& hash, std::string_view tag) {
    const auto prefix = Digest(AsBytes(tag));
    hash.Add(prefix); hash.Add(prefix); return hash;
}
void MutexInit(mbedtls_threading_mutex_t* mutex) {
    if (mutex) mutex->mutex = new (std::nothrow) std::mutex;
}
void MutexFree(mbedtls_threading_mutex_t* mutex) {
    if (mutex) { delete static_cast<std::mutex*>(mutex->mutex); mutex->mutex = nullptr; }
}
int MutexLock(mbedtls_threading_mutex_t* mutex) {
    if (!mutex || !mutex->mutex) return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    try { static_cast<std::mutex*>(mutex->mutex)->lock(); return 0; }
    catch (...) { return MBEDTLS_ERR_THREADING_MUTEX_ERROR; }
}
int MutexUnlock(mbedtls_threading_mutex_t* mutex) {
    if (!mutex || !mutex->mutex) return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    try { static_cast<std::mutex*>(mutex->mutex)->unlock(); return 0; }
    catch (...) { return MBEDTLS_ERR_THREADING_MUTEX_ERROR; }
}
class CertificateChain {
public:
    mbedtls_x509_crt value;
    CertificateChain() { mbedtls_x509_crt_init(&value); }
    ~CertificateChain() { mbedtls_x509_crt_free(&value); }
    CertificateChain(const CertificateChain&) = delete;
    CertificateChain& operator=(const CertificateChain&) = delete;
};
bool CheckPublicKeys(const mbedtls_x509_crt& chain, std::string& error)
{
    // Check ALL supplied certificates, including unused path candidates, before
    // Mbed TLS can perform any expensive signature verification. The pinned
    // adapter represents both rsaEncryption and restricted RSA-PSS keys as RSA;
    // pk_can_do(RSA) would incorrectly skip restricted RSA-PSS public keys.
    for (const mbedtls_x509_crt* certificate{&chain}; certificate != nullptr; certificate = certificate->next) {
        if (mbedtls_pk_get_type(&certificate->pk) != MBEDTLS_PK_RSA) continue;
        const mbedtls_rsa_context* rsa{mbedtls_pk_rsa(certificate->pk)};
        if (!rsa) return SetError(error, "P2C certificate RSA public key is unavailable");
        mbedtls_mpi exponent;
        mbedtls_mpi_init(&exponent);
        const int result{mbedtls_rsa_export(rsa, nullptr, nullptr, nullptr, nullptr, &exponent)};
        const size_t bits{mbedtls_mpi_bitlen(&exponent)};
        mbedtls_mpi_free(&exponent);
        if (result != 0) return SetError(error, "failed to read P2C certificate RSA public exponent");
        if (bits > 64) {
            return SetError(error, "P2C certificate RSA public exponent exceeds 64 bits");
        }
    }
    return true;
}

bool IsLeapYear(int year)
{
    return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

int DaysInMonth(int year, int month)
{
    constexpr std::array<int, 12> DAYS{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month < 1 || month > 12) return 0;
    return DAYS[month - 1] + (month == 2 && IsLeapYear(year) ? 1 : 0);
}

/** Days since 1970-01-01, valid for the Gregorian calendar. */
constexpr int64_t DaysFromCivil(int year, int month, int day)
{
    const int64_t adjusted_year{static_cast<int64_t>(year) - (month <= 2 ? 1 : 0)};
    const int64_t era{(adjusted_year >= 0 ? adjusted_year : adjusted_year - 399) / 400};
    const int64_t year_of_era{adjusted_year - era * 400};
    const int64_t adjusted_month{month > 2 ? month - 3 : month + 9};
    const int64_t day_of_year{(153 * adjusted_month + 2) / 5 + day - 1};
    const int64_t day_of_era{year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year};
    return era * 146097 + day_of_era - 719468;
}

static_assert(DaysFromCivil(1970, 1, 1) == 0);
static_assert(DaysFromCivil(2000, 3, 1) - DaysFromCivil(2000, 2, 28) == 2);
static_assert(DaysFromCivil(2100, 3, 1) - DaysFromCivil(2100, 2, 28) == 1);

bool X509TimeToUnix(const mbedtls_x509_time& time, int64_t& result)
{
    if (time.year < 1970 || time.mon < 1 || time.mon > 12 || time.day < 1 ||
        time.day > DaysInMonth(time.year, time.mon) || time.hour < 0 || time.hour > 23 ||
        time.min < 0 || time.min > 59 || time.sec < 0 || time.sec > 59) return false;
    const int64_t days{DaysFromCivil(time.year, time.mon, time.day)};
    if (days > (std::numeric_limits<int64_t>::max() - 86399) / 86400) return false;
    result = days * 86400 + int64_t{time.hour} * 3600 + int64_t{time.min} * 60 + time.sec;
    return true;
}

bool CheckSuppliedCertificateTimes(const mbedtls_x509_crt& chain, int64_t validation_time, std::string& error)
{
    if (validation_time <= 0) return SetError(error, "P2C certificate validation time is unavailable");
    for (const mbedtls_x509_crt* certificate{&chain}; certificate != nullptr; certificate = certificate->next) {
        int64_t valid_from{0};
        int64_t valid_to{0};
        if (!X509TimeToUnix(certificate->valid_from, valid_from) ||
            !X509TimeToUnix(certificate->valid_to, valid_to) ||
            validation_time < valid_from || validation_time > valid_to) {
            return SetError(error, "P2C certificate is not valid at block median time");
        }
    }
    return true;
}

bool CheckLeafUsage(const mbedtls_x509_crt& leaf, std::string& error)
{
    if (mbedtls_x509_crt_check_key_usage(&leaf, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) != 0 ||
        mbedtls_x509_crt_check_extended_key_usage(
            &leaf, MBEDTLS_OID_SERVER_AUTH, MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH)) != 0) {
        return SetError(error, "P2C leaf certificate is not authorized for TLS server signatures");
    }
    return true;
}


const mbedtls_x509_crt& Roots() {
    struct RootStore {
        CertificateChain chain;
        RootStore() {
            std::string error;
            if (mbedtls_x509_crt_parse(&chain.value,
                    reinterpret_cast<const unsigned char*>(CLAIMER_ROOTS_V1), sizeof(CLAIMER_ROOTS_V1)) != 0 ||
                    !CheckPublicKeys(chain.value, error)) Fail("Immutable root store initialization failed");
        }
    };
    // Parsed RSA/EC public keys have mutable precomputation caches. Each worker
    // owns its copies, so path verification needs no process-wide root mutex.
    thread_local RootStore roots;
    return roots.chain.value;
}
std::vector<std::span<const unsigned char>> CertificateViews(std::span<const unsigned char> message) {
    ByteReader reader(message);
    std::span<const unsigned char> full, body;
    std::string error;
    ParsedProof parsed;
    if (!ReadHandshake(reader, TLS_HANDSHAKE_CERTIFICATE, MAX_P2C_CERTIFICATE_MESSAGE_SIZE, full, body, error) ||
        !reader.Empty() || !ParseCertificate(body, parsed, error)) Fail(error.empty() ? "Trailing certificate data" : error);
    return parsed.certificate_chain;
}
CertificateChain& CachedChain(std::span<const unsigned char> message) {
    struct Cache { Bytes message; std::unique_ptr<CertificateChain> parsed; };
    // A bounded DER-parsing cache, not a validity cache. Times, path, usage,
    // hostname, signature algorithm and CertificateVerify are rechecked below.
    thread_local Cache cache;
    if (!cache.parsed || !std::ranges::equal(cache.message, message)) {
        const auto views = CertificateViews(message);
        auto candidate = std::make_unique<CertificateChain>();
        for (auto der : views) {
            if (mbedtls_x509_crt_parse_der(&candidate->value, der.data(), der.size()) != 0) Fail("Invalid DER certificate");
        }
        std::string error;
        if (!CheckPublicKeys(candidate->value, error)) Fail(error);
        cache.message.assign(message.begin(), message.end());
        cache.parsed = std::move(candidate);
    }
    return *cache.parsed;
}
bool SchemeAllowed(uint8_t mask, uint16_t scheme) {
    return (scheme == 0x0403 && (mask & 1)) || (scheme == 0x0804 && (mask & 2)) || (scheme == 0x0809 && (mask & 4));
}
void VerifySignature(const mbedtls_x509_crt& leaf, const ParsedProof& proof) {
    std::array<unsigned char, 64> prefix;
    prefix.fill(0x20);
    Sha256 hash;
    hash.Add(prefix);
    hash.Add(AsBytes("TLS 1.3, server CertificateVerify"));
    const std::array<unsigned char, 1> zero{0};
    hash.Add(zero);
    hash.Add(proof.transcript_hash);
    const Hash signed_hash = hash.Finish();
    int result = -1;
    if (proof.certificate_verify_scheme == 0x0403) {
        const auto key_type = mbedtls_pk_get_type(&leaf.pk);
        if (key_type != MBEDTLS_PK_ECKEY && key_type != MBEDTLS_PK_ECDSA) Fail("CertificateVerify requires an EC key");
        auto* ec = mbedtls_pk_ec(leaf.pk);
        if (!ec || mbedtls_ecp_keypair_get_group_id(ec) != MBEDTLS_ECP_DP_SECP256R1) Fail("CertificateVerify requires P-256");
        result = mbedtls_pk_verify_ext(MBEDTLS_PK_ECDSA, nullptr,
            const_cast<mbedtls_pk_context*>(&leaf.pk), MBEDTLS_MD_SHA256,
            signed_hash.data(), signed_hash.size(),
            proof.certificate_verify_signature.data(), proof.certificate_verify_signature.size());
    } else {
        if (!connectcoin_mbedtls_rsa_tls_scheme_matches(&leaf.pk, proof.certificate_verify_scheme) ||
            mbedtls_pk_get_bitlen(&leaf.pk) < 2048) Fail("CertificateVerify RSA key/scheme mismatch");
        const mbedtls_pk_rsassa_pss_options options{MBEDTLS_MD_SHA256, 32};
        result = mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS, &options,
            const_cast<mbedtls_pk_context*>(&leaf.pk), MBEDTLS_MD_SHA256,
            signed_hash.data(), signed_hash.size(),
            proof.certificate_verify_signature.data(), proof.certificate_verify_signature.size());
    }
    if (result != 0) Fail("Invalid TLS CertificateVerify signature");
}
} // namespace
void InitializeCrypto() {
    static std::once_flag initialized;
    std::call_once(initialized, [] {
        mbedtls_threading_set_alt(MutexInit, MutexFree, MutexLock, MutexUnlock);
        if (psa_crypto_init() != PSA_SUCCESS) Fail("PSA initialization failed");
    });
    // Also make --self-test reject an unusable embedded trust bundle. The
    // parse occurs once per worker; no connection can race a shared key cache.
    (void)Roots();
}
void RandomBytes(std::span<unsigned char> output) {
    while (!output.empty()) {
#ifdef _WIN32
        const auto size = static_cast<ULONG>(std::min<size_t>(output.size(), std::numeric_limits<ULONG>::max()));
        if (BCryptGenRandom(nullptr, output.data(), size, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) Fail("OS random source failed");
        output = output.subspan(size);
#elif defined(__linux__)
        const auto result = getrandom(output.data(), output.size(), 0);
        if (result < 0) { if (errno == EINTR) continue; Fail("OS random source failed"); }
        if (result == 0) Fail("OS random source returned no bytes");
        output = output.subspan(static_cast<size_t>(result));
#else
        const size_t size = std::min<size_t>(256, output.size());
        if (getentropy(output.data(), size) != 0) { if (errno == EINTR) continue; Fail("OS random source failed"); }
        output = output.subspan(size);
#endif
    }
}
std::string Hex(std::span<const unsigned char> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result(bytes.size() * 2, '0');
    for (size_t i = 0; i < bytes.size(); ++i) {
        result[2*i] = digits[bytes[i] >> 4]; result[2*i+1] = digits[bytes[i] & 15];
    }
    return result;
}
Bytes Unhex(std::string_view text) {
    if (text.size() % 2 != 0) Fail("Hex value has odd length");
    auto nibble = [](char c) -> unsigned char {
        if (c >= '0' && c <= '9') return static_cast<unsigned char>(c-'0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(c-'a'+10);
        Fail("Hex value must use canonical lowercase digits");
    };
    Bytes value(text.size()/2);
    for (size_t i = 0; i < value.size(); ++i) value[i] = static_cast<unsigned char>((nibble(text[2*i]) << 4) | nibble(text[2*i+1]));
    return value;
}
bool IsCanonicalDomain(std::string_view domain) {
    if (domain.empty() || domain.size() > 253 || domain.back() == '.') return false;
    size_t start = 0;
    while (start < domain.size()) {
        size_t end = domain.find('.', start);
        if (end == std::string_view::npos) end = domain.size();
        if (end == start || end-start > 63 || domain[start] == '-' || domain[end-1] == '-') return false;
        for (size_t i = start; i < end; ++i) {
            const char c = domain[i];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
        }
        start = end+1;
    }
    return true;
}
void ValidateContext(const Context& context) {
    if (!IsCanonicalDomain(context.domain) || context.domain.find('.') == std::string::npos ||
        context.domain.ends_with(".localhost") || context.domain.ends_with(".local") || context.domain.ends_with(".internal"))
        Fail("Context requires a canonical public DNS name");
    if (context.txid.size() != 64 || context.connection_work_target.size() != 64) Fail("Context hash must have 64 hex digits");
    (void)Unhex(context.txid); (void)Unhex(context.connection_work_target);
    if (context.root_certificates_version != 1) Fail("Unsupported root certificate version");
    if (context.signature_algorithms_mask == 0 || context.signature_algorithms_mask > 7) Fail("Invalid signature mask");
    if (context.validation_time <= 0 || context.validation_time > 253402300799LL) Fail("Invalid certificate validation time");
}
Hash ClaimChallenge(const Context& context) {
    ValidateContext(context);
    auto txid = Unhex(context.txid);
    std::reverse(txid.begin(), txid.end());
    std::array<unsigned char, 4> index{};
    for (unsigned i = 0; i < 4; ++i) index[i] = static_cast<unsigned char>(context.input_index >> (8*i));
    Sha256 hash;
    Tag(hash, "ConnectCoin/P2C/claim/v1").Add(txid);
    hash.Add(index);
    return hash.Finish();
}
ParsedProof ParseProof(std::span<const unsigned char> encoded, const Context& context) {
    ValidateContext(context);
    if (encoded.empty() || encoded.size() > MAX_P2C_PROOF_SIZE) Fail("Invalid P2C proof size");
    ByteReader proof(encoded);
    uint8_t version{};
    if (!proof.ReadU8(version) || version != 2) Fail("Unsupported P2C proof version");
    ParsedProof parsed;
    std::span<const unsigned char> ch, sh, ee, cert, cv;
    std::string error;
    if (!ReadHandshake(proof, 1, MAX_CLIENT_HELLO_SIZE, parsed.client_hello, ch, error) ||
        !ReadHandshake(proof, 2, MAX_SERVER_HELLO_SIZE, parsed.server_hello, sh, error) ||
        !ReadHandshake(proof, 8, MAX_ENCRYPTED_EXTENSIONS_SIZE, parsed.encrypted_extensions, ee, error) ||
        !ReadHandshake(proof, 11, MAX_P2C_CERTIFICATE_MESSAGE_SIZE, parsed.certificate, cert, error) ||
        !ReadHandshake(proof, 15, MAX_CERTIFICATE_VERIFY_SIZE, parsed.certificate_verify, cv, error)) Fail(error);
    if (!proof.Empty()) Fail("Trailing bytes after CertificateVerify");
    ClientHelloState client;
    if (!ParseClientHello(ch, context.domain, ClaimChallenge(context), client, error) ||
        !ParseServerHello(sh, client, error) || !ParseEncryptedExtensions(ee, error) ||
        !ParseCertificate(cert, parsed, error) || !ParseCertificateVerify(cv, client, parsed, error)) Fail(error);
    Sha256 transcript, work;
    Tag(work, "ConnectCoin/P2C/work/v2");
    for (auto message : {parsed.client_hello, parsed.server_hello, parsed.encrypted_extensions, parsed.certificate}) {
        transcript.Add(message); work.Add(message);
    }
    parsed.transcript_hash = transcript.Finish();
    parsed.connection_work_hash = work.Finish();
    return parsed;
}
void ValidateCertificateMessage(std::span<const unsigned char> message) {
    InitializeCrypto();
    (void)CachedChain(message);
}
namespace {
Verification VerifyWithRoots(std::span<const unsigned char> encoded, const Context& context, const mbedtls_x509_crt& roots) {
    InitializeCrypto();
    const auto parsed = ParseProof(encoded, context);
    auto& chain = CachedChain(parsed.certificate).value;
    std::string error;
    if (!CheckPublicKeys(chain, error) || !CheckSuppliedCertificateTimes(chain, context.validation_time, error) ||
        !CheckLeafUsage(chain, error)) Fail(error);
    if (!SchemeAllowed(context.signature_algorithms_mask, parsed.certificate_verify_scheme)) Fail("Signature scheme is not allowed by bounty");
    uint32_t flags{};
    if (connectcoin_mbedtls_x509_crt_verify_root_first(&chain, const_cast<mbedtls_x509_crt*>(&roots),
            &mbedtls_x509_crt_profile_default, context.domain.c_str(), &flags, nullptr, nullptr) != 0 || flags != 0)
        Fail("Certificate path or DNS name validation failed");
    VerifySignature(chain, parsed);
    auto hash = parsed.connection_work_hash;
    std::reverse(hash.begin(), hash.end());
    const auto target = Unhex(context.connection_work_target);
    const bool meets = !std::lexicographical_compare(target.begin(), target.end(), hash.begin(), hash.end());
    return {Hex(hash), meets, parsed.certificate_verify_scheme};
}
} // namespace
Verification VerifyProof(std::span<const unsigned char> encoded, const Context& context) {
    InitializeCrypto();
    return VerifyWithRoots(encoded, context, Roots());
}
#ifdef CLAIMER_CRYPTO_TESTING
Verification VerifyProofForTesting(std::span<const unsigned char> encoded, const Context& context, std::span<const unsigned char> roots_pem) {
    InitializeCrypto();
    CertificateChain roots;
    Bytes pem(roots_pem.begin(), roots_pem.end());
    pem.push_back(0);
    std::string error;
    if (mbedtls_x509_crt_parse(&roots.value, pem.data(), pem.size()) != 0 || !CheckPublicKeys(roots.value, error)) Fail("Invalid test roots");
    return VerifyWithRoots(encoded, context, roots.value);
}
#endif
} // namespace claimer
