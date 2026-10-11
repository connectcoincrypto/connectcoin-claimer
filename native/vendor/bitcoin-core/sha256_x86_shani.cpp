// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Based on https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-x86.c,
// Written and placed in public domain by Jeffrey Walton.
// Based on code from Intel, and by Sean Gulley for the miTLS project.

#if defined(ENABLE_SSE41) && defined(ENABLE_X86_SHANI)

#include <cstddef>
#include <cstdint>
#include <immintrin.h>

#include <mbedtls/platform_util.h>
#if defined(_MSC_VER)
#define ALWAYS_INLINE __forceinline
#else
#define ALWAYS_INLINE inline __attribute__((always_inline))
#endif

namespace {

alignas(__m128i) const uint8_t MASK[16] = {0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, 0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c};

void ALWAYS_INLINE QuadRound(__m128i& state0, __m128i& state1, uint64_t k1, uint64_t k0)
{
    const __m128i msg = _mm_set_epi64x(k1, k0);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(msg, 0x0e));
}

void ALWAYS_INLINE QuadRound(__m128i& state0, __m128i& state1, __m128i m, uint64_t k1, uint64_t k0)
{
    const __m128i msg = _mm_add_epi32(m, _mm_set_epi64x(k1, k0));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(msg, 0x0e));
}

void ALWAYS_INLINE ShiftMessageA(__m128i& m0, __m128i m1)
{
    m0 = _mm_sha256msg1_epu32(m0, m1);
}

void ALWAYS_INLINE ShiftMessageC(__m128i& m0, __m128i m1, __m128i& m2)
{
    m2 = _mm_sha256msg2_epu32(_mm_add_epi32(m2, _mm_alignr_epi8(m1, m0, 4)), m1);
}

void ALWAYS_INLINE ShiftMessageB(__m128i& m0, __m128i m1, __m128i& m2)
{
    ShiftMessageC(m0, m1, m2);
    ShiftMessageA(m0, m1);
}

void ALWAYS_INLINE Shuffle(__m128i& s0, __m128i& s1)
{
    const __m128i t1 = _mm_shuffle_epi32(s0, 0xB1);
    const __m128i t2 = _mm_shuffle_epi32(s1, 0x1B);
    s0 = _mm_alignr_epi8(t1, t2, 0x08);
    s1 = _mm_blend_epi16(t2, t1, 0xF0);
}

void ALWAYS_INLINE Unshuffle(__m128i& s0, __m128i& s1)
{
    const __m128i t1 = _mm_shuffle_epi32(s0, 0x1B);
    const __m128i t2 = _mm_shuffle_epi32(s1, 0xB1);
    s0 = _mm_blend_epi16(t1, t2, 0xF0);
    s1 = _mm_alignr_epi8(t2, t1, 0x08);
}

__m128i ALWAYS_INLINE Load(const unsigned char* in)
{
    return _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)in), _mm_load_si128((const __m128i*)MASK));
}

void ALWAYS_INLINE Save(unsigned char* out, __m128i s)
{
    _mm_storeu_si128((__m128i*)out, _mm_shuffle_epi8(s, _mm_load_si128((const __m128i*)MASK)));
}
}

namespace sha256_x86_shani {
void Transform(uint32_t* s, const unsigned char* chunk, size_t blocks)
{
    // Adaptation: retain no addressable schedule/state temporaries after use.
    struct Scratch { __m128i m0, m1, m2, m3, s0, s1, so0, so1; } scratch{};
    auto& [m0, m1, m2, m3, s0, s1, so0, so1] = scratch;

    /* Load state */
    s0 = _mm_loadu_si128((const __m128i*)s);
    s1 = _mm_loadu_si128((const __m128i*)(s + 4));
    Shuffle(s0, s1);

    while (blocks--) {
        /* Remember old state */
        so0 = s0;
        so1 = s1;

        /* Load data and transform */
        m0 = Load(chunk);
        QuadRound(s0, s1, m0, 0xe9b5dba5b5c0fbcfull, 0x71374491428a2f98ull);
        m1 = Load(chunk + 16);
        QuadRound(s0, s1, m1, 0xab1c5ed5923f82a4ull, 0x59f111f13956c25bull);
        ShiftMessageA(m0, m1);
        m2 = Load(chunk + 32);
        QuadRound(s0, s1, m2, 0x550c7dc3243185beull, 0x12835b01d807aa98ull);
        ShiftMessageA(m1, m2);
        m3 = Load(chunk + 48);
        QuadRound(s0, s1, m3, 0xc19bf1749bdc06a7ull, 0x80deb1fe72be5d74ull);
        ShiftMessageB(m2, m3, m0);
        QuadRound(s0, s1, m0, 0x240ca1cc0fc19dc6ull, 0xefbe4786E49b69c1ull);
        ShiftMessageB(m3, m0, m1);
        QuadRound(s0, s1, m1, 0x76f988da5cb0a9dcull, 0x4a7484aa2de92c6full);
        ShiftMessageB(m0, m1, m2);
        QuadRound(s0, s1, m2, 0xbf597fc7b00327c8ull, 0xa831c66d983e5152ull);
        ShiftMessageB(m1, m2, m3);
        QuadRound(s0, s1, m3, 0x1429296706ca6351ull, 0xd5a79147c6e00bf3ull);
        ShiftMessageB(m2, m3, m0);
        QuadRound(s0, s1, m0, 0x53380d134d2c6dfcull, 0x2e1b213827b70a85ull);
        ShiftMessageB(m3, m0, m1);
        QuadRound(s0, s1, m1, 0x92722c8581c2c92eull, 0x766a0abb650a7354ull);
        ShiftMessageB(m0, m1, m2);
        QuadRound(s0, s1, m2, 0xc76c51A3c24b8b70ull, 0xa81a664ba2bfe8a1ull);
        ShiftMessageB(m1, m2, m3);
        QuadRound(s0, s1, m3, 0x106aa070f40e3585ull, 0xd6990624d192e819ull);
        ShiftMessageB(m2, m3, m0);
        QuadRound(s0, s1, m0, 0x34b0bcb52748774cull, 0x1e376c0819a4c116ull);
        ShiftMessageB(m3, m0, m1);
        QuadRound(s0, s1, m1, 0x682e6ff35b9cca4full, 0x4ed8aa4a391c0cb3ull);
        ShiftMessageC(m0, m1, m2);
        QuadRound(s0, s1, m2, 0x8cc7020884c87814ull, 0x78a5636f748f82eeull);
        ShiftMessageC(m1, m2, m3);
        QuadRound(s0, s1, m3, 0xc67178f2bef9A3f7ull, 0xa4506ceb90befffaull);

        /* Combine with old state */
        s0 = _mm_add_epi32(s0, so0);
        s1 = _mm_add_epi32(s1, so1);

        /* Advance */
        chunk += 64;
    }

    Unshuffle(s0, s1);
    _mm_storeu_si128((__m128i*)s, s0);
    _mm_storeu_si128((__m128i*)(s + 4), s1);
    mbedtls_platform_zeroize(&scratch, sizeof(scratch));
}
}

extern "C" void connectcoin_sha256_shani(uint32_t* state, const unsigned char* input)
{
    sha256_x86_shani::Transform(state, input, 1);
}
#endif
