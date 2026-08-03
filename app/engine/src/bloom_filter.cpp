#include "bloom_filter.h"
#include <cmath>
#include <cstring>
#include <algorithm>

BloomFilter::BloomFilter(size_t expected_items, double target_fp_rate) {
    if (expected_items < 1) expected_items = 1;
    if (target_fp_rate <= 0.0 || target_fp_rate >= 1.0) target_fp_rate = 0.001;

    double m = -(static_cast<double>(expected_items) * std::log(target_fp_rate)) /
               (std::log(2.0) * std::log(2.0));
    double k = (m / static_cast<double>(expected_items)) * std::log(2.0);

    size_t bit_count = static_cast<size_t>(std::ceil(m));
    if (bit_count < 64) bit_count = 64;
    k_ = std::max<size_t>(1, std::min<size_t>(8, static_cast<size_t>(std::round(k))));

    bits_.assign((bit_count + 7) / 8, 0);
}

uint64_t BloomFilter::SliceToIndex(const uint8_t sha256[32], size_t slice) const {
    // sha256 co 32 byte -> tach thanh toi da 8 slice 4-byte doc lap de lam
    // k ham hash gia lap (double hashing tren chinh digest, khong can ham
    // hash rieng vi input da la mot ma bam mat ma hoc chat luong cao).
    size_t offset = (slice % 8) * 4;
    uint32_t v = (uint32_t(sha256[offset]) << 24) | (uint32_t(sha256[offset + 1]) << 16) |
                 (uint32_t(sha256[offset + 2]) << 8) | uint32_t(sha256[offset + 3]);
    uint64_t total_bits = bits_.size() * 8ULL;
    return v % total_bits;
}

void BloomFilter::SetBit(uint64_t idx) { bits_[idx / 8] |= static_cast<uint8_t>(1u << (idx % 8)); }
bool BloomFilter::GetBit(uint64_t idx) const { return (bits_[idx / 8] & (1u << (idx % 8))) != 0; }

void BloomFilter::Add(const uint8_t sha256[32]) {
    for (size_t i = 0; i < k_; i++) SetBit(SliceToIndex(sha256, i));
}

bool BloomFilter::MightContain(const uint8_t sha256[32]) const {
    for (size_t i = 0; i < k_; i++) {
        if (!GetBit(SliceToIndex(sha256, i))) return false; // chac chan khong co
    }
    return true; // co the co (hoac false positive)
}

void BloomFilter::SaveTo(std::vector<uint8_t>& out) const {
    uint64_t bit_count = bits_.size() * 8ULL;
    uint64_t k64 = k_;
    const uint8_t* p1 = reinterpret_cast<const uint8_t*>(&bit_count);
    const uint8_t* p2 = reinterpret_cast<const uint8_t*>(&k64);
    out.insert(out.end(), p1, p1 + 8);
    out.insert(out.end(), p2, p2 + 8);
    out.insert(out.end(), bits_.begin(), bits_.end());
}

BloomFilter BloomFilter::LoadFrom(const uint8_t* data, size_t len) {
    BloomFilter f;
    if (len < 16) return f;
    uint64_t bit_count = 0, k64 = 0;
    memcpy(&bit_count, data, 8);
    memcpy(&k64, data + 8, 8);
    f.k_ = static_cast<size_t>(k64);
    size_t byte_count = static_cast<size_t>((bit_count + 7) / 8);
    if (len < 16 + byte_count) return f;
    f.bits_.assign(data + 16, data + 16 + byte_count);
    return f;
}
