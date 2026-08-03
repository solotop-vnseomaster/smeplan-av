// Bloom filter RAM cho tra cuu hash nhanh, xem modules/02-kien-truc.md muc 2:
// "Bloom filter (RAM) ... loc phan lon truy van truoc khi cham dia".
#pragma once
#include <stdint.h>
#include <vector>
#include <string>

class BloomFilter {
public:
    // expected_items: so luong sha256 se duoc them; target_fp_rate: vi du 0.001 (0.1%).
    BloomFilter(size_t expected_items, double target_fp_rate);

    void Add(const uint8_t sha256[32]);
    bool MightContain(const uint8_t sha256[32]) const;

    size_t BitCount() const { return bits_.size(); }
    size_t HashCount() const { return k_; }

    // Serialize/deserialize don gian de nhung vao file CSDL.
    void SaveTo(std::vector<uint8_t>& out) const;
    static BloomFilter LoadFrom(const uint8_t* data, size_t len);

private:
    BloomFilter() = default;
    std::vector<uint8_t> bits_; // 1 bit/phan tu, dong goi 8 bit/byte
    size_t k_ = 0;

    void SetBit(uint64_t idx);
    bool GetBit(uint64_t idx) const;
    uint64_t SliceToIndex(const uint8_t sha256[32], size_t slice) const;
};
