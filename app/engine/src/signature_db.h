// CSDL signature tren dia: header + Bloom filter (nap toan bo vao RAM) +
// mang SignatureRecord do dai co dinh, sap xep tang dan theo sha256, tra
// cuu bang binary search truc tiep tren vung nho da memory-map.
// Khop data-models/04-du-lieu.md muc SignatureRecord va modules/02-kien-truc.md muc 2.
#pragma once
#include <stdint.h>
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>
#include <optional>
#include "bloom_filter.h"

#pragma pack(push, 1)
struct SignatureRecord {
    uint8_t sha256[32];
    uint32_t threat_id;
    uint8_t severity;   // 0-255
    uint32_t reserved;
};
#pragma pack(pop)
static_assert(sizeof(SignatureRecord) == 41, "SignatureRecord phai dung 41 byte (packed)");

class SignatureDb {
public:
    SignatureDb() = default;
    ~SignatureDb();

    SignatureDb(const SignatureDb&) = delete;
    SignatureDb& operator=(const SignatureDb&) = delete;

    bool Load(const wchar_t* path);
    void Close();

    std::optional<SignatureRecord> Lookup(const uint8_t sha256[32]) const;

    size_t RecordCount() const { return record_count_; }

    // Xay CSDL tu file CSV "sha256_hex,threat_id,severity" (moi dong 1 ban ghi).
    static bool BuildFromCsv(const wchar_t* csv_path, const wchar_t* out_db_path,
                              double bloom_fp_rate);

private:
    HANDLE file_handle_ = INVALID_HANDLE_VALUE;
    HANDLE mapping_handle_ = nullptr;
    const uint8_t* view_ = nullptr;
    size_t view_size_ = 0;

    const SignatureRecord* records_ = nullptr;
    size_t record_count_ = 0;
    std::optional<BloomFilter> bloom_;
};
