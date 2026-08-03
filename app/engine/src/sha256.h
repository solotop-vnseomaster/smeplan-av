// Cai dat SHA-256 (FIPS 180-4) doc lap, khong phu thuoc thu vien ngoai —
// dung cho ca hash file (Engine_Sha256File) lan tra CSDL signature.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string>

class Sha256 {
public:
    Sha256();
    void Update(const uint8_t* data, size_t len);
    void Final(uint8_t out_digest[32]);

    static std::string ToHex(const uint8_t digest[32]);
    static bool FileSha256(const wchar_t* path, uint8_t out_digest[32]);

private:
    void Transform(const uint8_t block[64]);

    uint32_t state_[8];
    uint64_t bit_len_;
    uint8_t buffer_[64];
    size_t buffer_len_;
};
