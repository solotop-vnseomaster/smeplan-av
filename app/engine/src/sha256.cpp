#include "sha256.h"
#include <cstring>
#include <cstdio>
#define NOMINMAX
#include <windows.h>
#include "win32_path_util.h"

namespace {
constexpr uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline uint32_t Rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
}

Sha256::Sha256() : bit_len_(0), buffer_len_(0) {
    state_[0] = 0x6a09e667; state_[1] = 0xbb67ae85; state_[2] = 0x3c6ef372; state_[3] = 0xa54ff53a;
    state_[4] = 0x510e527f; state_[5] = 0x9b05688c; state_[6] = 0x1f83d9ab; state_[7] = 0x5be0cd19;
}

void Sha256::Transform(const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t(block[i * 4]) << 24) | (uint32_t(block[i * 4 + 1]) << 16) |
               (uint32_t(block[i * 4 + 2]) << 8) | uint32_t(block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
}

void Sha256::Update(const uint8_t* data, size_t len) {
    bit_len_ += static_cast<uint64_t>(len) * 8;
    size_t offset = 0;
    if (buffer_len_ > 0) {
        size_t take = 64 - buffer_len_;
        if (take > len) take = len;
        memcpy(buffer_ + buffer_len_, data, take);
        buffer_len_ += take;
        offset += take;
        if (buffer_len_ == 64) {
            Transform(buffer_);
            buffer_len_ = 0;
        }
    }
    while (offset + 64 <= len) {
        Transform(data + offset);
        offset += 64;
    }
    if (offset < len) {
        memcpy(buffer_, data + offset, len - offset);
        buffer_len_ = len - offset;
    }
}

void Sha256::Final(uint8_t out_digest[32]) {
    uint8_t pad[72];
    size_t pad_len = 0;
    pad[pad_len++] = 0x80;
    size_t zeros = (buffer_len_ < 56) ? (56 - buffer_len_ - 1) : (120 - buffer_len_ - 1);
    for (size_t i = 0; i < zeros; i++) pad[pad_len++] = 0x00;
    for (int i = 7; i >= 0; i--) pad[pad_len++] = static_cast<uint8_t>((bit_len_ >> (i * 8)) & 0xff);
    Update(pad, pad_len);
    // Update() se doi bit_len_, nen ta phai dung buffer noi bo truoc do de finalize dung —
    // don gian hoa: goi truc tiep Transform tren cac block da xep san thay vi qua Update.
    // (Cach lam o tren van dung logic vi Update chi cong don bit_len_ cho phan pad, khong
    // anh huong ket qua Final vi ta doc state_ ngay sau khi cac block da duoc Transform.)
    for (int i = 0; i < 8; i++) {
        out_digest[i * 4] = static_cast<uint8_t>((state_[i] >> 24) & 0xff);
        out_digest[i * 4 + 1] = static_cast<uint8_t>((state_[i] >> 16) & 0xff);
        out_digest[i * 4 + 2] = static_cast<uint8_t>((state_[i] >> 8) & 0xff);
        out_digest[i * 4 + 3] = static_cast<uint8_t>(state_[i] & 0xff);
    }
}

std::string Sha256::ToHex(const uint8_t digest[32]) {
    static const char* hexch = "0123456789abcdef";
    std::string out;
    out.resize(64);
    for (int i = 0; i < 32; i++) {
        out[i * 2] = hexch[(digest[i] >> 4) & 0xf];
        out[i * 2 + 1] = hexch[digest[i] & 0xf];
    }
    return out;
}

bool Sha256::FileSha256(const wchar_t* path, uint8_t out_digest[32]) {
    // [SUA LOI] Them tien to long-path — xem win32_path_util.h.
    std::wstring long_path = ToLongPath(path);
    HANDLE h = CreateFileW(long_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    Sha256 hasher;
    uint8_t buf[65536];
    DWORD read = 0;
    BOOL ok = TRUE;
    while ((ok = ReadFile(h, buf, sizeof(buf), &read, nullptr)) && read > 0) {
        hasher.Update(buf, read);
    }
    CloseHandle(h);
    if (!ok) return false;
    hasher.Final(out_digest);
    return true;
}
