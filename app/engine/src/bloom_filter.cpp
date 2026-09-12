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
    // Phong thu: bits_ rong (total_bits == 0) chi co the xay ra tu mot blob
    // CSDL bi craft/hong nap qua LoadFrom (k_ != 0 nhung khong co bit nao) —
    // LoadFrom da duoc sua de khong con roi vao truong hop nay, nhung giu
    // guard o day de SliceToIndex khong bao gio chia cho 0 du duoc goi tu
    // duong nao trong tuong lai.
    if (total_bits == 0) return 0;
    return v % total_bits;
}

// [SUA LOI NGHIEM TRONG] Ca hai ham TRUOC DAY index thang vao bits_ ma
// khong kiem tra bien. Chung chi duoc goi voi chi so do SliceToIndex sinh
// ra (da mod theo total_bits) nen ve ly thuyet luon hop le — nhung "ve ly
// thuyet" o day dua vao mot bat bien duoc thiet lap o LoadFrom, tuc la dua
// vao du lieu tu MOT FILE TREN DIA co the bi thay the (dung threat model da
// nêu trong chinh file nay). Mot guard mot phep so sanh la cai gia re de
// khong bao gio doc/ghi ngoai bien heap du bat bien do bi pha.
void BloomFilter::SetBit(uint64_t idx) {
    size_t byte_index = static_cast<size_t>(idx / 8);
    if (byte_index >= bits_.size()) return;
    bits_[byte_index] |= static_cast<uint8_t>(1u << (idx % 8));
}
bool BloomFilter::GetBit(uint64_t idx) const {
    size_t byte_index = static_cast<size_t>(idx / 8);
    if (byte_index >= bits_.size()) return false; // fail-closed: coi nhu "khong co"
    return (bits_[byte_index] & (1u << (idx % 8))) != 0;
}

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
    // [SUA LOI NGHIEM TRONG] TRUOC DAY f.k_ duoc gan TRUOC khi validate
    // bit_count: neu blob bi craft/hong voi bit_count=0 nhung k64 != 0, ket
    // qua la bits_ rong nhung k_ != 0 — SliceToIndex sau do chia cho
    // total_bits=0 (bits_.size()*8) -> crash chia cho 0 tren mot CSDL
    // signature bi thay the/hong (dung threat model "CSDL tren dia co the
    // bi thay the"). Sua: chi gan k_ SAU KHI da xac nhan bit_count hop le
    // va du du lieu bits thuc su trong blob; neu khong, tra ve filter rong
    // an toan (k_=0, MightContain/Add khong lam gi, khong chia cho 0).
    // [SUA LOI NGHIEM TRONG] Ban truoc tinh `(bit_count + 7) / 8` trong khi
    // bit_count la uint64_t doc THANG tu file. Voi bit_count >= 2^64 - 7
    // (blob bi craft), phep cong TRAN SO va vong ve 0..6, chia 8 ra
    // byte_count = 0. Khi do: `bit_count == 0` la false (bit_count khong he
    // bang 0), `len < 16 + 0` cung false voi moi len >= 16 — ca hai guard
    // deu di qua sach se. Ket qua la bits_ RONG nhung k_ duoc gan 1..8, va
    // MightContain sau do goi GetBit(0) => bits_[0] tren mot vector rong:
    // doc ngoai bien heap (UB), khong phai chia cho 0 nhu ghi chu cu noi.
    // Sua: tinh so byte KHONG cong truoc khi chia (khong the tran), roi
    // rang buoc no vao kich thuoc blob THAT SU truoc khi ep ve size_t.
    uint64_t byte_count64 = bit_count / 8 + ((bit_count % 8) != 0 ? 1 : 0);
    if (bit_count == 0 || byte_count64 == 0) return f;
    // len >= 16 da duoc kiem o dau ham, nen (len - 16) khong am.
    if (byte_count64 > static_cast<uint64_t>(len - 16)) return f;
    size_t byte_count = static_cast<size_t>(byte_count64);
    // [SUA LOI] k64 doc thang tu file va TRUOC DAY duoc nhan bat ke gia tri.
    // SliceToIndex chi lay duoc toi da 8 lat 4 byte tu mot sha256 32 byte,
    // nen k > 8 la du lieu khong hop le (CSDL hong hoac bi sua tay) — va
    // k lon con lam MightContain quet vo ich hang ty vong. k = 0 nghia la
    // "khong loc gi", tuong duong khong co bloom. Ca hai truong hop deu tra
    // ve filter rong an toan thay vi tin vao gia tri tu file.
    if (k64 == 0 || k64 > 8) return f;
    f.k_ = static_cast<size_t>(k64);
    f.bits_.assign(data + 16, data + 16 + byte_count);
    return f;
}
