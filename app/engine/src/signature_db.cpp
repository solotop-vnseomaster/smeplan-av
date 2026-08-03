#include "signature_db.h"
#include "sha256.h"
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace {
constexpr char kMagic[8] = { 'A','V','S','I','G','D','B','1' };

uint8_t HexNibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return 0;
}

bool HexToBytes32(const std::string& hex, uint8_t out[32]) {
    if (hex.size() != 64) return false;
    for (int i = 0; i < 32; i++) {
        out[i] = static_cast<uint8_t>((HexNibble(hex[i * 2]) << 4) | HexNibble(hex[i * 2 + 1]));
    }
    return true;
}
}

SignatureDb::~SignatureDb() { Close(); }

void SignatureDb::Close() {
    if (view_) { UnmapViewOfFile(view_); view_ = nullptr; }
    if (mapping_handle_) { CloseHandle(mapping_handle_); mapping_handle_ = nullptr; }
    if (file_handle_ != INVALID_HANDLE_VALUE) { CloseHandle(file_handle_); file_handle_ = INVALID_HANDLE_VALUE; }
    records_ = nullptr;
    record_count_ = 0;
    bloom_.reset();
}

bool SignatureDb::Load(const wchar_t* path) {
    Close();
    // [SUA LOI NGHIEM TRONG] Thieu FILE_SHARE_DELETE khien moi lan update
    // service goi File.Move/MoveFileEx de hoan doi CSDL moi (API-02,
    // UpdateClientService.RebuildAndSwap) THAT BAI voi sharing violation
    // sau LAN DAU TIEN — vi handle nay van giu mo (khong dong cho toi khi
    // Close()/engine Shutdown) tren chinh file dang bi thay the. Windows
    // yeu cau file dich phai duoc mo VOI CO FILE_SHARE_DELETE moi cho phep
    // rename/replace trong khi con handle khac dang mo. Them co nay de
    // MoveFileEx (voi MOVEFILE_REPLACE_EXISTING) hoat dong dung nhu
    // security/09-bao-mat.md muc 3 mo ta ("ghi vao file tam roi doi ten
    // hoan doi nguyen tu").
    file_handle_ = CreateFileW(path, GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_handle_ == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file_handle_, &size) || size.QuadPart < 24) { Close(); return false; }

    mapping_handle_ = CreateFileMappingW(file_handle_, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mapping_handle_) { Close(); return false; }

    view_ = static_cast<const uint8_t*>(MapViewOfFile(mapping_handle_, FILE_MAP_READ, 0, 0, 0));
    if (!view_) { Close(); return false; }
    view_size_ = static_cast<size_t>(size.QuadPart);

    if (memcmp(view_, kMagic, 8) != 0) { Close(); return false; }
    uint64_t record_count = 0, bloom_size = 0;
    memcpy(&record_count, view_ + 8, 8);
    memcpy(&bloom_size, view_ + 16, 8);

    // [SUA LOI] record_count/bloom_size doc truc tiep tu 16 byte dau file
    // (khong duoc validate truoc do), dung de NHAN voi sizeof(SignatureRecord)
    // hoac CONG vao header_size. Voi gia tri du lon (file CSDL bi hong hoac
    // bi sua tay), phep nhan/cong co the TRAN SO (wrap) ve mot gia tri nho,
    // khien kiem tra bien "view_size_ < expected_size" sai lech va bi bo
    // qua — sau do record_count_ duoc gan bang gia tri khong lo, va
    // Lookup() (binary search) doc records_[mid] vuot xa vung da
    // MapViewOfFile -> access violation. Sua: so sanh bang PHEP CHIA (khong
    // the tran so) THAY VI nhan truoc khi kiem tra, va kiem tra bloom_size
    // truoc khi cong.
    size_t header_size = 24;
    if (bloom_size > view_size_ || view_size_ - header_size < bloom_size) { Close(); return false; }
    bloom_ = BloomFilter::LoadFrom(view_ + header_size, static_cast<size_t>(bloom_size));

    size_t records_offset = header_size + static_cast<size_t>(bloom_size);
    size_t available_for_records = view_size_ - records_offset;
    size_t max_records_that_fit = available_for_records / sizeof(SignatureRecord);
    if (record_count > static_cast<uint64_t>(max_records_that_fit)) { Close(); return false; }

    size_t expected_size = records_offset + static_cast<size_t>(record_count) * sizeof(SignatureRecord);
    if (view_size_ < expected_size) { Close(); return false; }

    records_ = reinterpret_cast<const SignatureRecord*>(view_ + records_offset);
    record_count_ = static_cast<size_t>(record_count);
    return true;
}

std::optional<SignatureRecord> SignatureDb::Lookup(const uint8_t sha256[32]) const {
    if (!records_ || record_count_ == 0) return std::nullopt;
    if (bloom_.has_value() && !bloom_->MightContain(sha256)) return std::nullopt; // chac chan khong co

    size_t lo = 0, hi = record_count_;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = memcmp(records_[mid].sha256, sha256, 32);
        if (cmp == 0) return records_[mid];
        if (cmp < 0) lo = mid + 1; else hi = mid;
    }
    return std::nullopt;
}

bool SignatureDb::BuildFromCsv(const wchar_t* csv_path, const wchar_t* out_db_path,
                                double bloom_fp_rate) {
    std::ifstream in(csv_path, std::ios::binary);
    if (!in.is_open()) return false;

    std::vector<SignatureRecord> records;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::stringstream ss(line);
        std::string hash_hex, threat_id_s, severity_s;
        if (!std::getline(ss, hash_hex, ',')) continue;
        if (!std::getline(ss, threat_id_s, ',')) continue;
        if (!std::getline(ss, severity_s, ',')) continue;

        SignatureRecord rec{};
        if (!HexToBytes32(hash_hex, rec.sha256)) continue;

        // [SUA LOI NGHIEM TRONG] std::stoul NEM std::invalid_argument (chuoi
        // khong phai so) hoac std::out_of_range (so vuot pham vi unsigned
        // long) - truoc day khong duoc bat, nen mot dong CSV loi (vi du CSDL
        // update bi hong/bi can thiep, hoac chi mot truong trong bi ghi sai
        // dinh dang) se nem exception xuyen qua BuildFromCsv -> extern "C"
        // Engine_BuildSignatureDb() -> qua bien P/Invoke sang service C# ->
        // hanh vi khong xac dinh (P/Invoke boundary khong duoc thiet ke de
        // truyen C++ exception) va lam CRASH tien trinh service dang cap
        // nhat CSDL. Sua: bat loi parse, BO QUA dong hong nay (khong throw
        // ra ngoai) va tiep tuc voi cac dong con lai, giu dung tinh chat
        // "graceful" da ap dung cho cac loi I/O khac trong file nay.
        try {
            rec.threat_id = static_cast<uint32_t>(std::stoul(threat_id_s));
            rec.severity = static_cast<uint8_t>(std::stoul(severity_s));
        } catch (const std::exception&) {
            continue;
        }
        rec.reserved = 0;
        records.push_back(rec);
    }
    in.close();

    std::sort(records.begin(), records.end(), [](const SignatureRecord& a, const SignatureRecord& b) {
        return memcmp(a.sha256, b.sha256, 32) < 0;
    });

    BloomFilter bloom(std::max<size_t>(1, records.size()), bloom_fp_rate);
    for (const auto& r : records) bloom.Add(r.sha256);
    std::vector<uint8_t> bloom_blob;
    bloom.SaveTo(bloom_blob);

    std::ofstream out(out_db_path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) return false;

    uint64_t record_count = records.size();
    uint64_t bloom_size = bloom_blob.size();
    out.write(kMagic, 8);
    out.write(reinterpret_cast<const char*>(&record_count), 8);
    out.write(reinterpret_cast<const char*>(&bloom_size), 8);
    out.write(reinterpret_cast<const char*>(bloom_blob.data()), static_cast<std::streamsize>(bloom_blob.size()));
    for (const auto& r : records) {
        out.write(reinterpret_cast<const char*>(&r), sizeof(SignatureRecord));
    }
    out.flush();

    // [SUA LOI NGHIEM TRONG] TRUOC DAY ham nay tra ve `true` vo dieu kien
    // sau out.close(), khong kiem tra failbit/badbit cua stream. Neu het
    // dung luong dia GIUA CHUNG cac loi write() o tren, ofstream KHONG nem
    // exception (mac dinh) — no chi lang le set failbit, va file ket qua bi
    // CAT CUT (thieu mot phan records/bloom). Ham van tra `true`, khien
    // caller (UpdateClientService) swap thang CSDL hong nay vao production
    // — TAT AM THAM toan bo phat hien theo hash cho toi chu ky update ke
    // tiep, ma khong co bao loi nao ca. Sua: kiem tra out.fail() sau flush
    // VA sau close (close co the that bai khi flush buffer cuoi cung), neu
    // co loi thi xoa file cut nay di va tra ve false thay vi de lai mot
    // CSDL hong duoc coi la thanh cong.
    bool writeOk = !out.fail();
    out.close();
    writeOk = writeOk && !out.fail();

    if (!writeOk) {
        DeleteFileW(out_db_path);
        return false;
    }
    return true;
}
