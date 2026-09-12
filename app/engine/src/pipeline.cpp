// Trien khai cac ham xuat trong scan_engine.h.
// Pipeline dung dung thu tu tang chi phi trong flows/11-luong-xu-ly.md muc
// "Luong quet file trong scan engine": hash SHA-256 -> YARA -> heuristic,
// dung ngay khi co ket luan du chac chan (business-rules/05).
#define SCANENGINE_EXPORTS
#include "../include/scan_engine.h"
#include "sha256.h"
#include "signature_db.h"
#include "heuristic.h"
#include "yara_dynamic.h"
#include "win32_path_util.h"

#include <windows.h>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <cstring>
#include <cstdio>

namespace {
// [SUA LOI NGHIEM TRONG] Truoc day RunPipeline/Engine_ScanFile doc
// g_sig_db/g_yara/g_heuristic KHONG khoa mutex nao, trong khi
// Engine_Initialize/Engine_Shutdown ghi de (reset) cac unique_ptr nay CO
// khoa. UpdateClientService goi lai Engine_Initialize() sau MOI lan cap
// nhat CSDL thanh cong (moi 1-4 gio, hoac khi bam "Kiem tra ngay"); neu
// dung luc do co mot luong khac dang chay RunPipeline (Downloads watcher
// hoac Full Scan dang quet song song — hoan toan co the trung thoi diem),
// doc mot std::unique_ptr trong khi thread khac ghi de no la data race
// (UB), co the doc con tro nua-huy/da-huy -> dereference vung nho da
// unmap -> crash tien trinh service. Sua: dung std::shared_mutex — cac
// luong QUET (doc) lay shared_lock (chay song song voi nhau binh thuong),
// cac thao tac NAP LAI (ghi) lay unique_lock (doc quyen, chan cac luong
// dang quet cho toi khi nap xong).
std::shared_mutex g_state_mutex;
std::unique_ptr<SignatureDb> g_sig_db;
std::unique_ptr<YaraEngine> g_yara;
std::unique_ptr<HeuristicEngine> g_heuristic;
bool g_initialized = false;

// [SUA LOI NGHIEM TRONG] Cua so hoan doi CSDL chu ky.
//
// Engine_UnmapSignatureDb() giai phong g_sig_db de UpdateClientService co the
// File.Move file CSDL, roi Engine_LoadSignatureDb() nap lai. TRUOC DAY giua
// hai loi goi do, g_initialized VAN la true, nen guard fail-closed o
// Engine_ScanFile/Engine_ScanBuffer (chi kiem g_initialized) VAN PASS:
//   TryApplyHashSignatureMatch -> `if (!g_sig_db) return false;` (im lang)
//   -> khong khop YARA/heuristic -> verdict = Clean, rc = 0, kem cau
//      "Khong phat hien qua ca ba buoc hash/YARA/heuristic" — mot khang dinh
//      SAI, vi buoc hash chua bao gio chay.
// Cua so nay khong phai vai mili giay: giua Unmap va Load co mot File.Copy
// toan bo CSDL, va neu Load that bai thi trang thai keo dai toi chu ky cap
// nhat tiep theo.
//
// KHONG the dung bat bien "g_sig_db != nullptr" lam dieu kien fail-closed
// chung, vi g_sig_db CUNG null mot cach HOP LE khi may chua co CSDL chu ky
// (Engine_Initialize tra ENGINE_INIT_SIGNATURE_DB_FAILED, YARA + heuristic
// van chay — day la che do suy giam co chu dich, xem ScanEngineService.
// SignatureDbMissing). Hai trang thai do khac nhau ve ban chat, nen duoc
// theo doi rieng: co duoi day CHI danh dau cua so hoan doi.
bool g_sig_db_swap_in_progress = false;

void CopyReason(ScanResult* out, const char* text) {
    strncpy_s(out->reason, sizeof(out->reason), text, _TRUNCATE);
}

// [DEDUPE] Truoc day khoi "tra CSDL hash -> neu khop, gan verdict=Malicious/
// stage=HashSignature/threat_id/severity" duoc LAP LAI y het o hai noi:
// RunPipeline (buoc 1, hash tinh tren buffer trong bo nho) va Engine_ScanFile
// (nhanh file lon hon 64MB, hash tinh rieng qua Sha256::FileSha256 streaming
// tren TOAN BO file — mot gia tri hash KHAC voi hash cua buffer da cat bot,
// nen khong the gop lam MOT lan tra CSDL duy nhat, nhung PHAN AP DUNG ket
// qua tra duoc thi giong het nhau). Gop phan do vao ham dung chung nay de
// hai noi khong the lech nhau khi sua (vi du quen cap nhat mot trong hai
// khi doi cau reason hoac them truong moi vao ScanResult).
bool TryApplyHashSignatureMatch(const uint8_t digest[32], ScanResult* out, const char* reason) {
    if (!g_sig_db) return false;
    auto rec = g_sig_db->Lookup(digest);
    if (!rec.has_value()) return false;

    out->verdict = ScanVerdict_Malicious;
    out->stage = DetectionStage_HashSignature;
    out->threat_id = rec->threat_id;
    out->severity = rec->severity;
    CopyReason(out, reason);
    return true;
}

// [PHAN LOAI LOI — theo yeu cau phan tich nguyen nhan ScanError that su]
// Truoc day moi loi mo file deu tra ve mot chuoi chung chung
// "Khong mo duoc file (bi khoa hoac hong)" — khong the biet duoc mot
// ScanError la do file dang bi khoa boi tien trinh khac, do thieu quyen
// (file he thong duoc TrustedInstaller/WRP bao ve), hay do gioi han
// duong dan. Ham nay doc GetLastError() that va gan mot MA LOI dang
// "[MA_LOI]" o dau chuoi reason de tang UI co the gom nhom/thong ke theo
// loai (xem app.js phan renderFlaggedItems/errorBreakdown).
void CopyClassifiedIoError(ScanResult* out, const char* context) {
    DWORD err = GetLastError();
    const char* code;
    char detail[192];

    switch (err) {
        case ERROR_SHARING_VIOLATION:
            code = "SHARING_VIOLATION";
            sprintf_s(detail, "File dang duoc mot tien trinh khac khoa doc/ghi doc quyen (dang chay/dang duoc su dung) - %s", context);
            break;
        case ERROR_ACCESS_DENIED:
            code = "ACCESS_DENIED";
            sprintf_s(detail, "Khong du quyen doc file - thuong la file he thong duoc TrustedInstaller/Windows Resource Protection bao ve - %s", context);
            break;
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
            code = "NOT_FOUND";
            sprintf_s(detail, "File/duong dan khong con ton tai (co the da bi xoa hoac di chuyen giua luc liet ke va luc quet) - %s", context);
            break;
        case ERROR_FILENAME_EXCED_RANGE:
            code = "PATH_TOO_LONG";
            sprintf_s(detail, "Duong dan vuot gioi han he thong ngay ca sau khi da them tien to long-path - %s", context);
            break;
        case 0:
            code = "UNKNOWN";
            sprintf_s(detail, "Khong doc duoc thong tin loi cu the - %s", context);
            break;
        default:
            code = "WIN32";
            sprintf_s(detail, "Loi Win32 ma %lu - %s", static_cast<unsigned long>(err), context);
            break;
    }

    char full[256];
    sprintf_s(full, "[%s] %s", code, detail);
    CopyReason(out, full);
}

// Nhom file duoc chan dong bo theo phan mo rong / magic bytes 'MZ' (ERR-RT-01
// trong errors/10-so-tay-loi.md: "chi chan dong bo nhom file co kha nang
// thuc thi truc tiep").
//
// [SUA COMMENT SAI SU THAT] Comment cu o day tung ghi "dat trong engine de
// DUNG CHUNG logic, tranh lech giua cac noi goi" — SAI: driver kernel-mode
// (app/drivers/minifilter/minifilter.c, ham SmePlanAvMfIsExecutableCandidate + mang
// gExecutableExtensions) chay trong dia chi kernel, VE MAT KY THUAT KHONG
// THE goi vao ham C++ user-mode nay (khac hoan toan dia chi/che do thuc
// thi) — day KHONG PHAI mot ham "dung chung" thuc su, ma la HAI BAN SAO
// doc lap CUNG mot danh sach duoi (hien dang trung nhau: .exe/.dll/.ps1/
// .bat/.scr/.cmd/.vbs/.js). Neu sua danh sach nay o MOT noi ma quen noi
// kia, hai tang bao ve (real-time watcher user-mode qua ham nay, va
// SmePlanAvMfPreCreateCallback kernel-mode qua gExecutableExtensions) se LECH NHAU
// ma khong co canh bao bien dich nao bao hieu — phai sua ca hai noi THU
// CONG moi khi thay doi danh sach duoi thuc thi.
bool IsExecutableCandidateInternal(const uint8_t* data, size_t length, const wchar_t* path) {
    if (length >= 2 && data[0] == 'M' && data[1] == 'Z') return true;
    if (!path) return false;
    const wchar_t* dot = wcsrchr(path, L'.');
    if (!dot) return false;
    static const wchar_t* kExts[] = { L".exe", L".dll", L".ps1", L".bat", L".scr", L".cmd", L".vbs", L".js" };
    for (auto ext : kExts) {
        if (_wcsicmp(dot, ext) == 0) return true;
    }
    return false;
}

void RunPipeline(const uint8_t* data, size_t length, const wchar_t* path_for_ext_check,
                  ScanResult* out) {
    memset(out, 0, sizeof(ScanResult));
    out->verdict = ScanVerdict_ScanError;
    out->stage = DetectionStage_IoError;

    uint8_t digest[32];
    Sha256 hasher;
    hasher.Update(data, length);
    hasher.Final(digest);
    std::string hex = Sha256::ToHex(digest);
    strncpy_s(out->sha256_hex, sizeof(out->sha256_hex), hex.c_str(), _TRUNCATE);

    // Buoc 1: tra CSDL hash cuc bo.
    {
        if (TryApplyHashSignatureMatch(digest, out,
                "Khop CSDL signature (hash SHA-256) - ket luan ngay, khong chay YARA/heuristic")) {
            return;
        }
    }

    uint32_t score = 0;

    // Buoc 2 (neu khong khop CSDL hash): chay rule YARA neu co san.
    //
    // [DEAD CODE — xem yara_dynamic.cpp] Nhanh "high_severity -> Malicious
    // ngay" duoi day KHONG BAO GIO dung trong cau hinh hien tai, vi
    // YaraCallbackTrampoline luon tra severity_meta = 0 (chua doc duoc meta
    // that tu YR_RULE khi thieu yara.h that). Moi rule YARA khop hien chi
    // cong diem heuristic. PHAI sua YaraCallbackTrampoline truoc khi coi
    // day la tinh nang hoan thien.
    if (g_yara && g_yara->IsAvailable()) {
        std::vector<YaraMatch> matches;
        if (g_yara->ScanBuffer(data, length, matches) && !matches.empty()) {
            bool high_severity = false;
            for (const auto& m : matches) {
                if (m.severity_meta >= 150) { high_severity = true; break; }
            }
            if (high_severity) {
                out->verdict = ScanVerdict_Malicious;
                out->stage = DetectionStage_Yara;
                CopyReason(out, "Khop rule YARA severity cao - ket luan Malicious ngay");
                return;
            }
            // severity thap (hoac khong doc duoc meta severity qua callback toi gian) -> cong diem.
            score += 40 * static_cast<uint32_t>(matches.size());
        }
    }

    // Buoc 3 (neu van chua ket luan): heuristic.
    HeuristicResult hres = g_heuristic ? g_heuristic->Analyze(data, length)
                                        : HeuristicResult{};
    score += hres.score;
    out->heuristic_score = score;

    if (score >= (g_heuristic ? g_heuristic->Threshold() : 100)) {
        out->verdict = ScanVerdict_Suspicious;
        out->stage = DetectionStage_Heuristic;
        CopyReason(out, "Vuot nguong diem heuristic tong hop (entropy/IAT/entry-point) - can nguoi dung/quy trinh xac nhan them");
        return;
    }

    // [SUA LOI] Cau ket luan TRUOC DAY luon khang dinh da chay "ca ba buoc",
    // ke ca khi khong buoc nao trong so do kha dung. Tren mot may chua co CSDL
    // chu ky (g_sig_db == nullptr, che do suy giam hop le) hoac khong nap duoc
    // YARA, verdict Clean van kem nguyen cau do — bao cao sai ve PHAM VI da
    // quet, va do la thu khien ca nguoi dung lan nguoi dieu tra sau su co tin
    // vao mot dieu chua tung xay ra. Noi dung thuc te da chay.
    out->verdict = ScanVerdict_Clean;
    out->stage = DetectionStage_None;
    if (!g_sig_db) {
        CopyReason(out, "Khong phat hien qua YARA/heuristic - CHUA doi chieu CSDL hash (khong co CSDL chu ky)");
    } else if (!g_yara || !g_yara->IsAvailable()) {
        CopyReason(out, "Khong phat hien qua hash/heuristic - CHUA chay YARA (khong nap duoc libyara/rule)");
    } else {
        CopyReason(out, "Khong phat hien qua ca ba buoc hash/YARA/heuristic");
    }
}
}

extern "C" {

SCANENGINE_API int Engine_Initialize(const wchar_t* signature_db_path,
                                      const wchar_t* yara_rules_dir,
                                      double bloom_false_positive_rate) {
    std::unique_lock<std::shared_mutex> lock(g_state_mutex);
    (void)bloom_false_positive_rate; // da co hieu luc luc build CSDL (Engine_BuildSignatureDb)

    // [SUA LOI NGHIEM TRONG] TRUOC DAY ham nay LUON tra 0 (thanh cong) ke
    // ca khi duong dan CSDL duoc chi dinh nhung nap that bai — va phia goi
    // (Program.cs) cung bo qua gia tri tra ve, nen service chay binh thuong
    // voi engine KHONG CO CSDL chu ky trong khi UI bao "dang bao ve". Sua:
    // ghi nhan that bai va tra ve ma loi rieng de phia goi bat buoc phai xu
    // ly; engine van khoi tao duoc (YARA/heuristic con chay) nhung trang
    // thai "thieu CSDL hash" khong con bi giau di.
    bool sig_db_failed = false;
    g_sig_db = std::make_unique<SignatureDb>();
    if (signature_db_path && !g_sig_db->Load(signature_db_path)) {
        g_sig_db.reset();
        sig_db_failed = true;
    }

    g_yara = std::make_unique<YaraEngine>();
    if (yara_rules_dir && g_yara->IsAvailable()) {
        g_yara->LoadRules(yara_rules_dir);
    }

    g_heuristic = std::make_unique<HeuristicEngine>(100);
    g_initialized = true;
    return sig_db_failed ? ENGINE_INIT_SIGNATURE_DB_FAILED : 0;
}

SCANENGINE_API void Engine_Shutdown(void) {
    std::unique_lock<std::shared_mutex> lock(g_state_mutex);
    g_sig_db.reset();
    g_yara.reset();
    g_heuristic.reset();
    g_initialized = false;
}

// [SUA LOI NGHIEM TRONG] Xem scan_engine.h — goi truoc khi doi ten file
// CSDL (File.Move/MoveFileEx) de giai phong view memory-map dang hoat
// dong; Windows tu choi rename/xoa mot file con dang co user-mapped
// section (ERROR_ACCESS_DENIED/ERROR_USER_MAPPED_FILE) bat ke handle co
// FILE_SHARE_DELETE hay khong.
SCANENGINE_API void Engine_UnmapSignatureDb(void) {
    std::unique_lock<std::shared_mutex> lock(g_state_mutex);
    g_sig_db.reset();
    // Mo cua so hoan doi: tu day toi khi Engine_LoadSignatureDb thanh cong,
    // moi lan quet PHAI tra ScanError chu tuyet doi khong duoc tra Clean.
    g_sig_db_swap_in_progress = true;
}

SCANENGINE_API int Engine_LoadSignatureDb(const wchar_t* signature_db_path) {
    std::unique_lock<std::shared_mutex> lock(g_state_mutex);
    auto new_db = std::make_unique<SignatureDb>();
    if (!signature_db_path || !new_db->Load(signature_db_path)) {
        // [SUA LOI NGHIEM TRONG] TRUOC DAY nhanh loi goi g_sig_db.reset(),
        // tuc la mot lan cap nhat tai ve HONG se HUY LUON CSDL CU DANG TOT
        // — sau do moi lan quet deu bo qua buoc hash va tra Clean kem cau
        // "Khong phat hien qua ca ba buoc", tuc la BAO CAO SAI la da quet
        // du ba tang. Fail-closed dung nghia o day la GIU NGUYEN CSDL cu
        // (van phat hien duoc nhung gi da biet) va bao loi len tren de
        // UpdateClientService rollback, thay vi tu tuoc vu khi cua chinh
        // minh. Chi thay the g_sig_db khi CSDL moi da nap THANH CONG.
        return -1;
    }
    g_sig_db = std::move(new_db);
    // Dong cua so hoan doi CHI khi da that su co CSDL moi trong tay. Neu Load
    // that bai o tren, co van bat va moi lan quet tiep tuc tra ScanError —
    // dung nghia fail-closed: mat kha nang quet la trang thai nhin thay duoc,
    // con tra Clean sai la mat kha nang quet ma khong ai biet.
    g_sig_db_swap_in_progress = false;
    return 0;
}

SCANENGINE_API int Engine_ScanFile(const wchar_t* file_path, ScanResult* out_result) {
    if (!out_result) return -1;
    memset(out_result, 0, sizeof(ScanResult));

    // [SUA LOI NGHIEM TRONG] g_initialized TRUOC DAY duoc GHI o
    // Engine_Initialize/Engine_Shutdown nhung KHONG BAO GIO DUOC DOC — mot
    // lan quet phat ra truoc khi Initialize chay xong, hoac sau khi
    // Shutdown da chay (vi du service dang dung trong khi mot worker full
    // scan con dang chay), se di tiep qua toan bo pipeline voi g_sig_db/
    // g_yara/g_heuristic deu null va ket thuc o nhanh cuoi: verdict Clean,
    // stage None, ma tra ve 0 (thanh cong) — tuc la "sach" va "khong co
    // loi", dung hai dieu SAI nhat co the noi. Fail-closed: ScanError.
    {
        std::shared_lock<std::shared_mutex> state_lock(g_state_mutex);
        if (!g_initialized) {
            out_result->verdict = ScanVerdict_ScanError;
            out_result->stage = DetectionStage_IoError;
            CopyReason(out_result,
                       "Engine chua khoi tao xong hoac da shutdown - KHONG duoc coi la Clean");
            return -1;
        }
        // Xem g_sig_db_swap_in_progress: trong cua so hoan doi CSDL, tang hash
        // KHONG chay duoc. Tra Clean o day la noi doi ve pham vi da quet.
        if (g_sig_db_swap_in_progress) {
            out_result->verdict = ScanVerdict_ScanError;
            out_result->stage = DetectionStage_IoError;
            CopyReason(out_result,
                       "Dang hoan doi CSDL chu ky - tang hash tam thoi khong kha dung, KHONG duoc coi la Clean");
            return -1;
        }
    }

    // [SUA LOI] Them tien to long-path ("\\?\") — CreateFileW tho gioi han
    // MAX_PATH (260 ky tu), trong khi thu muc WinSxS cua Windows
    // (C:\Windows\WinSxS\...) va nhieu duong dan node_modules/cache sau
    // thuong VUOT gioi han nay. Day rat co the la nguyen nhan chinh gay
    // phan lon ScanError khi full scan quet qua C:\Windows.
    std::wstring long_path = ToLongPath(file_path);

    HANDLE h = CreateFileW(long_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        out_result->verdict = ScanVerdict_ScanError;
        out_result->stage = DetectionStage_IoError;
        CopyClassifiedIoError(out_result, "khong mo duoc file de quet - KHONG duoc coi la Clean");
        return 0;
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size)) {
        DWORD err = GetLastError();
        CloseHandle(h);
        out_result->verdict = ScanVerdict_ScanError;
        out_result->stage = DetectionStage_IoError;
        SetLastError(err);
        CopyClassifiedIoError(out_result, "khong doc duoc kich thuoc file");
        return 0;
    }

    // Gioi han doc vao RAM cho ban tham chieu nay (64MB) de tranh cap phat
    // qua lon trong 1 lan quet dong bo; file lon hon van duoc hash day du
    // (Sha256::FileSha256 doc streaming) nhung phan phan tich PE/heuristic
    // chi chay tren phan dau file trong gioi han nay.
    constexpr uint64_t kMaxInMemory = 64ULL * 1024 * 1024;
    size_t to_read = static_cast<size_t>(size.QuadPart < static_cast<LONGLONG>(kMaxInMemory)
                                              ? size.QuadPart : kMaxInMemory);
    std::vector<uint8_t> buffer(to_read);
    DWORD read = 0;
    BOOL ok = to_read == 0 ? TRUE : ReadFile(h, buffer.data(), static_cast<DWORD>(to_read), &read, nullptr);
    DWORD read_err = ok ? 0 : GetLastError();
    CloseHandle(h);
    if (!ok) {
        out_result->verdict = ScanVerdict_ScanError;
        out_result->stage = DetectionStage_IoError;
        SetLastError(read_err);
        CopyClassifiedIoError(out_result, "loi doc noi dung file");
        return 0;
    }
    buffer.resize(read);

    // Shared_lock: nhieu luong QUET duoc chay song song voi nhau, chi bi
    // chan khi co mot luong dang NAP LAI CSDL (unique_lock, xem
    // Engine_Initialize/Engine_LoadSignatureDb).
    std::shared_lock<std::shared_mutex> lock(g_state_mutex);

    if (static_cast<uint64_t>(size.QuadPart) > kMaxInMemory) {
        // File lon hon gioi han doc trong bo nho: hash toan bo file bang
        // duong streaming rieng de dam bao ket qua hash dung, van chay
        // YARA/heuristic tren phan dau da doc.
        //
        // [SUA LOI NGHIEM TRONG] Hai loi lien quan o day:
        // (1) Truoc day, neu Sha256::FileSha256() THAT BAI (loi doc file
        // giua chung - hong dia, mat quyen, file bi khoa sau khi da mo...),
        // code roi tuot xuong RunPipeline(buffer,...) ben duoi va COI NHU
        // quet thanh cong: sha256_hex tra ve la hash cua CHI phan dau file
        // (buffer, do RunPipeline tu tinh hash tren du lieu duoc truyen vao)
        // chu KHONG PHAI hash that cua toan bo file, va khong co canh bao
        // loi nao duoc tra ve cho caller. Sua: neu FileSha256 that bai, tra
        // ve ScanError ro rang (giong het pattern loi I/O khac trong ham
        // nay), KHONG duoc coi day la mot lan quet hop le voi hash sai.
        // (2) Thu tu goi cu la RunPipeline() TRUOC (tu quyet dinh verdict,
        // co the ket luan Malicious/HashSignature ngay tu buoc 1 ben trong
        // no dua tren hash cua BUFFER cat bot) roi moi tra CSDL bang hash
        // THAT cua toan bo file va ghi de sha256_hex SAU - neu tra cuu bang
        // hash that KHONG khop, verdict cu (da dua tren hash buffer) van
        // duoc giu nguyen trong khi sha256_hex hien thi lai la hash that,
        // khien nguoi/dich vu doc log khong the doi chieu duoc tai sao co
        // ket luan do tu chinh hash duoc hien thi. Sua: tra CSDL bang hash
        // THAT truoc (dung y het nhu nhanh file nho: khop la ket luan ngay,
        // khong chay YARA/heuristic), chi khi KHONG khop moi chay
        // RunPipeline tren buffer cat bot, va luon ghi lai hash THAT vao
        // sha256_hex sau cung de gia tri tra ve khong bao gio phu thuoc thu
        // tu goi ngam ben trong.
        uint8_t digest[32];
        if (!Sha256::FileSha256(file_path, digest)) {
            DWORD err = GetLastError();
            out_result->verdict = ScanVerdict_ScanError;
            out_result->stage = DetectionStage_IoError;
            SetLastError(err);
            CopyClassifiedIoError(out_result, "loi tinh hash SHA-256 tren toan bo file lon - KHONG duoc coi la da quet xong");
            return 0;
        }

        std::string hex = Sha256::ToHex(digest);
        strncpy_s(out_result->sha256_hex, sizeof(out_result->sha256_hex), hex.c_str(), _TRUNCATE);

        // Tra CSDL bang hash TOAN BO file THAT (khac hash cua buffer cat bot)
        // TRUOC KHI chay YARA/heuristic — dung chung ham voi buoc 1 cua
        // RunPipeline (xem TryApplyHashSignatureMatch). Khop la ket luan
        // ngay, giong het hanh vi nhanh file nho.
        if (TryApplyHashSignatureMatch(digest, out_result,
                "Khop CSDL signature (hash SHA-256 tinh tren toan bo file)")) {
            return 0;
        }

        RunPipeline(buffer.data(), buffer.size(), file_path, out_result);
        // RunPipeline vua ghi de sha256_hex bang hash cua BUFFER cat bot
        // (chi phan dau file, do gioi han doc kMaxInMemory) — ghi lai hash
        // THAT cua toan bo file da tinh o tren de gia tri tra ve luon dung
        // voi noi dung THAT cua file, bat ke RunPipeline lam gi ben trong.
        strncpy_s(out_result->sha256_hex, sizeof(out_result->sha256_hex), hex.c_str(), _TRUNCATE);

        // [SUA LOI NGHIEM TRONG] Voi file lon hon kMaxInMemory, YARA va
        // heuristic CHI nhin thay 64MB DAU. TRUOC DAY khi khong tim thay gi,
        // RunPipeline van gan cau "Khong phat hien qua ca ba buoc hash/YARA/
        // heuristic" — mot khang dinh SAI ve pham vi da quet, va la cong thuc
        // ne tranh san co: don 64MB rac vao truoc payload thi payload nam
        // ngoai tam nhin cua ca hai tang, con ket qua tra ve noi rang da quet
        // day du.
        //
        // Hash tren TOAN BO file thi van dung (da tinh o tren bang streaming),
        // nen phat hien theo chu ky khong bi anh huong. Chi YARA/heuristic bi
        // gioi han — va dieu do phai duoc noi ra.
        if (out_result->verdict == ScanVerdict_Clean) {
            CopyReason(out_result,
                       "Hash toan file khong khop CSDL; YARA/heuristic CHI quet 64MB dau "
                       "- phan con lai cua file CHUA duoc kiem tra");
        }
        return 0;
    }

    RunPipeline(buffer.data(), buffer.size(), file_path, out_result);
    return 0;
}

SCANENGINE_API int Engine_ScanBuffer(const uint8_t* data, size_t length,
                                      const char* virtual_name, ScanResult* out_result) {
    if (!out_result || (!data && length > 0)) return -1;
    (void)virtual_name;
    std::shared_lock<std::shared_mutex> lock(g_state_mutex);

    // [SUA LOI NGHIEM TRONG — GUARD DUNG, TRUOC DAY AP THIEU DUONG]
    // Engine_ScanFile (o tren) da duoc sua de doc g_initialized va tra
    // ScanError khi engine chua Initialize xong hoac da Shutdown. Ham nay —
    // duong VAO DUY NHAT cho noi dung ben trong archive (ArchiveScanner giai
    // nen tung entry ra bo nho roi goi Engine_ScanBuffer) — thi khong.
    // Hau qua giong het cai da duoc mo ta o Engine_ScanFile: g_sig_db/
    // g_yara/g_heuristic deu null, RunPipeline roi xuong nhanh cuoi va tra
    // ve verdict Clean, stage None, ma tra ve 0 (thanh cong). Tuc la moi
    // entry trong moi file nen deu duoc bao la "sach" va "khong co loi" —
    // dung hai dieu sai nhat co the noi — trong suot ca giai doan khoi dong
    // va sau khi shutdown (vi du service dang dung trong khi mot worker full
    // scan con dang giai nen do).
    // Cung mot bat bien, cung mot cach fail-closed.
    if (!g_initialized) {
        memset(out_result, 0, sizeof(ScanResult));
        out_result->verdict = ScanVerdict_ScanError;
        out_result->stage = DetectionStage_IoError;
        CopyReason(out_result,
                   "Engine chua khoi tao xong hoac da shutdown - KHONG duoc coi la Clean");
        return -1;
    }
    // Xem g_sig_db_swap_in_progress: trong cua so hoan doi CSDL, tang hash
    // KHONG chay duoc. Tra Clean o day la noi doi ve pham vi da quet.
    if (g_sig_db_swap_in_progress) {
        out_result->verdict = ScanVerdict_ScanError;
        out_result->stage = DetectionStage_IoError;
        CopyReason(out_result,
                   "Dang hoan doi CSDL chu ky - tang hash tam thoi khong kha dung, KHONG duoc coi la Clean");
        return -1;
    }

    RunPipeline(data, length, nullptr, out_result);
    return 0;
}

SCANENGINE_API int Engine_BuildSignatureDb(const wchar_t* csv_path, const wchar_t* out_db_path) {
    return SignatureDb::BuildFromCsv(csv_path, out_db_path, 0.001) ? 0 : -1;
}

SCANENGINE_API int Engine_Sha256File(const wchar_t* file_path, char out_hex65[65]) {
    uint8_t digest[32];
    if (!Sha256::FileSha256(file_path, digest)) return -1;
    std::string hex = Sha256::ToHex(digest);
    strncpy_s(out_hex65, 65, hex.c_str(), _TRUNCATE);
    return 0;
}

SCANENGINE_API int Engine_Sha256Buffer(const uint8_t* data, size_t length, char out_hex65[65]) {
    Sha256 hasher;
    hasher.Update(data, length);
    uint8_t digest[32];
    hasher.Final(digest);
    std::string hex = Sha256::ToHex(digest);
    strncpy_s(out_hex65, 65, hex.c_str(), _TRUNCATE);
    return 0;
}

} // extern "C"
