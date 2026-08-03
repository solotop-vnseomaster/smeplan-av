// scan_engine.h
// Public C ABI cho Scan Engine (spec-output/v1/modules/02-kien-truc.md muc 1:
// "Scan engine - thu vien xu ly viec quet file thuc te ... dung chung cho
// full scan lan real-time scanning").
//
// Bon trang thai verdict theo dung business-rules/05-nghiep-vu.md muc
// "Ket qua quet file (Scan Verdict)": Clean, Malicious, Suspicious, ScanError.
#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef SCANENGINE_EXPORTS
#define SCANENGINE_API __declspec(dllexport)
#else
#define SCANENGINE_API __declspec(dllimport)
#endif

// business-rules/05: "Clean, Malicious, Suspicious, ScanError"
typedef enum ScanVerdict {
    ScanVerdict_Clean = 0,
    ScanVerdict_Malicious = 1,
    ScanVerdict_Suspicious = 2,
    ScanVerdict_ScanError = 3
} ScanVerdict;

// Nguon phat hien nao da ket luan (de UI/service hien thi ly do).
typedef enum DetectionStage {
    DetectionStage_None = 0,
    DetectionStage_HashSignature = 1,
    DetectionStage_Yara = 2,
    DetectionStage_Heuristic = 3,
    DetectionStage_ZipBombGuard = 4,
    DetectionStage_IoError = 5
} DetectionStage;

#pragma pack(push, 1)
typedef struct ScanResult {
    ScanVerdict verdict;
    DetectionStage stage;
    uint32_t threat_id;       // hop le khi stage == HashSignature
    uint8_t severity;         // 0-255, khop data-models/04 SignatureRecord.severity
    uint32_t heuristic_score; // tong diem weighted score cua heuristic
    char sha256_hex[65];      // hash SHA-256 dang hex, NUL-terminated
    char reason[256];         // ly do doc duoc, UTF-8, NUL-terminated
} ScanResult;
#pragma pack(pop)

// --- Vong doi engine ---
// Nap CSDL signature (Bloom filter + sorted array, xem ARCH-07) va (neu co)
// libyara + thu muc rule .yar (xem ARCH-08). Tra 0 neu OK.
SCANENGINE_API int Engine_Initialize(const wchar_t* signature_db_path,
                                      const wchar_t* yara_rules_dir,
                                      double bloom_false_positive_rate);
SCANENGINE_API void Engine_Shutdown(void);

// --- Nap lai rieng CSDL signature, dung khi update service thay CSDL luc
// dang chay (KHONG dung Engine_Initialize cho truong hop nay) ---
// [SUA LOI NGHIEM TRONG] File.Move/MoveFileEx de hoan doi CSDL moi
// (security/09-bao-mat.md muc 3) se bi Windows tu choi (ERROR_ACCESS_DENIED /
// ERROR_USER_MAPPED_FILE) neu file dich con dang co MOT VIEW MEMORY-MAP
// DANG HOAT DONG — rieng FILE_SHARE_DELETE tren handle KHONG du, ban than
// view dang map cung phai duoc giai phong truoc. Quy trinh dung: goi
// Engine_UnmapSignatureDb() TRUOC KHI doi ten file, roi goi
// Engine_LoadSignatureDb() SAU KHI da doi ten xong.
SCANENGINE_API void Engine_UnmapSignatureDb(void);
SCANENGINE_API int Engine_LoadSignatureDb(const wchar_t* signature_db_path);

// --- Pipeline quet (FLOW: hash -> YARA -> heuristic, dung som khi du chac
// chan, xem flows/11 "Luong quet file trong scan engine") ---
SCANENGINE_API int Engine_ScanFile(const wchar_t* file_path, ScanResult* out_result);
SCANENGINE_API int Engine_ScanBuffer(const uint8_t* data, size_t length,
                                      const char* virtual_name, ScanResult* out_result);

// --- Tien ich xay CSDL signature tu CSV (sha256_hex,threat_id,severity) ---
// Dung cho update service / seed du lieu demo (EICAR ...).
SCANENGINE_API int Engine_BuildSignatureDb(const wchar_t* csv_path, const wchar_t* out_db_path);

// --- Hash tien ich rieng, cho cac noi can chi hash (vi du service tinh
// hash de tra rule truoc khi goi toan bo pipeline) ---
SCANENGINE_API int Engine_Sha256File(const wchar_t* file_path, char out_hex65[65]);
SCANENGINE_API int Engine_Sha256Buffer(const uint8_t* data, size_t length, char out_hex65[65]);

#ifdef __cplusplus
}
#endif
