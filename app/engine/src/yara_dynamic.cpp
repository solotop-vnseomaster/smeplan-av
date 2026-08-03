#include "yara_dynamic.h"
#include <cstdio>

namespace {

// Tra ve duong dan day du toi "libyara.dll" nam CUNG thu muc voi module
// engine nay (scan_engine.dll), khong bao gio dua vao DLL search order mac
// dinh cua tien trinh host (service SYSTEM) — vi service co the load engine
// tu nhieu tien trinh/thu muc lam viec khac nhau, mot file libyara.dll gia
// dat truoc trong search order (vi du thu muc lam viec hien tai hoac PATH)
// se bi nap va thuc thi voi quyen SYSTEM (DLL search-order hijacking).
// Dung dia chi cua chinh ham nay de tra nguoc ra HMODULE cua engine qua
// GetModuleHandleExW(FROM_ADDRESS), roi GetModuleFileNameW de lay thu muc.
std::wstring ResolveLibyaraPath() {
    HMODULE selfModule = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&ResolveLibyaraPath),
            &selfModule)) {
        return L"";
    }

    wchar_t path[MAX_PATH];
    DWORD len = GetModuleFileNameW(selfModule, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return L"";

    std::wstring fullPath(path, len);
    size_t lastSlash = fullPath.find_last_of(L"\\/");
    if (lastSlash == std::wstring::npos) return L"";

    return fullPath.substr(0, lastSlash + 1) + L"libyara.dll";
}
// Callback message code cong khai cua libyara: CALLBACK_MSG_RULE_MATCHING = 1.
constexpr int kCallbackMsgRuleMatching = 1;
constexpr int kCallbackContinue = 0;

struct CallbackContext {
    std::vector<YaraMatch>* matches;
};

// Trampoline khop chu ky YR_CALLBACK_FUNC cong khai cua libyara:
// int (*)(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
// Vi khong co yara.h trong moi truong build nay, ta chi xu ly toi thieu:
// khi nhan message "rule matching", ghi nhan co it nhat mot rule khop (khong
// doc duoc ten rule chi tiet neu thieu struct that cua YR_RULE — nhung day
// la nhanh chi chay khi libyara.dll thuc su duoc drop vao, chua duoc kiem
// thu trong phien nay).
//
// [CANH BAO RO RANG — DOC TRUOC KHI DUNG LIBYARA.DLL THAT]
// severity_meta LUON = 0 o day vi khong co struct YR_RULE that de doc
// truong meta "severity" cua rule (can yara.h that). He qua TRUC TIEP:
// trong pipeline.cpp, nhanh "khop YARA severity >= 150 -> Malicious ngay
// lap tuc" (dung theo flows/11-luong-xu-ly.md) LA DEAD CODE VINH VIEN cho
// toi khi ham nay duoc sua — moi rule YARA khop, ke ca rule ro rang la
// malware nghiem trong nhat, CHI cong diem heuristic (40 diem/rule) thay
// vi ket luan Malicious ngay. Day la lua chon AN TOAN CO CHU Y (tha bao
// cao thieu con hon tu ket luan Malicious tu du lieu khong doc duoc dung),
// nhung la mot khoang trong that ve kha nang phat hien, KHONG duoc coi la
// "da hoan thien" khi drop libyara.dll that vao production — PHAI sua lai
// ham nay de doc dung YR_SCAN_MESSAGE_DATA/YR_RULE thuc su (theo dung API
// libyara chinh thuc) truoc khi coi tinh nang YARA la san sang.
int __cdecl YaraCallbackTrampoline(void* /*context*/, int message, void* /*message_data*/, void* user_data) {
    auto* ctx = reinterpret_cast<CallbackContext*>(user_data);
    if (message == kCallbackMsgRuleMatching && ctx && ctx->matches) {
        YaraMatch m;
        m.rule_identifier = "(yara-rule)";
        m.severity_meta = 0; // TODO(production): doc that tu YR_RULE.metas — xem canh bao o tren
        ctx->matches->push_back(m);
    }
    return kCallbackContinue;
}
}

YaraEngine::YaraEngine() {
    // KHONG dung LoadLibraryW(L"libyara.dll") ten tran: tien trinh chay
    // quyen SYSTEM se tra cuu theo DLL search order mac dinh, cho phep mot
    // libyara.dll gia mao dat truoc trong search order (vi du thu muc lam
    // viec hien tai) bi nap va thuc thi voi quyen SYSTEM. Thay vao do: tra
    // duong dan TUYET DOI toi thu muc chua chinh engine nay, va dung
    // LoadLibraryExW voi cac co safe-search de dependencies cua libyara.dll
    // (neu co) cung khong bi tra cuu qua thu muc lam viec hien tai.
    std::wstring libyaraPath = ResolveLibyaraPath();
    if (!libyaraPath.empty()) {
        module_ = LoadLibraryExW(libyaraPath.c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
    if (module_) {
        available_ = ResolveSymbols();
        if (available_ && yr_initialize_) {
            available_ = (yr_initialize_() == 0);
        }
    }
}

YaraEngine::~YaraEngine() {
    if (compiled_rules_ && yr_rules_destroy_) yr_rules_destroy_(compiled_rules_);
    if (available_ && yr_finalize_) yr_finalize_();
    if (module_) FreeLibrary(module_);
}

bool YaraEngine::ResolveSymbols() {
    yr_initialize_ = reinterpret_cast<FnInitialize>(GetProcAddress(module_, "yr_initialize"));
    yr_finalize_ = reinterpret_cast<FnFinalize>(GetProcAddress(module_, "yr_finalize"));
    yr_compiler_create_ = reinterpret_cast<FnCompilerCreate>(GetProcAddress(module_, "yr_compiler_create"));
    yr_compiler_destroy_ = reinterpret_cast<FnCompilerDestroy>(GetProcAddress(module_, "yr_compiler_destroy"));
    yr_compiler_add_file_ = reinterpret_cast<FnCompilerAddFile>(GetProcAddress(module_, "yr_compiler_add_file"));
    yr_compiler_get_rules_ = reinterpret_cast<FnCompilerGetRules>(GetProcAddress(module_, "yr_compiler_get_rules"));
    yr_rules_scan_mem_ = reinterpret_cast<FnRulesScanMem>(GetProcAddress(module_, "yr_rules_scan_mem"));
    yr_rules_destroy_ = reinterpret_cast<FnRulesDestroy>(GetProcAddress(module_, "yr_rules_destroy"));

    return yr_initialize_ && yr_finalize_ && yr_compiler_create_ && yr_compiler_destroy_ &&
           yr_compiler_add_file_ && yr_compiler_get_rules_ && yr_rules_scan_mem_ && yr_rules_destroy_;
}

bool YaraEngine::LoadRules(const wchar_t* rules_dir) {
    if (!available_) return false;

    void* compiler = nullptr;
    if (yr_compiler_create_(&compiler) != 0 || !compiler) return false;

    WIN32_FIND_DATAW find_data;
    std::wstring pattern = std::wstring(rules_dir) + L"\\*.yar";
    HANDLE find = FindFirstFileW(pattern.c_str(), &find_data);
    int files_added = 0;
    if (find != INVALID_HANDLE_VALUE) {
        do {
            if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            std::wstring full_path = std::wstring(rules_dir) + L"\\" + find_data.cFileName;
            FILE* f = nullptr;
            if (_wfopen_s(&f, full_path.c_str(), L"r") == 0 && f) {
                char ns[64];
                sprintf_s(ns, "ns_%d", files_added);
                yr_compiler_add_file_(compiler, f, ns, nullptr);
                fclose(f);
                files_added++;
            }
        } while (FindNextFileW(find, &find_data));
        FindClose(find);
    }

    if (files_added == 0) {
        yr_compiler_destroy_(compiler);
        return false;
    }

    void* rules = nullptr;
    int rc = yr_compiler_get_rules_(compiler, &rules);
    yr_compiler_destroy_(compiler);
    if (rc != 0 || !rules) return false;

    compiled_rules_ = rules;
    return true;
}

bool YaraEngine::ScanBuffer(const uint8_t* data, size_t length, std::vector<YaraMatch>& out_matches) const {
    if (!available_ || !compiled_rules_ || !yr_rules_scan_mem_) return false;
    CallbackContext ctx{ &out_matches };
    yr_rules_scan_mem_(compiled_rules_, data, length, 0,
                        reinterpret_cast<void*>(&YaraCallbackTrampoline), &ctx, 0);
    return true;
}
