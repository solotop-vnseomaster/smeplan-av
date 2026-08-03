// Lien ket dong (LoadLibrary/GetProcAddress) toi libyara.dll, dung API C
// cong khai cua libyara thay vi goi cong cu dong lenh rieng (dung ly do
// trong modules/02-kien-truc.md muc 2: "libyara nhung truc tiep ... cho
// phep compile rule mot lan luc khoi dong").
//
// QUAN TRONG: moi truong build/chay trong phien lam viec nay KHONG co san
// libyara.dll. Lop nay tu phat hien va bao IsAvailable()==false trong
// truong hop do; pipeline se bo qua buoc YARA va chuyen thang sang
// heuristic thay vi loi — dung yeu cau "graceful fallback" da ghi trong
// features.md (ARCH-08). Neu sau nay drop libyara.dll (build tu
// https://github.com/VirusTotal/yara) vao cung thu muc engine, lop nay se
// nap va dung that.
#pragma once
#include <stdint.h>
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>

struct YaraMatch {
    std::string rule_identifier;
    int severity_meta = 0; // doc tu meta "severity" cua rule neu co, mac dinh 0
};

class YaraEngine {
public:
    YaraEngine();
    ~YaraEngine();

    bool IsAvailable() const { return available_; }

    // Nap + compile toan bo file *.yar trong thu muc rules_dir.
    bool LoadRules(const wchar_t* rules_dir);

    // Quet buffer, tra danh sach rule khop. Tra false neu YARA khong san sang.
    bool ScanBuffer(const uint8_t* data, size_t length, std::vector<YaraMatch>& out_matches) const;

private:
    HMODULE module_ = nullptr;
    bool available_ = false;
    void* compiled_rules_ = nullptr; // YR_RULES*, giu opaque de khong can yara.h

    // Con tro ham nap dong tu libyara.dll (chu ky tuong thich API cong khai cua libyara).
    using FnInitialize = int(__cdecl*)();
    using FnFinalize = int(__cdecl*)();
    using FnCompilerCreate = int(__cdecl*)(void**);
    using FnCompilerDestroy = void(__cdecl*)(void*);
    using FnCompilerAddFile = int(__cdecl*)(void*, void*, const char*, const char*);
    using FnCompilerGetRules = int(__cdecl*)(void*, void**);
    using FnRulesScanMem = int(__cdecl*)(void*, const uint8_t*, size_t, int, void*, void*, int);
    using FnRulesDestroy = int(__cdecl*)(void*);

    FnInitialize yr_initialize_ = nullptr;
    FnFinalize yr_finalize_ = nullptr;
    FnCompilerCreate yr_compiler_create_ = nullptr;
    FnCompilerDestroy yr_compiler_destroy_ = nullptr;
    FnCompilerAddFile yr_compiler_add_file_ = nullptr;
    FnCompilerGetRules yr_compiler_get_rules_ = nullptr;
    FnRulesScanMem yr_rules_scan_mem_ = nullptr;
    FnRulesDestroy yr_rules_destroy_ = nullptr;

    bool ResolveSymbols();
};
