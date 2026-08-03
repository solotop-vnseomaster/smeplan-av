#include "heuristic.h"
#define NOMINMAX
#include <windows.h>
#include <cmath>
#include <cstring>
#include <array>
#include <algorithm>

HeuristicEngine::HeuristicEngine(uint32_t suspicious_threshold) : threshold_(suspicious_threshold) {}

double HeuristicEngine::ShannonEntropy(const uint8_t* data, size_t length) const {
    if (length == 0) return 0.0;
    std::array<uint64_t, 256> freq{};
    freq.fill(0);
    for (size_t i = 0; i < length; i++) freq[data[i]]++;

    double entropy = 0.0;
    double len = static_cast<double>(length);
    for (uint64_t f : freq) {
        if (f == 0) continue;
        double p = static_cast<double>(f) / len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

namespace {
// RVA -> file offset dua theo bang section headers cua PE.
DWORD RvaToOffset(DWORD rva, const IMAGE_SECTION_HEADER* sections, WORD section_count) {
    for (WORD i = 0; i < section_count; i++) {
        DWORD start = sections[i].VirtualAddress;
        DWORD end = start + std::max(sections[i].Misc.VirtualSize, sections[i].SizeOfRawData);
        if (rva >= start && rva < end) {
            return sections[i].PointerToRawData + (rva - start);
        }
    }
    return 0;
}

// Danh sach API nhay cam thuong gap trong ky thuat process injection / tai
// payload dong. Khong phai bang chung tuyet doi, chi la tin hieu cong diem.
const char* kHighRiskApis[] = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtUnmapViewOfSection", "SetThreadContext", "QueueUserAPC",
    "WinExec", "ShellExecuteA", "ShellExecuteW",
    "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA",
    "SetWindowsHookExA", "SetWindowsHookExW",
};
const char* kModerateRiskApis[] = {
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "VirtualAlloc", "VirtualProtect", "IsDebuggerPresent",
    "CreateToolhelp32Snapshot", "CryptEncrypt",
};
}

void HeuristicEngine::AnalyzePe(const uint8_t* data, size_t length, HeuristicResult& result) const {
    if (length < sizeof(IMAGE_DOS_HEADER)) return;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return; // khong phai PE, bo qua phan tich PE
    if (dos->e_lfanew < 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > length) return;

    auto* nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(data + dos->e_lfanew);
    if (nt32->Signature != IMAGE_NT_SIGNATURE) return;

    bool is_pe32_plus = (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    DWORD entry_point_rva;
    DWORD import_dir_rva = 0, import_dir_size = 0;
    const IMAGE_SECTION_HEADER* sections;
    WORD section_count = nt32->FileHeader.NumberOfSections;

    if (is_pe32_plus) {
        auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(data + dos->e_lfanew);
        entry_point_rva = nt64->OptionalHeader.AddressOfEntryPoint;
        if (nt64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            import_dir_rva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            import_dir_size = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
        sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            reinterpret_cast<const uint8_t*>(nt64) + sizeof(IMAGE_NT_HEADERS64));
    } else {
        entry_point_rva = nt32->OptionalHeader.AddressOfEntryPoint;
        if (nt32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            import_dir_rva = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            import_dir_size = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
        sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            reinterpret_cast<const uint8_t*>(nt32) + sizeof(IMAGE_NT_HEADERS32));
    }

    if (reinterpret_cast<const uint8_t*>(sections + section_count) > data + length) return;

    // --- Entry point ngoai section co code, hoac khong nam trong section nao ---
    bool found_section_for_entry = false;
    bool entry_in_code_section = false;
    for (WORD i = 0; i < section_count; i++) {
        DWORD start = sections[i].VirtualAddress;
        DWORD end = start + std::max(sections[i].Misc.VirtualSize, sections[i].SizeOfRawData);
        if (entry_point_rva >= start && entry_point_rva < end) {
            found_section_for_entry = true;
            entry_in_code_section = (sections[i].Characteristics & IMAGE_SCN_CNT_CODE) != 0;
            break;
        }
    }
    if (!found_section_for_entry || !entry_in_code_section) {
        result.entry_point_outside_section = true;
        result.score += 50;
        result.reasons.push_back("Entry point nam ngoai section co code (bat thuong so voi PE thong thuong)");
    }

    // --- Quet IAT tim to hop API nhay cam ---
    if (import_dir_rva != 0 && import_dir_size != 0) {
        DWORD desc_offset = RvaToOffset(import_dir_rva, sections, section_count);
        if (desc_offset != 0 && desc_offset < length) {
            const auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(data + desc_offset);
            int high_risk_hits = 0, moderate_risk_hits = 0;
            for (; reinterpret_cast<const uint8_t*>(desc + 1) <= data + length && desc->Name != 0; desc++) {
                DWORD thunk_rva = desc->OriginalFirstThunk != 0 ? desc->OriginalFirstThunk : desc->FirstThunk;
                if (thunk_rva == 0) continue;
                DWORD thunk_offset = RvaToOffset(thunk_rva, sections, section_count);
                if (thunk_offset == 0) continue;

                if (is_pe32_plus) {
                    auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA64*>(data + thunk_offset);
                    for (; reinterpret_cast<const uint8_t*>(thunk + 1) <= data + length && thunk->u1.AddressOfData != 0; thunk++) {
                        if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) continue;
                        DWORD name_offset = RvaToOffset(static_cast<DWORD>(thunk->u1.AddressOfData), sections, section_count);
                        // [SUA LOI NGHIEM TRONG] "name_offset + 2" o day PHAI
                        // tinh trong mien size_t (64-bit): neu tinh trong mien
                        // DWORD (32-bit) nhu truoc day, gia tri co the "wrap"
                        // ve mot so nho va vuot qua check ">= length", nhung
                        // phep tinh con tro thuc te "data + name_offset + 2"
                        // ben duoi lai la 64-bit (KHONG wrap) — dan toi doc
                        // lech ~4GB tren du lieu PE crafted du y do xau.
                        size_t name_offset_sz = static_cast<size_t>(name_offset);
                        if (name_offset == 0 || name_offset_sz + 2 >= length) continue;
                        const char* fn_name = reinterpret_cast<const char*>(data + name_offset_sz + 2);
                        for (auto* api : kHighRiskApis) if (strncmp(fn_name, api, 64) == 0) high_risk_hits++;
                        for (auto* api : kModerateRiskApis) if (strncmp(fn_name, api, 64) == 0) moderate_risk_hits++;
                    }
                } else {
                    auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA32*>(data + thunk_offset);
                    for (; reinterpret_cast<const uint8_t*>(thunk + 1) <= data + length && thunk->u1.AddressOfData != 0; thunk++) {
                        if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) continue;
                        DWORD name_offset = RvaToOffset(thunk->u1.AddressOfData, sections, section_count);
                        // Xem ghi chu o nhanh PE32+ ben tren: check phai tinh
                        // trong mien size_t de khong bi wrap 32-bit lech voi
                        // phep tinh con tro thuc te.
                        size_t name_offset_sz = static_cast<size_t>(name_offset);
                        if (name_offset == 0 || name_offset_sz + 2 >= length) continue;
                        const char* fn_name = reinterpret_cast<const char*>(data + name_offset_sz + 2);
                        for (auto* api : kHighRiskApis) if (strncmp(fn_name, api, 64) == 0) high_risk_hits++;
                        for (auto* api : kModerateRiskApis) if (strncmp(fn_name, api, 64) == 0) moderate_risk_hits++;
                    }
                }
            }

            if (high_risk_hits >= 3) {
                result.suspicious_iat_combo = true;
                result.score += 60;
                result.reasons.push_back("To hop >=3 API nhay cam trong IAT (kieu process injection: VirtualAllocEx/WriteProcessMemory/CreateRemoteThread...)");
            } else if (high_risk_hits >= 1) {
                result.score += 20;
                result.reasons.push_back("IAT co API nhay cam rieng le");
            }
            if (moderate_risk_hits >= 4) {
                result.score += 10;
                result.reasons.push_back("IAT co nhieu API tai/thuc thi dong");
            }
        }
    }
}

HeuristicResult HeuristicEngine::Analyze(const uint8_t* data, size_t length) const {
    HeuristicResult result;
    result.entropy = ShannonEntropy(data, length);

    // Entropy cao dong deu tren toan bo buffer goi y noi dung da nen/ma hoa —
    // chi la mot tin hieu, khong ket luan rieng le (nhieu file nen hop le
    // cung co entropy cao).
    if (result.entropy >= 7.5) {
        result.score += 15;
        result.reasons.push_back("Entropy Shannon cao (>=7.5 bit/byte) — co the da nen/ma hoa/packed");
    }

    AnalyzePe(data, length, result);
    return result;
}
