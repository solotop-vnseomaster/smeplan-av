// win32_path_util.h
// [SUA LOI] Engine goi CreateFileW/GetFileAttributesW voi duong dan tho —
// Win32 API cap thap gioi han MAX_PATH (260 ky tu) TRU KHI duong dan mang
// tien to "\\?\" (long path prefix). Thu muc WinSxS cua Windows
// (C:\Windows\WinSxS\...) noi tieng co ten thu muc/file rat dai, thuong
// vuot 260 ky tu — day rat co the la NGUYEN NHAN CHINH gay ra phan lon
// ScanError khi full scan quet qua C:\Windows\WinSxS. .NET (qua
// Directory.EnumerateFiles) tu dong ho tro long path noi bo, nhung ham
// native CreateFileW trong engine C++ nay THI KHONG, tru khi tu them tien
// to nay.
#pragma once
#include <string>
#include <windows.h>

inline std::wstring ToLongPath(const wchar_t* path) {
    if (!path || !path[0]) return std::wstring();
    std::wstring p(path);

    // Da co tien to long-path hoac la duong dan device (\\.\...) — giu nguyen.
    if (p.rfind(L"\\\\?\\", 0) == 0 || p.rfind(L"\\\\.\\", 0) == 0) {
        return p;
    }

    // Duong dan UNC (\\server\share\...) -> \\?\UNC\server\share\...
    if (p.rfind(L"\\\\", 0) == 0) {
        return L"\\\\?\\UNC\\" + p.substr(2);
    }

    // Duong dan tuyet doi thong thuong (C:\...) -> \\?\C:\...
    // Chi ap dung khi la duong dan tuyet doi (co "X:\" o dau); duong dan
    // tuong doi khong the dung voi tien to nay nen giu nguyen (hiem gap
    // trong engine vi service luon truyen duong dan tuyet doi).
    if (p.size() >= 3 && p[1] == L':' && (p[2] == L'\\' || p[2] == L'/')) {
        return L"\\\\?\\" + p;
    }

    return p;
}
