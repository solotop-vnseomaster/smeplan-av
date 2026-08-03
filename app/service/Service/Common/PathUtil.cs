namespace Antivirus.Service.Common;

public static class PathUtil
{
    // [SUA LOI LON] StartsWith(root) tran mot minh KHONG kiem tra ky tu
    // tiep theo co phai dau phan cach thu muc hay khong — "C:\Program Files"
    // (khong co dau \ cuoi) se khop nham voi "C:\Program FilesXYZ\evil.exe"
    // hoac "C:\Program Files (Fake)\...". Dung o ca ProcessTrustEngine
    // (kiem tra 1 trong 3 tieu chi trusted-by-default) va QuarantineManager
    // (kiem tra thu muc he thong duoc WRP bao ve — quyet dinh truc tiep
    // tu dong quarantine hay cho xac nhan thu cong).
    public static bool IsPathUnderDirectory(string fullPath, string directoryRoot)
    {
        var normalizedRoot = Path.GetFullPath(directoryRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var normalizedPath = Path.GetFullPath(fullPath);

        if (!normalizedPath.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Phai hoac trung khop hoan toan, hoac ky tu ngay sau prefix la dau
        // phan cach thu muc — khong chap nhan "C:\Program FilesXYZ" khop
        // voi root "C:\Program Files".
        if (normalizedPath.Length == normalizedRoot.Length) return true;
        char nextChar = normalizedPath[normalizedRoot.Length];
        return nextChar == Path.DirectorySeparatorChar || nextChar == Path.AltDirectorySeparatorChar;
    }

    // [SUA LOI NGHIEM TRONG] Dung cho cac endpoint nhan duong dan file THO
    // tu client (vi du /api/scan/file) TRUOC KHI cham vao he thong file.
    // TRUOC DAY nhung endpoint nay dua thang req.Path vao File.Exists/
    // File.OpenRead ma khong kiem tra gi — tien trinh service chay quyen
    // SYSTEM, neu client (hoac mot tien trinh cuc bo khac loi dung UI) truyen
    // vao mot duong dan UNC (\\host\share\...), CHI VIEC cham vao duong dan
    // do (du file khong ton tai) da du de Windows tu dong khoi tao ket noi
    // SMB + xac thuc NTLM toi may chu do ATTACKER chi dinh — rui ro "forced
    // authentication"/NTLM relay, dung danh tinh SYSTEM cua chinh may nan
    // nhan. Ham nay tu choi bat ky duong dan nao KHONG PHAI duong dan cuc bo
    // hop le tren mot o dia (vi du "C:\..."), dac biet la loai bo UNC.
    public static bool IsLocalDrivePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        // UAC/UNC bat dau bang "\\" hoac "//" — tu choi ngay, khong can di
        // qua GetFullPath (ban than viec goi GetFullPath tren mot duong dan
        // UNC khong cham mang, nhung van tu choi som cho ro rang).
        if (path.StartsWith(@"\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
        {
            return false;
        }
        if (!Path.IsPathRooted(path)) return false;

        string full;
        try
        {
            full = Path.GetFullPath(path);
        }
        catch
        {
            return false;
        }

        if (full.StartsWith(@"\\", StringComparison.Ordinal)) return false;

        // Duong dan cuc bo hop le phai co root dang "X:\" (mot chu cai o
        // dia). Bat ky dang khac (UNC, device path la, ...) deu bi tu choi.
        string root = Path.GetPathRoot(full) ?? string.Empty;
        return root.Length == 3 && char.IsLetter(root[0]) && root[1] == ':'
            && (root[2] == Path.DirectorySeparatorChar || root[2] == Path.AltDirectorySeparatorChar);
    }
}
