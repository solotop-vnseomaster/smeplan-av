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
}
