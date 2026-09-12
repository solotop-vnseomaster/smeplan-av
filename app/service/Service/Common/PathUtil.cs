namespace Antivirus.Service.Common;

public static class PathUtil
{
    // So hop reparse-point (junction/symlink) toi da duoc theo trong mot lan
    // resolve — chan vong lap/chuoi reparse point bat thuong (co the tu tao,
    // khong can quyen admin) khien ResolveRealPath chay vo han hoac qua lau.
    private const int MaxReparseHops = 32;

    // [SUA LOI LON] StartsWith(root) tran mot minh KHONG kiem tra ky tu
    // tiep theo co phai dau phan cach thu muc hay khong — "C:\Program Files"
    // (khong co dau \ cuoi) se khop nham voi "C:\Program FilesXYZ\evil.exe"
    // hoac "C:\Program Files (Fake)\...". Dung o ca ProcessTrustEngine
    // (kiem tra 1 trong 3 tieu chi trusted-by-default) va QuarantineManager
    // (kiem tra thu muc he thong duoc WRP bao ve — quyet dinh truc tiep
    // tu dong quarantine hay cho xac nhan thu cong).
    public static bool IsPathUnderDirectory(string fullPath, string directoryRoot)
    {
        if (!IsPathUnderDirectoryLexical(fullPath, directoryRoot)) return false;

        // [SUA LOI NGHIEM TRONG] Xem ghi chu ResolveRealPath: kiem tra lexical
        // o tren co the bi qua mat boi mot junction/symlink CUC BO (khong can
        // quyen admin de tao) dat trong directoryRoot nhung THAT SU tro ra
        // ngoai (vi du ra UNC share hoac thu muc khac do attacker kiem soat).
        // Vi IsPathUnderDirectory la 1 trong 3 tieu chi quyet dinh
        // "trusted-by-default" (ProcessTrustEngine) va quyet dinh auto-
        // quarantine vs cho xac nhan thu cong (QuarantineManager), phai
        // resolve ca hai duong dan ve dang THAT SU (sau reparse point) roi
        // so sanh lai truoc khi tin tuong ket qua lexical.
        string realPath = ResolveRealPath(SafeGetFullPath(fullPath) ?? fullPath);
        string realRoot = ResolveRealPath(SafeGetFullPath(directoryRoot) ?? directoryRoot);
        return IsPathUnderDirectoryLexical(realPath, realRoot);
    }

    private static bool IsPathUnderDirectoryLexical(string fullPath, string directoryRoot)
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
        if (!HasLocalDriveRoot(full)) return false;

        // [SUA LOI NGHIEM TRONG] Xem ghi chu ResolveRealPath ben duoi: kiem
        // tra lexical o tren KHONG du — mot junction/symlink NTFS cuc bo
        // (khong can quyen admin de tao) dat tren mot thanh phan thu muc bat
        // ky trong duong dan co the khien mot duong dan "C:\..." nhin hop le
        // THAT SU tro ra UNC share khi Windows resolve no, tai hien dung lo
        // hong NTLM-relay ham nay ton tai de chan. Phai resolve het reparse
        // point roi kiem tra lai dinh dang o dia cuc bo tren duong dan THAT
        // SU truoc khi cham vao he thong file.
        string real = ResolveRealPath(full);
        return HasLocalDriveRoot(real);
    }

    // [SUA LOI NGHIEM TRONG] Duong dan GHI cua cac luong khoi phuc chay
    // duoi quyen SYSTEM (VersionStore.RestoreLatestVersion,
    // QuarantineManager.Restore) TRUOC DAY ghi thang vao duong dan goc da
    // luu trong DB ma khong resolve reparse point. Duong dan do den tu vung
    // ATTACKER kiem soat (FileSystemWatcher trong chinh thu muc cua ho, hoac
    // ban ghi quarantine cua file ho tao) — nen ke tan cong quyen thuong co
    // the: snapshot mot file cua chinh minh -> bien duong dan do thanh
    // junction tro toi dich dac quyen -> ep he thong tu dong rollback ->
    // tien trinh SYSTEM ghi de dich do. Day la leo thang quyen day du,
    // khong can token API vi duong auto-rollback khong di qua /api/*.
    //
    // Quy tac fail-closed o day: duong dan dich chi an toan khi
    //  (1) la duong dan o dia cuc bo (khong UNC, khong device path la), VA
    //  (2) resolve het reparse point van ra DUNG chinh no — nghia la khong
    //      mot thanh phan thu muc nao tren duong di bi thay bang junction/
    //      symlink giua luc ghi nhan va luc khoi phuc, VA
    //  (3) ban than dich khong phai reparse point.
    // Bat ky sai lech nao deu bi tu choi thay vi "co gang ghi cho bang duoc".
    public static bool IsSafeRestoreTarget(string? recordedPath)
    {
        if (!IsLocalDrivePath(recordedPath)) return false;

        string full;
        try { full = Path.GetFullPath(recordedPath!); }
        catch { return false; }

        // Dich ton tai va CHINH NO la reparse point -> tu choi (ghi qua no
        // se cham vao muc tieu do attacker chon).
        try
        {
            var attrs = File.GetAttributes(full);
            if ((attrs & FileAttributes.ReparsePoint) != 0) return false;
        }
        catch (FileNotFoundException) { /* chua ton tai — hop le */ }
        catch (DirectoryNotFoundException) { /* thu muc cha chua ton tai */ }
        catch { return false; }

        // Duong di THAT SU phai trung khop duong di lexical. Neu lech, co
        // reparse point xen vao dau do tren chuoi thu muc.
        string real = ResolveRealPath(full);
        return string.Equals(real, full, StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasLocalDriveRoot(string full)
    {
        // Duong dan cuc bo hop le phai co root dang "X:\" (mot chu cai o
        // dia). Bat ky dang khac (UNC, device path la, ...) deu bi tu choi.
        string root = Path.GetPathRoot(full) ?? string.Empty;
        return root.Length == 3 && char.IsLetter(root[0]) && root[1] == ':'
            && (root[2] == Path.DirectorySeparatorChar || root[2] == Path.AltDirectorySeparatorChar);
    }

    private static string? SafeGetFullPath(string path)
    {
        try { return Path.GetFullPath(path); }
        catch { return null; }
    }

    // Duyet tung thanh phan cua duong dan tu goc o dia xuong, giong cach
    // Windows I/O Manager tu resolve reparse point (junction/symlink) khi
    // duyet qua chung: neu mot thanh phan la reparse point, thay THANH PHAN
    // DO (va moi thu truoc no) bang muc tieu THAT SU cua no roi tiep tuc
    // ghep cac thanh phan con lai cua duong dan goc. Khong lam dieu nay thi
    // validation thuan lexical (Path.GetFullPath) hoan toan bi qua mat: mot
    // junction do NGUOI DUNG THUONG (khong can admin) tao ra ben trong mot
    // o dia cuc bo co the tro ra UNC share hoac thu muc khac ma van "nhin"
    // giong mot duong dan cuc bo hop le / nam "duoi" mot thu muc tin cay.
    //
    // Neu khong the resolve (khong quyen, khong ho tro, hoac thanh phan
    // chua ton tai tren dia) thi giu nguyen thanh phan do va tiep tuc —
    // dung hanh vi truoc day cho duong dan chua ton tai (khong lam hong
    // kha nang tu choi lexical som cho file/thu muc chua duoc tao).
    //
    // [SUA LOI] Khi vuot MaxReparseHops, gia tri tra ve nay duoc DUNG TRUC
    // TIEP cho 2 quyet dinh bao mat (IsLocalDrivePath, IsPathUnderDirectory)
    // — TRUOC DAY vuot gioi han thi "break" khoi vong lap va tra ve "current"
    // dang do (chi moi resolve toi hop thu MaxReparseHops, CAC THANH PHAN
    // DUONG DAN CON LAI BI BO HAN), nhin van co ve la mot duong dan cuc bo
    // hop le. Ke tan cong co the dan mot chuoi >32 reparse point (khong can
    // quyen admin de tao) sao cho HOP THU 33+ (chua kip resolve) moi la hop
    // thuc su dan ra UNC — validation se BI QUA MAT vi vong lap dung truoc
    // khi cham toi hop do. Sua: fail-closed — tra ve sentinel dang UNC (chac
    // chan KHONG bao gio la duong dan o dia cuc bo hop le) de moi noi goi ham
    // nay (HasLocalDriveRoot, IsPathUnderDirectoryLexical) deu tu dong tu
    // choi, thay vi am tham tra ve mot duong dan cat cut trong co ve hop le.
    private const string ReparseLimitExceededSentinel = @"\\reparse-hop-limit-exceeded\deny";

    public static string ResolveRealPath(string fullPath)
    {
        string root = Path.GetPathRoot(fullPath) ?? string.Empty;
        if (root.Length == 0) return fullPath;

        var relative = fullPath.Substring(root.Length);
        var segments = relative.Split(
            new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
            StringSplitOptions.RemoveEmptyEntries);

        string current = root;
        int reparseHops = 0;

        foreach (var segment in segments)
        {
            current = Path.Combine(current, segment);

            FileAttributes attrs;
            try
            {
                attrs = File.GetAttributes(current);
            }
            catch
            {
                // Thanh phan chua ton tai (hoac khong doc duoc) — khong the
                // la reparse point, giu nguyen va tiep tuc ghep cac thanh
                // phan con lai theo dang lexical.
                continue;
            }

            if ((attrs & FileAttributes.ReparsePoint) == 0) continue;
            if (++reparseHops > MaxReparseHops) return ReparseLimitExceededSentinel;

            string? target;
            try
            {
                FileSystemInfo info = (attrs & FileAttributes.Directory) != 0
                    ? new DirectoryInfo(current)
                    : new FileInfo(current);
                target = info.ResolveLinkTarget(returnFinalTarget: true)?.FullName;
            }
            catch
            {
                target = null;
            }

            if (!string.IsNullOrEmpty(target))
            {
                current = target;
            }
        }

        return current;
    }
}
