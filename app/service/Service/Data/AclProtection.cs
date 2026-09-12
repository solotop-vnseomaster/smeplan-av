using System.Security.AccessControl;
using System.Security.Principal;

namespace Antivirus.Service.Data;

// SEC-06: "ACL: chi SYSTEM/Administrator ghi duoc thu muc du lieu (rule DB),
// chi SYSTEM doc/ghi quarantine" (security/09-bao-mat.md muc 2, 3).
// Neu tien trinh thuong ghi duoc truc tiep vao rule DB, toan bo co che phan
// quyen sup do vi malware chi can tu them rule "Cho phep luon" cho chinh no.
public static class AclProtection
{
    private static readonly SecurityIdentifier SystemSid =
        new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdminsSid =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    // [SUA LOI NGHIEM TRONG — CHU SO HUU] DACL khong phai la lop phong thu
    // cuoi cung: tren NTFS, CHU SO HUU cua mot doi tuong LUON giu ngam
    // READ_CONTROL va WRITE_DAC, bat ke DACL noi gi. Truoc day khong cho
    // nao trong file nay goi SetOwner, trong khi cac thu muc du lieu lai
    // duoc tao boi loi goi DataPaths.EnsureDir dau tien — co the la mot
    // tien trinh quyen thap chay TRUOC service (thu muc con cua ProgramData
    // mac dinh cho Users quyen tao). Ke tao ra thu muc do tro thanh chu so
    // huu vinh vien va co the tu cap lai quyen BAT CU LUC NAO, ke ca ngay
    // sau khi SetAccessRuleProtection(true, false) vua siet DACL xong —
    // nghia la toan bo co che ACL o duoi chi la trang tri.
    // Sua: truoc khi ghi DACL, bao dam chu so huu la mot principal tin cay;
    // neu khong doat duoc quyen so huu thi KHONG ghi DACL nua ma bao loi
    // len tren (fail-loud), vi mot DACL chat tren doi tuong do ke tan cong
    // so huu tao ra cam giac an toan gia.
    private static bool IsTrustedOwner(IdentityReference? owner)
    {
        if (owner is null) return false;
        SecurityIdentifier sid;
        try
        {
            sid = owner as SecurityIdentifier
                  ?? (SecurityIdentifier)owner.Translate(typeof(SecurityIdentifier));
        }
        catch
        {
            return false;
        }
        return sid == SystemSid || sid == AdminsSid || sid == WindowsIdentity.GetCurrent().User;
    }

    // Thu tu uu tien: SYSTEM (danh tinh cua service that) -> Administrators
    // -> danh tinh dang chay (moi truong dev khong elevate).
    private static IEnumerable<SecurityIdentifier> TrustedOwnerCandidates()
    {
        yield return SystemSid;
        yield return AdminsSid;
        var current = WindowsIdentity.GetCurrent().User;
        if (current is not null) yield return current;
    }

    // Ghi security descriptor xuong dia, doat quyen so huu truoc neu chu so
    // huu hien tai khong dang tin. Nem neu khong lam duoc — xem ghi chu tren.
    private static void CommitWithTrustedOwner(
        FileSystemSecurity security, string path, Action commit)
    {
        IdentityReference? currentOwner = null;
        try { currentOwner = security.GetOwner(typeof(SecurityIdentifier)); }
        catch { /* khong doc duoc chu so huu -> coi nhu khong dang tin */ }

        if (IsTrustedOwner(currentOwner))
        {
            commit();
            return;
        }

        Exception? lastError = null;
        foreach (var candidate in TrustedOwnerCandidates())
        {
            try
            {
                security.SetOwner(candidate);
                commit();
                return;
            }
            catch (Exception ex)
            {
                lastError = ex;
            }
        }

        throw new InvalidOperationException(
            $"Khong doat duoc quyen so huu cho '{path}' (chu so huu hien tai: " +
            $"{currentOwner?.ToString() ?? "khong doc duoc"}). Chu so huu giu WRITE_DAC ngam nen " +
            "viec siet DACL se khong co tac dung — tu choi bao ve nua voi.", lastError);
    }

    // [SUA LOI] Ban truoc CHI cap FullControl cho SID SYSTEM/Administrators
    // (nhom), khong bao gio cap cho danh tinh THUC SU dang chay tien trinh.
    // Tren may san xuat that, service chay duoi LocalSystem nen khong sao —
    // nhung trong moi truong dev/test KHONG elevate (`dotnet run` thong
    // thuong), token cua tien trinh KHONG bat "Administrators" trong danh
    // sach nhom du tai khoan dang nhap co quyen admin (UAC loc bo group do
    // o token mac dinh) — ket qua la CHINH TIEN TRINH VUA TAO RA THU MUC bi
    // tu khoa ra khoi du lieu cua no ngay sau khi goi ham nay (moi lan doc/
    // ghi tiep theo trong CUNG mot lan chay se nem UnauthorizedAccessException).
    // Sua: LUON cap them cho danh tinh dang chay tien trinh hien tai
    // (WindowsIdentity.GetCurrent().User), ben canh SYSTEM/Administrators —
    // trong production danh tinh do la SYSTEM (da co san), trong dev/test
    // do la user hien tai, dam bao tien trinh luon truy cap duoc file/thu
    // muc chinh no vua tao ra du chay elevate hay khong.
    public static void ProtectDataDirectory(string path)
    {
        var dirInfo = new DirectoryInfo(path);
        var security = dirInfo.GetAccessControl();
        security.SetAccessRuleProtection(true, false);
        PurgeExplicitAccessRules(security); // ngat ke thua, khong giu rule cu

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var currentUser = WindowsIdentity.GetCurrent().User;

        security.AddAccessRule(new FileSystemAccessRule(
            system, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            admins, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        if (currentUser is not null && currentUser != system)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                currentUser, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        }

        CommitWithTrustedOwner(security, dirInfo.FullName, () => dirInfo.SetAccessControl(security));
    }

    // Khoa ACL cho MOT FILE cu the (khong phai thu muc) — dung cho cac file
    // bi mat nhu PFX khoa riêng ky goi cap nhat va file token API, noi ma
    // dua vao ACL ke thua tu thu muc cha la khong du chac chan (thu muc cha
    // co the bi doi ACL sau do, hoac file duoc tao truoc khi thu muc kip
    // duoc bao ve).
    // [SUA LOI NGHIEM TRONG] SetAccessRuleProtection(true, false) CHI ngat ke
    // thua va bo cac ACE KE THUA — no KHONG dong den ACE EXPLICIT da co san
    // tren doi tuong. Sau do code ben duoi chi AddAccessRule, khong bao gio
    // xoa gi. Nghia la mot ACE explicit do KE TAN CONG dat truoc van con
    // nguyen sau khi lop "gia co" chay xong.
    //
    // Kich ban khai thac, khong can dac quyen: nguoi dung thuong tao truoc
    // %ProgramData%\AntivirusApp\data\api-token.txt (thu muc cha ke thua tu
    // ProgramData cho phep CREATOR OWNER) voi mot ACE Everyone:FullControl.
    // Service khoi dong, ghi token MOI vao dung file do, goi ProtectFile —
    // ACE Everyone song sot. Ke tan cong doc duoc token gac TOAN BO /api/*
    // cua mot service chay LocalSystem. Cung duong do ap cho file PFX chua
    // khoa rieng ky goi cap nhat.
    //
    // Purge sach ACE explicit truoc khi dung lai DACL la cach duy nhat khien
    // ket qua cuoi cung khong phu thuoc vao trang thai co truoc cua file.
    private static void PurgeExplicitAccessRules(FileSystemSecurity security)
    {
        var existing = security.GetAccessRules(
            includeExplicit: true, includeInherited: false, targetType: typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in existing)
        {
            security.RemoveAccessRuleSpecific(rule);
        }
    }

    public static void ProtectFile(string path)
    {
        var fileInfo = new FileInfo(path);
        var security = fileInfo.GetAccessControl();
        security.SetAccessRuleProtection(true, false);
        PurgeExplicitAccessRules(security);

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var currentUser = WindowsIdentity.GetCurrent().User;

        security.AddAccessRule(new FileSystemAccessRule(
            system, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            admins, FileSystemRights.FullControl, AccessControlType.Allow));
        if (currentUser is not null && currentUser != system)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                currentUser, FileSystemRights.FullControl, AccessControlType.Allow));
        }

        CommitWithTrustedOwner(security, fileInfo.FullName, () => fileInfo.SetAccessControl(security));
    }

    public static void ProtectQuarantineDirectory(string path)
    {
        var dirInfo = new DirectoryInfo(path);
        var security = dirInfo.GetAccessControl();
        security.SetAccessRuleProtection(true, false);
        PurgeExplicitAccessRules(security);

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var currentUser = WindowsIdentity.GetCurrent().User;
        // Chi SYSTEM (+ danh tinh dang chay tien trinh hien tai — xem ghi
        // chu tren ProtectDataDirectory) doc/ghi quarantine, KHONG cap cho
        // Administrators noi chung (khac voi thu muc rule DB) — dung theo
        // bang phan quyen security/09 muc 2: "SYSTEM (qua ACL thu muc
        // quarantine) - Duy nhat co quyen doc/ghi khu vuc quarantine".
        security.AddAccessRule(new FileSystemAccessRule(
            system, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        if (currentUser is not null && currentUser != system)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                currentUser, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        }

        CommitWithTrustedOwner(security, dirInfo.FullName, () => dirInfo.SetAccessControl(security));
    }

    // [SUA LOI NGHIEM TRONG] TRUOC DAY chi DataDir, thu muc token va
    // quarantine duoc ACL — RootDir, signatures/, yara-rules/, logs/,
    // state/, version-store/ va cac thu muc drop cap nhat KHONG BAO GIO
    // duoc bao ve, du DataPaths.cs tu nhan nguoc lai. Hau qua truc tiep:
    //  - state/signature_accumulator.csv (goc tin cay THAT cua CSDL chu ky,
    //    van ban thuan khong ky) sua duoc bang quyen user thuong -> xoa am
    //    tham tung chu ky;
    //  - signatures/*.avsigdb sua duoc -> zero-hoa vai byte bloom filter la
    //    bypass co muc tieu, Lookup thoat som, RecordCount van bao du;
    //  - logs/audit.jsonl sua/xoa duoc -> khong con gia tri lam bang chung;
    //  - version-store/ ghi duoc -> dau doc snapshot rollback ransomware;
    //  - update-drop*/ va company-cert PFX ghi/doc duoc -> tu ky goi cap
    //    nhat va ep service SYSTEM nap CSDL do attacker soan.
    // Sua: khoa TAT CA thu muc du lieu ngay luc khoi dong, RootDir truoc
    // (ngat ke thua o goc) roi tung thu muc con (moi thu muc tu dat ACL
    // rieng de khong phu thuoc ke thua). Quarantine giu quy tac chat hon
    // (khong cap cho Administrators) nen duoc goi rieng SAU cung.
    public static IReadOnlyList<string> ProtectAllDataDirectories(Action<string, Exception>? onError = null)
    {
        var failed = new List<string>();

        void Try(string dir, Action<string> protect)
        {
            try
            {
                Directory.CreateDirectory(dir);
                protect(dir);
            }
            catch (Exception ex)
            {
                // Khong nem ra ngoai: mot thu muc khong khoa duoc (vi du dang
                // bi tien trinh khac giu, hoac chay khong du quyen trong
                // dev) khong duoc phep chan service khoi dong — nhung PHAI
                // duoc bao cao ro rang thay vi nuot im lang, vi day chinh la
                // mau "catch {} roi audit ghi thanh cong" ma review chi ra.
                failed.Add(dir);
                onError?.Invoke(dir, ex);
            }
        }

        // RootDir truoc tien: ngat ke thua tu ProgramData (mac dinh cho
        // Users quyen ghi + CREATOR OWNER full control tren file tu tao).
        Try(DataPaths.RootDir, ProtectDataDirectory);

        foreach (var dir in DataPaths.AllProtectedDirectories)
        {
            Try(dir, ProtectDataDirectory);
        }

        // Quarantine sau cung va bang quy tac rieng (chi SYSTEM).
        Try(DataPaths.QuarantineDir, ProtectQuarantineDirectory);

        return failed;
    }
}
