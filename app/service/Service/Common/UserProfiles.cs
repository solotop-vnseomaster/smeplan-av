using Microsoft.Win32;

namespace Antivirus.Service.Common;

// [SUA LOI NGHIEM TRONG] Service nay chay duoi LocalSystem. Moi API "thu muc
// cua nguoi dung hien tai" (Environment.GetFolderPath, Registry.CurrentUser,
// SHGetKnownFolderPath voi hToken = NULL) tra ve du lieu cua chinh tai khoan
// SYSTEM — tuc la C:\Windows\System32\config\systemprofile\... va hive
// S-1-5-18 — CHU KHONG PHAI cua nguoi dung that. Hau qua truoc day:
//   - RansomwareGuardService dat watcher tren systemprofile\Documents (thu
//     muc trong, khong ai ghi vao) => chong ransomware vo hieu 100% trong
//     khi UI van bao dang giam sat;
//   - WebcamMicMonitorService doc ConsentStore trong hive cua SYSTEM =>
//     khong bao gio phat hien duoc app nao dung webcam/mic;
//   - KnownFolders.GetDownloadsPath tra ve systemprofile\Downloads => module
//     quet file tai ve khong quet gi ca.
// Lop nay liet ke cac PROFILE NGUOI DUNG THAT tren may (qua ProfileList
// trong registry) va cac hive DANG DUOC NAP (HKEY_USERS) de cac module tren
// lam viec dung doi tuong can bao ve.
public static class UserProfiles
{
    private const string ProfileListKey =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    // SID cua cac tai khoan dich vu tich hop san — KHONG phai nguoi dung
    // that, phai loai bo neu khong se lap lai dung loi cu duoi mot dang khac.
    private static bool IsBuiltInServiceSid(string sid) =>
        sid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20";

    // Duong dan thu muc profile cua tung nguoi dung that (vi du
    // "C:\Users\an"). Tra ve rong neu khong doc duoc registry — phia goi
    // phai xu ly truong hop rong nhu "khong co gi de bao ve" mot cach ro
    // rang, khong duoc am tham fallback ve profile cua SYSTEM.
    public static IReadOnlyList<string> GetUserProfileDirectories()
    {
        var result = new List<string>();
        try
        {
            using var profileList = Registry.LocalMachine.OpenSubKey(ProfileListKey);
            if (profileList is null) return result;

            foreach (var sid in profileList.GetSubKeyNames())
            {
                if (IsBuiltInServiceSid(sid)) continue;
                // Chi tai khoan nguoi dung that (S-1-5-21-...) moi co profile
                // can bao ve; bo qua moi SID dang khac.
                if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;

                using var profile = profileList.OpenSubKey(sid);
                if (profile?.GetValue("ProfileImagePath") is not string raw) continue;

                string expanded;
                try { expanded = Environment.ExpandEnvironmentVariables(raw); }
                catch { continue; }

                if (string.IsNullOrWhiteSpace(expanded) || !Directory.Exists(expanded)) continue;
                result.Add(expanded);
            }
        }
        catch
        {
            // Khong doc duoc ProfileList (moi truong bi han che) — tra ve
            // danh sach rong; KHONG fallback ve thu muc cua SYSTEM.
        }
        return result;
    }

    // Cac thu muc tai lieu can bao ve khoi ransomware, tren MOI profile
    // nguoi dung that. Ten thu muc dung ten mac dinh cua Windows: doc duong
    // dan da tuy bien cua tung nguoi dung can nap hive cua ho, khong lam
    // duoc mot cach dang tin cay tu service khi ho chua dang nhap.
    public static IReadOnlyList<string> GetProtectedDocumentFolders()
    {
        string[] names = { "Documents", "Pictures", "Desktop" };
        var result = new List<string>();
        foreach (var profile in GetUserProfileDirectories())
        {
            foreach (var name in names)
            {
                var path = Path.Combine(profile, name);
                if (Directory.Exists(path)) result.Add(path);
            }
        }
        return result;
    }

    // Thu muc Downloads cua moi nguoi dung that.
    public static IReadOnlyList<string> GetDownloadsFolders()
    {
        var result = new List<string>();
        foreach (var profile in GetUserProfileDirectories())
        {
            var path = Path.Combine(profile, "Downloads");
            if (Directory.Exists(path)) result.Add(path);
        }
        return result;
    }

    // Cac hive nguoi dung DANG duoc nap (nguoi dung dang dang nhap) — dung
    // thay cho Registry.CurrentUser trong tien trinh SYSTEM. Phia goi chiu
    // trach nhiem Dispose tung key tra ve.
    public static IEnumerable<(string Sid, RegistryKey Hive)> OpenLoadedUserHives()
    {
        string[] sids;
        try { sids = Registry.Users.GetSubKeyNames(); }
        catch { yield break; }

        foreach (var sid in sids)
        {
            if (IsBuiltInServiceSid(sid)) continue;
            if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;
            // Bo qua hive "_Classes" (khong chua cai dat nguoi dung can doc).
            if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;

            RegistryKey? hive;
            try { hive = Registry.Users.OpenSubKey(sid); }
            catch { continue; }
            if (hive is null) continue;

            yield return (sid, hive);
        }
    }
}
