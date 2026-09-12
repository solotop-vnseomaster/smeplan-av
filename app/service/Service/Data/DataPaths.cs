namespace Antivirus.Service.Data;

// Duong dan thu muc du lieu cuc bo cua app — theo dung mo ta trong
// data-models/04 va security/09: "thu muc du lieu duoc ACL bao ve chi cho
// SYSTEM va Administrator ghi duoc".
public static class DataPaths
{
    // ProgramData la vi tri dung cho du lieu dich vu he thong (khong phai
    // AppData nguoi dung, vi service chay quyen SYSTEM doc lap voi UI).
    // [SUA LOI] Cho phep DOI GOC bang bien moi truong.
    //
    // TRUOC DAY RootDir la hang so tro thang vao %ProgramData%\AntivirusApp,
    // khong co duong nao thay the. Hau qua: bo test chay tren thu muc du lieu
    // THAT cua san pham — CompanyCertificateProviderTests ghi ca file PFX
    // chua KHOA RIENG vao do. Chung "chay duoc" chi vi thu muc do chua duoc
    // khoa ACL; noi cach khac, bo test dua vao viec may dang KHONG an toan.
    // Sau khi cai dat that (ACL chi cho SYSTEM + Administrators), chung do
    // ngay voi UnauthorizedAccessException.
    //
    // Do la loi cua test, khong phai cua ACL: mot bo test khong duoc dong
    // vao du lieu san xuat tren may chay no. Bien moi truong nay la duong de
    // test tro sang thu muc tam; ma san xuat khong bao gio dat no.
    public const string RootDirOverrideEnvVar = "SMEPLANAV_DATA_ROOT";

    public static string RootDir { get; } =
        Environment.GetEnvironmentVariable(RootDirOverrideEnvVar) is { Length: > 0 } custom
            ? custom
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "AntivirusApp");

    public static string DataDir => EnsureDir(Path.Combine(RootDir, "data"));
    public static string QuarantineDir => EnsureDir(Path.Combine(RootDir, "quarantine"));
    public static string SignatureDir => EnsureDir(Path.Combine(RootDir, "signatures"));
    public static string YaraRulesDir => EnsureDir(Path.Combine(RootDir, "yara-rules"));
    public static string LogDir => EnsureDir(Path.Combine(RootDir, "logs"));
    public static string StateDir => EnsureDir(Path.Combine(RootDir, "state"));

    public static string RulesDbPath => Path.Combine(DataDir, "rules.db");
    public static string QuarantineDbPath => Path.Combine(DataDir, "quarantine.db");
    public static string SignatureDbPath => Path.Combine(SignatureDir, "signatures.avsigdb");
    public static string AuditLogPath => Path.Combine(LogDir, "audit.jsonl");
    public static string ScanCacheDbPath => Path.Combine(DataDir, "scan_cache.db");
    public static string SettingsPath => Path.Combine(DataDir, "settings.json");
    public static string FirewallRulesDbPath => Path.Combine(DataDir, "firewall_rules.db");
    public static string UsbRulesDbPath => Path.Combine(DataDir, "usb_rules.db");
    public static string VersionStoreDbPath => Path.Combine(DataDir, "version_store.db");
    public static string VersionStoreDir => EnsureDir(Path.Combine(RootDir, "version-store"));
    public static string CamMicWhitelistDbPath => Path.Combine(DataDir, "cam_mic_whitelist.db");
    public static string KnownNetworkDevicesDbPath => Path.Combine(DataDir, "known_network_devices.db");
    public static string CloudReputationDbPath => Path.Combine(DataDir, "cloud_reputation_mock.db");
    public static string PhishingListDbPath => Path.Combine(DataDir, "phishing_list.db");

    // Thu muc drop cho goi cap nhat — TRUOC DAY nam ngoai moi pham vi ACL
    // (Program.cs chi khoa RootDir/data), nen user thuong ghi duoc goi vao
    // day. Khai bao tap trung o dday de khong con noi nao tu ghep chuoi
    // duong dan drop ma quen dua vao danh sach can bao ve.
    public static string UpdateDropDir => EnsureDir(Path.Combine(RootDir, "update-drop"));
    public static string PhishingUpdateDropDir => EnsureDir(Path.Combine(RootDir, "update-drop-phishing"));

    // Danh sach DUY NHAT cac thu muc phai duoc ACL bao ve luc khoi dong
    // (xem AclProtection.ProtectAllDataDirectories). Them thu muc du lieu
    // moi o tren thi PHAI them vao day — day la cho duy nhat quyet dinh
    // "thu muc nay co duoc bao ve khong".
    public static IReadOnlyList<string> AllProtectedDirectories => new[]
    {
        DataDir,
        SignatureDir,
        YaraRulesDir,
        LogDir,
        StateDir,
        VersionStoreDir,
        UpdateDropDir,
        PhishingUpdateDropDir,
    };

    private static string EnsureDir(string path)
    {
        Directory.CreateDirectory(path);
        return path;
    }
}
