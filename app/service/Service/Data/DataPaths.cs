namespace Antivirus.Service.Data;

// Duong dan thu muc du lieu cuc bo cua app — theo dung mo ta trong
// data-models/04 va security/09: "thu muc du lieu duoc ACL bao ve chi cho
// SYSTEM va Administrator ghi duoc".
public static class DataPaths
{
    // ProgramData la vi tri dung cho du lieu dich vu he thong (khong phai
    // AppData nguoi dung, vi service chay quyen SYSTEM doc lap voi UI).
    public static string RootDir { get; } = Path.Combine(
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
    public static string FullScanStatePath => Path.Combine(StateDir, "fullscan.state.json");
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

    private static string EnsureDir(string path)
    {
        Directory.CreateDirectory(path);
        return path;
    }
}
