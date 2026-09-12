using System.Text.Json;
using Antivirus.Service.Audit;

namespace Antivirus.Service.Settings;

public sealed class AppSettings
{
    // Nguoi dung yeu cau: nut bat/tat cache full scan (skip file khong doi
    // so voi lan quet truoc, cung phien ban CSDL). Mac dinh BAT vi day la
    // toi uu an toan khi da gan dung version CSDL (xem ScanCacheStore).
    public bool FullScanCacheEnabled { get; set; } = true;

    // "tai lieu moi.txt" muc "Tich hop cloud threat intelligence": "cho
    // phep nguoi dung tat hoan toan tinh nang nay (chap nhan do tre phat
    // hien threat moi cao hon) neu uu tien khong muon hash file cua minh
    // roi khoi may duoi bat ky hinh thuc nao". Mac dinh BAT vi loi ich phat
    // hien threat moi vuot troi hon so voi viec chi gui HASH (khong phai
    // noi dung file).
    public bool CloudIntelEnabled { get; set; } = true;
}

// Luu cai dat don gian dang JSON — chi mot vai co bat/tat, khong can SQLite.
public sealed class AppSettingsStore
{
    private readonly string _path;
    private readonly object _lock = new();
    private readonly AuditLogger? _audit;
    private AppSettings _settings;

    // [SUA LOI] "audit" la tham so tuy chon (khong bat buoc DI) de khong phai
    // sua moi noi dang goi "new AppSettingsStore(path)" truc tiep (Program.cs,
    // test) — nhung khi co, Load() se ghi audit log khi JSON hong thay vi
    // AM THAM roi ve mac dinh. Xem ghi chu trong Load(): mac dinh
    // CloudIntelEnabled=true la mot downgrade privacy that su neu nguoi dung
    // da tung tat no va file settings.json sau do bi hong/bi ghi de.
    public AppSettingsStore(string settingsFilePath, AuditLogger? audit = null)
    {
        _path = settingsFilePath;
        _audit = audit;
        _settings = Load();
    }

    public AppSettings Current
    {
        get { lock (_lock) { return _settings; } }
    }

    public void Update(Action<AppSettings> mutate)
    {
        lock (_lock)
        {
            mutate(_settings);
            File.WriteAllText(_path, JsonSerializer.Serialize(_settings));
        }
    }

    private AppSettings Load()
    {
        try
        {
            if (File.Exists(_path))
            {
                var json = File.ReadAllText(_path);
                var loaded = JsonSerializer.Deserialize<AppSettings>(json);
                if (loaded is not null) return loaded;

                // JsonSerializer.Deserialize tra ve null cho input hop le
                // cu phap nhung khong phai object (vi du "null" hoac mang
                // rong) — cung la truong hop can fallback ve mac dinh, KHONG
                // im lang bo qua khong log nhu ngoai le ben duoi.
                LogCorruptSettings(exception: null);
            }
        }
        catch (Exception ex)
        {
            // [SUA LOI] File hong/khong doc duoc -> dung mac dinh (khong
            // chan khoi dong service), NHUNG truoc day hoan toan AM THAM,
            // khong log gi ca. AppSettings.CloudIntelEnabled mac dinh la
            // true (bat) — neu nguoi dung da tung tat CloudIntel va file
            // settings.json sau do bi hong (crash giua luc ghi, hoac bi mot
            // tien trinh khac ghi de), lan khoi dong tiep theo se AM THAM
            // BAT LAI CloudIntel ma khong canh bao gi, tuong duong mot
            // downgrade privacy khong chu y. Ghi audit log de it nhat co the
            // phat hien duoc su co nay, du hanh vi fallback (dung mac dinh
            // an toan, khong crash service) van giu nguyen.
            LogCorruptSettings(exception: ex);
        }
        return new AppSettings();
    }

    private void LogCorruptSettings(Exception? exception)
    {
        try
        {
            _audit?.Log("settings",
                "settings.json khong doc duoc hoac khong hop le - dung mac dinh (CloudIntelEnabled=true, FullScanCacheEnabled=true). " +
                "Neu nguoi dung da tung tat CloudIntel, gia tri do se bi mat cho toi khi luu lai qua UI.",
                new { path = _path, error = exception?.Message });
        }
        catch { /* khong de loi ghi audit lam hong luong khoi dong settings */ }
    }
}
