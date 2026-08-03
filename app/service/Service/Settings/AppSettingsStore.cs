using System.Text.Json;

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
    private AppSettings _settings;

    public AppSettingsStore(string settingsFilePath)
    {
        _path = settingsFilePath;
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
            }
        }
        catch
        {
            // File hong/khong doc duoc -> dung mac dinh, khong chan khoi dong service.
        }
        return new AppSettings();
    }
}
