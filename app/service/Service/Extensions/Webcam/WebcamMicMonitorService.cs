using Microsoft.Win32;

namespace Antivirus.Service.Extensions.Webcam;

// "tai lieu moi.txt" muc "Bao ve webcam va microphone khoi truy cap trai phep".
//
// [QUYET DINH TRIEN KHAI] Tai lieu de xuat IoRegisterPlugPlayNotification
// cho device interface KSCATEGORY_VIDEO_CAMERA/KSCATEGORY_AUDIO_RECORDING —
// can driver kernel, va chinh tai lieu cung thua nhan cach nay "chi cho biet
// lich su, khong du nhanh de canh bao NGAY luc dang dien ra" khi dung
// registry. Moi truong nay khong co WDK nen dung CHINH cach do (polling
// registry ConsentStore) lam giai phap DUY NHAT kha thi — do la fallback
// tai lieu da neu san, khong phai tu bien; do tre vai giay thay vi tuc thi.
// Khong co PID chinh xac tu nguon nay (chi co dinh danh tien trinh/package),
// nen overlay "chi bao icon sang len" thuc te theo tai lieu (can ve len man
// hinh o tang UI) duoc thay bang canh bao qua Event Bus + danh sach truy
// cap gan day hien trong UI — cung muc dich "nguoi dung biet duoc ai dang
// truy cap", chi khac co che hien thi.
public sealed class WebcamMicMonitorService : BackgroundService
{
    public sealed class CamMicAccessRecord
    {
        public required string DeviceType { get; init; } // "webcam" | "microphone"
        public required string ProcessIdentity { get; init; }
        public bool Whitelisted { get; init; }
        public long DetectedAtUnixMs { get; init; }
    }

    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(3);
    private const string ConsentStoreBase = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    private readonly CamMicWhitelistStore _whitelist;
    private readonly EventBus _eventBus;
    private readonly ILogger<WebcamMicMonitorService> _logger;

    private readonly Dictionary<string, HashSet<string>> _previouslyActive = new()
    {
        ["webcam"] = new(),
        ["microphone"] = new(),
    };

    private readonly List<CamMicAccessRecord> _recentAccesses = new();
    private readonly object _lock = new();

    public WebcamMicMonitorService(CamMicWhitelistStore whitelist, EventBus eventBus, ILogger<WebcamMicMonitorService> logger)
    {
        _whitelist = whitelist;
        _eventBus = eventBus;
        _logger = logger;
    }

    public IReadOnlyList<CamMicAccessRecord> GetRecentAccesses()
    {
        lock (_lock) { return _recentAccesses.TakeLast(50).ToList(); }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                foreach (var deviceType in new[] { "webcam", "microphone" })
                {
                    PollDevice(deviceType);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Loi doc ConsentStore");
            }

            try { await Task.Delay(PollInterval, stoppingToken); }
            catch (TaskCanceledException) { }
        }
    }

    // [SUA LOI NGHIEM TRONG] TRUOC DAY doc Registry.CurrentUser. Service chay
    // duoi LocalSystem nen HKCU o day la hive cua chinh SYSTEM (S-1-5-18) —
    // ConsentStore trong hive do KHONG BAO GIO ghi nhan viec nguoi dung that
    // mo webcam/mic, nen module giam sat khong the phat hien duoc bat cu gi
    // trong khi UI van bao dang giam sat. Sua: duyet cac hive nguoi dung
    // DANG DUOC NAP qua HKEY_USERS (xem Common/UserProfiles.OpenLoadedUserHives)
    // — do la noi ConsentStore cua nguoi dung dang dang nhap thuc su nam.
    private void PollDevice(string deviceType)
    {
        var currentlyActive = new HashSet<string>();

        foreach (var (sid, hive) in Antivirus.Service.Common.UserProfiles.OpenLoadedUserHives())
        {
            using (hive)
            {
                try { CollectActiveForHive(hive, deviceType, currentlyActive); }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Khong doc duoc ConsentStore {Device} cua hive {Sid}", deviceType, sid);
                }
            }
        }

        var newlyActive = currentlyActive.Except(_previouslyActive[deviceType]).ToList();
        foreach (var identity in newlyActive)
        {
            HandleNewAccess(deviceType, identity);
        }
        _previouslyActive[deviceType] = currentlyActive;
    }

    private static void CollectActiveForHive(RegistryKey hive, string deviceType, HashSet<string> currentlyActive)
    {
        using var deviceKey = hive.OpenSubKey($@"{ConsentStoreBase}\{deviceType}");
        if (deviceKey is null) return;

        foreach (var subKeyName in deviceKey.GetSubKeyNames())
        {
            if (string.Equals(subKeyName, "NonPackaged", StringComparison.OrdinalIgnoreCase))
            {
                using var nonPackaged = deviceKey.OpenSubKey("NonPackaged");
                if (nonPackaged is null) continue;
                foreach (var appKeyName in nonPackaged.GetSubKeyNames())
                {
                    using var appKey = nonPackaged.OpenSubKey(appKeyName);
                    if (appKey is null) continue;
                    if (IsCurrentlyActive(appKey))
                    {
                        currentlyActive.Add(appKeyName.Replace('#', '\\'));
                    }
                }
                continue;
            }

            using var pkgKey = deviceKey.OpenSubKey(subKeyName);
            if (pkgKey is null) continue;
            if (IsCurrentlyActive(pkgKey))
            {
                currentlyActive.Add(subKeyName);
            }
        }
    }

    // LastUsedTimeStop == 0 nghia la thiet bi DANG duoc mo (chua ket thuc
    // truy cap), theo dung ngu nghia Windows dung cho ConsentStore.
    private static bool IsCurrentlyActive(RegistryKey key)
    {
        var stopRaw = key.GetValue("LastUsedTimeStop");
        if (stopRaw is null) return false;
        long stop = Convert.ToInt64(stopRaw);
        return stop == 0;
    }

    private void HandleNewAccess(string deviceType, string processIdentity)
    {
        bool whitelisted = _whitelist.IsWhitelisted(processIdentity);
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var record = new CamMicAccessRecord
        {
            DeviceType = deviceType,
            ProcessIdentity = processIdentity,
            Whitelisted = whitelisted,
            DetectedAtUnixMs = now,
        };
        lock (_lock)
        {
            _recentAccesses.Add(record);
            if (_recentAccesses.Count > 200) _recentAccesses.RemoveAt(0);
        }

        // "hanh dong mac dinh o day nen la canh bao tuc thi thay vi tu dong
        // chan" — luon chi publish su kien, khong bao gio tu dong thu hoi
        // quyen truy cap thiet bi.
        _eventBus.Publish(new CorrelationEvent
        {
            EntityKey = $"cammic:{deviceType}:{processIdentity}",
            SourceEngine = "cam-mic",
            Severity = whitelisted ? 5 : 50,
            Summary = whitelisted
                ? $"{processIdentity} truy cap {deviceType} (da whitelist)"
                : $"CANH BAO: {processIdentity} vua mo {deviceType}, chua nam trong whitelist",
            TimestampUnixMs = now,
        });
    }
}
