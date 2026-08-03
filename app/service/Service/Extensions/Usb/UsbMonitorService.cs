using System.Management;
using Antivirus.Service.FullScan;

namespace Antivirus.Service.Extensions.Usb;

// "tai lieu moi.txt" muc "Kiem soat thiet bi USB khi cam vao may" +
// "Chinh sach allow/block theo VID/PID thiet bi".
//
// [QUYET DINH TRIEN KHAI] Tai lieu dung WM_DEVICECHANGE/RegisterDeviceNotification
// (can mot message-pump window hoac handle service kernel, va bat su kien
// TUC THOI). Antivirus.Service la Worker Service khong co message loop —
// thay bang POLLING danh sach o dia moi vai giay (DriveInfo.GetDrives()),
// phat hien o Removable MOI xuat hien, roi tra VID/PID qua WMI
// (Win32_DiskDrive.PNPDeviceID) — cham hon vai giay so voi thong bao kernel
// tuc thi nhung van la phat hien THAT dua tren thiet bi that, khong gia lap.
public sealed class UsbMonitorService : BackgroundService
{
    private readonly UsbRuleStore _rules;
    private readonly FullScanService _fullScan;
    private readonly EventBus _eventBus;
    private readonly ILogger<UsbMonitorService> _logger;

    private HashSet<string> _knownDrives = new();

    public sealed class UsbArrivalRecord
    {
        public required string DriveLetter { get; init; }
        public required string VendorId { get; init; }
        public required string ProductId { get; init; }
        public string? SerialNumber { get; init; }
        public required string ResolvedAction { get; init; }
        public bool AutoScanTriggered { get; init; }
        public long DetectedAtUnixMs { get; init; }
    }

    private readonly List<UsbArrivalRecord> _recentArrivals = new();
    private readonly object _lock = new();

    public UsbMonitorService(UsbRuleStore rules, FullScanService fullScan, EventBus eventBus, ILogger<UsbMonitorService> logger)
    {
        _rules = rules;
        _fullScan = fullScan;
        _eventBus = eventBus;
        _logger = logger;
    }

    public IReadOnlyList<UsbArrivalRecord> GetRecentArrivals()
    {
        lock (_lock) { return _recentArrivals.TakeLast(50).ToList(); }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _knownDrives = GetCurrentRemovableDrives();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var current = GetCurrentRemovableDrives();
                var newDrives = current.Except(_knownDrives).ToList();
                foreach (var drive in newDrives) HandleArrival(drive);
                _knownDrives = current;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Loi kiem tra o dia rieng biet");
            }

            try { await Task.Delay(TimeSpan.FromSeconds(3), stoppingToken); }
            catch (TaskCanceledException) { }
        }
    }

    private static HashSet<string> GetCurrentRemovableDrives()
    {
        return DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Removable && d.IsReady)
            .Select(d => d.Name)
            .ToHashSet();
    }

    private void HandleArrival(string driveLetter)
    {
        var (vendorId, productId, serial) = ResolveDeviceIds(driveLetter);
        if (vendorId is null || productId is null)
        {
            _logger.LogWarning("Khong tra duoc VID/PID cho o dia {Drive}", driveLetter);
            return;
        }

        var policy = _rules.ResolvePolicy(vendorId, productId, serial);
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        bool autoScanTriggered = false;

        if (policy.Action != UsbAction.Block && policy.AutoScan)
        {
            // "kich hoat full scan CHI TREN volume vua gan (dung lai dung
            // scan engine da co, gioi han pham vi enumerate vao volume moi
            // thay vi toan bo o dia)".
            autoScanTriggered = _fullScan.Start(driveLetter);
        }

        var record = new UsbArrivalRecord
        {
            DriveLetter = driveLetter,
            VendorId = vendorId,
            ProductId = productId,
            SerialNumber = serial,
            ResolvedAction = policy.Action.ToString(),
            AutoScanTriggered = autoScanTriggered,
            DetectedAtUnixMs = now,
        };
        lock (_lock)
        {
            _recentArrivals.Add(record);
            if (_recentArrivals.Count > 200) _recentArrivals.RemoveAt(0);
        }

        _eventBus.Publish(new CorrelationEvent
        {
            EntityKey = $"usb:{vendorId}:{productId}:{serial ?? "?"}",
            SourceEngine = "usb",
            Severity = policy.Action == UsbAction.Block ? 60 : (policy.Action == UsbAction.Ask ? 30 : 5),
            Summary = $"Thiet bi USB moi {driveLetter} (VID={vendorId} PID={productId}) — chinh sach: {policy.Action}" +
                      (autoScanTriggered ? ", da tu dong quet" : ""),
            TimestampUnixMs = now,
        });
    }

    // Tra VID/PID/serial qua Win32_DiskDrive.PNPDeviceID, dinh dang chuan
    // cua Windows: "USBSTOR\DISK&VEN_...&PROD_...&REV_...\<serial>&0"
    // hoac "USB\VID_xxxx&PID_yyyy\<serial>". Chi loc thiet bi USBSTOR (mass
    // storage) — KHONG xu ly HID (ban phim/chuot), dung theo pham vi tai lieu.
    private static (string? VendorId, string? ProductId, string? Serial) ResolveDeviceIds(string driveLetter)
    {
        try
        {
            string driveLetterNoSlash = driveLetter.TrimEnd('\\');
            using var searcher = new ManagementObjectSearcher(
                $"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{driveLetterNoSlash}'}} WHERE AssocClass=Win32_LogicalDiskToPartition");

            foreach (ManagementObject partition in searcher.Get())
            {
                using var diskSearcher = new ManagementObjectSearcher(
                    $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{partition["DeviceID"]}'}} WHERE AssocClass=Win32_DiskDriveToDiskPartition");

                foreach (ManagementObject disk in diskSearcher.Get())
                {
                    string? pnpId = disk["PNPDeviceID"]?.ToString();
                    if (pnpId is null) continue;
                    return ParsePnpDeviceId(pnpId);
                }
            }
        }
        catch
        {
            // WMI co the khong san sang/loi tren mot so cau hinh — tra ve
            // null, HandleArrival se log va bo qua thiet bi nay.
        }
        return (null, null, null);
    }

    public static (string? VendorId, string? ProductId, string? Serial) ParsePnpDeviceId(string pnpId)
    {
        // Vi du: "USBSTOR\DISK&VEN_KINGSTON&PROD_DATATRAVELER&REV_1.00\112233445566&0"
        // hoac:  "USB\VID_0951&PID_1666\112233445566"
        var upper = pnpId.ToUpperInvariant();
        string? vid = ExtractTag(upper, "VID_") ?? ExtractTag(upper, "VEN_");
        string? pid = ExtractTag(upper, "PID_") ?? ExtractTag(upper, "PROD_");

        string? serial = null;
        var parts = pnpId.Split('\\');
        if (parts.Length >= 3)
        {
            serial = parts[2].Split('&')[0];
        }

        return (vid, pid, serial);
    }

    private static string? ExtractTag(string source, string tag)
    {
        int idx = source.IndexOf(tag, StringComparison.Ordinal);
        if (idx < 0) return null;
        int start = idx + tag.Length;
        int end = start;
        while (end < source.Length && source[end] != '&' && source[end] != '\\') end++;
        return end > start ? source[start..end] : null;
    }
}
