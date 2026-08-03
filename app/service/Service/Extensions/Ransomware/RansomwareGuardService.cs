using System.Collections.Concurrent;

namespace Antivirus.Service.Extensions.Ransomware;

// "tai lieu moi.txt" muc "Phat hien hanh vi ransomware dang ma hoa hang
// loat file" — BA tin hieu phai xuat hien DONG THOI trong cung cua so thoi
// gian ngan (10-30s) truoc khi ket luan ransomware:
//   1. Toc do ghi/doi ten vuot nguong bat thuong so voi baseline may do.
//   2. Entropy noi dung tang vot so voi phien ban truoc.
//   3. Phan mo rong bi doi hang loat sang CUNG mot duoi la.
//
// [QUYET DINH TRIEN KHAI] Tai lieu dat viec chan/backup tai callback
// kernel IRP_MJ_WRITE/IRP_MJ_SET_INFORMATION (bat duoc TRUOC khi ghi xay
// ra, va biet chinh xac PID). Moi truong nay khong co WDK nen dung
// FileSystemWatcher (user-mode) — he qua: (a) snapshot chi chac chan co
// "ban sao sach" cho file ĐÃ TỒN TẠI truoc luc service khoi dong (baseline
// quet luc dau), file tao SAU do se duoc snapshot ngay lan dau quan sat
// thay vi truoc khi bi ghi; (b) KHONG co PID chinh xac cua tien trinh ghi
// (FileSystemWatcher khong cung cap), nen rollback thuc hien theo DUONG
// DAN trong cua so phat hien thay vi theo triggered_by_pid nhu tai lieu
// mo ta; (c) whitelist rieng cho quyen ghi (EXT-RW-02/06) THEO TUNG TIEN
// TRINH khong the ap dung o CHINH class nay vi FileSystemWatcher (API
// .NET) khong bao gio cung cap PID cua tien trinh vua ghi — day la gioi
// han cua chinh API, khong phai thieu sot trien khai. [SUA GHI CHU] Ban
// truoc day tung ghi sai la "da thay bang nguong phat hien cao hon" —
// khong dung, khong co co che fallback nao nhu vay ton tai trong class
// nay (WriteRateThreshold/EntropyJumpThreshold/ExtensionBurstThreshold la
// hang so co dinh, khong doi theo whitelist). Thiet ke DUNG cho whitelist
// theo PID chi kha thi qua driver kernel that (xem
// app/drivers/minifilter/minifilter.c QueryProtectedFolderWrite — nhan
// duoc PsGetCurrentProcessId() chinh xac qua MsgType_ProtectedWriteQuery,
// service co the tra whitelist bang PID that o do), nhung driver chua
// duoc bien dich/nap (khong co WDK — xem app/drivers/README.md), nen day
// van la HAN CHE THAT trong pham vi dang chay duoc cua phien nay.
public sealed class RansomwareGuardService : BackgroundService
{
    public sealed class RansomwareAlert
    {
        public required List<string> AffectedPaths { get; init; }
        public int WriteRateSignal { get; init; }
        public int EntropyJumpSignal { get; init; }
        public int ExtensionBurstSignal { get; init; }
        public required string CommonNewExtension { get; init; }
        public long DetectedAtUnixMs { get; init; }
        public bool AutoRolledBack { get; init; }
    }

    private static readonly TimeSpan WindowDuration = TimeSpan.FromSeconds(20);
    private const int WriteRateThreshold = 15; // so file khac nhau bi ghi/doi ten trong 1 cua so
    private const double EntropyJumpThreshold = 1.5; // bit/byte tang them
    private const double HighEntropyFloor = 7.0;
    private const int ExtensionBurstThreshold = 8; // so file cung doi sang 1 duoi la trong 1 cua so

    private readonly VersionStore _versionStore;
    private readonly EventBus _eventBus;
    private readonly ILogger<RansomwareGuardService> _logger;

    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentQueue<(string Path, long TimestampMs)> _pendingEvents = new();
    private readonly List<RansomwareAlert> _recentAlerts = new();
    private readonly object _alertsLock = new();

    public static readonly string[] DefaultProtectedFolders =
    {
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
    };

    public RansomwareGuardService(VersionStore versionStore, EventBus eventBus, ILogger<RansomwareGuardService> logger)
    {
        _versionStore = versionStore;
        _eventBus = eventBus;
        _logger = logger;
    }

    public IReadOnlyList<RansomwareAlert> GetRecentAlerts()
    {
        lock (_alertsLock) { return _recentAlerts.TakeLast(50).ToList(); }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        BaselineSnapshotExistingFiles();
        StartWatchers();

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(WindowDuration, stoppingToken);
                EvaluateWindow();
            }
        }
        catch (TaskCanceledException) { }
        finally
        {
            foreach (var w in _watchers) w.Dispose();
        }
    }

    // Snapshot cac file DANG CO SAN trong thu muc bao ve luc service vua
    // khoi dong, de dam bao co "ban sao sach" thuc su truoc khi bi tan
    // cong — bu dap cho viec khong co hook pre-write kernel.
    private void BaselineSnapshotExistingFiles()
    {
        // Gioi han vua phai va bo qua file lon (video/ISO...) de tranh
        // chiem qua nhieu dung luong/dia ngay luc dau tren may nguoi dung
        // that — day la ban DEMO minh hoa co che, khong phai backup toan
        // dien moi file nguoi dung co.
        // [HAN CHE DA BIET] File VUOT qua maxFilesToSnapshot hoac lon hon
        // maxFileSizeBytes se KHONG BAO GIO co baseline snapshot — neu
        // ransomware ma hoa dung nhung file nay TRUOC khi co su kien ghi
        // nao khac (FileSystemWatcher chua kip snapshot "lan dau quan sat"
        // cho chung), noi dung goc bi mat vinh vien, RestoreLatestVersion
        // se tra ve false cho cac duong dan do. Day la gioi han co chu y
        // cua ban DEMO minh hoa co che (khong phai backup toan dien), khong
        // phai loi — nhung can neu ro de khong bi hieu nham la "moi file
        // trong thu muc bao ve deu phuc hoi duoc".
        const int maxFilesToSnapshot = 500;
        const long maxFileSizeBytes = 20L * 1024 * 1024; // 20MB
        int count = 0;
        // Dung CHUNG mot ket noi SQLite cho toan bo vong lap (co the qua
        // hang tram file) thay vi moi file tu mo/dong ket noi rieng — xem
        // ghi chu tai VersionStore.OpenBatch.
        using var batch = _versionStore.OpenBatch();
        foreach (var folder in DefaultProtectedFolders)
        {
            if (!Directory.Exists(folder)) continue;

            // [SUA LOI NGHIEM TRONG] try/catch quanh LOI GOI EnumerateFiles
            // khong du — EnumerateFiles tra ve mot iterator LAZY, loi
            // UnauthorizedAccessException (vi du thu muc con la junction/
            // reparse-point khong co quyen doc nhu "My Music") chi thuc su
            // nem ra KHI foreach dang lap, tuc la NGOAI pham vi try/catch
            // nay — lam sap toan bo service ngay luc khoi dong (khong bat
            // duoc, EventBus/RansomwareGuardService la mot HostedService).
            // Sua bang EnumerationOptions.IgnoreInaccessible=true: bo qua
            // rieng le tung thu muc con khong doc duoc thay vi nem ngoai le
            // giua chung lam hong toan bo vong enumerate.
            var enumOptions = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true };
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(folder, "*", enumOptions); }
            catch { continue; }

            foreach (var file in files)
            {
                if (count >= maxFilesToSnapshot) return;
                if (batch.GetLatestVersion(file) is not null) continue; // da co roi
                try { if (new FileInfo(file).Length > maxFileSizeBytes) continue; } catch { continue; }
                batch.SnapshotFile(file, triggeredByPid: 0);
                count++;
            }
        }
        _logger.LogInformation("Ransomware guard: da snapshot baseline {Count} file trong thu muc bao ve", count);
    }

    private void StartWatchers()
    {
        foreach (var folder in DefaultProtectedFolders)
        {
            if (!Directory.Exists(folder)) continue;
            try
            {
                var watcher = new FileSystemWatcher(folder)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName,
                };
                watcher.Changed += (_, e) => OnFileEvent(e.FullPath);
                watcher.Renamed += (_, e) => OnFileEvent(e.FullPath);
                watcher.Created += (_, e) => OnFileEvent(e.FullPath);
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
                _logger.LogInformation("Ransomware guard: dang giam sat {Folder}", folder);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Khong giam sat duoc thu muc {Folder}", folder);
            }
        }
    }

    private void OnFileEvent(string path)
    {
        if (Directory.Exists(path)) return; // bo qua su kien thu muc
        _pendingEvents.Enqueue((path, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));
    }

    private void EvaluateWindow()
    {
        var events = new List<(string Path, long TimestampMs)>();
        while (_pendingEvents.TryDequeue(out var evt)) events.Add(evt);
        if (events.Count == 0) return;

        var distinctPaths = events.Select(e => e.Path).Distinct().ToList();

        // Tin hieu 1: toc do ghi.
        bool writeRateSignal = distinctPaths.Count >= WriteRateThreshold;

        // Tin hieu 2: entropy tang vot (so voi phien ban truoc trong version store).
        // Dong thoi ghi nho TUNG file rieng le co entropy-jump hay khong
        // (suspiciousPaths) — dung lai ben duoi de KHONG snapshot de "phien
        // ban sach moi nhat" cho chinh nhung file nay khi ransomware CHUA
        // duoc xac nhan du 3 tin hieu (xem ghi chu o nhanh else ben duoi).
        int entropyJumps = 0;
        var suspiciousPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // Dung CHUNG mot ket noi SQLite cho ca cua so nay (kiem tra entropy,
        // rollback, snapshot ben duoi co the qua nhieu file) thay vi moi
        // loi goi VersionStore tu mo/dong ket noi rieng — xem ghi chu tai
        // VersionStore.OpenBatch.
        using var batch = _versionStore.OpenBatch();
        foreach (var path in distinctPaths)
        {
            var oldVersion = batch.GetLatestVersion(path);
            if (oldVersion is null || !File.Exists(oldVersion.StoredPath) || !File.Exists(path)) continue;
            try
            {
                double oldEntropy = ComputeEntropySample(oldVersion.StoredPath);
                double newEntropy = ComputeEntropySample(path);
                if (newEntropy > HighEntropyFloor && (newEntropy - oldEntropy) > EntropyJumpThreshold)
                {
                    entropyJumps++;
                    suspiciousPaths.Add(path);
                }
            }
            catch { /* file khoa/da bi xoa giua luc quet — bo qua */ }
        }
        bool entropySignal = entropyJumps >= Math.Max(3, distinctPaths.Count / 3);

        // Tin hieu 3: doi hang loat sang cung mot duoi la.
        var extCounts = distinctPaths
            .Select(Path.GetExtension)
            .Where(ext => !string.IsNullOrEmpty(ext))
            .GroupBy(ext => ext!.ToLowerInvariant())
            .OrderByDescending(g => g.Count())
            .FirstOrDefault();
        bool extensionSignal = extCounts is not null && extCounts.Count() >= ExtensionBurstThreshold;

        int signalCount = (writeRateSignal ? 1 : 0) + (entropySignal ? 1 : 0) + (extensionSignal ? 1 : 0);
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        if (signalCount == 0) return;

        bool ransomwareConfirmed = writeRateSignal && entropySignal && extensionSignal;
        bool rolledBack = false;
        int restoredCount = 0;

        if (ransomwareConfirmed)
        {
            foreach (var path in distinctPaths)
            {
                if (batch.RestoreLatestVersion(path)) restoredCount++;
            }
            // [SUA LOI NGHIEM TRONG] TRUOC DAY rolledBack (va thong bao keo
            // theo) chi phan biet "co khoi phuc duoc it nhat 1 file" (thanh
            // cong) hay "khong khoi phuc duoc file nao" (that bai mot phan) —
            // ke ca khi chi 1/500 file duoc khoi phuc, thong bao van ghi
            // "da tu dong khoi phuc (thanh cong)", khien nguoi dung tuong
            // TOAN BO file da duoc cuu trong khi 499 file con lai da mat
            // vinh vien (vi khong co baseline snapshot — xem ghi chu tren
            // BaselineSnapshotExistingFiles). Sua: rolledBack gio phan anh
            // dung "khoi phuc DAY DU" (restoredCount == distinctPaths.Count),
            // va Summary ben duoi bao ro so lieu X/Y thay vi mot chu
            // "thanh cong" khong dieu kien.
            rolledBack = restoredCount == distinctPaths.Count;
            _logger.LogWarning("RANSOMWARE XAC NHAN: {Count} file bi anh huong, da khoi phuc {Restored} file tu version store",
                distinctPaths.Count, restoredCount);
        }
        else
        {
            // Chi mot/hai tin hieu -> theo doi them, khong tu dong chan
            // (dung theo tai lieu: "hoac ha xuong muc theo doi them").
            //
            // [SUA LOI NGHIEM TRONG] TRUOC DAY ham nay snapshot VO DIEU KIEN
            // toan bo distinctPaths lam "phien ban sach moi nhat", ke ca khi
            // chinh file do vua duoc phat hien co entropy-jump bat thuong
            // (suspiciousPaths o tren) — tuc la NOI DUNG DA CO THE BI MA HOA
            // nhung van duoc luu de roi phia nguoi dung. Neu ransomware chi
            // moi dat 1-2/3 tin hieu trong cua so nay (vi du entropy+extension
            // nhung chua du toc do ghi) va van tiep tuc ma hoa them file o
            // cua so SAU, ban "sach" gia nay se day lui/ghi de phien ban sach
            // that trong luot xoay vong MaxVersionsPerFile=3 — khi ransomware
            // cuoi cung du 3 tin hieu, rollback se khoi phuc lai chinh noi
            // dung da bi ma hoa, lam mat tac dung tinh nang chong ransomware.
            // Sua: BO QUA snapshot cho nhung file da tu minh cho thay entropy-
            // jump bat thuong (suspiciousPaths) — giu nguyen phien ban sach
            // cu hon trong version store cho toi khi entropy tro lai binh
            // thuong hoac ransomware duoc xac nhan va rollback.
            foreach (var path in distinctPaths.Take(50))
            {
                if (suspiciousPaths.Contains(path)) continue;
                batch.SnapshotFile(path, triggeredByPid: 0);
            }
        }

        var alert = new RansomwareAlert
        {
            AffectedPaths = distinctPaths,
            WriteRateSignal = writeRateSignal ? 1 : 0,
            EntropyJumpSignal = entropySignal ? 1 : 0,
            ExtensionBurstSignal = extensionSignal ? 1 : 0,
            CommonNewExtension = extCounts?.Key ?? "",
            DetectedAtUnixMs = now,
            AutoRolledBack = rolledBack,
        };
        lock (_alertsLock)
        {
            _recentAlerts.Add(alert);
            if (_recentAlerts.Count > 200) _recentAlerts.RemoveAt(0);
        }

        _eventBus.Publish(new CorrelationEvent
        {
            EntityKey = $"ransomware-window:{now}",
            SourceEngine = "ransomware",
            Severity = ransomwareConfirmed ? 95 : (signalCount == 2 ? 55 : 25),
            Summary = ransomwareConfirmed
                ? $"XAC NHAN ransomware: {distinctPaths.Count} file bi anh huong, da khoi phuc {restoredCount}/{distinctPaths.Count} file" +
                  (restoredCount < distinctPaths.Count ? $" ({distinctPaths.Count - restoredCount} file KHONG the khoi phuc duoc)" : "")
                : $"Hoat dong ghi file dang ngo ({signalCount}/3 tin hieu): {distinctPaths.Count} file trong 20s",
            TimestampUnixMs = now,
        });
    }

    private static double ComputeEntropySample(string path)
    {
        const int sampleSize = 65536;
        using var fs = File.OpenRead(path);
        var buffer = new byte[Math.Min(sampleSize, fs.Length)];
        int read = fs.Read(buffer, 0, buffer.Length);
        if (read == 0) return 0;

        var freq = new int[256];
        for (int i = 0; i < read; i++) freq[buffer[i]]++;

        double entropy = 0;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            double p = (double)freq[i] / read;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
