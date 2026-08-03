using System.Collections.Concurrent;
using Antivirus.Service.Audit;
using Antivirus.Service.Engine;
using Antivirus.Service.Models;
using Antivirus.Service.Quarantine;

namespace Antivirus.Service.Downloads;

// flows/11-luong-xu-ly.md muc "Luong phat hien & xu ly file tai ve trong
// Downloads" — day du 5 buoc: bat rename/added, polling xac nhan ghi xong,
// quet dong bo day du (khong bo qua theo phan mo rong), verdict -> hanh dong.
public sealed class DownloadsWatcherService : BackgroundService
{
    private readonly ScanEngineService _engine;
    private readonly QuarantineManager _quarantine;
    private readonly DownloadsDecisionBroker _decisionBroker;
    private readonly AuditLogger _audit;
    private readonly ILogger<DownloadsWatcherService> _logger;
    private readonly BlockingCollection<string> _queue = new();
    private FileSystemWatcher? _watcher;

    public DownloadsWatcherService(ScanEngineService engine, QuarantineManager quarantine,
        DownloadsDecisionBroker decisionBroker, AuditLogger audit, ILogger<DownloadsWatcherService> logger)
    {
        _engine = engine;
        _quarantine = quarantine;
        _decisionBroker = decisionBroker;
        _audit = audit;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var downloadsPath = KnownFolders.GetDownloadsPath();
        if (!Directory.Exists(downloadsPath))
        {
            _logger.LogWarning("Thu muc Downloads khong ton tai: {Path}", downloadsPath);
            return;
        }

        _watcher = new FileSystemWatcher(downloadsPath)
        {
            IncludeSubdirectories = false,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
        };
        // Buoc 2: FILE_ACTION_RENAMED_NEW_NAME (trinh duyet doi ten tu
        // .crdownload/.part) hoac FILE_ACTION_ADDED (cong cu dong lenh).
        _watcher.Renamed += (_, e) => _queue.TryAdd(e.FullPath);
        _watcher.Created += (_, e) => _queue.TryAdd(e.FullPath);
        _watcher.EnableRaisingEvents = true;

        _logger.LogInformation("Downloads watcher da khoi dong tren {Path}", downloadsPath);
        _audit.Log("scan", $"Downloads watcher da khoi dong tren {downloadsPath}");

        await Task.Run(() => ProcessQueue(stoppingToken), stoppingToken);
    }

    private void ProcessQueue(CancellationToken ct)
    {
        foreach (var path in _queue.GetConsumingEnumerable(ct))
        {
            try
            {
                ProcessDownloadedFile(path, ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Loi xu ly file tai ve {Path}", path);
            }
        }
    }

    private void ProcessDownloadedFile(string path, CancellationToken ct)
    {
        // Bo qua file tam cua trinh duyet — ban than file tam se duoc bat lai
        // qua su kien Renamed khi trinh duyet doi ten xong.
        if (path.EndsWith(".crdownload", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".part", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // Buoc 3: xac nhan file da ghi xong bang polling CreateFile exclusive.
        if (!WaitUntilFileReady(path, TimeSpan.FromMilliseconds(200), TimeSpan.FromSeconds(30), ct))
        {
            _logger.LogWarning("File {Path} van bi khoa sau 30s polling (ERROR_SHARING_VIOLATION) — bo qua", path);
            return;
        }
        if (!File.Exists(path)) return;

        // Buoc 4: quet dong bo va day du, KHONG bo qua theo phan mo rong "it
        // rui ro" nhu real-time protection thong thuong.
        var result = _engine.ScanFile(path);

        // Buoc 5: hanh dong theo verdict.
        switch (result.Verdict)
        {
            case ScanVerdict.Clean:
                _audit.Log("scan", $"Downloads: file sach: {path}", result);
                break;

            case ScanVerdict.Malicious:
                _quarantine.QuarantineFile(path, result.Sha256Hex, result.Reason);
                _audit.Log("scan", $"Downloads: MALICIOUS -> da tu dong quarantine: {path}", result);
                break;

            case ScanVerdict.Suspicious:
                var id = _decisionBroker.Add(path, result.Sha256Hex, result.Reason);
                _audit.Log("scan", $"Downloads: SUSPICIOUS -> cho nguoi dung quyet dinh (id={id}): {path}", result);
                break;

            case ScanVerdict.ScanError:
                _audit.Log("scan", $"Downloads: ScanError khi quet {path}: {result.Reason}", result);
                break;
        }
    }

    // ERR-04 trong so tay loi: ERROR_SHARING_VIOLATION -> tiep tuc polling
    // moi ~200ms, timeout tong 30s cho file lon, khong coi la loi vinh vien.
    private static bool WaitUntilFileReady(string path, TimeSpan interval, TimeSpan totalTimeout, CancellationToken ct)
    {
        var deadline = DateTime.UtcNow + totalTimeout;
        while (DateTime.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None);
                return true;
            }
            catch (FileNotFoundException)
            {
                return false;
            }
            catch (IOException)
            {
                Thread.Sleep(interval);
            }
        }
        return false;
    }

    public override void Dispose()
    {
        _watcher?.Dispose();
        _queue.Dispose();
        base.Dispose();
    }
}
