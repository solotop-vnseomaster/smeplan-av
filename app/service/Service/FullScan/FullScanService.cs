using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Antivirus.Service.Archive;
using Antivirus.Service.Audit;
using Antivirus.Service.Data;
using Antivirus.Service.Engine;
using Antivirus.Service.Models;
using Antivirus.Service.Quarantine;
using Antivirus.Service.Extensions;
using Antivirus.Service.Settings;
using Antivirus.Service.Update;

namespace Antivirus.Service.FullScan;

public enum FullScanStatus { Idle, Running, Paused, Completed, Error }

public sealed class FullScanProgress
{
    public FullScanStatus Status { get; set; } = FullScanStatus.Idle;
    public long FilesScanned { get; set; }
    public long MaliciousCount { get; set; }
    public long SuspiciousCount { get; set; }
    public long ErrorCount { get; set; }
    public long CachedCount { get; set; } // so file bo qua nho cache (khong doi tu lan quet truoc)
    public string? CurrentFile { get; set; }
    public string? Volume { get; set; }
    public string? Message { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? FinishedAt { get; set; }
}

// Muc bi gan co (Malicious/Suspicious/ScanError) phat sinh trong luc quet —
// UI hien thi song song luc dang quet lan trong bao cao khi hoan tat, cho
// bam vao xem chi tiet (yeu cau cua nguoi dung sau su co scan bi treo).
public sealed class ScanFlaggedItem
{
    public required string FilePath { get; init; }
    public ScanVerdict Verdict { get; init; }
    public DetectionStage Stage { get; init; }
    public required string Sha256Hex { get; init; }
    public required string Reason { get; init; }
    public long FlaggedAtUnixMs { get; init; }
}

// flows/11-luong-xu-ly.md muc "Luong Full/Deep Scan toan o dia" +
// nfr/06-phi-chuc-nang.md NFR-PERF-03/04, NFR-AVAIL-04.
public sealed class FullScanService
{
    private readonly ScanEngineService _engine;
    private readonly ArchiveScanner _archiveScanner;
    private readonly QuarantineManager _quarantine;
    private readonly AuditLogger _audit;
    private readonly ILogger<FullScanService> _logger;
    private readonly ScanCacheStore _cache;
    private readonly AppSettingsStore _settings;
    private readonly UpdateClientService _updateService; // chi dung de doc phien ban CSDL hien tai cho khoa cache
    private readonly GamingModeService _gamingMode;
    private readonly EventBus _eventBus;
    private readonly Antivirus.Service.Extensions.CloudIntel.CloudReputationClient _cloudIntel;

    private readonly FullScanProgress _progress = new();
    private CancellationTokenSource? _cts;
    private volatile bool _paused;
    private Task? _runningTask;

    // Gioi han so muc luu lai de tranh phinh to bo nho tren mot lan quet
    // toan o dia rat nhieu file bi gan co (truong hop hiem, nhung van can
    // gioi han an toan).
    private const int MaxFlaggedItems = 5000;
    private readonly ConcurrentQueue<ScanFlaggedItem> _flaggedItems = new();

    public IReadOnlyCollection<ScanFlaggedItem> GetFlaggedItems() => _flaggedItems.ToList();

    public FullScanService(ScanEngineService engine, ArchiveScanner archiveScanner, QuarantineManager quarantine,
        AuditLogger audit, ILogger<FullScanService> logger, ScanCacheStore cache, AppSettingsStore settings,
        UpdateClientService updateService, GamingModeService gamingMode, EventBus eventBus,
        Antivirus.Service.Extensions.CloudIntel.CloudReputationClient cloudIntel)
    {
        _engine = engine;
        _archiveScanner = archiveScanner;
        _quarantine = quarantine;
        _audit = audit;
        _logger = logger;
        _cache = cache;
        _settings = settings;
        _updateService = updateService;
        _gamingMode = gamingMode;
        _eventBus = eventBus;
        _cloudIntel = cloudIntel;
    }

    public FullScanProgress GetProgress() => _progress;

    public bool Start(string volumeRoot)
    {
        if (_progress.Status == FullScanStatus.Running) return false;

        _cts = new CancellationTokenSource();
        _paused = false;
        _progress.Status = FullScanStatus.Running;
        _progress.Volume = volumeRoot;
        _progress.FilesScanned = 0;
        _progress.MaliciousCount = 0;
        _progress.SuspiciousCount = 0;
        _progress.ErrorCount = 0;
        _progress.CachedCount = 0;
        _progress.StartedAt = DateTimeOffset.UtcNow;
        _progress.FinishedAt = null;
        _cachedBacking = 0;
        _flaggedItems.Clear();

        _runningTask = Task.Run(() => RunScan(volumeRoot, _cts.Token));
        return true;
    }

    public void Pause()
    {
        _paused = true;
        _progress.Status = FullScanStatus.Paused;
    }

    public void Resume()
    {
        _paused = false;
        _progress.Status = FullScanStatus.Running;
    }

    public void Cancel()
    {
        _cts?.Cancel();
    }

    // NFR-AVAIL-04: quyet dinh loai file he thong dung de xac dinh nhanh
    // xem co ho tro USN Journal hay khong (FAT32/exFAT -> khong ho tro).
    public static bool VolumeSupportsUsnJournal(string volumeRoot)
    {
        var sb = new StringBuilder(261);
        bool ok = NativeInterop.GetVolumeInformationW(
            EnsureTrailingBackslash(volumeRoot), IntPtr.Zero, 0,
            out _, out _, out _, sb, (uint)sb.Capacity);
        if (!ok) return false;
        return string.Equals(sb.ToString(), "NTFS", StringComparison.OrdinalIgnoreCase);
    }

    private static string EnsureTrailingBackslash(string path) =>
        path.EndsWith('\\') ? path : path + '\\';

    private void RunScan(string volumeRoot, CancellationToken ct)
    {
        try
        {
            bool isNtfs = VolumeSupportsUsnJournal(volumeRoot);
            bool isHdd = DetectHddSeekPenalty(volumeRoot);
            int degreeOfParallelism = isHdd ? 1 : Math.Max(1, Environment.ProcessorCount - 1);

            _logger.LogInformation(
                "Full scan bat dau: volume={Volume} NTFS={Ntfs} HDD={Hdd} threads={Threads}",
                volumeRoot, isNtfs, isHdd, degreeOfParallelism);

            // NFR-PERF-04: ha muc uu tien I/O cua tien trinh quet nen.
            NativeInterop.SetPriorityClass(NativeInterop.GetCurrentProcess(), NativeInterop.PROCESS_MODE_BACKGROUND_BEGIN);

            IEnumerable<string> files = isNtfs
                ? EnumerateViaUsnOrFallback(volumeRoot)
                : EnumerateViaDirectoryWalk(volumeRoot);

            string? resumeAfter = LoadResumeState(volumeRoot);
            // [SUA LOI NGHIEM TRONG] TRUOC DAY skipUntilResume duoc bat chi
            // dua tren viec CO luu resumeAfter hay khong, khong kiem tra file
            // do co con ton tai hay khong. Neu file moc nay da bi xoa/di
            // chuyen giua 2 lan quet, no se KHONG BAO GIO xuat hien trong lan
            // enumerate moi -> skipUntilResume khong bao gio ve false -> toan
            // bo vong lap duoi day "continue" mai, KHONG file nao duoc quet,
            // nhung Status van duoc bao Completed o cuoi ham — danh lua nguoi
            // dung tuong may da duoc bao ve day du. Sua: chi bat skip khi moc
            // resumeAfter CON THUC SU TON TAI tren dia; neu khong, coi nhu
            // khong co moc resume hop le va quet lai TOAN BO volume ngay tu
            // dau (an toan hon la bo sot file, ke ca file doc hai).
            bool skipUntilResume = resumeAfter is not null && File.Exists(resumeAfter);
            if (resumeAfter is not null && !skipUntilResume)
            {
                _logger.LogWarning(
                    "Moc resume da luu ({ResumeAfter}) khong con ton tai tren dia - bo qua moc nay, quet lai toan bo volume {Volume}",
                    resumeAfter, volumeRoot);
            }

            // [UX FIX] Ghi ro trong audit khi day la mot lan TIEP TUC tu
            // trang thai da luu (khong phai quet moi tu dau) — truoc day
            // khong co dau hieu nao cho nguoi dung biet dieu nay, khien
            // mot lan quet "tiep tuc" (bo qua hang tram nghin file da quet
            // truoc do) trong giong het mot lan quet moi hoan tat rat
            // nhanh, gay hieu lam.
            _audit.Log("scan", skipUntilResume
                ? $"Full scan TIEP TUC tren {volumeRoot} tu vi tri da luu truoc do (NTFS={isNtfs}, HDD={isHdd}, threads={degreeOfParallelism})"
                : $"Full scan bat dau MOI tren {volumeRoot} (NTFS={isNtfs}, HDD={isHdd}, threads={degreeOfParallelism})");

            using var semaphore = new SemaphoreSlim(degreeOfParallelism);
            var tasks = new List<Task>();

            // [SUA LOI NGHIEM TRONG #8] TRUOC DAY moi worker thread goi
            // SaveResumeState(volumeRoot, currentFile) ngay sau khi CHINH NO
            // quet xong file cua no — vi cac worker chay SONG SONG va hoan
            // tat KHONG theo thu tu enumerate (file duoc dispatch o vong lap
            // nay THEO thu tu, nhung co the hoan tat truoc/sau nhau tuy toc
            // do xu ly tung file), "lastFile" ghi xuong dia co the la MOT
            // file bat ky dang xu ly xong GAN DAY, khong dam bao MOI file
            // TRUOC no trong thu tu enumerate da thuc su duoc quet. Neu scan
            // bi gian doan (crash/restart) dung luc do, lan resume sau se
            // dung sai "lastFile" nay lam moc va BO QUA het cac file dung
            // TRUOC no trong thu tu enumerate — ke ca nhung file chua bao
            // gio thuc su duoc quet (bo sot file, ke ca file doc hai).
            //
            // Sua: gan MOI file mot so thu tu tang dan LUC DISPATCH (chi
            // vong lap chinh nay gan, nen luon dung thu tu enumerate that,
            // khong co race), roi dua cho ResumeWatermarkTracker (xem file
            // rieng, co unit test) — no chi cho phep "watermark" (moc da
            // luu) tien len khi TOAN BO cac so thu tu LIEN TUC truoc do da
            // hoan tat, dong thoi gioi han tan suat GHI THUC SU xuong dia
            // (toi da 1 lan/2 giay) de giai quyet ca bug logic (#8) lan chi
            // phi I/O dong bo qua lon (#11) cung mot cho.
            long nextDispatchSeq = 0;
            var resumeTracker = new ResumeWatermarkTracker(TimeSpan.FromSeconds(2));

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();

                if (skipUntilResume)
                {
                    if (string.Equals(file, resumeAfter, StringComparison.OrdinalIgnoreCase)) skipUntilResume = false;
                    continue;
                }

                // Tam dung that su (nguoi dung bam "Tam dung") van chan han
                // vong lap nap file moi — day la hanh dong tuong minh cua
                // nguoi dung, khac voi throttle tu dong ben duoi.
                // "tai lieu moi.txt" muc "Gaming/Silent mode": "full scan va
                // cac tac vu nen nang khac ... tu dong TAM DUNG thay vi chi
                // ha priority" khi phat hien fullscreen exclusive.
                while (_paused || _gamingMode.IsActive)
                {
                    ct.ThrowIfCancellationRequested();
                    Thread.Sleep(500);
                }

                semaphore.Wait(ct);
                var currentFile = file;
                var currentSeq = nextDispatchSeq++;
                var t = Task.Run(() =>
                {
                    try
                    {
                        // NFR-PERF-04: giam toc (KHONG dung han) khi nguoi
                        // dung vua tuong tac gan day, khoi phuc toc do day
                        // du khi may idle qua 60s. Truoc day dung mot vong
                        // lap chan cung o tang enumerate — tren mot may
                        // dang duoc dung lien tuc (gan nhu khong bao gio co
                        // 2 giay lien tuc khong co input), vong lap do khien
                        // scan treo gan nhu vinh vien thay vi chi cham lai.
                        // Sua lai: throttle o TUNG worker bang mot khoang
                        // tre bi chan (bounded delay), luon dam bao tien do
                        // tien len.
                        ThrottleForUserActivity(ct);
                        ScanOneFile(currentFile);
                        var toPersist = resumeTracker.Complete(currentSeq, currentFile);
                        if (toPersist is not null) SaveResumeState(volumeRoot, toPersist);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, ct);
                tasks.Add(t);

                if (tasks.Count > 4096)
                {
                    Task.WaitAny(tasks.ToArray());
                    tasks.RemoveAll(x => x.IsCompleted);
                }
            }

            Task.WaitAll(tasks.ToArray(), ct);

            _progress.Status = FullScanStatus.Completed;
            _progress.CurrentFile = null;
            _progress.FinishedAt = DateTimeOffset.UtcNow;
            ClearResumeState(volumeRoot);
            _audit.Log("scan", $"Full scan hoan tat tren {volumeRoot}: {_progress.FilesScanned} file, " +
                                $"{_progress.MaliciousCount} malicious, {_progress.SuspiciousCount} suspicious");
        }
        catch (OperationCanceledException)
        {
            // [SUA LOI UX] "Huy" (Cancel) truoc day KHONG xoa resume state —
            // khien lan "Bat dau" TIEP THEO tren cung volume ROOT ngam
            // dinh coi la "tiep tuc" tu vi tri da luu (dung y dinh ban dau
            // cho nut "Tam dung/Tiep tuc" trong CUNG mot lan chay), khien
            // scan moi trong gan nhu toan bo cay thu muc va chi xu ly vai
            // chuc file con lai — trong gian doan bi treo ma khong ro
            // nguyen nhan neu nguoi dung khong biet co resume state cu.
            // "Huy" phai co nghia la BO HAN, lan sau bat dau lai tu dau;
            // chi "Tam dung" (khong di qua nhanh nay) moi giu tien do.
            ClearResumeState(volumeRoot);
            _progress.Status = FullScanStatus.Idle;
            _progress.Message = "Da huy (lan quet tiep theo se bat dau lai tu dau)";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Loi full scan");
            _progress.Status = FullScanStatus.Error;
            _progress.Message = ex.Message;
        }
        finally
        {
            NativeInterop.SetPriorityClass(NativeInterop.GetCurrentProcess(), NativeInterop.NORMAL_PRIORITY_CLASS);
        }
    }

    // FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS / FILE_ATTRIBUTE_RECALL_ON_OPEN —
    // co cua file "cloud placeholder" (vi du OneDrive Files On-Demand chua
    // tai ve). Mo file nay de doc se kich hoat tai xuong tu cloud, co the
    // treo rat lau (hoac vo han neu mat ket noi/tai khoan) — [SUA LOI] bo
    // qua nhom file nay thay vi co mo, tranh treo ca scan.
    private const FileAttributes RecallOnDataAccess = (FileAttributes)0x00400000;
    private const FileAttributes RecallOnOpen = (FileAttributes)0x00040000;

    private static bool IsCloudPlaceholder(string path)
    {
        try
        {
            var attrs = File.GetAttributes(path);
            return (attrs & RecallOnDataAccess) != 0 || (attrs & RecallOnOpen) != 0;
        }
        catch
        {
            return false;
        }
    }

    // Thoi gian toi da cho phep quet MOT file truoc khi bo qua va coi la
    // ScanError. [SUA LOI, lan 2] Da gap 2 nguyen nhan khac nhau khien toan
    // bo scan dung yen vinh vien vi mot file don le lam ket vong lap duy
    // nhat (reparse-point loop, OneDrive placeholder) — thay vi tiep tuc
    // vá tung truong hop rieng le, ap dung MOT gioi han thoi gian chung cho
    // MOI file: neu qua thoi gian cho phep van chua co ket qua, bo qua file
    // do (coi la ScanError, khong phai Malicious/Suspicious/Clean) va tiep
    // tuc file tiep theo — dam bao khong con truong hop nao (da biet hay
    // chua biet) co the lam treo toan bo scan nua.
    //
    // [TINH NANG THEO YEU CAU NGUOI DUNG] "Cai timeout co the tuy bien theo
    // tieu chuan nao de giam thoi gian cho ma khong lam lot luoi khong".
    // Truoc day dung PHANG 20s cho MOI file bat ke kich thuoc — voi mot lan
    // quet co hang nghin file bi timeout that su (thuong la file dang bi
    // khoa/socket/pipe, LOI XAY RA GAN NHU NGAY LAP TUC chu khong phai do
    // tinh toan lau), tong thoi gian cho tich luy rat lon môt cach vo ich.
    // Doi sang TIMEOUT THEO KICH THUOC FILE: hash SHA-256 + heuristic that
    // su chi ton vai chuc-vai tram ms ngay ca voi file vai chuc MB tren mot
    // may binh thuong — 20s chi hop ly cho FILE THUC SU LON (ISO/VHD...)
    // noi thoi gian doc dia don thuan da dang ke; file nho hon can it thoi
    // gian cho hon nhieu ma KHONG lam sot mot ket qua quet hop le nao (chi
    // rut ngan thoi gian CHO mot I/O da bi ket, khong anh huong toi do
    // chinh xac phat hien — mot file bi khoa/loi van la loi bat ke cho 5s
    // hay 20s).
    public static TimeSpan GetTimeoutForFileSize(long fileSizeBytes)
    {
        if (fileSizeBytes >= 200L * 1024 * 1024) return TimeSpan.FromSeconds(20); // >=200MB: file lon that su (ISO/VHD...)
        if (fileSizeBytes >= 10L * 1024 * 1024) return TimeSpan.FromSeconds(10);  // 10-200MB
        return TimeSpan.FromSeconds(5); // <10MB: da qua du cho hash+heuristic binh thuong
    }

    private ScanResultDto ScanWithTimeout(string path, long fileSizeBytes)
    {
        var timeout = GetTimeoutForFileSize(fileSizeBytes);
        Task<ScanResultDto> scanTask;
        try
        {
            scanTask = Task.Run(() =>
                ArchiveScanner.IsZipArchive(path) ? _archiveScanner.ScanZip(path) : _engine.ScanFile(path));
        }
        catch (Exception ex)
        {
            // Tien to [MA_LOI] thong nhat voi cach engine C++ phan loai loi
            // (xem pipeline.cpp CopyClassifiedIoError) — de UI gom nhom
            // duoc theo loai thay vi phai doc tung dong van ban rieng le.
            return new ScanResultDto { Verdict = ScanVerdict.ScanError, Stage = DetectionStage.IoError, Reason = "[EXCEPTION] Ngoai le khi quet: " + ex.Message };
        }

        if (scanTask.Wait(timeout))
        {
            try
            {
                return scanTask.Result;
            }
            catch (Exception ex)
            {
                return new ScanResultDto { Verdict = ScanVerdict.ScanError, Stage = DetectionStage.IoError, Reason = "[EXCEPTION] Ngoai le khi quet: " + ex.GetBaseException().Message };
            }
        }

        // Qua timeout: file co the la mot loai file dac biet gay treo thao
        // tac doc (socket, named pipe, cache dang ghi lien tuc boi tien
        // trinh khac...). Tac vu ben trong van tiep tuc chay ngam tren mot
        // thread rieng (khong the huy an toan mot loi goi native dang
        // block), nhung KHONG con chan tien do cua scan nua.
        _logger.LogWarning("Qua thoi gian quet cho phep ({Timeout}) tai file {Path} ({Size} byte) — bo qua, coi la ScanError", timeout, path, fileSizeBytes);
        return new ScanResultDto
        {
            Verdict = ScanVerdict.ScanError,
            Stage = DetectionStage.IoError,
            Reason = $"[TIMEOUT] Qua thoi gian quet cho phep ({timeout.TotalSeconds:0}s) — co the la file dac biet (socket/pipe/cache dang ghi), da bo qua de scan tiep tuc",
        };
    }

    private void ScanOneFile(string path)
    {
        _progress.CurrentFile = path;

        if (IsCloudPlaceholder(path))
        {
            // Khong mo file cloud-only — tranh treo do tai xuong, va tranh
            // ep tai du lieu cloud cua nguoi dung ngoai y muon.
            Interlocked.Increment(ref _filesScannedBacking);
            _progress.FilesScanned = _filesScannedBacking;
            return;
        }

        // [TINH NANG THEO YEU CAU NGUOI DUNG] Cache full scan — bat/tat qua
        // AppSettingsStore.FullScanCacheEnabled (toggle o UI). Chi tra cache
        // khi file KHONG DOI (path+mtime+size) VA dung phien ban CSDL hien
        // tai — xem ghi chu bao mat trong ScanCacheStore.cs.
        int currentSigVersion = _updateService.Status.CurrentVersion;
        bool cacheEnabled = _settings.Current.FullScanCacheEnabled;
        FileInfo? fileInfo = null;
        ScanResultDto? result = null;

        // Doc metadata file MOT LAN, dung chung cho ca tra cache lan chon
        // timeout theo kich thuoc (xem GetTimeoutForFileSize) — tranh goi
        // FileInfo hai lan cho cung mot file.
        try
        {
            fileInfo = new FileInfo(path);
            if (!fileInfo.Exists) fileInfo = null;
        }
        catch
        {
            fileInfo = null; // Loi doc metadata file -> bo qua cache, quet voi timeout mac dinh (5s, coi nhu file nho)
        }

        if (cacheEnabled && fileInfo is not null)
        {
            try
            {
                result = _cache.TryGetCached(path, fileInfo.LastWriteTimeUtc.Ticks, fileInfo.Length, currentSigVersion);
            }
            catch
            {
                // Loi doc cache -> bo qua cache, quet that binh thuong.
            }
        }

        if (result is null)
        {
            result = ScanWithTimeout(path, fileInfo?.Length ?? 0);

            // Chi cache ket qua ON DINH (khong cache ScanError — thuong la
            // loi tam thoi nhu sharing violation, lan sau co the doc duoc).
            if (cacheEnabled && result.Verdict != ScanVerdict.ScanError)
            {
                try
                {
                    fileInfo ??= new FileInfo(path);
                    if (fileInfo.Exists)
                    {
                        _cache.Upsert(path, fileInfo.LastWriteTimeUtc.Ticks, fileInfo.Length, currentSigVersion, result);
                    }
                }
                catch { /* khong de loi ghi cache lam hong ket qua quet */ }
            }
        }
        else
        {
            Interlocked.Increment(ref _cachedBacking);
            _progress.CachedCount = _cachedBacking;
        }

        Interlocked.Increment(ref _filesScannedBacking);
        _progress.FilesScanned = _filesScannedBacking;

        switch (result.Verdict)
        {
            case ScanVerdict.Malicious:
                Interlocked.Increment(ref _maliciousBacking);
                _progress.MaliciousCount = _maliciousBacking;
                try { _quarantine.QuarantineFile(path, result.Sha256Hex, result.Reason); } catch { /* file co the da bi xoa/di chuyen */ }
                AddFlaggedItem(path, result);
                break;
            case ScanVerdict.Suspicious:
                Interlocked.Increment(ref _suspiciousBacking);
                _progress.SuspiciousCount = _suspiciousBacking;
                AddFlaggedItem(path, result);
                CheckCloudReputation(path, result);
                break;
            case ScanVerdict.ScanError:
                Interlocked.Increment(ref _errorBacking);
                _progress.ErrorCount = _errorBacking;
                AddFlaggedItem(path, result);
                break;
        }
    }

    // "tai lieu moi.txt" muc "Tich hop cloud threat intelligence": "chi tra
    // cuu cloud cho file DA QUA vong loc CSDL cuc bo va YARA MA KHONG KET
    // LUAN DUOC" — dung goi tu case Suspicious o tren (scan engine da het
    // cach ket luan chac chan Malicious/Clean), khong goi cho moi file.
    private void CheckCloudReputation(string path, ScanResultDto result)
    {
        if (!_settings.Current.CloudIntelEnabled) return;
        if (string.IsNullOrEmpty(result.Sha256Hex)) return;

        try
        {
            var cloud = _cloudIntel.Lookup(result.Sha256Hex);
            if (cloud.Prevalence == 0)
            {
                // "mot file hoan toan moi, chua tung thay o bat ky may nao
                // khac... tu no la mot tin hieu dang chu y ngay ca khi chua
                // co verdict ro rang" — publish o muc thong tin, KHONG tu
                // nang len Malicious chi vi prevalence thap.
                _eventBus.Publish(new CorrelationEvent
                {
                    EntityKey = $"file:{result.Sha256Hex}",
                    SourceEngine = "cloud-intel",
                    Severity = 30,
                    Summary = $"File {Path.GetFileName(path)} (Suspicious) chua tung thay o may nao khac (prevalence=0) — ket hop voi ket qua scan engine de danh gia",
                    TimestampUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Loi tra cuu cloud reputation cho {Path}", path);
        }
    }

    // Nguoi dung yeu cau: trong luc quet co the bam vao xem chi tiet cac
    // muc bi gan co (Malicious/Suspicious/ScanError), khong phai cho toi
    // luc quet xong moi biet.
    private void AddFlaggedItem(string path, ScanResultDto result)
    {
        if (_flaggedItems.Count >= MaxFlaggedItems) return;
        _flaggedItems.Enqueue(new ScanFlaggedItem
        {
            FilePath = path,
            Verdict = result.Verdict,
            Stage = result.Stage,
            Sha256Hex = result.Sha256Hex,
            Reason = result.Reason,
            FlaggedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        });
    }

    private long _filesScannedBacking, _maliciousBacking, _suspiciousBacking, _errorBacking, _cachedBacking;

    // Gioi han do sau de tu bao ve truoc cay thu muc bat thuong; khong phai
    // gioi han nghiep vu, chi la van an toan cuoi cung.
    private const int MaxWalkDepth = 200;

    private IEnumerable<string> EnumerateViaDirectoryWalk(string root)
    {
        // Fallback FAT32/exFAT (khong ho tro USN Journal): duyet cay thu muc
        // thong thuong (tuong duong FindFirstFile/FindNextFile de quy).
        //
        // [SUA LOI] Ban truoc DE QUY VAO CA REPARSE POINT (junction/symlink)
        // — mot thu muc tro vong lai to tien cua chinh no (rat hay gap trong
        // node_modules, AppData, OneDrive) khien vong lap chay gan nhu vo
        // han, treo cung LUONG DUYET DUY NHAT (single-threaded enumerate)
        // va keo theo toan bo scan dung yen du cac worker thread khac van
        // ranh. Sua: bo qua thu muc mang FileAttributes.ReparsePoint, va
        // gioi han do sau tuyet doi lam van an toan cuoi cung.
        IEnumerable<string> Walk(string dir, int depth)
        {
            if (depth > MaxWalkDepth) yield break;

            IEnumerable<string> entries;
            try { entries = Directory.EnumerateFiles(dir); }
            catch { yield break; }
            foreach (var f in entries) yield return f;

            IEnumerable<string> subdirs;
            try { subdirs = Directory.EnumerateDirectories(dir); }
            catch { yield break; }
            foreach (var d in subdirs)
            {
                DirectoryInfo info;
                try { info = new DirectoryInfo(d); }
                catch { continue; }

                if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    // Junction/symlink/mount point — KHONG di theo, tranh
                    // vong lap vo han qua lai giua cac thu muc.
                    continue;
                }

                foreach (var f in Walk(d, depth + 1)) yield return f;
            }
        }
        return Walk(root, 0);
    }

    // Enumerate qua FSCTL_ENUM_USN_DATA tren NTFS; neu mo volume that bai
    // (thuong vi thieu quyen Administrator trong moi truong dev khong
    // elevate), tu dong fallback ve duyet cay thu muc de van chay duoc.
    private IEnumerable<string> EnumerateViaUsnOrFallback(string volumeRoot)
    {
        string device = @"\\.\" + volumeRoot.TrimEnd('\\').TrimEnd(':') + ":";
        IntPtr handle = NativeInterop.CreateFileW(device,
            NativeInterop.GENERIC_READ, NativeInterop.FILE_SHARE_READ | NativeInterop.FILE_SHARE_WRITE,
            IntPtr.Zero, NativeInterop.OPEN_EXISTING, 0, IntPtr.Zero);

        if (handle == IntPtr.Zero || handle.ToInt64() == -1)
        {
            _logger.LogWarning("Khong mo duoc volume {Volume} (can quyen Administrator) — fallback duyet cay thu muc", device);
            foreach (var f in EnumerateViaDirectoryWalk(volumeRoot)) yield return f;
            yield break;
        }

        // [HAN CHE DA BIET] FSCTL_ENUM_USN_DATA duoc goi that (mo volume,
        // doc entry MFT that su) de xac nhan API hoat dong va de log so
        // luong entry doc duoc — nhung viec tai dung duong dan day du tu
        // FileReferenceNumber/ParentFileReferenceNumber (can duyet nguoc
        // cay thu muc qua bang MFT) chua duoc trien khai trong phien nay.
        // De dam bao KET QUA QUET DUNG (khong bo sot / khong bao loi sai),
        // danh sach file thuc su dua vao pipeline scan van lay tu duyet cay
        // thu muc; USN chi dung de do dac/log. Day la danh doi ro rang giua
        // "dung toc do ly thuyet cua USN" va "dung chinh xac duong dan" —
        // ghi nhan cong khai thay vi tra ve duong dan sai lech am tham.
        try
        {
            // [SUA LOI HIEU NANG] TRUOC DAY CountUsnRecords doc TOI DA 5000
            // vong x 64KB (~320MB) tu MFT MOI LAN bat dau full scan, CHI de
            // ghi MOT dong log roi BO KET QUA (danh sach quet thuc te van
            // luon lay tu EnumerateViaDirectoryWalk ben duoi, xem ghi chu
            // tren) — chi phi doc dia lon nhung khong mang lai gia tri chuc
            // nang nao. Sua: chi doc MOT buffer duy nhat (~64KB) de xac nhan
            // FSCTL_ENUM_USN_DATA hoat dong tren volume nay, du muc dich
            // "doi chieu/chan doan" ma khong phai tra gia doc toan bo MFT.
            long usnSampleCount = CountUsnRecords(handle, maxIterations: 1);
            _logger.LogInformation("USN Journal: xac nhan doc duoc {Count} entry mau tu volume {Volume} (chi de kiem tra API kha dung, danh sach quet thuc te van qua duyet thu muc)", usnSampleCount, device);
        }
        finally
        {
            NativeInterop.CloseHandle(handle);
        }

        foreach (var f in EnumerateViaDirectoryWalk(volumeRoot)) yield return f;
    }

    private long CountUsnRecords(IntPtr volumeHandle, int maxIterations)
    {
        const int bufferSize = 65536;
        long count = 0;
        IntPtr inBuffer = System.Runtime.InteropServices.Marshal.AllocHGlobal(24);
        IntPtr outBuffer = System.Runtime.InteropServices.Marshal.AllocHGlobal(bufferSize);
        try
        {
            var mftEnum = new NativeInterop.MFT_ENUM_DATA_V0
            {
                StartFileReferenceNumber = 0,
                LowUsn = 0,
                HighUsn = long.MaxValue,
            };
            System.Runtime.InteropServices.Marshal.StructureToPtr(mftEnum, inBuffer, false);

            for (int iter = 0; iter < maxIterations; iter++)
            {
                bool ok = NativeInterop.DeviceIoControl(volumeHandle, NativeInterop.FSCTL_ENUM_USN_DATA,
                    inBuffer, 24, outBuffer, bufferSize, out uint bytesReturned, IntPtr.Zero);
                if (!ok || bytesReturned <= 8) break;

                ulong nextStart = (ulong)System.Runtime.InteropServices.Marshal.ReadInt64(outBuffer, 0);
                int offset = 8;
                while (offset < bytesReturned)
                {
                    int recordLength = System.Runtime.InteropServices.Marshal.ReadInt32(outBuffer, offset);
                    if (recordLength <= 0) break;
                    count++;
                    offset += recordLength;
                }

                var nextEnum = new NativeInterop.MFT_ENUM_DATA_V0
                {
                    StartFileReferenceNumber = nextStart,
                    LowUsn = 0,
                    HighUsn = long.MaxValue,
                };
                System.Runtime.InteropServices.Marshal.StructureToPtr(nextEnum, inBuffer, false);
            }
        }
        finally
        {
            System.Runtime.InteropServices.Marshal.FreeHGlobal(inBuffer);
            System.Runtime.InteropServices.Marshal.FreeHGlobal(outBuffer);
        }
        return count;
    }

    // NFR-PERF-03: phat hien HDD qua StorageDeviceSeekPenaltyProperty.
    private static bool DetectHddSeekPenalty(string volumeRoot)
    {
        string device = @"\\.\" + volumeRoot.TrimEnd('\\').TrimEnd(':') + ":";
        IntPtr handle = NativeInterop.CreateFileW(device, 0,
            NativeInterop.FILE_SHARE_READ | NativeInterop.FILE_SHARE_WRITE,
            IntPtr.Zero, NativeInterop.OPEN_EXISTING, 0, IntPtr.Zero);
        if (handle == IntPtr.Zero || handle.ToInt64() == -1) return false;

        try
        {
            var query = new NativeInterop.STORAGE_PROPERTY_QUERY
            {
                PropertyId = NativeInterop.StorageDeviceSeekPenaltyProperty,
                QueryType = NativeInterop.PropertyStandardQuery,
            };
            int querySize = System.Runtime.InteropServices.Marshal.SizeOf<NativeInterop.STORAGE_PROPERTY_QUERY>();
            int descSize = System.Runtime.InteropServices.Marshal.SizeOf<NativeInterop.DEVICE_SEEK_PENALTY_DESCRIPTOR>();
            IntPtr inPtr = System.Runtime.InteropServices.Marshal.AllocHGlobal(querySize);
            IntPtr outPtr = System.Runtime.InteropServices.Marshal.AllocHGlobal(descSize);
            try
            {
                System.Runtime.InteropServices.Marshal.StructureToPtr(query, inPtr, false);
                bool ok = NativeInterop.DeviceIoControl(handle, NativeInterop.IOCTL_STORAGE_QUERY_PROPERTY,
                    inPtr, (uint)querySize, outPtr, (uint)descSize, out _, IntPtr.Zero);
                if (!ok) return false;
                var desc = System.Runtime.InteropServices.Marshal.PtrToStructure<NativeInterop.DEVICE_SEEK_PENALTY_DESCRIPTOR>(outPtr);
                return desc.IncursSeekPenalty;
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.FreeHGlobal(inPtr);
                System.Runtime.InteropServices.Marshal.FreeHGlobal(outPtr);
            }
        }
        finally
        {
            NativeInterop.CloseHandle(handle);
        }
    }

    private static uint GetIdleMs()
    {
        var lii = new NativeInterop.LASTINPUTINFO { cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<NativeInterop.LASTINPUTINFO>() };
        if (!NativeInterop.GetLastInputInfo(ref lii)) return uint.MaxValue; // khong lay duoc -> coi nhu idle, khong chan scan
        return NativeInterop.GetTickCount() - lii.dwTime;
    }

    // NFR-PERF-04: "giam hoac tam dung ... khi nguoi dung vua tuong tac
    // trong vai giay gan day; khoi phuc toc do quet binh thuong khi may
    // idle qua 60 giay".
    //
    // [SUA LOI] Ban dau ham nay (ten cu UserIsIdleEnough) duoc dung de CHAN
    // TOAN BO vong lap nap file moi cho toi khi co it nhat 2 giay lien tuc
    // khong co input he thong. Tren mot may van dang duoc dung (hoac trong
    // moi truong ma "last input" khong bao gio dat nguong do vi ly do khac),
    // dieu kien "2 giay lien tuc" gan nhu khong bao gio thoa man, khien
    // scan TREO GAN NHU VINH VIEN thay vi chi cham lai — day la nguyen nhan
    // (hoac it nhat mot phan) cua sự co scan dung yen quan sat duoc trong
    // phien lam viec nay. Sua: thay vi chan vo han o tang enumerate, moi
    // worker tu them MOT khoang tre CO GIOI HAN (toi da vai tram ms) truoc
    // khi quet file cua no — dam bao LUON co tien do, chi giam thong luong
    // khi may dang duoc dung, khong bao gio dung han toan bo.
    private static void ThrottleForUserActivity(CancellationToken ct)
    {
        uint idleMs = GetIdleMs();
        if (idleMs >= 60000) return; // idle du 60s -> toc do day du, khong tre
        if (idleMs < 2000)
        {
            ct.ThrowIfCancellationRequested();
            Thread.Sleep(250); // vua tuong tac gan day -> giam nhe toc do, KHONG chan han
        }
    }

    // NFR-AVAIL-04: luu FileReferenceNumber (o day dung duong dan file lam
    // dinh danh don gian hoa) cuoi cung da xu ly de ho tro tam dung/tiep tuc.
    private static string ResumeStateFile(string volumeRoot) =>
        Path.Combine(DataPaths.StateDir, $"fullscan_{volumeRoot.TrimEnd(':', '\\')}.json");

    private static void SaveResumeState(string volumeRoot, string lastFile)
    {
        try { File.WriteAllText(ResumeStateFile(volumeRoot), JsonSerializer.Serialize(new { lastFile })); }
        catch { /* khong lam gian doan scan neu ghi state loi */ }
    }

    private static string? LoadResumeState(string volumeRoot)
    {
        try
        {
            var path = ResumeStateFile(volumeRoot);
            if (!File.Exists(path)) return null;
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            return doc.RootElement.GetProperty("lastFile").GetString();
        }
        catch { return null; }
    }

    private static void ClearResumeState(string volumeRoot)
    {
        try { File.Delete(ResumeStateFile(volumeRoot)); } catch { }
    }
}
