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
    private readonly Antivirus.Service.Archive.ArchiveScanner _archiveScanner;
    private readonly QuarantineManager _quarantine;
    private readonly DownloadsDecisionBroker _decisionBroker;
    private readonly AuditLogger _audit;
    // [SUA LOI NGHIEM TRONG] Xem PublishDetection ben duoi: tang real-time
    // DUY NHAT that su bat duoc ma doc lai la tang duy nhat KHONG phat su
    // kien nao vao EventBus.
    private readonly Antivirus.Service.Extensions.EventBus _eventBus;
    private readonly ILogger<DownloadsWatcherService> _logger;
    private readonly BlockingCollection<string> _queue = new();
    private readonly List<FileSystemWatcher> _watchers = new();

    public DownloadsWatcherService(ScanEngineService engine,
        Antivirus.Service.Archive.ArchiveScanner archiveScanner, QuarantineManager quarantine,
        DownloadsDecisionBroker decisionBroker, AuditLogger audit,
        Antivirus.Service.Extensions.EventBus eventBus, ILogger<DownloadsWatcherService> logger)
    {
        _engine = engine;
        _archiveScanner = archiveScanner;
        _quarantine = quarantine;
        _decisionBroker = decisionBroker;
        _audit = audit;
        _eventBus = eventBus;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // [SUA LOI NGHIEM TRONG] Xem KnownFolders.GetAllUserDownloadsPaths:
        // TRUOC DAY chi dat MOT watcher tren KnownFolders.GetDownloadsPath(),
        // ma tu tien trinh SYSTEM duong dan do la thu muc Downloads cua
        // TAI KHOAN SYSTEM (systemprofile) — khong bao gio co file nao. Dat
        // watcher tren thu muc Downloads cua TUNG nguoi dung that.
        var downloadsPaths = KnownFolders.GetAllUserDownloadsPaths();
        if (downloadsPaths.Count == 0)
        {
            _logger.LogError(
                "Khong tim thay thu muc Downloads cua bat ky nguoi dung nao — quet file tai ve KHONG hoat dong");
            _audit.Log("scan", "ERR: khong tim thay thu muc Downloads nao — quet file tai ve KHONG hoat dong");
            return;
        }

        foreach (var downloadsPath in downloadsPaths)
        {
            try
            {
                var watcher = new FileSystemWatcher(downloadsPath)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                };
                // Buoc 2: FILE_ACTION_RENAMED_NEW_NAME (trinh duyet doi ten tu
                // .crdownload/.part) hoac FILE_ACTION_ADDED (cong cu dong lenh).
                watcher.Renamed += (_, e) => _queue.TryAdd(e.FullPath);
                watcher.Created += (_, e) => _queue.TryAdd(e.FullPath);
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
                _logger.LogInformation("Downloads watcher da khoi dong tren {Path}", downloadsPath);
                _audit.Log("scan", $"Downloads watcher da khoi dong tren {downloadsPath}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Khong dat duoc watcher tren {Path}", downloadsPath);
                _audit.Log("scan", $"ERR: khong dat duoc Downloads watcher tren {downloadsPath}");
            }
        }

        if (_watchers.Count == 0)
        {
            _audit.Log("scan", "ERR: khong dat duoc watcher tren bat ky thu muc Downloads nao");
            return;
        }

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

        // [SUA LOI NGHIEM TRONG — GUARD DUNG, TRUOC DAY AP THIEU DUONG]
        // PathUtil.IsLocalDrivePath duoc goi o 3 endpoint /api/* de chan
        // forced-authentication/NTLM-relay, nhung KHONG duoc goi o day. Duong
        // dan toi day den tu FileSystemWatcher tren thu muc Downloads cua
        // NGUOI DUNG — vung ma nguoi dung quyen thuong ghi duoc tu do. Ho co
        // the dat mot junction trong Downloads tro ra UNC share cua ho; moi
        // thao tac File.* ben duoi (chay quyen SYSTEM) se tu khoi tao ket noi
        // SMB + xac thuc NTLM toi may chu do ho chi dinh.
        // Cung mot bat bien, cung mot ham kiem tra, chi la truoc day khong ai
        // truy nguoc xem "con duong nao khac cham vao File.* voi duong dan
        // ngoai kiem soat khong".
        if (!Antivirus.Service.Common.PathUtil.IsLocalDrivePath(path))
        {
            _logger.LogWarning(
                "Bo qua {Path}: khong phai duong dan o dia cuc bo (UNC hoac reparse point tro ra ngoai)", path);
            _audit.Log("scan",
                $"Downloads: BO QUA {path} — duong dan khong phai o dia cuc bo (chan NTLM-relay)");
            return;
        }

        // Buoc 3: xac nhan file da ghi xong bang polling CreateFile exclusive.
        // [PARTIALLY-FIXED — xem ghi chu tai WaitUntilFileReady va sau
        // ScanFile ben duoi] Van CON mot khoang ho TOCTOU giua luc dong
        // handle doc-doc-quyen o day va luc _engine.ScanFile mo lai file
        // BANG DUONG DAN ben duoi — ScanEngineService.ScanFile(string) chi
        // nhan mot duong dan (engine native tu mo file rieng), KHONG co
        // overload nhan stream/handle da mo san, nen KHONG THE quet xuyen
        // qua handle dang giu ma khong sua doi engine C++ (ngoai pham vi
        // file nay). Giai phap ap dung: thu hep toi da cua so (khong them
        // buoc nao giua dong handle va goi ScanFile) VA them mot buoc kiem
        // tra toan ven SAU KHI scan xong (size/mtime khong doi) de PHAT HIEN
        // (khong ngan chan hoan toan) ky thuat "scan-then-swap": neu file bi
        // doi trong luc quet, KHONG tin ket qua Clean, coi la ScanError va
        // ghi canh bao ro rang thay vi am tham bao Clean sai.
        if (!WaitUntilFileReady(path, TimeSpan.FromMilliseconds(200), TimeSpan.FromSeconds(30), ct, out var preScanSize, out var preScanWriteUtc))
        {
            _logger.LogWarning("File {Path} van bi khoa sau 30s polling (ERROR_SHARING_VIOLATION) — bo qua", path);
            return;
        }
        if (!File.Exists(path)) return;

        // Buoc 4: quet dong bo va day du, KHONG bo qua theo phan mo rong "it
        // rui ro" nhu real-time protection thong thuong.
        //
        // [SUA LOI NGHIEM TRONG — GUARD DUNG, TRUOC DAY AP THIEU DUONG] Re
        // nhanh archive TRUOC DAY chi co o POST /api/scan/file va
        // FullScanService.ScanOneFile. Duong nay — file VUA TAI VE, tuc la
        // duong nhieu kha nang gap malware nhat trong ca san pham — goi thang
        // _engine.ScanFile, va engine chi bam hash + heuristic tren chinh file
        // .zip. Mot payload trong archive khong bao gio bi mo ra, nen mot
        // mau da co trong CSDL chu ky van di qua sach se.
        // Dung dung mot bieu thuc nhu hai duong kia de ba duong khong the
        // lech nhau nua (xem invariant "cung file f -> cung verdict").
        var result = Antivirus.Service.Archive.ArchiveScanner.IsZipArchive(path)
            ? _archiveScanner.ScanZip(path)
            : _engine.ScanFile(path);

        // [PARTIALLY-FIXED] Kiem tra toan ven SAU scan — neu kich thuoc/mtime
        // da doi so voi luc xac nhan file san sang (truoc khi mo lai de
        // quet), rat co the noi dung da bi thay the GIUA hai buoc do (cua so
        // TOCTOU con lai, khong the dong hoan toan neu khong sua engine).
        // Khong tin verdict Clean/Suspicious trong truong hop nay — ep ve
        // ScanError va canh bao ro de nguoi van hanh biet co nghi van bi
        // "scan-then-swap", thay vi am tham chap nhan ket qua co the sai.
        if (TryGetFileSignature(path, out var postScanSize, out var postScanWriteUtc) &&
            (postScanSize != preScanSize || postScanWriteUtc != preScanWriteUtc) &&
            result.Verdict != ScanVerdict.Malicious)
        {
            _logger.LogWarning(
                "File {Path} da THAY DOI trong luc quet (size {PreSize}->{PostSize}, mtime {PreMtime}->{PostMtime}) — nghi ky thuat scan-then-swap, KHONG tin ket qua verdict={Verdict}, coi la ScanError",
                path, preScanSize, postScanSize, preScanWriteUtc, postScanWriteUtc, result.Verdict);
            result = new ScanResultDto
            {
                Verdict = ScanVerdict.ScanError,
                Stage = result.Stage,
                Reason = "[TOCTOU_SUSPECTED] File thay doi giua luc xac nhan san sang va luc quet xong — ket qua truoc do khong dang tin, can quet lai",
            };
        }

        // Buoc 5: hanh dong theo verdict.
        switch (result.Verdict)
        {
            case ScanVerdict.Clean:
                _audit.Log("scan", $"Downloads: file sach: {path}", result);
                break;

            case ScanVerdict.Malicious:
                // [SUA LOI] TRUOC DAY goi QuarantineFile truc tiep, KHONG co
                // try/catch — neu file bi xoa/di chuyen dung luc nay (hoac
                // loi I/O khac khi quarantine), ngoai le se bay len va lam
                // hong ca ProcessDownloadedFile (bi ProcessQueue's catch bat
                // lai o tang tren, nhung audit "da quarantine" ben duoi se
                // KHONG bao gio duoc ghi, gay sai lech giua thuc te va audit
                // trail). Sua cho khop voi FullScanService.ScanOneFile (noi
                // xu ly Malicious da duoc hardened voi try/catch tuong tu).
                // [SUA LOI CAO] TRUOC DAY: try { QuarantineFile(...) } catch { }
                // roi audit ghi "da tu dong quarantine" VO DIEU KIEN ngay ben
                // duoi. Malware GIU HANDLE file cua chinh no la hanh vi hoan
                // toan binh thuong — khi do QuarantineFile nem sharing
                // violation, catch {} nuot, FILE VAN NAM NGUYEN TREN DIA, va
                // nhat ky khang dinh no da bi cach ly. Nguoi dung va nguoi
                // dieu tra sau nay deu tin vao mot dieu khong xay ra.
                // Sua: audit phai phan anh KET QUA THAT, va that bai phai
                // duoc bao ra ro rang thay vi bi nuot.
                try
                {
                    _quarantine.QuarantineFile(path, result.Sha256Hex, result.Reason);
                    _audit.Log("scan", $"Downloads: MALICIOUS -> da tu dong quarantine: {path}", result);
                    PublishDetection(path, result.Sha256Hex, 95,
                        $"Đã chặn mã độc trong Downloads và cách ly: {Path.GetFileName(path)} ({result.Reason})");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Downloads: KHONG quarantine duoc {Path} — file VAN CON tren dia", path);
                    _audit.Log("scan",
                        $"Downloads: MALICIOUS nhung KHONG quarantine duoc: {path} — file VAN CON TREN DIA ({ex.GetType().Name}: {ex.Message})",
                        result);
                    // Muc do NGHIEM TRONG HON truong hop cach ly duoc: ma doc
                    // da duoc xac dinh nhung VAN CON tren dia.
                    PublishDetection(path, result.Sha256Hex, 100,
                        $"PHÁT HIỆN mã độc nhưng KHÔNG cách ly được — file VẪN CÒN trên đĩa: {path}");
                }
                break;

            case ScanVerdict.Suspicious:
                var id = _decisionBroker.Add(path, result.Sha256Hex, result.Reason);
                _audit.Log("scan", $"Downloads: SUSPICIOUS -> cho nguoi dung quyet dinh (id={id}): {path}", result);
                PublishDetection(path, result.Sha256Hex, 55,
                    $"File tải về đáng ngờ, đang chờ bạn quyết định: {Path.GetFileName(path)} ({result.Reason})");
                break;

            case ScanVerdict.ScanError:
                _audit.Log("scan", $"Downloads: ScanError khi quet {path}: {result.Reason}", result);
                break;
        }
    }

    // [SUA LOI NGHIEM TRONG] TRUOC DAY service nay KHONG publish gi vao
    // EventBus. Firewall, ransomware guard, USB, webcam, home-network va full
    // scan deu publish — rieng DownloadsWatcher thi khong, trong khi day la
    // tang REAL-TIME DUY NHAT that su bat duoc ma doc khi no vua xuat hien.
    //
    // Hau qua quan sat duoc truc tiep: tha mot file EICAR vao Downloads,
    // service quet ra Malicious va cach ly thanh cong, ghi day du audit —
    // nhung GET /api/alerts van tra ve rong. Alert Center trong tron, va giao
    // dien khong co gi de bao cho nguoi dung rang vua co mot lan chan that.
    // Nguoi dung ngoi nhin man hinh "dang bao ve" va khong bao gio biet.
    private void PublishDetection(string path, string sha256Hex, int severity, string summary)
    {
        _eventBus.Publish(new Antivirus.Service.Extensions.CorrelationEvent
        {
            // Khoa theo hash de cac tang khac (full scan, cloud intel...) bao
            // cao ve CUNG mot file se gop chung vao mot canh bao, dung y do
            // hop nhat cua EventBus.
            EntityKey = string.IsNullOrEmpty(sha256Hex) ? $"file:{path}" : $"sha256:{sha256Hex}",
            SourceEngine = "scan",
            Severity = severity,
            Summary = summary,
            TimestampUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        });
    }

    // ERR-04 trong so tay loi: ERROR_SHARING_VIOLATION -> tiep tuc polling
    // moi ~200ms, timeout tong 30s cho file lon, khong coi la loi vinh vien.
    //
    // [PARTIALLY-FIXED] preScanSize/preScanWriteUtc duoc doc NGAY TRONG LUC
    // con giu handle doc-doc-quyen (truoc khi dong) — dung lam "chu ky" de
    // doi chieu sau khi quet (xem ProcessDownloadedFile). Day KHONG ngan
    // chan hoan toan TOCTOU (van phai dong handle o day de ScanFile mo lai
    // duoc BANG DUONG DAN — engine khong nhan handle da mo san), chi giup
    // PHAT HIEN truong hop noi dung bi thay doi giua hai lan mo.
    private static bool WaitUntilFileReady(string path, TimeSpan interval, TimeSpan totalTimeout, CancellationToken ct,
        out long preScanSize, out DateTime preScanWriteUtc)
    {
        var deadline = DateTime.UtcNow + totalTimeout;
        while (DateTime.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None);
                preScanSize = stream.Length;
                preScanWriteUtc = File.GetLastWriteTimeUtc(path);
                return true;
            }
            catch (FileNotFoundException)
            {
                preScanSize = 0;
                preScanWriteUtc = default;
                return false;
            }
            catch (IOException)
            {
                Thread.Sleep(interval);
            }
        }
        preScanSize = 0;
        preScanWriteUtc = default;
        return false;
    }

    private static bool TryGetFileSignature(string path, out long size, out DateTime writeUtc)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                size = 0;
                writeUtc = default;
                return false;
            }
            size = info.Length;
            writeUtc = info.LastWriteTimeUtc;
            return true;
        }
        catch
        {
            size = 0;
            writeUtc = default;
            return false;
        }
    }

    public override void Dispose()
    {
        foreach (var w in _watchers) w.Dispose();
        _queue.Dispose();
        base.Dispose();
    }
}
