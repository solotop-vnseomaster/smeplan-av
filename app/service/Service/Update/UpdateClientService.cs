using System.Security.Cryptography.X509Certificates;
using Antivirus.Service.Audit;
using Antivirus.Service.Data;
using Antivirus.Service.Engine;
using Antivirus.Service.FullScan;

namespace Antivirus.Service.Update;

// API-01..04 + flows/11 (khong co luong rieng cho update trong flows/11,
// nhung business-rules/05 va security/09 mo ta hanh vi ro rang) +
// TEST-10: ca luong incremental delta lan fallback full download, verify
// chu ky truoc khi ap dung, ghi file tam roi swap nguyen tu.
public sealed class UpdateClientService : BackgroundService
{
    // "chu ky ngan (vi du moi 1-4 gio)" — mac dinh 2 gio; co the chinh qua config.
    public static readonly TimeSpan DefaultCheckInterval = TimeSpan.FromHours(2);
    public const int FullDownloadThresholdVersions = 30;

    private readonly IUpdatePackageSource _source;
    private readonly ScanEngineService _engine;
    private readonly AuditLogger _audit;
    private readonly ILogger<UpdateClientService> _logger;
    private readonly X509Certificate2 _trustedCert;
    private readonly TimeSpan _interval;

    private readonly string _versionStatePath;
    private readonly string _accumulatorCsvPath;
    private readonly string _signatureDbPath;
    private readonly ScanCacheStore? _scanCache;

    public UpdateStatus Status { get; } = new();

    // Cac tham so path la optional, mac dinh dung DataPaths (san xuat that);
    // kiem thu co the truyen path rieng de co lap voi ProgramData that.
    // scanCache la optional (null trong test) — khi co, moi lan ap dung
    // CSDL moi thanh cong se xoa toan bo cache full scan (xem
    // ScanCacheStore.cs muc "DIEM AN TOAN BAT BUOC").
    public UpdateClientService(IUpdatePackageSource source, ScanEngineService engine, AuditLogger audit,
        ILogger<UpdateClientService> logger, X509Certificate2 trustedCert, TimeSpan? interval = null,
        string? versionStatePath = null, string? accumulatorCsvPath = null, string? signatureDbPath = null,
        ScanCacheStore? scanCache = null)
    {
        _source = source;
        _engine = engine;
        _audit = audit;
        _logger = logger;
        _trustedCert = trustedCert;
        _interval = interval ?? DefaultCheckInterval;
        _versionStatePath = versionStatePath ?? Path.Combine(DataPaths.StateDir, "update_version.json");
        _accumulatorCsvPath = accumulatorCsvPath ?? Path.Combine(DataPaths.StateDir, "signature_accumulator.csv");
        _signatureDbPath = signatureDbPath ?? DataPaths.SignatureDbPath;
        _scanCache = scanCache;
        Status.CurrentVersion = LoadCurrentVersion();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckAndApplyAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Loi update service");
            }

            try { await Task.Delay(_interval, stoppingToken); }
            catch (TaskCanceledException) { }
        }
    }

    public async Task<UpdateStatus> CheckAndApplyAsync(CancellationToken ct)
    {
        Status.CheckInProgress = true;
        try
        {
            var latest = await _source.CheckLatestVersionAsync(ct);
            Status.LastCheckedAt = DateTimeOffset.UtcNow;

            if (latest.LatestVersion <= Status.CurrentVersion)
            {
                Status.LastResult = "Da o phien ban moi nhat";
                return Status;
            }

            int versionsBehind = latest.LatestVersion - Status.CurrentVersion;
            _audit.Log("update", $"Phat hien CSDL moi: v{latest.LatestVersion} (dang o v{Status.CurrentVersion}, tut {versionsBehind} phien ban)");

            bool ok = versionsBehind > FullDownloadThresholdVersions
                ? await ApplyFullAsync(latest.LatestVersion, ct)
                : await ApplyDeltaSequenceAsync(Status.CurrentVersion, latest.LatestVersion, ct);

            Status.LastResult = ok ? $"Cap nhat thanh cong len v{latest.LatestVersion}" : "Cap nhat that bai (xem log)";
            return Status;
        }
        finally
        {
            Status.CheckInProgress = false;
        }
    }

    private async Task<bool> ApplyFullAsync(int targetVersion, CancellationToken ct)
    {
        string pkgName = $"full_v{targetVersion}.full";
        var pkg = await _source.DownloadPackageAsync(pkgName, ct);
        if (pkg is null)
        {
            _audit.Log("update", $"ERR-UPD: khong tai duoc goi full {pkgName}");
            return false;
        }

        if (!UpdatePackageVerifier.TryVerifyAndExtract(pkg, _trustedCert, out var csvBytes))
        {
            _audit.Log("update", $"ERR-UPD-01: goi {pkgName} KHONG hop le chu ky so — tu choi ap dung");
            _logger.LogWarning("Goi CSDL {Pkg} khong verify duoc chu ky, bi tu choi", pkgName);
            return false;
        }

        File.WriteAllBytes(_accumulatorCsvPath, csvBytes);
        bool applied = RebuildAndSwap();
        if (applied)
        {
            SaveCurrentVersion(targetVersion);
            _audit.Log("update", $"Da ap dung full CSDL v{targetVersion} (verify chu ky OK, swap nguyen tu)");
        }
        return applied;
    }

    private async Task<bool> ApplyDeltaSequenceAsync(int fromVersion, int toVersion, CancellationToken ct)
    {
        // "client tai cac goi delta con thieu dung thu tu vX_to_vY.delta va
        // ap dung tuan tu len CSDL cuc bo"
        //
        // [SUA LOI TRUNG BINH] TRUOC DAY accumulated la mot List<string> don
        // gian, CHI noi (append) cac dong CSV moi vao cuoi danh sach da doc
        // tu file, roi ghi CA danh sach xuong _accumulatorCsvPath TRUOC KHI
        // biet RebuildAndSwap() ben duoi co thanh cong hay khong. Neu build
        // that bai (vi du BuildFromCsv gap loi, dia day...), ham tra ve
        // false va SaveCurrentVersion KHONG duoc goi — client van nghi minh
        // dang o fromVersion, nen chu ky sau se GOI LAI ApplyDeltaSequenceAsync
        // VOI CUNG (fromVersion, toVersion). Lan goi lai do doc lai file da
        // BI GHI DE o lan truoc (da chua san du lieu cua chinh cac goi delta
        // nay), roi tai lai CUNG cac goi delta do va APPEND THEM MOT LAN
        // NUA — moi hash bi nhan doi trong file CSV, ngay cang phinh to qua
        // moi lan retry that bai. Sua: gop du lieu theo KEY la sha256 hash
        // (cot dau tien moi dong CSV) vao mot Dictionary — dong MOI cho
        // cung mot hash se GHI DE (khong nhan doi) dong CU, nen viec doc lai
        // file da tung ghi (thanh cong hay dang do) roi ghi lai VOI CUNG
        // input luon cho ra CUNG mot ket qua (idempotent khi retry).
        var accumulated = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (File.Exists(_accumulatorCsvPath))
        {
            foreach (var line in await File.ReadAllLinesAsync(_accumulatorCsvPath, ct))
            {
                AddCsvLine(accumulated, line);
            }
        }

        for (int v = fromVersion + 1; v <= toVersion; v++)
        {
            string pkgName = $"v{v - 1}_to_v{v}.delta";
            var pkg = await _source.DownloadPackageAsync(pkgName, ct);
            if (pkg is null)
            {
                _audit.Log("update", $"ERR-UPD: thieu goi delta {pkgName} — dung luong incremental");
                return false;
            }

            if (!UpdatePackageVerifier.TryVerifyAndExtract(pkg, _trustedCert, out var csvBytes))
            {
                _audit.Log("update", $"ERR-UPD-01: goi {pkgName} KHONG hop le chu ky so — tu choi ap dung, dung luong incremental");
                _logger.LogWarning("Goi delta {Pkg} khong verify duoc chu ky, bi tu choi", pkgName);
                return false;
            }

            var lines = System.Text.Encoding.UTF8.GetString(csvBytes)
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var line in lines) AddCsvLine(accumulated, line);
        }

        await File.WriteAllLinesAsync(_accumulatorCsvPath, accumulated.Values, ct);
        bool applied = RebuildAndSwap();
        if (applied)
        {
            SaveCurrentVersion(toVersion);
            _audit.Log("update", $"Da ap dung {toVersion - fromVersion} goi delta lien tiep, len toi v{toVersion}");
        }
        return applied;
    }

    // Dong CSV dang "sha256_hex,threat_id,severity" — dung cot dau (hash)
    // lam key de gop, dong SAU khop cung hash se GHI DE dong TRUOC (chap
    // nhan gia tri moi nhat neu delta cap nhat lai severity/threat_id cho
    // cung mot hash), tranh nhan doi hang loat khi retry (xem ghi chu o
    // ApplyDeltaSequenceAsync).
    private static void AddCsvLine(Dictionary<string, string> accumulated, string line)
    {
        var trimmed = line.Trim();
        if (trimmed.Length == 0) return;
        int commaIdx = trimmed.IndexOf(',');
        string key = commaIdx > 0 ? trimmed[..commaIdx] : trimmed;
        accumulated[key] = trimmed;
    }

    // API-02/ERR-UPD-02: "ghi CSDL moi vao file tam roi doi ten hoan doi
    // nguyen tu (MoveFileEx/MOVEFILE_REPLACE_EXISTING) thay the file cu, de
    // khong bao gio co khoang thoi gian CSDL o trang thai ghi do dang".
    private bool RebuildAndSwap()
    {
        var tempDb = _signatureDbPath + ".tmp";
        bool built = ScanEngineService.BuildSignatureDb(_accumulatorCsvPath, tempDb);
        if (!built)
        {
            _logger.LogError("Khong build lai duoc CSDL signature tu {Csv}", _accumulatorCsvPath);
            return false;
        }

        // [SUA LOI NGHIEM TRONG] Truoc day goi File.Move roi Engine_Initialize
        // — nhung tai thoi diem File.Move chay, engine VAN CON giu mot VIEW
        // MEMORY-MAP dang hoat dong tren _signatureDbPath (tu lan Initialize
        // truoc do), khien Windows tu choi rename (ERROR_ACCESS_DENIED /
        // "user-mapped file") NGAY CA KHI handle da co FILE_SHARE_DELETE —
        // co nay chi cho phep rename khi KHONG CON view nao dang map, rieng
        // no khong du. Ket qua thuc te: cap nhat CSDL LAN DAU thanh cong
        // (file dich chua ton tai nen khong co gi de "thay the"), nhung MOI
        // lan cap nhat KE TIEP deu nem UnauthorizedAccessException, tinh
        // nang auto-update coi nhu chet vinh vien ma khong co canh bao ro
        // rang. Kiem chung bang test hoi quy
        // SecondConsecutiveUpdate_StillSucceeds_AfterShareDeleteFix.
        //
        // Sua: giai phong view TRUOC (UnmapSignatureDb), roi moi rename, roi
        // nap lai (LoadSignatureDb) — dung "cua so trong khong co CSDL"
        // trong luc rename cuc ngan (vai mili giay), duoc chap nhan duoc vi
        // trong luc do cac luong quet van chay binh thuong, chi tam thoi
        // khong co g_sig_db (tuong duong hanh vi "chua co CSDL" luc dau moi
        // cai app — khong crash, chi tam thoi mat nhanh phat hien hash).
        _engine.UnmapSignatureDb();
        try
        {
            File.Move(tempDb, _signatureDbPath, overwrite: true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Khong doi ten duoc CSDL moi vao vi tri {Path}", _signatureDbPath);
            // Co gang nap lai CSDL CU (neu con) de khong bo lai dich vu o
            // trang thai hoan toan khong co CSDL nao.
            if (File.Exists(_signatureDbPath)) _engine.LoadSignatureDb(_signatureDbPath);
            return false;
        }

        bool loaded = _engine.LoadSignatureDb(_signatureDbPath);
        if (!loaded)
        {
            _logger.LogError("Da doi ten CSDL moi nhung nap lai vao engine that bai: {Path}", _signatureDbPath);
        }
        return loaded;
    }

    private int LoadCurrentVersion() => Antivirus.Service.Common.JsonVersionState.Load(_versionStatePath);

    private void SaveCurrentVersion(int version)
    {
        Status.CurrentVersion = version;
        Antivirus.Service.Common.JsonVersionState.Save(_versionStatePath, version);

        // [DIEM AN TOAN BAT BUOC] Xoa toan bo cache full scan moi khi CSDL
        // doi version — neu khong, mot file tung "Clean" duoi CSDL cu se bi
        // bo qua vinh vien ke ca sau khi CSDL moi da nhan dien no la ma doc.
        try
        {
            _scanCache?.ClearAll();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Khong xoa duoc cache full scan sau khi cap nhat CSDL len v{Version}", version);
        }
    }
}
