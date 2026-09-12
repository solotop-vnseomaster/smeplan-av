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
    // [SUA LOI CHAN PHAT HANH — A3] Cert co the VANG MAT: tren may san
    // xuat, neu operator chua cau hinh UpdateSigning:CertPath thi service
    // van phai khoi dong va bao ve may (quet, real-time, quarantine), CHI
    // rieng kenh cap nhat bi tat. Truoc day Program.cs lay cert bang mot
    // loi goi lượng gia tuc thi ngay tai dong dang ky DI, nen thieu cau
    // hinh = nem InvalidOperationException = service KHONG BAO GIO khoi
    // dong duoc tren bat ky may nao cai bang MSI. Mot AV khong chay con te
    // hon mot AV khong tu cap nhat.
    // null = KHONG co neo tin cay => moi goi cap nhat deu bi tu choi
    // (fail-closed, xem TryVerifyPackage).
    private readonly X509Certificate2? _trustedCert;
    private readonly TimeSpan _interval;

    private readonly string _versionStatePath;
    private readonly string _accumulatorCsvPath;
    private readonly string _signatureDbPath;
    private readonly ScanCacheStore? _scanCache;

    public UpdateStatus Status { get; } = new();

    // Phoi ra ngoai de /api/status hien duoc trang thai suy giam thay vi
    // im lang bo qua moi goi cap nhat.
    public bool SigningTrustConfigured => _trustedCert is not null;

    // Chi cho phep MOT luot check/apply chay tai mot thoi diem — xem ghi chu
    // trong CheckAndApplyAsync.
    private readonly SemaphoreSlim _updateGate = new(1, 1);

    // Cua DUY NHAT di toi UpdatePackageVerifier trong class nay — de khong
    // co duong nao xac thuc goi ma bo qua kiem tra "co neo tin cay khong".
    private bool TryVerifyPackage(byte[] signedPackage, out byte[] payload)
    {
        if (_trustedCert is null)
        {
            payload = Array.Empty<byte>();
            return false;
        }
        return UpdatePackageVerifier.TryVerifyAndExtract(signedPackage, _trustedCert, out payload);
    }

    // Cac tham so path la optional, mac dinh dung DataPaths (san xuat that);
    // kiem thu co the truyen path rieng de co lap voi ProgramData that.
    // scanCache la optional (null trong test) — khi co, moi lan ap dung
    // CSDL moi thanh cong se xoa toan bo cache full scan (xem
    // ScanCacheStore.cs muc "DIEM AN TOAN BAT BUOC").
    public UpdateClientService(IUpdatePackageSource source, ScanEngineService engine, AuditLogger audit,
        ILogger<UpdateClientService> logger, X509Certificate2? trustedCert, TimeSpan? interval = null,
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
        if (_trustedCert is null)
        {
            // Khong co neo tin cay -> khong quay vong lap vo ich moi 6 tieng,
            // nhung PHAI de lai dau vet ro rang: day la trang thai suy giam,
            // khong phai "moi thu binh thuong".
            Status.LastResult = "Kenh cap nhat DA TAT: chua cau hinh certificate ky goi cap nhat";
            _logger.LogWarning(
                "Kenh cap nhat CSDL DA TAT vi thieu cau hinh UpdateSigning:CertPath / " +
                "UpdateSigning:CertPasswordEnvVar — service van quet va bao ve binh thuong, " +
                "nhung CSDL chu ky se KHONG duoc cap nhat tu dong.");
            _audit.Log("update", "Kenh cap nhat DA TAT: thieu certificate ky goi cap nhat (fail-closed)");
            return;
        }

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
        // Cung guard nhu ExecuteAsync — endpoint /api/update/check-now goi
        // thang vao day, khong di qua vong lap nen.
        if (_trustedCert is null)
        {
            Status.LastResult = "Kenh cap nhat DA TAT: chua cau hinh certificate ky goi cap nhat";
            return Status;
        }

        // [SUA LOI NGHIEM TRONG] TRUOC DAY co Status.CheckInProgress duoc GAN
        // o day va xoa o finally, nhung KHONG MOT NOI NAO trong toan bo ma
        // nguon doc no — no khong phai la mot khoa, chi la mot bao cao trang
        // thai khong ai xem. Nghia la POST /api/update/check-now co the chay
        // DONG THOI voi vong lap nen (ExecuteAsync): hai luot cap nhat cung
        // ghi vao _accumulatorCsvPath, cung tao file CSDL tam, va cung goi
        // RebuildAndSwap — trong do co UnmapSignatureDb() / File.Move /
        // LoadSignatureDb(). Hai luong dan xen trong day thao tac do co the
        // de lai signatures.avsigdb la file tam do dang cua luot kia, hoac
        // de engine o trang thai khong co CSDL nao duoc nap.
        //
        // Sua: mot khoa THAT SU. Luot goi thu hai khong xep hang doi (khong
        // co ich gi khi cung kiem tra mot phien ban) ma tra ve ngay trang
        // thai hien tai — dung ngu nghia ma CheckInProgress ham y tu dau.
        if (!await _updateGate.WaitAsync(0, ct))
        {
            Status.LastResult = "Dang co mot luot kiem tra cap nhat chay — bo qua yeu cau nay";
            return Status;
        }

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
            _updateGate.Release();
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

        if (!TryVerifyPackage(pkg, out var csvBytes))
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
        int rejectedExisting = 0;
        if (File.Exists(_accumulatorCsvPath))
        {
            foreach (var line in await File.ReadAllLinesAsync(_accumulatorCsvPath, ct))
            {
                if (!AddCsvLine(accumulated, line)) rejectedExisting++;
            }
        }

        // Dong hong TRONG FILE TICH LUY DA CO SAN tren dia la dau hieu file
        // bi can thiep hoac hong — khong phai loi cua goi dang tai. Bao dong
        // ro rang; file van dung duoc (dong hong bi loai) nhung su viec phai
        // duoc ghi nhan de dieu tra.
        if (rejectedExisting > 0)
        {
            _audit.Log("update",
                $"CANH BAO: {rejectedExisting} dong KHONG hop le trong {_accumulatorCsvPath} — da loai bo, file tich luy chu ky co the da bi can thiep");
            _logger.LogError(
                "{Count} dong khong hop le trong file tich luy chu ky {Path} — da loai bo",
                rejectedExisting, _accumulatorCsvPath);
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

            if (!TryVerifyPackage(pkg, out var csvBytes))
            {
                _audit.Log("update", $"ERR-UPD-01: goi {pkgName} KHONG hop le chu ky so — tu choi ap dung, dung luong incremental");
                _logger.LogWarning("Goi delta {Pkg} khong verify duoc chu ky, bi tu choi", pkgName);
                return false;
            }

            var lines = System.Text.Encoding.UTF8.GetString(csvBytes)
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            int rejected = 0;
            foreach (var line in lines) { if (!AddCsvLine(accumulated, line)) rejected++; }
            if (rejected > 0)
            {
                // Goi da qua verify chu ky nhung chua dong sai dinh dang —
                // khong duoc am tham ap dung mot phan. Dung luong lai.
                _audit.Log("update",
                    $"ERR-UPD: goi {pkgName} chua {rejected} dong CSV khong hop le — tu choi ap dung, dung luong incremental");
                _logger.LogError("Goi delta {Pkg} chua {Count} dong khong hop le, bi tu choi", pkgName, rejected);
                return false;
            }
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
    // [SUA LOI NGHIEM TRONG] TRUOC DAY ham nay chap nhan BAT KY chuoi nao:
    // key la phan truoc dau phay dau tien, gia tri la ca dong, khong kiem
    // tra dinh dang gi. Ket hop voi viec engine (SignatureDb::BuildFromCsv)
    // AM THAM BO QUA moi dong CSV hong roi van bao build thanh cong, day la
    // mot duong VO HIEU HOA CO MUC TIEU tung chu ky mot:
    //   ghi mot dong "<hash_that>,notanumber,5" vao signature_accumulator.csv
    //   -> dong nay GHI DE ban ghi that (cung key hash) -> BuildFromCsv bo
    //   qua vi threat_id khong parse duoc -> CSDL moi thieu DUNG chu ky do,
    //   record_count nho hon 1 don vi, va log ghi "cap nhat thanh cong".
    // File nay la GOC TIN CAY THAT SU cua CSDL chu ky (chu ky so chi gac cac
    // GOI delta, chua bao gio gac chinh file tich luy nay).
    //
    // Sua: validate dung dinh dang truoc khi nhan. Dong khong hop le bi TU
    // CHOI (khong ghi de duoc ban ghi that) va duoc dem lai de phia goi bao
    // dong ro rang thay vi mat chu ky trong im lang.
    private static bool AddCsvLine(Dictionary<string, string> accumulated, string line)
    {
        var trimmed = line.Trim();
        if (trimmed.Length == 0) return true; // dong trong: bo qua, khong phai loi

        var parts = trimmed.Split(',');
        if (parts.Length != 3) return false;

        string hash = parts[0].Trim();
        if (hash.Length != 64) return false;
        foreach (char c in hash)
        {
            bool isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!isHex) return false;
        }

        // Phai khop dung pham vi ma engine dung: threat_id la uint32,
        // severity la uint8. Gia tri ngoai pham vi se bi BuildFromCsv nem/bo
        // qua — chan ngay tai day de khong bao gio ghi de duoc ban ghi that.
        if (!uint.TryParse(parts[1].Trim(), out _)) return false;
        if (!byte.TryParse(parts[2].Trim(), out _)) return false;

        accumulated[hash] = $"{hash},{parts[1].Trim()},{parts[2].Trim()}";
        return true;
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

        // [SUA LOI NGHIEM TRONG] TRUOC DAY neu File.Move thanh cong nhung
        // LoadSignatureDb() SAU DO that bai (file moi build OK nhung vi ly
        // do nao đo — dia hong, file bi khoa tuc thoi... — khong nap duoc
        // vao engine), ham chi log loi roi return false, BO MAC engine o
        // trang thai KHONG CO g_sig_db nao ca (UnmapSignatureDb da giai
        // phong view CU tu truoc do). Vi CheckAndApplyAsync() KHONG goi
        // SaveCurrentVersion khi applied=false, client van nghi minh o
        // phien ban CU va se chi thu lai o CHU KY SAU (mac dinh 2 GIO) — tuc
        // la dich vu chay KHONG CO CSDL signature nao (moi hash-scan deu bo
        // qua) trong toan bo khoang thoi gian do, khong phai "vai mili giay"
        // nhu ghi chu ben duoi mo ta cho truong hop binh thuong. Sua: sao
        // luu CSDL CU truoc khi swap, va neu nap CSDL MOI that bai thi thu
        // KHOI PHUC LAI CSDL CU tu ban sao luu do (van tra ve false — phien
        // ban CHUA duoc ap dung thanh cong, se thu lai o lan check tiep
        // theo — nhung engine co CSDL de dung ngay, khong bi "trang" keo dai).
        var backupDb = tempDb + ".bak";
        bool hadExistingDb = File.Exists(_signatureDbPath);

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
            if (hadExistingDb)
            {
                // Sao chep (khong phai move) CSDL CU sang ban sao luu tam —
                // giu nguyen file goc tai _signatureDbPath cho toi khi
                // File.Move ben duoi thay the no, de neu chinh buoc copy nay
                // that bai thi chua co gi bi dong den.
                File.Copy(_signatureDbPath, backupDb, overwrite: true);
            }
            File.Move(tempDb, _signatureDbPath, overwrite: true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Khong doi ten duoc CSDL moi vao vi tri {Path}", _signatureDbPath);
            // Co gang nap lai CSDL CU (neu con) de khong bo lai dich vu o
            // trang thai hoan toan khong co CSDL nao.
            if (File.Exists(_signatureDbPath)) _engine.LoadSignatureDb(_signatureDbPath);
            CleanupBackup(backupDb);
            return false;
        }

        bool loaded = _engine.LoadSignatureDb(_signatureDbPath);
        if (!loaded)
        {
            _logger.LogError("Da doi ten CSDL moi nhung nap lai vao engine that bai: {Path} — thu khoi phuc CSDL CU tu ban sao luu de tranh dich vu chay khong co CSDL nao cho toi chu ky sau", _signatureDbPath);
            if (hadExistingDb && File.Exists(backupDb))
            {
                try
                {
                    File.Copy(backupDb, _signatureDbPath, overwrite: true);
                    if (_engine.LoadSignatureDb(_signatureDbPath))
                    {
                        _logger.LogWarning("Da khoi phuc va nap lai CSDL CU thanh cong sau khi CSDL moi loi — se thu ap dung lai o chu ky check tiep theo");
                    }
                    else
                    {
                        _logger.LogError("Khoi phuc CSDL CU tu ban sao luu cung khong nap lai duoc — dich vu tam thoi khong co CSDL signature nao");
                    }
                }
                catch (Exception ex2)
                {
                    _logger.LogError(ex2, "Khong khoi phuc duoc CSDL CU tu ban sao luu sau khi CSDL moi nap loi");
                }
            }
        }
        CleanupBackup(backupDb);
        // Luu y: `loaded` phan anh ket qua nap CSDL MOI — neu that bai va da
        // roll-back ve CSDL CU o tren, ham VAN tra ve false (phien ban moi
        // CHUA duoc ap dung thanh cong nen KHONG duoc SaveCurrentVersion),
        // nhung engine luc nay van co mot CSDL hop le de dung ngay thay vi
        // trong rong toi chu ky sau.
        return loaded;
    }

    private void CleanupBackup(string backupDb)
    {
        try { if (File.Exists(backupDb)) File.Delete(backupDb); }
        catch (Exception ex) { _logger.LogWarning(ex, "Khong xoa duoc file backup tam {Path}", backupDb); }
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
