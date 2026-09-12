using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Antivirus.Service.Archive;
using Antivirus.Service.Audit;
using Antivirus.Service.Data;
using Antivirus.Service.Engine;
using Antivirus.Service.Extensions;
using Antivirus.Service.Extensions.CloudIntel;
using Antivirus.Service.FullScan;
using Antivirus.Service.Quarantine;
using Antivirus.Service.Settings;
using Antivirus.Service.Update;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Antivirus.Service.Tests;

// flows/11 "Luong Full/Deep Scan": buoc 2 "kiem tra file system type qua
// GetVolumeInformation" quyet dinh nhanh USN Journal (NTFS) hay fallback
// duyet cay thu muc (FAT32/exFAT) — TEST-08.
// [HAN CHE MOI TRUONG] Khong co o dia FAT32/exFAT vat ly trong moi truong
// nay de test nhanh fallback that; test nay xac nhan logic quyet dinh chay
// dung tren volume NTFS that (o C: trong hau het may Windows hien dai) va
// khong crash tren dau vao khong hop le.
//
// [Collection("EngineSequential")] Cac test ben duoi dung ScanEngineService
// that (P/Invoke toi scan_engine.dll voi mutex trang thai toan cuc) —
// giong EngineTests/UpdateClientServiceTests/ArchiveScannerTests, phai
// chay TUAN TU (khong song song giua cac lop test) de tranh dung do
// Engine_Initialize/Engine_Shutdown giua cac test class khac nhau.
[Collection("EngineSequential")]
public class FullScanServiceTests : IDisposable
{
    [Fact]
    public void SystemDrive_DetectedAsNtfs()
    {
        var systemDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))!;

        bool isNtfs = FullScanService.VolumeSupportsUsnJournal(systemDrive);

        Assert.True(isNtfs, $"O dia he thong {systemDrive} duoc ky vong la NTFS tren Windows hien dai");
    }

    [Fact]
    public void InvalidVolume_ReturnsFalse_DoesNotThrow()
    {
        bool result = FullScanService.VolumeSupportsUsnJournal("Z:\\khong-ton-tai\\");

        Assert.False(result);
    }

    // ---------- Start/Pause/Resume/Cancel lifecycle (truoc day khong co test nao) ----------

    private readonly string _tempDir;
    private readonly ScanEngineService _engine;
    private readonly FullScanService _scan;

    public FullScanServiceTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("avtest_fullscan_").FullName;

        _engine = new ScanEngineService(NullLogger<ScanEngineService>.Instance);
        _engine.Initialize(null, null);

        var archiveScanner = new ArchiveScanner(_engine, NullLogger<ArchiveScanner>.Instance);

        var quarantineDbPath = Path.Combine(_tempDir, "quarantine.db");
        var quarantineStore = new QuarantineStore(quarantineDbPath);
        var audit = new AuditLogger(Path.Combine(_tempDir, "audit.jsonl"));
        var quarantineDir = Directory.CreateTempSubdirectory("avtest_fullscan_qtn_").FullName;
        var quarantine = new QuarantineManager(quarantineStore, audit, NullLogger<QuarantineManager>.Instance,
            quarantineDir, applyAcl: false);

        var cache = new ScanCacheStore(Path.Combine(_tempDir, "scan_cache.db"));
        var settings = new AppSettingsStore(Path.Combine(_tempDir, "settings.json"));

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test FullScan", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var trustedCert = X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx, "test"), "test", X509KeyStorageFlags.Exportable);
        var dropFolder = Directory.CreateTempSubdirectory("avtest_fullscan_drop_").FullName;
        var updateService = new UpdateClientService(new LocalFolderUpdatePackageSource(dropFolder), _engine, audit,
            NullLogger<UpdateClientService>.Instance, trustedCert,
            versionStatePath: Path.Combine(_tempDir, "update_version.json"),
            accumulatorCsvPath: Path.Combine(_tempDir, "accumulator.csv"),
            signatureDbPath: Path.Combine(_tempDir, "sigs.avsigdb"));

        var gamingMode = new GamingModeService(NullLogger<GamingModeService>.Instance);
        var eventBus = new EventBus(audit, NullLogger<EventBus>.Instance);
        var cloudIntel = new CloudReputationClient(Path.Combine(_tempDir, "cloud_reputation.db"));

        _scan = new FullScanService(_engine, archiveScanner, quarantine, audit,
            NullLogger<FullScanService>.Instance, cache, settings, updateService, gamingMode, eventBus, cloudIntel);
    }

    // Thu muc rong (khong co file nao) — quet xong gan nhu tuc thi, dung de
    // test cac chuyen doi trang thai KHONG can cho lau.
    private string EmptyScanTarget() => Directory.CreateTempSubdirectory("avtest_fullscan_empty_").FullName;

    // [SUA LOI TEST FLAKY] Mot so test can lan quet VAN CON DANG CHAY trong
    // suot thoi gian test thao tac. Voi EmptyScanTarget() thi RunScan ket
    // thuc gan nhu tuc thi, nen bat ky khang dinh nao dua tren "dang Running"
    // deu tro thanh mot cuoc dua voi chinh no. Target nay du lon de lan quet
    // song lau hon nhieu so voi cua so dua (xem ghi chu tai
    // Start_CalledConcurrentlyFromMultipleThreads_OnlyOneSucceeds).
    private string SlowScanTarget(int fileCount = 3000)
    {
        var dir = Directory.CreateTempSubdirectory("avtest_fullscan_slow_").FullName;
        var content = new byte[1024];
        for (int i = 0; i < fileCount; i++)
        {
            // Noi dung khac nhau tung file de khong bi cache hash lam ngan
            // lai (ScanCacheStore khoa theo hash).
            content[0] = (byte)(i & 0xFF);
            content[1] = (byte)((i >> 8) & 0xFF);
            File.WriteAllBytes(Path.Combine(dir, $"f{i}.bin"), content);
        }
        return dir;
    }

    [Fact]
    public void Start_ReturnsTrue_AndSetsStatusRunningImmediately()
    {
        bool started = _scan.Start(EmptyScanTarget());

        Assert.True(started);
        // Status duoc gan Running DONG BO ngay trong Start() (truoc khi
        // Task.Run bat dau chay nen), nen kiem tra ngay sau khi Start() tra
        // ve la an toan, khong phu thuoc timing cua luong nen.
        Assert.Equal(FullScanStatus.Running, _scan.GetProgress().Status);
    }

    // [test-coverage] Truoc day khong co test nao xac nhan Start() TU CHOI
    // khoi dong lan hai khi dang co mot lan quet chay do dang — neu guard
    // nay hong (vi du bi xoa nham khi refactor), 2 lan quet song song co
    // the dam vao nhau (cung ghi resume-state, cung tang counter FilesScanned...).
    [Fact]
    public void Start_WhileAlreadyRunning_ReturnsFalse()
    {
        bool first = _scan.Start(EmptyScanTarget());
        // Goi lai NGAY LAP TUC tren cung luong test, khong yield/await —
        // luong nen (Task.Run) chua kip chay xong (can it nhat 2 P/Invoke
        // native de xac dinh NTFS/HDD) nen Status van con Running luc nay.
        bool second = _scan.Start(EmptyScanTarget());

        Assert.True(first);
        Assert.False(second);
    }

    [Fact]
    public async Task Start_EmptyDirectory_EventuallyCompletes()
    {
        _scan.Start(EmptyScanTarget());

        var status = await WaitForStatusAsync(s => s == FullScanStatus.Completed || s == FullScanStatus.Error);

        Assert.Equal(FullScanStatus.Completed, status);
    }

    // [test-coverage] Pause()/Resume() truoc day khong co test nao. Dung
    // mot thu muc co VAI FILE (khong rong) de vong lap enumerate chinh
    // thuc su di qua nhanh kiem tra "while (_paused) Thread.Sleep(500)" —
    // goi Pause() ngay sau Start() de bat kip truoc khi file dau tien duoc
    // xu ly xong, giu trang thai o Paused du lau de kiem tra duoc.
    [Fact]
    public async Task Pause_WhileRunning_SetsStatusPaused_ThenResume_SetsStatusRunning()
    {
        var dir = Directory.CreateTempSubdirectory("avtest_fullscan_files_").FullName;
        for (int i = 0; i < 5; i++)
        {
            File.WriteAllText(Path.Combine(dir, $"f{i}.txt"), "noi dung demo de quet, khong doc hai");
        }

        _scan.Start(dir);
        _scan.Pause();

        var pausedStatus = await WaitForStatusAsync(s => s == FullScanStatus.Paused || s == FullScanStatus.Completed);
        Assert.Equal(FullScanStatus.Paused, pausedStatus);

        _scan.Resume();
        var afterResume = await WaitForStatusAsync(s => s != FullScanStatus.Paused);
        Assert.NotEqual(FullScanStatus.Paused, afterResume);

        // Don dep: khong de scan treo o Paused sau khi test ket thuc.
        _scan.Cancel();
        await WaitForStatusAsync(s => s != FullScanStatus.Running && s != FullScanStatus.Paused);
    }

    // [test-coverage] Cancel() truoc day khong co test nao. Theo [SUA LOI
    // UX] da ghi trong RunScan: "Huy" phai dua ve Idle (bo han, lan sau bat
    // dau lai tu dau) — KHAC voi Pause (giu nguyen tien do de Resume tiep).
    [Fact]
    public async Task Cancel_WhilePaused_SetsStatusIdle()
    {
        var dir = Directory.CreateTempSubdirectory("avtest_fullscan_files2_").FullName;
        for (int i = 0; i < 5; i++)
        {
            File.WriteAllText(Path.Combine(dir, $"f{i}.txt"), "noi dung demo de quet, khong doc hai");
        }

        _scan.Start(dir);
        _scan.Pause();
        await WaitForStatusAsync(s => s == FullScanStatus.Paused || s == FullScanStatus.Completed);

        _scan.Cancel();

        var finalStatus = await WaitForStatusAsync(s => s != FullScanStatus.Running && s != FullScanStatus.Paused);
        Assert.Equal(FullScanStatus.Idle, finalStatus);
    }

    // Sau khi mot lan quet Cancel/Completed xong, Start() phai duoc phep
    // chay LAI (guard chi chan khi dang Running, khong khoa vinh vien).
    [Fact]
    public async Task Start_AfterPreviousScanCompleted_ReturnsTrueAgain()
    {
        _scan.Start(EmptyScanTarget());
        await WaitForStatusAsync(s => s == FullScanStatus.Completed || s == FullScanStatus.Error);

        bool startedAgain = _scan.Start(EmptyScanTarget());

        Assert.True(startedAgain);
    }

    // [test-coverage] Kich ban chinh xac cua bug da sua: Start() truoc day
    // la check-then-act KHONG khoa, goi dong thoi tu nhieu luong (giong HTTP
    // request va UsbMonitorService cung kich hoat auto-scan) co the ca hai
    // cung vuot qua check truoc khi luong nao kip gan Status=Running. Bat
    // nhieu luong that su dong thoi bang Barrier de toi da hoa co hoi trung
    // race neu guard bi mat khoa; sau khi sua, CHI DUNG MOT luong duoc phep
    // thanh cong.
    [Fact]
    public async Task Start_CalledConcurrentlyFromMultipleThreads_OnlyOneSucceeds()
    {
        // [SUA LOI TEST FLAKY] Test nay TRUOC DAY dung EmptyScanTarget() va
        // that bai khoang 2/3 so lan khi chay CA BO test (chay rieng thi gan
        // nhu luon xanh — dau hieu dien hinh cua phu thuoc timing chu khong
        // phai loi san pham). Nguyen nhan da xac dinh bang do dac: thong diep
        // that bai luon la "so lan Start() thanh cong = 2; status = Completed".
        //
        // Tuc la KHONG phai Start() cho hai lan quet chay song song — khoa
        // trong Start() hoan toan dung. Ma la: lan quet dau tren mot thu muc
        // RONG ket thuc trong vai chuc micro giay, TRUOC khi ca 16 thread kip
        // goi Start(). Thread nao goi sau do gap Status = Completed nen
        // thanh cong — dung theo dac ta. Test dang khang dinh mot dieu manh
        // hon thuc te: no gia dinh lan quet con song suot cuoc dua.
        //
        // Sua: cho lan quet mot khoi luong that de no chac chan con Running
        // trong suot cua so dua, VA khang dinh ro tien de do — neu may qua
        // nhanh/qua tai lam lan quet van kip xong, test bao dung ly do ("tien
        // de bi pha") thay vi do voi mot con so kho hieu.
        var target = SlowScanTarget();

        const int threadCount = 16;
        var barrier = new Barrier(threadCount);
        var results = new bool[threadCount];
        var statusesSeen = new FullScanStatus[threadCount];
        var tasks = new Task[threadCount];

        for (int i = 0; i < threadCount; i++)
        {
            int idx = i;
            tasks[idx] = Task.Run(() =>
            {
                barrier.SignalAndWait();
                results[idx] = _scan.Start(target);
                statusesSeen[idx] = _scan.GetProgress().Status;
            });
        }

        await Task.WhenAll(tasks);

        // Tien de: lan quet phai VAN CON SONG khi cuoc dua ket thuc. Neu
        // khong, khang dinh "chi mot lan thanh cong" khong con y nghia.
        Assert.False(statusesSeen.Contains(FullScanStatus.Completed),
            "TIEN DE BI PHA: lan quet da hoan tat NGAY TRONG cuoc dua, nen nhieu lan " +
            "Start() thanh cong la dung dac ta chu khong phai loi. Tang so file trong " +
            "SlowScanTarget() de lan quet song lau hon cua so dua.");

        Assert.True(results.Count(r => r) == 1,
            $"so lan Start() thanh cong = {results.Count(r => r)}; status hien tai = {_scan.GetProgress().Status}");

        _scan.Cancel();
        await WaitForStatusAsync(s => s != FullScanStatus.Running && s != FullScanStatus.Paused);
    }

    // [test-coverage] Truoc day Resume()/Pause() khong kiem tra trang thai
    // hien tai — goi Resume() khi dang Idle (chua tung Start()) se tao
    // Status=Running "ma" (khong RunScan nao thuc su chay phia sau).
    [Fact]
    public void Resume_WhenIdle_ReturnsFalse_DoesNotChangeStatus()
    {
        bool resumed = _scan.Resume();

        Assert.False(resumed);
        Assert.Equal(FullScanStatus.Idle, _scan.GetProgress().Status);
    }

    [Fact]
    public async Task Pause_WhenIdle_ReturnsFalse_DoesNotChangeStatus()
    {
        bool paused = _scan.Pause();

        Assert.False(paused);
        Assert.Equal(FullScanStatus.Idle, _scan.GetProgress().Status);
        await Task.CompletedTask;
    }

    // [test-coverage][KIEM THU HOI QUY] Kich ban chinh xac cua bug CRITICAL
    // da sua: Start() truoc day CHI chan khi Status == Running, KHONG chan
    // Paused — trong khi task nen cu van con song, dang block trong vong lap
    // cho _paused. Goi Start() luc dang Paused (nguoi dung doi o dia, hoac
    // UsbMonitorService tu dong quet khi cam USB moi) truoc day se duoc chap
    // nhan va set _paused = false, danh thuc CA task cu (chay song song voi
    // task moi, cung ghi de _progress/_flaggedItems dung chung).
    [Fact]
    public async Task Start_WhilePaused_ReturnsFalse()
    {
        var dir = Directory.CreateTempSubdirectory("avtest_fullscan_pausedstart_").FullName;
        for (int i = 0; i < 5; i++)
        {
            File.WriteAllText(Path.Combine(dir, $"f{i}.txt"), "noi dung demo de quet, khong doc hai");
        }

        _scan.Start(dir);
        _scan.Pause();
        var pausedStatus = await WaitForStatusAsync(s => s == FullScanStatus.Paused || s == FullScanStatus.Completed);
        Assert.Equal(FullScanStatus.Paused, pausedStatus);

        bool startedWhilePaused = _scan.Start(EmptyScanTarget());

        Assert.False(startedWhilePaused);
        Assert.Equal(FullScanStatus.Paused, _scan.GetProgress().Status);
    }

    [Fact]
    public async Task Resume_WhenAlreadyRunning_ReturnsFalse()
    {
        _scan.Start(EmptyScanTarget());

        bool resumed = _scan.Resume();

        Assert.False(resumed);

        await WaitForStatusAsync(s => s == FullScanStatus.Completed || s == FullScanStatus.Error);
    }

    private async Task<FullScanStatus> WaitForStatusAsync(Func<FullScanStatus, bool> predicate, int timeoutMs = 10_000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        FullScanStatus last;
        do
        {
            last = _scan.GetProgress().Status;
            if (predicate(last)) return last;
            await Task.Delay(25);
        } while (DateTime.UtcNow < deadline);
        return last;
    }

    public void Dispose()
    {
        try { _scan.Cancel(); } catch { }
        try { _engine.Dispose(); } catch { }
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }
}
