using System.Reflection;
using System.Security.Cryptography;
using Antivirus.Service.Audit;
using Antivirus.Service.Extensions;
using Antivirus.Service.Extensions.Ransomware;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Antivirus.Service.Tests;

// [test-coverage] RansomwareGuardService.EvaluateWindow (3-tin-hieu +
// nhanh rollback tung phan) truoc day KHONG co test nao — day la logic tu
// dong GHI DE/ROLLBACK file nguoi dung, rui ro cao nhat neu sai (mat du
// lieu that hoac bo lo ransomware that). EvaluateWindow/OnFileEvent la
// private (khong duoc thiet ke de goi tu ben ngoai — chi ExecuteAsync/
// BackgroundService goi dinh ky moi 20s), nen test dung reflection de goi
// truc tiep, tranh phai cho that 20s hoac dung FileSystemWatcher/thu muc
// Documents/Pictures/Desktop that cua may chay test.
//
// [LUU Y THIET KE] Cac file mo phong GIU NGUYEN ten (khong doi ten/duoi) —
// entropy-jump signal tra cuu baseline trong VersionStore theo original_path
// CHINH XAC (batch.GetLatestVersion(path)); neu file bi doi ten thuc su
// (nhu FileSystemWatcher.Renamed cung cap duong dan MOI), baseline duoc
// snapshot duoi ten CU se khong con khop — day la mot han che rieng cua
// thiet ke that (nam ngoai pham vi test-coverage nay), nen test mo phong
// "ghi de tai cho" (giong watcher.Changed) de kiem tra dung logic 3-tin-hieu
// + rollback, khong phu thuoc vao han che do. Tin hieu "doi duoi hang loat"
// van duoc kich hoat vi >= ExtensionBurstThreshold file cung chia se mot
// duoi (.txt) trong cua so — dung ham GroupBy hien tai, khong phan biet
// "duoi cu" hay "duoi moi".
public class RansomwareGuardServiceTests : IDisposable
{
    private readonly string _tempDir;
    private readonly VersionStore _versionStore;
    private readonly EventBus _eventBus;
    private readonly RansomwareGuardService _guard;

    public RansomwareGuardServiceTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("avtest_ransomware_").FullName;
        _versionStore = new VersionStore(
            Path.Combine(_tempDir, "versions.db"),
            Path.Combine(_tempDir, "storage"));
        _eventBus = new EventBus(new AuditLogger(Path.Combine(_tempDir, "audit.jsonl")), NullLogger<EventBus>.Instance);
        _guard = new RansomwareGuardService(_versionStore, _eventBus, NullLogger<RansomwareGuardService>.Instance);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    private void OnFileEvent(string path) =>
        typeof(RansomwareGuardService)
            .GetMethod("OnFileEvent", BindingFlags.NonPublic | BindingFlags.Instance)!
            .Invoke(_guard, new object[] { path });

    private void EvaluateWindow() =>
        typeof(RansomwareGuardService)
            .GetMethod("EvaluateWindow", BindingFlags.NonPublic | BindingFlags.Instance)!
            .Invoke(_guard, null);

    // Tao mot file "sach" voi noi dung entropy THAP (mot byte lap lai) va
    // snapshot no lam baseline trong version store TRUOC KHI "ma hoa" —
    // giong trinh tu that: BaselineSnapshotExistingFiles chup luc con sach.
    private string CreateBaselinedFile(string name)
    {
        var path = Path.Combine(_tempDir, name);
        File.WriteAllBytes(path, Enumerable.Repeat((byte)0x41, 4096).ToArray());
        _versionStore.SnapshotFile(path, triggeredByPid: 0);
        return path;
    }

    // Mo phong ransomware ghi de tai cho: noi dung entropy CAO (byte ngau
    // nhien), giu nguyen duong dan/ten file.
    private static void EncryptInPlace(string path)
    {
        var random = new byte[4096];
        RandomNumberGenerator.Fill(random);
        File.WriteAllBytes(path, random);
    }

    [Fact]
    public void NoEvents_EvaluateWindow_PublishesNoAlert()
    {
        EvaluateWindow();

        Assert.Empty(_guard.GetRecentAlerts());
    }

    // [test-coverage] Kich ban chinh: DU CA 3 tin hieu (>=15 file bi ghi,
    // entropy tang vot dong loat, >=8 file cung chia se mot duoi) VA moi
    // file co baseline sach -> RestoreLatestVersion phai thanh cong cho TAT
    // CA, AutoRolledBack phai la true (khoi phuc DAY DU, khong chi "co khoi
    // phuc it nhat 1 file" nhu bug da sua trong ghi chu class).
    [Fact]
    public void AllThreeSignalsWithFullBaseline_ConfirmsRansomware_RestoresAllFiles_AutoRolledBackTrue()
    {
        const int fileCount = 15; // >= WriteRateThreshold va ExtensionBurstThreshold, cung chia se .txt
        var paths = new List<string>();
        for (int i = 0; i < fileCount; i++)
        {
            paths.Add(CreateBaselinedFile($"doc{i}.txt"));
        }

        foreach (var path in paths)
        {
            EncryptInPlace(path);
            OnFileEvent(path);
        }

        EvaluateWindow();

        var alert = Assert.Single(_guard.GetRecentAlerts());
        Assert.Equal(1, alert.WriteRateSignal);
        Assert.Equal(1, alert.EntropyJumpSignal);
        Assert.Equal(1, alert.ExtensionBurstSignal);
        Assert.True(alert.AutoRolledBack, "Ca 15 file deu co baseline -> phai khoi phuc DAY DU");
        Assert.Equal(fileCount, alert.AffectedPaths.Count);

        // Noi dung goc phai duoc khoi phuc that su tren dia, khong chi co
        // trong DB — phai co lai byte 0x41 lap lai (noi dung baseline),
        // khong con la byte ngau nhien cua "ban ma hoa".
        foreach (var path in paths)
        {
            var content = File.ReadAllBytes(path);
            Assert.All(content, b => Assert.Equal(0x41, b));
        }
    }

    // [test-coverage] Nhanh rollback TUNG PHAN da duoc sua ("SUA LOI NGHIEM
    // TRONG" trong EvaluateWindow): neu KHONG PHAI moi file bi anh huong deu
    // co baseline (vi du file duoc tao SAU khi service khoi dong, truoc khi
    // co su kien ghi dau tien duoc quan sat — han che da biet cua
    // BaselineSnapshotExistingFiles), restoredCount < distinctPaths.Count va
    // AutoRolledBack PHAI la false — khong duoc bao "thanh cong" khi chi
    // khoi phuc duoc mot phan.
    [Fact]
    public void AllThreeSignalsWithPartialBaseline_RestoresOnlyBaselinedFiles_AutoRolledBackFalse()
    {
        const int baselinedCount = 10;
        const int noBaselineCount = 5; // tong 15, du WriteRateThreshold/ExtensionBurstThreshold
        var baselined = new List<string>();
        var noBaseline = new List<string>();

        for (int i = 0; i < baselinedCount; i++)
        {
            baselined.Add(CreateBaselinedFile($"has-baseline-{i}.txt"));
        }
        for (int i = 0; i < noBaselineCount; i++)
        {
            // KHONG snapshot — mo phong file moi tao, chua kip co baseline.
            var path = Path.Combine(_tempDir, $"no-baseline-{i}.txt");
            File.WriteAllBytes(path, Enumerable.Repeat((byte)0x42, 4096).ToArray());
            noBaseline.Add(path);
        }

        foreach (var path in baselined.Concat(noBaseline))
        {
            EncryptInPlace(path);
            OnFileEvent(path);
        }

        EvaluateWindow();

        var alert = Assert.Single(_guard.GetRecentAlerts());
        Assert.True(alert.WriteRateSignal == 1 && alert.EntropyJumpSignal == 1 && alert.ExtensionBurstSignal == 1,
            "Ca 3 tin hieu phai dat de di vao nhanh rollback dang xet");
        Assert.False(alert.AutoRolledBack, "Chi 10/15 file co baseline -> khong duoc coi la khoi phuc DAY DU");
        Assert.Equal(baselinedCount + noBaselineCount, alert.AffectedPaths.Count);

        // Cac file CO baseline phai duoc khoi phuc that su.
        foreach (var path in baselined)
        {
            Assert.All(File.ReadAllBytes(path), b => Assert.Equal(0x41, b));
        }
        // Cac file KHONG co baseline phai VAN CON la noi dung ma hoa (random)
        // — khong the khoi phuc noi dung khong ton tai.
        foreach (var path in noBaseline)
        {
            Assert.False(File.ReadAllBytes(path).All(b => b == 0x42));
        }
    }

    // [test-coverage] Chi 1-2/3 tin hieu (o day: entropy + duoi la, KHONG du
    // toc do ghi) -> theo doi them, KHONG tu dong rollback (dung theo tai
    // lieu "ha xuong muc theo doi them"). AutoRolledBack phai la false va
    // KHONG file nao bi ghi de boi RestoreLatestVersion.
    [Fact]
    public void OnlyTwoSignals_DoesNotAutoRestore()
    {
        const int fileCount = 8; // du ExtensionBurstThreshold nhung KHONG du WriteRateThreshold (15)
        var paths = new List<string>();
        for (int i = 0; i < fileCount; i++)
        {
            paths.Add(CreateBaselinedFile($"partial{i}.txt"));
        }

        foreach (var path in paths)
        {
            EncryptInPlace(path);
            OnFileEvent(path);
        }

        EvaluateWindow();

        var alert = Assert.Single(_guard.GetRecentAlerts());
        Assert.Equal(0, alert.WriteRateSignal);
        Assert.False(alert.AutoRolledBack);

        // Noi dung van phai la ban ma hoa (random), KHONG bi rollback ve
        // baseline, vi ransomware CHUA duoc xac nhan du 3 tin hieu.
        foreach (var path in paths)
        {
            var content = File.ReadAllBytes(path);
            Assert.False(content.All(b => b == 0x41), "Chua xac nhan du 3 tin hieu thi KHONG duoc tu dong rollback");
        }
    }
}
