using System.Diagnostics;
using Antivirus.Service.Audit;
using Antivirus.Service.Data;
using Antivirus.Service.Models;
using Antivirus.Service.Trust;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Xunit.Abstractions;

namespace Antivirus.Service.Tests;

// Nhung test nay khoa BA bản sửa khiến tầng đánh giá tin cậy tiến trình không
// còn làm nghẹt máy đang làm việc. Cả ba đều từ một sự cố thật: AV chặn công cụ
// phát triển tới mức không dùng được, vì mỗi tiến trình mới đều bị băm lại toàn
// bộ file và mỗi tiến trình lạ đều sinh một hộp thoại chờ 30 giây.
public sealed class ProcessTrustPerformanceTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly string _dbPath;
    private readonly string _auditPath;
    private readonly RuleStore _rules;
    private readonly AuditLogger _audit;

    public ProcessTrustPerformanceTests(ITestOutputHelper output)
    {
        _output = output;
        _dbPath = Path.Combine(Path.GetTempPath(), $"avtest_perf_{Guid.NewGuid():N}.db");
        _auditPath = Path.Combine(Path.GetTempPath(), $"avtest_perf_{Guid.NewGuid():N}.jsonl");
        _rules = new RuleStore(_dbPath);
        _audit = new AuditLogger(_auditPath);
    }

    private ProcessTrustEngine CreateEngine(PermissionRequestBroker broker, FileIdentityCache cache) =>
        new(_rules, broker, _audit, NullLogger<ProcessTrustEngine>.Instance,
            userDecisionTimeout: TimeSpan.FromMilliseconds(200), identityCache: cache);

    // Mot binary Microsoft that, ky catalog, du lon de chi phi bam nhin thay duoc.
    private static string BigSystemBinary()
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "shell32.dll"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "certutil.exe"),
        };
        return candidates.First(File.Exists);
    }

    // ------------------------------------------------------------------
    // 1. CACHE — day la ban sua co tac dung lon nhat.
    //
    // Truoc khi sua: moi lan EvaluateAsync deu bam SHA-256 TOAN BO file va tra
    // chu ky (ke ca tra catalog he thong). Do tren may that: node.exe 90 MB mat
    // 209 ms mot lan bam. Mot cong cu phat trien sinh no hang tram lan trong
    // mot phien lam viec.
    // ------------------------------------------------------------------
    [Fact]
    public async Task RepeatedEvaluationOfSameBinary_IsServedFromCache()
    {
        var binary = BigSystemBinary();
        var cache = new FileIdentityCache();
        var broker = new PermissionRequestBroker();
        var engine = CreateEngine(broker, cache);

        var cold = Stopwatch.StartNew();
        await engine.EvaluateAsync(binary, 1001, CancellationToken.None);
        cold.Stop();

        // 20 lan tiep theo — dung kich ban mot cong cu sinh lai cung mot binary.
        var warm = Stopwatch.StartNew();
        for (int i = 0; i < 20; i++)
        {
            await engine.EvaluateAsync(binary, 2000 + i, CancellationToken.None);
        }
        warm.Stop();

        double perWarmCall = warm.Elapsed.TotalMilliseconds / 20.0;
        _output.WriteLine($"File            : {binary} ({new FileInfo(binary).Length / 1024:N0} KB)");
        _output.WriteLine($"Lan dau (lanh)  : {cold.Elapsed.TotalMilliseconds:N1} ms");
        _output.WriteLine($"20 lan sau      : {warm.Elapsed.TotalMilliseconds:N1} ms ({perWarmCall:N2} ms/lan)");
        _output.WriteLine($"Cache hit/miss  : {cache.Hits}/{cache.Misses}");

        // Dung 1 lan tinh that, 20 lan con lai lay tu cache.
        Assert.Equal(1, cache.Misses);
        Assert.Equal(20, cache.Hits);

        // Moi lan sau phai re hon HAN lan dau. Dat nguong long (mot nua) de
        // test khong vo vi nhieu do thoi gian tren may ban — dieu can chung
        // minh la cache CO duoc dung, va hai assert o tren da chung minh dieu do.
        Assert.True(perWarmCall < cold.Elapsed.TotalMilliseconds / 2,
            $"Lan goi sau ({perWarmCall:N2} ms) phai re hon han lan dau ({cold.Elapsed.TotalMilliseconds:N1} ms)");
    }

    // Cache PHAI tu vo hieu khi file doi — neu khong, thay mot binary da duoc
    // duyet bang binary khac o cung duong dan se duoc tin cay theo.
    [Fact]
    public async Task CacheIsInvalidated_WhenFileContentChanges()
    {
        var path = Path.Combine(Path.GetTempPath(), $"avtest_swap_{Guid.NewGuid():N}.exe");
        await File.WriteAllBytesAsync(path, new byte[] { 0x4D, 0x5A, 0x01, 0x02 });
        try
        {
            var cache = new FileIdentityCache();
            var engine = CreateEngine(new PermissionRequestBroker(), cache);

            await engine.EvaluateAsync(path, 3001, CancellationToken.None);
            Assert.Equal(1, cache.Misses);

            await engine.EvaluateAsync(path, 3002, CancellationToken.None);
            Assert.Equal(1, cache.Hits);

            // Thay noi dung: kich thuoc va mtime deu doi -> phai tinh lai.
            await Task.Delay(50);
            await File.WriteAllBytesAsync(path, new byte[] { 0x4D, 0x5A, 0x09, 0x08, 0x07, 0x06 });

            await engine.EvaluateAsync(path, 3003, CancellationToken.None);
            Assert.Equal(2, cache.Misses);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    // ------------------------------------------------------------------
    // 2. KHONG HOI KHI KHONG CO GIAO DIEN.
    //
    // Truoc khi sua: moi tien trinh la deu sinh mot yeu cau xin quyen roi cho
    // 30 giay, ke ca khi khong ai nhin man hinh. Do la nguon con mua hop thoai.
    // ------------------------------------------------------------------
    [Fact]
    public async Task UnknownBinary_WithNoUiOpen_IsNotPrompted_AndDoesNotStall()
    {
        var path = Path.Combine(Path.GetTempPath(), $"avtest_noui_{Guid.NewGuid():N}.exe");
        await File.WriteAllBytesAsync(path, new byte[] { 0x4D, 0x5A, 0x00, 0x00 });
        try
        {
            var broker = new PermissionRequestBroker();   // chua ai poll -> khong co UI
            var engine = CreateEngine(broker, new FileIdentityCache());

            Assert.False(broker.IsUiListening);

            var sw = Stopwatch.StartNew();
            var decision = await engine.EvaluateAsync(path, 4001, CancellationToken.None);
            sw.Stop();

            _output.WriteLine($"Trang thai : {decision.State}");
            _output.WriteLine($"Thoi gian  : {sw.Elapsed.TotalMilliseconds:N1} ms");

            Assert.Equal(ProcessTrustState.AllowedNoUserPresent, decision.State);
            Assert.True(decision.Allowed);
            Assert.Empty(broker.ListPending());   // KHONG sinh hop thoai nao
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    // Khi giao dien DANG mo thi van phai hoi — ban sua tren khong duoc bien
    // thanh "khong bao gio hoi nua".
    [Fact]
    public async Task UnknownBinary_WithUiOpen_IsStillPrompted()
    {
        var path = Path.Combine(Path.GetTempPath(), $"avtest_ui_{Guid.NewGuid():N}.exe");
        await File.WriteAllBytesAsync(path, new byte[] { 0x4D, 0x5A, 0x00, 0x00 });
        try
        {
            var broker = new PermissionRequestBroker();
            broker.MarkUiPolled();                // giao dien vua poll
            Assert.True(broker.IsUiListening);

            var engine = CreateEngine(broker, new FileIdentityCache());
            var decision = await engine.EvaluateAsync(path, 5001, CancellationToken.None);

            // Khong ai tra loi trong 200 ms -> het gio, dung nhu truoc.
            Assert.Equal(ProcessTrustState.DeniedByTimeout, decision.State);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    // Giao dien mo nhung nguoi dung khong theo kip: hang doi day thi ngung hoi,
    // thay vi chong them hop thoai len nhung cai chua ai tra loi.
    [Fact]
    public void PromptingStops_WhenPendingQueueIsFull()
    {
        var broker = new PermissionRequestBroker();
        broker.MarkUiPolled();
        Assert.True(broker.CanPromptUser);

        // Ba yeu cau dang cho (khong await — chung se treo cho toi khi timeout).
        for (int i = 0; i < 3; i++)
        {
            _ = broker.RequestDecisionAsync($@"C:\tmp\app{i}.exe", $"hash{i}", null, null,
                TimeSpan.FromSeconds(5), CancellationToken.None);
        }

        Assert.Equal(3, broker.ListPending().Count);
        Assert.False(broker.CanPromptUser);   // day -> khong hoi them
    }

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { }
        try { File.Delete(_auditPath); } catch { }
    }
}
