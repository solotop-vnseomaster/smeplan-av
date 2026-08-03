using Antivirus.Service.Audit;
using Xunit;

namespace Antivirus.Service.Tests;

// [TINH NANG THEO YEU CAU NGUOI DUNG] "co co che nao xoa log tu dong va
// thu cong khong" — PruneToMaxLines/ClearAll dung chung cho ca hai co che.
public class AuditLoggerTests : IDisposable
{
    private readonly string _logPath;
    private readonly AuditLogger _logger;

    public AuditLoggerTests()
    {
        _logPath = Path.Combine(Path.GetTempPath(), $"avtest_audit_{Guid.NewGuid():N}.jsonl");
        _logger = new AuditLogger(_logPath);
    }

    [Fact]
    public void PruneToMaxLines_FileUnderLimit_DoesNothing()
    {
        for (int i = 0; i < 10; i++) _logger.Log("system", $"su kien {i}");

        int removed = _logger.PruneToMaxLines(100);

        Assert.Equal(0, removed);
        Assert.Equal(10, File.ReadAllLines(_logPath).Length);
    }

    [Fact]
    public void PruneToMaxLines_FileOverLimit_KeepsOnlyMostRecentLines()
    {
        for (int i = 0; i < 20; i++) _logger.Log("system", $"su kien {i}");

        int removed = _logger.PruneToMaxLines(5);

        Assert.Equal(15, removed);
        var remaining = File.ReadAllLines(_logPath);
        Assert.Equal(5, remaining.Length);
        // Dong CUOI CUNG (moi nhat) phai la "su kien 19" — khong bi mat.
        Assert.Contains("su kien 19", remaining[^1]);
    }

    [Fact]
    public void ClearAll_EmptiesFileAndInMemoryQueue()
    {
        for (int i = 0; i < 5; i++) _logger.Log("system", $"su kien {i}");

        _logger.ClearAll();

        Assert.Equal(0, File.ReadAllText(_logPath).Length);
        Assert.Empty(_logger.GetRecentForUi());
    }

    [Fact]
    public void GetLogFileSizeBytes_ReflectsActualFileSize()
    {
        _logger.Log("system", "mot dong log");

        long size = _logger.GetLogFileSizeBytes();

        Assert.True(size > 0);
        Assert.Equal(new FileInfo(_logPath).Length, size);
    }

    public void Dispose()
    {
        try { File.Delete(_logPath); } catch { }
    }
}
