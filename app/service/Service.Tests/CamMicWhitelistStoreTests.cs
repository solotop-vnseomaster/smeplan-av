using Antivirus.Service.Extensions.Webcam;
using Xunit;

namespace Antivirus.Service.Tests;

// "tai lieu moi.txt" muc "Bao ve webcam va microphone": whitelist rieng
// cho truy cap camera/mic, khac whitelist thuc thi/ghi thu muc.
public class CamMicWhitelistStoreTests : IDisposable
{
    private readonly string _dbPath;
    private readonly CamMicWhitelistStore _store;

    public CamMicWhitelistStoreTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"avtest_cammic_{Guid.NewGuid():N}.db");
        _store = new CamMicWhitelistStore(_dbPath);
    }

    [Fact]
    public void NotAdded_IsNotWhitelisted()
    {
        Assert.False(_store.IsWhitelisted(@"C:\Program Files\Zoom\Zoom.exe"));
    }

    [Fact]
    public void AfterAdd_IsWhitelisted()
    {
        _store.Add(@"C:\Program Files\Zoom\Zoom.exe");
        Assert.True(_store.IsWhitelisted(@"C:\Program Files\Zoom\Zoom.exe"));
    }

    [Fact]
    public void AfterDelete_NoLongerWhitelisted()
    {
        var id = _store.Add(@"C:\Program Files\Zoom\Zoom.exe");
        _store.Delete(id);
        Assert.False(_store.IsWhitelisted(@"C:\Program Files\Zoom\Zoom.exe"));
    }

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { }
    }
}
