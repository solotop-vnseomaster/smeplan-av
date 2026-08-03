using Antivirus.Service.Extensions.Ransomware;
using Xunit;

namespace Antivirus.Service.Tests;

// "tai lieu moi.txt" muc "Tu dong backup va rollback khi phat hien ransomware".
public class VersionStoreTests : IDisposable
{
    private readonly string _dbPath;
    private readonly string _storageDir;
    private readonly string _testFilePath;
    private readonly VersionStore _store;

    public VersionStoreTests()
    {
        var tempDir = Directory.CreateTempSubdirectory("avtest_vstore_").FullName;
        _dbPath = Path.Combine(tempDir, "vstore.db");
        _storageDir = Path.Combine(tempDir, "storage");
        _testFilePath = Path.Combine(tempDir, "document.txt");
        _store = new VersionStore(_dbPath, _storageDir);
    }

    [Fact]
    public void SnapshotThenRestore_RecoversOriginalContent()
    {
        File.WriteAllText(_testFilePath, "noi dung goc, chua bi ma hoa");
        _store.SnapshotFile(_testFilePath, triggeredByPid: 0);

        File.WriteAllText(_testFilePath, "NOI DUNG DA BI MA HOA BOI RANSOMWARE!!!");

        bool restored = _store.RestoreLatestVersion(_testFilePath);

        Assert.True(restored);
        Assert.Equal("noi dung goc, chua bi ma hoa", File.ReadAllText(_testFilePath));
    }

    [Fact]
    public void OnlyKeepsMaxVersionsPerFile()
    {
        for (int i = 0; i < VersionStore.MaxVersionsPerFile + 3; i++)
        {
            File.WriteAllText(_testFilePath, $"version {i}");
            _store.SnapshotFile(_testFilePath, triggeredByPid: 0);
            Thread.Sleep(5); // dam bao timestamp khac nhau
        }

        var tracked = _store.ListAllTrackedPaths().Where(r => r.OriginalPath == _testFilePath).ToList();

        Assert.Equal(VersionStore.MaxVersionsPerFile, tracked.Count);
    }

    [Fact]
    public void NoSnapshotExists_RestoreReturnsFalse()
    {
        Assert.False(_store.RestoreLatestVersion(_testFilePath));
    }

    public void Dispose()
    {
        try { Directory.Delete(Path.GetDirectoryName(_dbPath)!, recursive: true); } catch { }
    }
}
