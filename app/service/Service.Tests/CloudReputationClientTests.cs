using Antivirus.Service.Extensions.CloudIntel;
using Xunit;

namespace Antivirus.Service.Tests;

// "tai lieu moi.txt" muc "Tich hop cloud threat intelligence": prevalence
// = 0 danh cho hash CHUA TUNG THAY truoc do, tang dan khi gap lai.
public class CloudReputationClientTests : IDisposable
{
    private readonly string _dbPath;
    private readonly CloudReputationClient _client;

    public CloudReputationClientTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"avtest_cloudrep_{Guid.NewGuid():N}.db");
        _client = new CloudReputationClient(_dbPath);
    }

    [Fact]
    public void FirstLookup_NeverSeenHash_ReturnsPrevalenceZero()
    {
        var result = _client.Lookup("aaaa1111");

        Assert.Equal(0, result.Prevalence);
        Assert.Equal(CloudVerdict.Unknown, result.Verdict);
    }

    [Fact]
    public void SecondLookup_SameHash_PrevalenceIncreases()
    {
        _client.Lookup("bbbb2222");
        var result = _client.Lookup("bbbb2222");

        Assert.Equal(1, result.Prevalence);
    }

    [Fact]
    public void DifferentHashes_TrackedIndependently()
    {
        _client.Lookup("hash-a");
        _client.Lookup("hash-a");
        var resultB = _client.Lookup("hash-b");

        Assert.Equal(0, resultB.Prevalence);
    }

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { }
    }
}
