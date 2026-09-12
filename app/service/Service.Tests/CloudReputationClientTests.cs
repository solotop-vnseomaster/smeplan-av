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

    // [test-coverage] IsValidSha256Hex la cong validate cho /api/cloud-intel/lookup
    // (chan chuoi khong phai hash 64 hex hop le truoc khi vao Lookup) —
    // truoc day khong co test nao.
    [Theory]
    [InlineData("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", false)] // ngan hon 64 (SHA-1, khong phai SHA-256)
    [InlineData("", false)]
    [InlineData(null, false)]
    [InlineData("khong-phai-hex-nhung-du-64-ky-tuXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", false)]
    public void IsValidSha256Hex_InvalidInputs_ReturnsFalse(string? value, bool expected)
    {
        Assert.Equal(expected, CloudReputationClient.IsValidSha256Hex(value));
    }

    [Fact]
    public void IsValidSha256Hex_ValidLowercaseHex64_ReturnsTrue()
    {
        var validHash = new string('a', 64);
        Assert.True(CloudReputationClient.IsValidSha256Hex(validHash));
    }

    [Fact]
    public void IsValidSha256Hex_ValidUppercaseHex64_ReturnsTrue()
    {
        var validHash = new string('F', 64);
        Assert.True(CloudReputationClient.IsValidSha256Hex(validHash));
    }

    [Fact]
    public void IsValidSha256Hex_65Characters_ReturnsFalse()
    {
        var tooLong = new string('a', 65);
        Assert.False(CloudReputationClient.IsValidSha256Hex(tooLong));
    }

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { }
    }
}
