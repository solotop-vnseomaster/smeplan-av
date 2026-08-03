using Antivirus.Service.Extensions.Phishing;
using Xunit;

namespace Antivirus.Service.Tests;

// "tai lieu moi.txt" muc "Chan URL va domain phishing o tang mang" +
// "Tich hop canh bao phishing vao trinh duyet" (logic kiem tra o service).
public class PhishingUrlCheckerTests : IDisposable
{
    private readonly string _dbPath;
    private readonly PhishingListStore _store;
    private readonly PhishingUrlChecker _checker;

    public PhishingUrlCheckerTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"avtest_phish_{Guid.NewGuid():N}.db");
        _store = new PhishingListStore(_dbPath);
        _checker = new PhishingUrlChecker(_store);
    }

    [Fact]
    public void ExactDomainMatch_ReturnsMalicious()
    {
        _store.ReplaceAll(new[] { "evil-login.com" }, Array.Empty<string>());

        var result = _checker.CheckUrl("https://evil-login.com/steal-password");

        Assert.True(result.Malicious);
        Assert.Equal("domain", result.MatchedOn);
    }

    [Fact]
    public void SubdomainOfListedParentDomain_ReturnsMalicious()
    {
        _store.ReplaceAll(new[] { "evil.com" }, Array.Empty<string>());

        var result = _checker.CheckUrl("https://login.secure.evil.com/");

        Assert.True(result.Malicious);
        Assert.Equal("evil.com", result.MatchedValue);
    }

    [Fact]
    public void CleanDomain_ReturnsNotMalicious()
    {
        _store.ReplaceAll(new[] { "evil.com" }, Array.Empty<string>());

        var result = _checker.CheckUrl("https://www.google.com/");

        Assert.False(result.Malicious);
    }

    [Fact]
    public void ListedIpAddress_ReturnsMalicious()
    {
        _store.ReplaceAll(Array.Empty<string>(), new[] { "203.0.113.5" });

        var result = _checker.CheckUrl("http://203.0.113.5/phishing-page");

        Assert.True(result.Malicious);
        Assert.Equal("ip", result.MatchedOn);
    }

    [Fact]
    public void InvalidUrl_DoesNotThrow_ReturnsNotMalicious()
    {
        var result = _checker.CheckUrl("not a valid url");

        Assert.False(result.Malicious);
    }

    [Fact]
    public void ReplaceAll_ClearsPreviousEntries()
    {
        _store.ReplaceAll(new[] { "old-evil.com" }, Array.Empty<string>());
        _store.ReplaceAll(new[] { "new-evil.com" }, Array.Empty<string>());

        Assert.False(_checker.CheckUrl("https://old-evil.com/").Malicious);
        Assert.True(_checker.CheckUrl("https://new-evil.com/").Malicious);
    }

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { }
    }
}
