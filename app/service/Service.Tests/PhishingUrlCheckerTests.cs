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

    // [test-coverage][KIEM THU HOI QUY] Fix bao mat da ghi trong comment cua
    // CheckUrl ("evil.com." voi dau cham cuoi") truoc day KHONG co test nao —
    // DNS coi "evil.com." va "evil.com" la CUNG mot ten (dau cham goc FQDN),
    // trinh duyet van mo dung site bi chan neu bypass check nay thanh cong.
    [Fact]
    public void DomainWithTrailingDot_StillMatchesBlocklist()
    {
        _store.ReplaceAll(new[] { "evil-login.com" }, Array.Empty<string>());

        var result = _checker.CheckUrl("https://evil-login.com./steal-password");

        Assert.True(result.Malicious);
        Assert.Equal("domain", result.MatchedOn);
        Assert.Equal("evil-login.com", result.MatchedValue);
    }

    [Fact]
    public void SubdomainWithTrailingDot_StillMatchesParentDomain()
    {
        _store.ReplaceAll(new[] { "evil.com" }, Array.Empty<string>());

        var result = _checker.CheckUrl("https://login.secure.evil.com./");

        Assert.True(result.Malicious);
        Assert.Equal("evil.com", result.MatchedValue);
    }

    // [test-coverage] Xac nhan uu tien khop domain CU THE NHAT (khong phai
    // domain cha) khi ca hai deu nam trong blocklist — hanh vi cua
    // FindMostSpecificListedDomain phai giu dung thu tu uu tien cu nhu vong
    // lap IsDomainListed tuan tu truoc day, du gio chi con 1 truy van SQL.
    [Fact]
    public void MultipleListedAncestors_ReturnsMostSpecificMatch()
    {
        _store.ReplaceAll(new[] { "evil.com", "login.evil.com" }, Array.Empty<string>());

        var result = _checker.CheckUrl("https://login.evil.com/");

        Assert.True(result.Malicious);
        Assert.Equal("login.evil.com", result.MatchedValue);
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
