using Antivirus.Service.Extensions.Firewall;
using Xunit;

namespace Antivirus.Service.Tests;

// "tai lieu moi.txt" muc "Thiet ke rule engine cho firewall": "luon lay
// rule co priority cao nhat trong so cac rule khop dieu kien, khong dung o
// rule khop dau tien tim thay".
public class FirewallRuleStoreTests : IDisposable
{
    private readonly string _dbPath;
    private readonly FirewallRuleStore _store;

    public FirewallRuleStoreTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"avtest_fw_{Guid.NewGuid():N}.db");
        _store = new FirewallRuleStore(_dbPath);
    }

    [Fact]
    public void HigherPriorityRule_WinsOverLowerPriority_EvenIfAddedFirst()
    {
        _store.Add(new FirewallRule
        {
            AppSha256 = "app1", Direction = FirewallDirection.Outbound, Protocol = FirewallProtocol.Any,
            Action = FirewallAction.Block, Priority = 10, CreatedBy = "default_policy",
        });
        _store.Add(new FirewallRule
        {
            AppSha256 = "app1", Direction = FirewallDirection.Outbound, Protocol = FirewallProtocol.Tcp,
            RemotePortStart = 443, RemotePortEnd = 443, Action = FirewallAction.Allow, Priority = 200, CreatedBy = "user",
        });

        var match = _store.FindBestMatch("app1", FirewallDirection.Outbound, FirewallProtocol.Tcp, 443);

        Assert.NotNull(match);
        Assert.Equal(FirewallAction.Allow, match!.Action);
        Assert.Equal(200, match.Priority);
    }

    [Fact]
    public void PortOutsideRange_DoesNotMatch()
    {
        _store.Add(new FirewallRule
        {
            AppSha256 = "app1", Direction = FirewallDirection.Outbound, Protocol = FirewallProtocol.Tcp,
            RemotePortStart = 443, RemotePortEnd = 443, Action = FirewallAction.Allow, Priority = 200, CreatedBy = "user",
        });

        var match = _store.FindBestMatch("app1", FirewallDirection.Outbound, FirewallProtocol.Tcp, 8080);

        Assert.Null(match);
    }

    [Fact]
    public void NoRuleMatches_ReturnsNull_CallerFallsBackToDefaultPolicy()
    {
        var match = _store.FindBestMatch("unknown-app", FirewallDirection.Inbound, FirewallProtocol.Tcp, 3389);

        Assert.Null(match);
    }

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { }
    }
}
