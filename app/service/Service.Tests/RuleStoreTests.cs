using Antivirus.Service.Data;
using Antivirus.Service.Models;
using Xunit;

namespace Antivirus.Service.Tests;

// DATA-01/02 + business-rules/05 "tra rule theo thu tu hash roi publisher".
public class RuleStoreTests : IDisposable
{
    private readonly string _dbPath;
    private readonly RuleStore _store;

    public RuleStoreTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"avtest_rules_{Guid.NewGuid():N}.db");
        _store = new RuleStore(_dbPath);
    }

    [Fact]
    public void FindByHash_ReturnsExactMatch()
    {
        _store.Add(new AppRule
        {
            Sha256Hash = "aaaa", FilePath = "C:\\a.exe", Action = RuleAction.Allow,
            Scope = RuleScope.Hash, CreatedAt = 1, CreatedBy = RuleCreatedBy.User,
        });

        var found = _store.FindByHash("aaaa");

        Assert.NotNull(found);
        Assert.Equal(RuleAction.Allow, found!.Action);
    }

    [Fact]
    public void FindByPublisher_ReturnsExactMatch()
    {
        _store.Add(new AppRule
        {
            Sha256Hash = "bbbb", PublisherThumbprint = "THUMB123", FilePath = "C:\\b.exe",
            Action = RuleAction.Block, Scope = RuleScope.Publisher, CreatedAt = 1, CreatedBy = RuleCreatedBy.User,
        });

        var found = _store.FindByPublisher("THUMB123");

        Assert.NotNull(found);
        Assert.Equal(RuleAction.Block, found!.Action);
    }

    [Fact]
    public void NoMatch_ReturnsNull()
    {
        Assert.Null(_store.FindByHash("khong-ton-tai"));
        Assert.Null(_store.FindByPublisher("khong-ton-tai"));
    }

    [Fact]
    public void Delete_RemovesRule()
    {
        var id = _store.Add(new AppRule
        {
            Sha256Hash = "cccc", FilePath = "C:\\c.exe", Action = RuleAction.Allow,
            Scope = RuleScope.Hash, CreatedAt = 1, CreatedBy = RuleCreatedBy.User,
        });

        _store.Delete(id);

        Assert.Null(_store.FindByHash("cccc"));
    }

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { }
    }
}
