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

    // [KIEM THU HOI QUY] Cho loi da sua trong FindByHash: idx_rules_hash_unique
    // CHI la UNIQUE INDEX pham vi WHERE scope='hash', KHONG chan duoc mot rule
    // scope='publisher' tao qua POST /api/rules mang sha256_hash KHONG RONG
    // trung voi mot rule scope='hash' co san — hai hang nay CO THAT cung
    // sha256_hash. FindByHash phai chi khop dung hang scope='hash', khong duoc
    // lac sang hang scope='publisher' trung hash do (du no den TRUOC hay SAU).
    [Fact]
    public void FindByHash_DoesNotMatchPublisherScopedRule_EvenWithSameHash()
    {
        _store.Add(new AppRule
        {
            Sha256Hash = "sharedhash", PublisherThumbprint = "PUBQ", FilePath = "C:\\publisher-rule.exe",
            Action = RuleAction.Block, Scope = RuleScope.Publisher, CreatedAt = 1, CreatedBy = RuleCreatedBy.User,
        });
        _store.Add(new AppRule
        {
            Sha256Hash = "sharedhash", FilePath = "C:\\hash-rule.exe",
            Action = RuleAction.Allow, Scope = RuleScope.Hash, CreatedAt = 2, CreatedBy = RuleCreatedBy.User,
        });

        var found = _store.FindByHash("sharedhash");

        Assert.NotNull(found);
        Assert.Equal(RuleScope.Hash, found!.Scope);
        Assert.Equal(RuleAction.Allow, found.Action);
        Assert.Equal("C:\\hash-rule.exe", found.FilePath);
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

    // [KIEM THU HOI QUY] Cho loi da sua trong FindByPublisher: mot rule
    // scope=hash (tao tu "Cho phep luon" tren file A, chi dinh danh CHINH
    // XAC file A qua hash) van ghi kem publisher_thumbprint cua file A. Neu
    // FindByPublisher khong loc scope='publisher', no se khop nham vao rule
    // scope=hash nay khi tra cuu boi publisher cua mot file B khac hoan
    // toan (hash khac) nhung cung publisher — cho phep chay B ma nguoi dung
    // chua bao gio cap quyen (ho chi trust rieng file A).
    [Fact]
    public void FindByPublisher_DoesNotMatchHashScopedRule_EvenWithSamePublisher()
    {
        // Rule scope=hash cho file A: sha256="hashA", publisher chung "PUBX".
        _store.Add(new AppRule
        {
            Sha256Hash = "hashA", PublisherThumbprint = "PUBX", FilePath = "C:\\a.exe",
            Action = RuleAction.Allow, Scope = RuleScope.Hash, CreatedAt = 1, CreatedBy = RuleCreatedBy.User,
        });

        // File B khac hoan toan (hash "hashB") nhung cung publisher "PUBX"
        // KHONG duoc phep khop qua FindByPublisher — vi nguoi dung chi
        // trust rieng file A theo hash, khong phai "bat ky file nao PUBX ky".
        Assert.Null(_store.FindByHash("hashB"));
        Assert.Null(_store.FindByPublisher("PUBX"));
    }

    // Doi chung: mot rule THAT SU scope=publisher voi cung thumbprint van
    // phai duoc FindByPublisher tim thay binh thuong (khong bi loc qua tay).
    [Fact]
    public void FindByPublisher_MatchesPublisherScopedRule_AlongsideUnrelatedHashRule()
    {
        _store.Add(new AppRule
        {
            Sha256Hash = "hashA", PublisherThumbprint = "PUBX", FilePath = "C:\\a.exe",
            Action = RuleAction.Allow, Scope = RuleScope.Hash, CreatedAt = 1, CreatedBy = RuleCreatedBy.User,
        });
        _store.Add(new AppRule
        {
            Sha256Hash = "", PublisherThumbprint = "PUBX", FilePath = "C:\\b.exe",
            Action = RuleAction.Allow, Scope = RuleScope.Publisher, CreatedAt = 2, CreatedBy = RuleCreatedBy.User,
        });

        var found = _store.FindByPublisher("PUBX");

        Assert.NotNull(found);
        Assert.Equal(RuleScope.Publisher, found!.Scope);
    }

    // [KIEM THU HOI QUY] Cho loi da sua trong FindByPublisher: khong co
    // ORDER BY nen khi ton tai HAI rule scope=publisher trung
    // publisher_thumbprint (vi du admin doi y Allow -> Block cho cung mot
    // publisher qua POST /api/rules, khong co unique constraint chan viec
    // nay), hang nao duoc tra ve la khong xac dinh. Sua: sap xep theo
    // created_at giam dan, luon lay rule MOI NHAT.
    [Fact]
    public void FindByPublisher_WithDuplicateRules_ReturnsMostRecent()
    {
        _store.Add(new AppRule
        {
            Sha256Hash = "", PublisherThumbprint = "PUBY", FilePath = "C:\\old.exe",
            Action = RuleAction.Allow, Scope = RuleScope.Publisher, CreatedAt = 1, CreatedBy = RuleCreatedBy.User,
        });
        _store.Add(new AppRule
        {
            Sha256Hash = "", PublisherThumbprint = "PUBY", FilePath = "C:\\new.exe",
            Action = RuleAction.Block, Scope = RuleScope.Publisher, CreatedAt = 2, CreatedBy = RuleCreatedBy.User,
        });

        var found = _store.FindByPublisher("PUBY");

        Assert.NotNull(found);
        Assert.Equal(RuleAction.Block, found!.Action);
        Assert.Equal("C:\\new.exe", found.FilePath);
    }

    // [KIEM THU HOI QUY] created_at chi phan giai toi 1 GIAY — hai rule tao
    // trong CUNG mot giay (vi du admin doi y Allow -> Block lien tiep rat
    // nhanh qua POST /api/rules) se hoa neu chi ORDER BY created_at. Phai co
    // tie-break "id DESC" de van lay dung rule MOI NHAT (id lon hon, chen
    // sau) thay vi phu thuoc vao thu tu vat ly khong dam bao cua SQLite.
    [Fact]
    public void FindByPublisher_WithDuplicateRules_SameCreatedAt_ReturnsHighestId()
    {
        _store.Add(new AppRule
        {
            Sha256Hash = "", PublisherThumbprint = "PUBZ", FilePath = "C:\\old.exe",
            Action = RuleAction.Allow, Scope = RuleScope.Publisher, CreatedAt = 100, CreatedBy = RuleCreatedBy.User,
        });
        _store.Add(new AppRule
        {
            Sha256Hash = "", PublisherThumbprint = "PUBZ", FilePath = "C:\\new.exe",
            Action = RuleAction.Block, Scope = RuleScope.Publisher, CreatedAt = 100, CreatedBy = RuleCreatedBy.User,
        });

        var found = _store.FindByPublisher("PUBZ");

        Assert.NotNull(found);
        Assert.Equal(RuleAction.Block, found!.Action);
        Assert.Equal("C:\\new.exe", found.FilePath);
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
