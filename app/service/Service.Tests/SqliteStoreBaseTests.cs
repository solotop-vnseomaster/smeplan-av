using Microsoft.Data.Sqlite;
using Antivirus.Service.Data;
using Antivirus.Service.Extensions.Firewall;
using Xunit;

namespace Antivirus.Service.Tests;

// [KIEM THU HOI QUY] SqliteStoreBase.cs bat PRAGMA journal_mode=WAL +
// busy_timeout=5000 tren MOI Open() — hanh vi cross-cutting nay duoc 8 store
// (RuleStore/QuarantineStore trong Data/, va Firewall/Usb/Phishing/
// Ransomware/Webcam/Network/CloudIntel trong Extensions/) dung chung, nhung
// truoc test nay khong co test nao xac nhan PRAGMA that su duoc ap dung —
// neu ai vo tinh xoa 2 dong PRAGMA trong Open(), toan bo test suite van
// xanh. Test o day dai dien cho CA HAI nhom (Data/ qua RuleStore, Extensions/
// qua FirewallRuleStore) thay vi lap lai 8 lan.
public class SqliteStoreBaseTests
{
    [Theory]
    [InlineData("data_store")]
    [InlineData("extensions_store")]
    public void Open_SetsWalJournalMode(string kind)
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"avtest_walcheck_{kind}_{Guid.NewGuid():N}.db");
        try
        {
            if (kind == "data_store")
            {
                _ = new RuleStore(dbPath);
            }
            else
            {
                _ = new FirewallRuleStore(dbPath);
            }

            // journal_mode=WAL duoc ghi lai TRONG CHINH FILE DB (khong phai
            // chi mot pragma tam thoi tren connection) — mo mot connection
            // RAW, doc lap voi store, de kiem tra tren dia thuc su o mode nao.
            using var checkConn = new SqliteConnection($"Data Source={dbPath}");
            checkConn.Open();
            using var cmd = checkConn.CreateCommand();
            cmd.CommandText = "PRAGMA journal_mode;";
            var mode = (string)cmd.ExecuteScalar()!;

            Assert.Equal("wal", mode, ignoreCase: true);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            try { File.Delete(dbPath); } catch { }
            try { File.Delete(dbPath + "-wal"); } catch { }
            try { File.Delete(dbPath + "-shm"); } catch { }
        }
    }

    // Xac nhan muc dich thuc su cua PRAGMA busy_timeout: nhieu luong ghi
    // dong thoi vao CUNG mot store (mo phong nhieu request HTTP song song
    // toi cung mot *RuleStore singleton) khong duoc nem SqliteException
    // "database is locked" — day chinh la loi ma SqliteStoreBase duoc viet
    // ra de chan (xem ghi chu trong SqliteStoreBase.cs).
    [Fact]
    public void ConcurrentWrites_DoNotThrowDatabaseLocked()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"avtest_concurrency_{Guid.NewGuid():N}.db");
        try
        {
            var store = new FirewallRuleStore(dbPath);
            var exceptions = new System.Collections.Concurrent.ConcurrentBag<Exception>();

            Parallel.For(0, 20, i =>
            {
                try
                {
                    store.Add(new FirewallRule
                    {
                        AppSha256 = $"hash{i}",
                        Direction = FirewallDirection.Outbound,
                        Protocol = FirewallProtocol.Tcp,
                        Action = FirewallAction.Allow,
                        CreatedBy = "test",
                    });
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            Assert.Empty(exceptions);
            Assert.Equal(20, store.List().Count);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            try { File.Delete(dbPath); } catch { }
            try { File.Delete(dbPath + "-wal"); } catch { }
            try { File.Delete(dbPath + "-shm"); } catch { }
        }
    }
}
