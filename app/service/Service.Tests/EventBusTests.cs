using Antivirus.Service.Audit;
using Antivirus.Service.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Antivirus.Service.Tests;

// "tai lieu moi.txt" muc "Xu ly khi nhieu lop bao ve cung phat hien mot su
// kien" — diem hoi tu quan trong nhat cua tai lieu mo rong.
public class EventBusTests : IDisposable
{
    private readonly string _auditPath;
    private readonly EventBus _bus;

    public EventBusTests()
    {
        _auditPath = Path.Combine(Path.GetTempPath(), $"avtest_eventbus_{Guid.NewGuid():N}.jsonl");
        _bus = new EventBus(new AuditLogger(_auditPath), NullLogger<EventBus>.Instance);
    }

    [Fact]
    public void MultipleEventsSameEntity_MergeIntoOneAlert_WithMaxSeverity()
    {
        _bus.Publish(new CorrelationEvent { EntityKey = "hash-abc", SourceEngine = "scan", Severity = 40, Summary = "Suspicious qua heuristic", TimestampUnixMs = 1000 });
        _bus.Publish(new CorrelationEvent { EntityKey = "hash-abc", SourceEngine = "firewall", Severity = 20, Summary = "Ket noi bi chan", TimestampUnixMs = 1500 });
        _bus.Publish(new CorrelationEvent { EntityKey = "hash-abc", SourceEngine = "sandbox", Severity = 90, Summary = "Malicious qua sandbox", TimestampUnixMs = 5000 });

        var alerts = _bus.ListOpenAlerts();

        Assert.Single(alerts);
        var alert = alerts[0];
        Assert.Equal(90, alert.MaxSeverity); // lay MAX, khong phai event cuoi
        Assert.Contains("scan", alert.SourceEngines);
        Assert.Contains("firewall", alert.SourceEngines);
        Assert.Contains("sandbox", alert.SourceEngines);
        Assert.Equal(3, alert.SummaryLines.Count);
    }

    [Fact]
    public void DifferentEntities_TrackedSeparately()
    {
        _bus.Publish(new CorrelationEvent { EntityKey = "hash-a", SourceEngine = "scan", Severity = 30, Summary = "a", TimestampUnixMs = 1000 });
        _bus.Publish(new CorrelationEvent { EntityKey = "hash-b", SourceEngine = "scan", Severity = 60, Summary = "b", TimestampUnixMs = 1000 });

        Assert.Equal(2, _bus.OpenAlertCount);
    }

    // [DIEM QUAN TRONG NHAT] Entity KHONG duoc dong qua som — sandbox that
    // co the mat vai phut de tra loi trong khi scan engine tra loi ngay.
    [Fact]
    public void RecentEntity_NotSweptAway()
    {
        _bus.Publish(new CorrelationEvent
        {
            EntityKey = "hash-recent", SourceEngine = "scan", Severity = 50, Summary = "vua phat hien",
            TimestampUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        });

        _bus.SweepExpiredEntities();

        Assert.Equal(1, _bus.OpenAlertCount);
    }

    [Fact]
    public void StaleEntity_SweptAfterSettleTimeout()
    {
        _bus.Publish(new CorrelationEvent
        {
            EntityKey = "hash-old", SourceEngine = "scan", Severity = 50, Summary = "tu lau roi",
            TimestampUnixMs = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeMilliseconds(),
        });

        _bus.SweepExpiredEntities();

        Assert.Equal(0, _bus.OpenAlertCount);
    }

    [Fact]
    public void UnifiedNotification_FiresOnceForFirstEvent_AgainOnlyWhenSeverityIncreases()
    {
        int fireCount = 0;
        _bus.UnifiedNotification += _ => fireCount++;

        _bus.Publish(new CorrelationEvent { EntityKey = "x", SourceEngine = "scan", Severity = 30, Summary = "a", TimestampUnixMs = 1 });
        _bus.Publish(new CorrelationEvent { EntityKey = "x", SourceEngine = "scan", Severity = 20, Summary = "b", TimestampUnixMs = 2 }); // thap hon -> khong fire lai
        _bus.Publish(new CorrelationEvent { EntityKey = "x", SourceEngine = "scan", Severity = 80, Summary = "c", TimestampUnixMs = 3 }); // cao hon -> fire lai

        Assert.Equal(2, fireCount);
    }

    // ================================================================
    // [TEST HOI QUY — NHAT KY BI NHAN CHIM]
    //
    // TRUOC DAY EventBus.Publish goi _audit.Log cho MOI su kien, dung mot
    // dong nhat ky moi lan — trong khi chinh module nay tuyen bo nguyen tac
    // "chi MOT thong bao hop nhat, khong tao moi moi lan" va da ap dung
    // dung nguyen tac do cho thong bao. Rieng nhat ky thi khong.
    //
    // Do luong tren may that: 23.499/23.634 dong (99,4%) la su kien lap lai
    // cua von ven 192 entity. 135 su kien THAT — gom ca cac ban ghi thay
    // doi chinh sach vua duoc bo sung — bi chon vui, va /api/audit?limit=N
    // khong con hien duoc chung.
    //
    // Cac test duoi day khoa lai hop dong moi.
    // ================================================================

    private int AuditLineCount()
    {
        if (!File.Exists(_auditPath)) return 0;
        return File.ReadAllLines(_auditPath).Count(l => l.Trim().Length > 0);
    }

    [Fact]
    public void RepeatedEventsSameEntitySameSeverity_WriteOnlyOneAuditLine()
    {
        for (int i = 0; i < 200; i++)
        {
            _bus.Publish(new CorrelationEvent
            {
                EntityKey = "pid:1234",
                SourceEngine = "firewall",
                Severity = 40,
                Summary = "Khoang cach ket noi deu dan bat thuong",
                TimestampUnixMs = 1000 + i,
            });
        }

        Assert.Equal(1, AuditLineCount());
    }

    // Muc do nghiem trong TANG LEN thi phai co dong moi — day la thong tin
    // that su moi, khong duoc gop mat.
    [Fact]
    public void SeverityEscalation_WritesAnAdditionalAuditLine()
    {
        _bus.Publish(new CorrelationEvent { EntityKey = "pid:99", SourceEngine = "firewall", Severity = 20, Summary = "thap", TimestampUnixMs = 1000 });
        _bus.Publish(new CorrelationEvent { EntityKey = "pid:99", SourceEngine = "firewall", Severity = 20, Summary = "thap lai", TimestampUnixMs = 1100 });
        Assert.Equal(1, AuditLineCount());

        _bus.Publish(new CorrelationEvent { EntityKey = "pid:99", SourceEngine = "sandbox", Severity = 90, Summary = "leo thang", TimestampUnixMs = 1200 });

        Assert.Equal(2, AuditLineCount());
    }

    // Moi entity rieng biet van co dong cua no — gop KHONG duoc lam mat mot
    // phat hien nao.
    [Fact]
    public void DistinctEntities_EachStillGetTheirOwnAuditLine()
    {
        for (int i = 0; i < 25; i++)
        {
            _bus.Publish(new CorrelationEvent
            {
                EntityKey = $"pid:{i}",
                SourceEngine = "firewall",
                Severity = 40,
                Summary = "beacon",
                TimestampUnixMs = 1000 + i,
            });
        }

        Assert.Equal(25, AuditLineCount());
    }

    // Cac lan lap lai duoc DEM chu khong bi vut bo lang le: khi entity dong
    // lai, phai co mot dong tong ket noi ro da gop bao nhieu su kien.
    [Fact]
    public void CoalescedEvents_AreReportedWhenEntityIsSwept()
    {
        long old = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - (long)TimeSpan.FromMinutes(10).TotalMilliseconds;
        for (int i = 0; i < 50; i++)
        {
            _bus.Publish(new CorrelationEvent
            {
                EntityKey = "pid:777",
                SourceEngine = "firewall",
                Severity = 40,
                Summary = "beacon lap lai",
                TimestampUnixMs = old + i,
            });
        }
        Assert.Equal(1, AuditLineCount());

        _bus.SweepExpiredEntities();

        var lines = File.ReadAllLines(_auditPath);
        Assert.Equal(2, lines.Length);
        // 50 su kien, 1 dong dau => 49 lan lap lai da duoc gop.
        Assert.Contains("49", lines[1]);
        Assert.Contains("pid:777", lines[1]);
    }

    // Alert Center van giu NGUYEN tung dong chi tiet — viec gop chi ap dung
    // cho nhat ky, khong dung cham vao du lieu phat hien.
    [Fact]
    public void Coalescing_DoesNotReduceDetailInAlertCenter()
    {
        for (int i = 0; i < 30; i++)
        {
            _bus.Publish(new CorrelationEvent
            {
                EntityKey = "pid:555",
                SourceEngine = "firewall",
                Severity = 40,
                Summary = $"su kien {i}",
                TimestampUnixMs = 1000 + i,
            });
        }

        var alert = Assert.Single(_bus.ListOpenAlerts());
        // ListOpenAlerts tra ve 20 dong gan nhat (TakeLast(20)) — day la gioi
        // han co san cua UI, khong phai hau qua cua viec gop nhat ky.
        Assert.Equal(20, alert.SummaryLines.Count);
        Assert.Contains("su kien 29", alert.SummaryLines[^1]);
    }

    public void Dispose()
    {
        try { File.Delete(_auditPath); } catch { }
    }
}
