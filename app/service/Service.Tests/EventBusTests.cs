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

    public void Dispose()
    {
        try { File.Delete(_auditPath); } catch { }
    }
}
