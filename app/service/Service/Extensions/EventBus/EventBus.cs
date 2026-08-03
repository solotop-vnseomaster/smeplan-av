using System.Collections.Concurrent;
using Antivirus.Service.Audit;

namespace Antivirus.Service.Extensions;

// "tai lieu moi.txt" muc "Xu ly khi nhieu lop bao ve cung phat hien mot su
// kien": diem hoi tu quan trong nhat cua toan bo tai lieu mo rong. Moi
// module (firewall, ransomware, sandbox, phishing, USB...) publish vao day
// THAY VI tu hien thi notification rieng (EXT-PRINCIPLE-01) — day la loi
// pho bien nhat khi mo rong tinh nang antivirus theo chinh tai lieu.
public sealed class CorrelationEvent
{
    public required string EntityKey { get; init; } // hash file, hoac "pid:createTimeTicks" cho tien trinh
    public required string SourceEngine { get; init; } // "scan" | "firewall" | "ransomware" | "sandbox" | "phishing" | "usb" | ...
    public int Severity { get; init; } // 0-100
    public required string Summary { get; init; }
    public long TimestampUnixMs { get; init; }
}

public sealed class EntityState
{
    public required string EntityKey { get; init; }
    public int MaxSeverity { get; set; }
    public HashSet<string> SourceEngines { get; } = new();
    public List<string> SummaryLines { get; } = new();
    public long FirstSeenUnixMs { get; set; }
    public long LastUpdateUnixMs { get; set; }
    public bool NotificationSent { get; set; }
    public int LastNotifiedSeverity { get; set; }
}

// Snapshot cua mot entity dang mo, dung de UI hien thi Alert Center.
public sealed class OpenAlert
{
    public required string EntityKey { get; init; }
    public int MaxSeverity { get; init; }
    public required List<string> SourceEngines { get; init; }
    public required List<string> SummaryLines { get; init; }
    public long FirstSeenUnixMs { get; init; }
    public long LastUpdateUnixMs { get; init; }
}

public sealed class EventBus
{
    // [DIEM QUAN TRONG NHAT theo tai lieu] KHONG dong entity qua som — moi
    // nguon co "toc do tra loi" khac nhau xa (scan engine ~vai tram ms,
    // sandbox that co the toi vai phut). Thay vi mot cua so co dinh ngan,
    // giu entity mo cho toi khi KHONG CON event moi nao trong khoang
    // SettleTimeout ke tu lan cap nhat GAN NHAT — xap xi dung "cho tat ca
    // module lien quan tra loi hoac het timeout rieng" ma khong can biet
    // truoc chinh xac module nao se con bao cao (vi cac module sandbox/
    // cloud-intel thuc su chua chay duoc trong moi truong nay).
    private static readonly TimeSpan SettleTimeout = TimeSpan.FromMinutes(3);

    private readonly ConcurrentDictionary<string, EntityState> _openEntities = new();
    private readonly AuditLogger _audit;
    private readonly ILogger<EventBus> _logger;

    public event Action<EntityState>? UnifiedNotification;

    public EventBus(AuditLogger audit, ILogger<EventBus> logger)
    {
        _audit = audit;
        _logger = logger;
    }

    public void Publish(CorrelationEvent evt)
    {
        var state = _openEntities.AddOrUpdate(evt.EntityKey,
            _ => new EntityState { EntityKey = evt.EntityKey, FirstSeenUnixMs = evt.TimestampUnixMs },
            (_, existing) => existing);

        lock (state)
        {
            state.MaxSeverity = Math.Max(state.MaxSeverity, evt.Severity);
            state.SourceEngines.Add(evt.SourceEngine);
            state.SummaryLines.Add($"[{evt.SourceEngine}] {evt.Summary}");
            state.LastUpdateUnixMs = evt.TimestampUnixMs;

            // Chi tao/cap nhat MOT thong bao hop nhat, khong tao moi moi lan
            // (ShowOrUpdateUnifiedNotification trong tai lieu).
            if (!state.NotificationSent || evt.Severity > state.LastNotifiedSeverity)
            {
                state.NotificationSent = true;
                state.LastNotifiedSeverity = Math.Max(state.LastNotifiedSeverity, evt.Severity);
                UnifiedNotification?.Invoke(state);
            }
        }

        _audit.Log(evt.SourceEngine, $"[event-bus] {evt.Summary} (entity={evt.EntityKey}, severity={evt.Severity})");
    }

    // Goi dinh ky tu BackgroundService (xem EventBusSweepService) de dong
    // cac entity da het "settle timeout".
    public void SweepExpiredEntities()
    {
        long cutoff = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - (long)SettleTimeout.TotalMilliseconds;
        foreach (var kv in _openEntities)
        {
            if (kv.Value.LastUpdateUnixMs < cutoff)
            {
                _openEntities.TryRemove(kv.Key, out _);
            }
        }
    }

    public IReadOnlyList<OpenAlert> ListOpenAlerts() => _openEntities.Values
        .Select(s => new OpenAlert
        {
            EntityKey = s.EntityKey,
            MaxSeverity = s.MaxSeverity,
            SourceEngines = s.SourceEngines.ToList(),
            SummaryLines = s.SummaryLines.TakeLast(20).ToList(),
            FirstSeenUnixMs = s.FirstSeenUnixMs,
            LastUpdateUnixMs = s.LastUpdateUnixMs,
        })
        .OrderByDescending(a => a.LastUpdateUnixMs)
        .ToList();

    public int OpenAlertCount => _openEntities.Count;

    public int CountBySeverityAtLeast(int minSeverity) =>
        _openEntities.Values.Count(s => s.MaxSeverity >= minSeverity);
}

// Quet dinh ky de dong entity het han — tach rieng khoi EventBus de EventBus
// khong phu thuoc BackgroundService (de kiem thu don vi truc tiep).
public sealed class EventBusSweepService : BackgroundService
{
    private readonly EventBus _bus;

    public EventBusSweepService(EventBus bus) => _bus = bus;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            _bus.SweepExpiredEntities();
            try { await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken); }
            catch (TaskCanceledException) { }
        }
    }
}
