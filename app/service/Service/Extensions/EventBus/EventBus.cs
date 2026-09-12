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

    // 0-100, cang cao cang nghiem trong. KHONG co validation ep buoc thang
    // do nay (moi module tu quyet gia tri, xem SeverityBand ben duoi cho
    // quy uoc THAM KHAO) — day la van de kien truc lon hon mot fix nho o
    // day co the giai quyet (can su dong thuan giua tat ca module publish
    // vao EventBus), nen KHONG doi lai gia tri hien co cua bat ky module
    // nao (Usb, Webcam, Network, Firewall/ConnectionMonitor, Ransomware,
    // FullScan...) trong lan sua nay de tranh thay doi hanh vi xep hang/
    // canh bao tren UI ngoai du kien.
    public int Severity { get; init; }
    public required string Summary { get; init; }
    public long TimestampUnixMs { get; init; }
}

// Quy uoc THAM KHAO cho CorrelationEvent.Severity — khong duoc code nao
// ep buoc, chi giup module MOI chon gia tri nhat quan voi cac module da
// co thay vi tu nghi ra mot con so tuy y. Doi chieu voi gia tri THUC TE
// dang dung tai thoi diem viet ghi chu nay: Usb (5/30/60), Webcam (5/50),
// Network/HomeNetworkMonitor (15/20), Firewall/ConnectionMonitor (40/55),
// Ransomware (25/55/95), FullScan (30) — nhin chung khop voi 4 muc duoi
// day, tuy khong tuyet doi nhat quan giua cac module (vi du Ransomware
// dung 25 cho "Medium" trong khi Network dung 15-20 cho cung y nghia).
public static class SeverityBand
{
    public const int Low = 0;        // theo doi nen, chua dang canh bao nguoi dung
    public const int Medium = 25;    // dang ngo, co the can chu y
    public const int High = 50;      // kha nghi ro, nen canh bao ro rang
    public const int Critical = 75;  // xac nhan hoac gan chac chan doc hai
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

    // [SUA LOI CAO — NHAT KY BI NHAN CHIM] So su kien LAP LAI cua cung entity
    // nay da duoc gop lai thay vi ghi rieng tung dong vao nhat ky. Duoc bao
    // cao trong MOT dong tong ket khi entity dong lai, de khong con so nao
    // bien mat trong im lang.
    public int CoalescedEventCount { get; set; }
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
            //
            // [SUA LOI CAO — NHAT KY BI NHAN CHIM] TRUOC DAY _audit.Log nam
            // NGOAI khoi if nay va ngoai ca lock — tuc la MOI su kien deu
            // sinh mot dong nhat ky, trong khi chinh module nay tuyen bo
            // nguyen tac nguoc lai ("chi MOT thong bao hop nhat, khong tao
            // moi moi lan") va da ap dung dung nguyen tac do cho thong bao.
            // Rieng nhat ky thi khong.
            //
            // Do luong tren may that: 23.499/23.634 dong nhat ky (99,4%) la
            // su kien lap lai cua VON VEN 192 entity — chu yeu tu
            // ConnectionMonitor, von gan co moi ket noi co nhip deu (moi
            // ung dung poll theo timer deu the: trinh duyet, Windows Update,
            // dong bo mail). Hau qua khong phai "hoi on": 135 su kien THAT
            // — gom ca cac ban ghi thay doi chinh sach vua duoc bo sung —
            // bi chon vui, va /api/audit?limit=N khong con hien duoc chung.
            // Mot nhat ky kiem toan khong tra cuu duoc thi gan nhu khong co.
            //
            // Sua: ghi nhat ky theo DUNG nguyen tac cua module — mot dong
            // khi entity xuat hien lan dau, va mot dong nua moi khi muc do
            // nghiem trong TANG LEN. Cac lan lap lai duoc DEM chu khong bi
            // vut bo (xem CoalescedEventCount va SweepExpiredEntities).
            // Ket qua: ~192 dong thay vi 23.499, khong mat mot phat hien nao.
            //
            // Luu y: phan PHAT HIEN khong he thay doi. Danh sach day du van
            // xem duoc qua /api/firewall/beacon-suspicions va Alert Center
            // (ListOpenAlerts), noi giu nguyen tung dong SummaryLines.
            if (!state.NotificationSent || evt.Severity > state.LastNotifiedSeverity)
            {
                state.NotificationSent = true;
                state.LastNotifiedSeverity = Math.Max(state.LastNotifiedSeverity, evt.Severity);
                UnifiedNotification?.Invoke(state);

                _audit.Log(evt.SourceEngine,
                    $"[event-bus] {evt.Summary} (entity={evt.EntityKey}, severity={evt.Severity})");
            }
            else
            {
                state.CoalescedEventCount++;
            }
        }
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
                if (_openEntities.TryRemove(kv.Key, out var closed))
                {
                    // [SUA LOI CAO] Khong duoc phep "gop" bang cach lang le
                    // vut bo. Khi entity dong lai, bao cao dung so lan lap
                    // lai da duoc gop — nguoi dieu tra sau nay van biet su
                    // viec xay ra bao nhieu lan, chi khac la doc mot dong
                    // thay vi cuon qua hang nghin dong giong het nhau.
                    int coalesced;
                    lock (closed) { coalesced = closed.CoalescedEventCount; }
                    if (coalesced > 0)
                    {
                        _audit.Log("event-bus",
                            $"[event-bus] Da dong theo doi {closed.EntityKey}: them {coalesced} su kien lap lai cung loai da duoc gop (muc cao nhat: {closed.MaxSeverity})");
                    }
                }
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
