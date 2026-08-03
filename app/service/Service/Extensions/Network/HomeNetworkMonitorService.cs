using System.Net.Sockets;

namespace Antivirus.Service.Extensions.Network;

public sealed class NetworkDeviceInfo
{
    public string MacAddress { get; set; } = "";
    public required string IpAddress { get; set; }
    public string Vendor { get; set; } = "Khong xac dinh";
    public string? DiscoveredName { get; set; }
    public bool SeenViaArp { get; set; }
    public bool SeenViaMdns { get; set; }
    public bool SeenViaSsdp { get; set; }
    public bool IsNewDevice { get; set; }
    public List<int> OpenAdminPorts { get; set; } = new();
    public long LastSeenUnixMs { get; set; }
}

// "tai lieu moi.txt" muc "Giam sat thiet bi trong mang gia dinh": ket hop
// bang ARP (thu dong, khong tu gui goi) + lang nghe mDNS/SSDP (thu dong)
// de liet ke thiet bi, tra OUI xac dinh hang, kiem tra thu dong vai cong
// hay bi de mo khong an toan — TAT CA chi mang tinh THONG TIN, khong tu
// dong chan thiet bi nao (ngoai pham vi kiem soat cua mot may don le).
//
// [HAN CHE DA BIET] Thiet bi chi phat hien qua mDNS/SSDP (chua co trong
// bang ARP tai thoi diem do) duoc tao mot ban ghi tam khoa theo IP; neu
// sau do ARP moi thay MAC cua chinh thiet bi do, co the tao thanh hai ban
// ghi rieng le cho cung 1 thiet bi thay vi gop lam mot — chap nhan duoc
// vi day la module CHI MANG TINH THONG TIN (khong anh huong quyet dinh
// chan/allow), uu tien don gian hoa thay vi logic gop phuc tap.
public sealed class HomeNetworkMonitorService : BackgroundService
{
    private static readonly TimeSpan ArpPollInterval = TimeSpan.FromSeconds(60);
    private static readonly int[] PassiveCheckPorts = { 23, 80, 8080 }; // Telnet + cong quan tri router pho bien
    private static readonly TimeSpan PortRecheckInterval = TimeSpan.FromMinutes(30);

    private readonly KnownNetworkDeviceStore _knownDevices;
    private readonly EventBus _eventBus;
    private readonly ILogger<HomeNetworkMonitorService> _logger;
    private readonly DiscoveryListener _discovery = new();

    private readonly Dictionary<string, NetworkDeviceInfo> _devices = new(); // khoa = MAC, hoac IP neu chua co MAC
    private readonly Dictionary<string, DateTime> _lastPortCheck = new();
    private readonly object _lock = new();

    private const string SchedulerTaskId = "home-network-monitor";
    private readonly Antivirus.Service.Extensions.Scheduler.BackgroundTaskScheduler _scheduler;

    public HomeNetworkMonitorService(KnownNetworkDeviceStore knownDevices, EventBus eventBus, ILogger<HomeNetworkMonitorService> logger,
        Antivirus.Service.Extensions.Scheduler.BackgroundTaskScheduler scheduler)
    {
        _knownDevices = knownDevices;
        _eventBus = eventBus;
        _logger = logger;
        _scheduler = scheduler;
        // "giam sat mang gia dinh" la mot trong cac tac vu khong khan cap
        // duoc tai lieu liet ke ro rang phai qua idle-gate.
        _scheduler.Register(new Antivirus.Service.Extensions.Scheduler.TaskRegistration
        {
            TaskId = SchedulerTaskId,
            ResourceClass = Antivirus.Service.Extensions.Scheduler.ResourceClass.NetworkBound,
            Priority = 5,
            RequiresIdle = true,
            MaxDurationBeforeYield = TimeSpan.FromMinutes(2),
        });
    }

    public List<NetworkDeviceInfo> GetDevices()
    {
        lock (_lock) { return _devices.Values.ToList(); }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _discovery.Start();

        while (!stoppingToken.IsCancellationRequested)
        {
            if (_scheduler.TryAcquire(SchedulerTaskId))
            {
                try
                {
                    PollArp();
                    MergeDiscovered();
                    await CheckPassivePortsAsync(stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Loi vong quet mang gia dinh");
                }
                finally { _scheduler.Release(SchedulerTaskId); }
            }
            else
            {
                // May dang ban — bo qua chu ky nay, cac listener mDNS/SSDP
                // thu dong (_discovery) van tiep tuc chay binh thuong vi
                // chung khong ton tai nguyen chu dong nhu ARP poll/port check.
                _logger.LogDebug("Bo qua chu ky giam sat mang gia dinh nay — may dang ban");
            }

            try { await Task.Delay(ArpPollInterval, stoppingToken); }
            catch (TaskCanceledException) { break; }
        }

        _discovery.Dispose();
    }

    private void PollArp()
    {
        List<ArpEntry> entries;
        try { entries = ArpTableReader.GetArpTable(); }
        catch (Exception ex) { _logger.LogDebug(ex, "Khong doc duoc bang ARP"); return; }

        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        foreach (var entry in entries)
        {
            lock (_lock)
            {
                if (!_devices.TryGetValue(entry.MacAddress, out var device))
                {
                    bool isNew = !_knownDevices.IsKnown(entry.MacAddress);
                    device = new NetworkDeviceInfo
                    {
                        MacAddress = entry.MacAddress,
                        IpAddress = entry.IpAddress,
                        Vendor = OuiLookup.Lookup(entry.MacAddress),
                        IsNewDevice = isNew,
                    };
                    _devices[entry.MacAddress] = device;
                    _knownDevices.MarkKnown(entry.MacAddress);

                    if (isNew)
                    {
                        _eventBus.Publish(new CorrelationEvent
                        {
                            EntityKey = $"netdevice:{entry.MacAddress}",
                            SourceEngine = "home-network",
                            Severity = 15,
                            Summary = $"Thiet bi moi trong mang: {device.Vendor} ({entry.IpAddress}, {entry.MacAddress})",
                            TimestampUnixMs = now,
                        });
                    }
                }

                device.IpAddress = entry.IpAddress;
                device.SeenViaArp = true;
                device.LastSeenUnixMs = now;
            }
        }
    }

    private void MergeDiscovered()
    {
        var discovered = _discovery.DrainDiscovered();
        if (discovered.Count == 0) return;
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        lock (_lock)
        {
            foreach (var item in discovered)
            {
                var existing = _devices.Values.FirstOrDefault(d => d.IpAddress == item.IpAddress);
                if (existing is null)
                {
                    if (!_devices.TryGetValue(item.IpAddress, out existing))
                    {
                        existing = new NetworkDeviceInfo { IpAddress = item.IpAddress };
                        _devices[item.IpAddress] = existing;
                    }
                }

                if (item.Source == "mdns") existing.SeenViaMdns = true; else existing.SeenViaSsdp = true;
                if (!string.IsNullOrEmpty(item.Name)) existing.DiscoveredName = item.Name;
                existing.LastSeenUnixMs = now;
            }
        }
    }

    // "kiem tra thu dong CAC CONG PHO BIEN hay bi de mo khong an toan...
    // bang ket noi TCP don gian, KHONG dung ky thuat quet cong tich cuc".
    private async Task CheckPassivePortsAsync(CancellationToken ct)
    {
        List<NetworkDeviceInfo> snapshot;
        lock (_lock) { snapshot = _devices.Values.ToList(); }

        foreach (var device in snapshot)
        {
            if (string.IsNullOrEmpty(device.IpAddress)) continue;
            if (_lastPortCheck.TryGetValue(device.IpAddress, out var last) && DateTime.UtcNow - last < PortRecheckInterval) continue;
            _lastPortCheck[device.IpAddress] = DateTime.UtcNow;

            var openPorts = new List<int>();
            foreach (var port in PassiveCheckPorts)
            {
                if (ct.IsCancellationRequested) return;
                if (await IsPortOpenAsync(device.IpAddress, port, ct)) openPorts.Add(port);
            }

            lock (_lock) { device.OpenAdminPorts = openPorts; }

            if (openPorts.Contains(23))
            {
                _eventBus.Publish(new CorrelationEvent
                {
                    EntityKey = $"netdevice-port:{device.MacAddress}:{device.IpAddress}",
                    SourceEngine = "home-network",
                    Severity = 20,
                    Summary = $"Thiet bi {device.IpAddress} ({device.Vendor}) dang mo cong Telnet (23) — nen kiem tra lai cau hinh",
                    TimestampUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                });
            }
        }
    }

    private static async Task<bool> IsPortOpenAsync(string ip, int port, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(ip, port, ct).AsTask();
            var timeoutTask = Task.Delay(500, ct);
            var completed = await Task.WhenAny(connectTask, timeoutTask);
            return completed == connectTask && client.Connected;
        }
        catch { return false; }
    }
}
