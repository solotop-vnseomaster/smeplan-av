using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Antivirus.Service.Extensions.Firewall;

// "tai lieu moi.txt" muc "Giam sat ket noi outbound dang ngo" — phat hien
// C2 beacon qua (1) do deu dan khoang cach ket noi (he so bien thien thap
// bat thuong) va (2) entropy ten mien (DGA).
//
// [QUYET DINH TRIEN KHAI] Tai lieu goc dat logic nay trong CALLOUT WFP
// (kernel, bat duoc MOI ket noi ngay khi mo). Moi truong nay khong co WDK
// nen khong the dang ky callout that. Thay the bang POLLING dinh ky bang
// `GetExtendedTcpTable` (API user-mode chuan, KHONG can driver) de liet ke
// cac ket noi TCP dang mo theo PID — phat hien duoc pattern beacon qua
// nhieu vong quet lien tiep (do tre vai giay thay vi tuc thi tai thoi diem
// mo ket noi), van la phat hien THAT dua tren du lieu ket noi THAT cua may,
// khong phai gia lap.
public sealed class ConnectionMonitor : BackgroundService
{
    public sealed class BeaconSuspicion
    {
        public required string ProcessPath { get; init; }
        public int Pid { get; init; }
        public required string RemoteAddress { get; init; }
        public string? ResolvedHostname { get; init; }
        public double IntervalCoefficientOfVariation { get; init; }
        public double? HostnameEntropy { get; init; }
        public required string Reason { get; init; }
        public long DetectedAtUnixMs { get; init; }
    }

    private const int MinSamplesForRegularity = 5;
    private const int MaxSamplesTracked = 30;
    private const double LowVariationThreshold = 0.15; // he so bien thien (stddev/mean) thap = deu dan bat thuong

    private readonly EventBus _eventBus;
    private readonly ILogger<ConnectionMonitor> _logger;

    // (pid, remoteAddress) -> danh sach timestamp cac lan quan sat ket noi.
    private readonly Dictionary<(int Pid, string Remote), List<long>> _observations = new();
    private readonly List<BeaconSuspicion> _recentSuspicions = new();
    private readonly object _lock = new();

    public ConnectionMonitor(EventBus eventBus, ILogger<ConnectionMonitor> logger)
    {
        _eventBus = eventBus;
        _logger = logger;
    }

    public IReadOnlyList<BeaconSuspicion> GetRecentSuspicions()
    {
        lock (_lock) { return _recentSuspicions.TakeLast(200).ToList(); }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                PollConnections();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Loi khi doc bang ket noi TCP");
            }

            try { await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken); }
            catch (TaskCanceledException) { }
        }
    }

    private void PollConnections()
    {
        var connections = TcpTableReader.GetActiveConnectionsWithPid();
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        foreach (var conn in connections)
        {
            if (IsPrivateOrLoopback(conn.RemoteAddress)) continue; // chi quan tam ket noi ra internet that

            var key = (conn.Pid, conn.RemoteAddress);
            bool shouldEvaluate = false;
            double cv = 0;

            // [SUA LOI HIEU NANG] TRUOC DAY EvaluateBeaconCandidate (goi
            // Dns.GetHostEntry DONG BO, KHONG co timeout — xem
            // TryReverseResolve) duoc goi NGAY TRONG luc dang giu _lock.
            // Neu DNS treo (mang cham/DNS server khong phan hoi), _lock bi
            // giu VO HAN, khoa luon ca vong poll TIEP THEO (cung can _lock)
            // LAN GetRecentSuspicions() (API doc danh sach nghi ngo, goi tu
            // luong khac) — mot lan DNS treo co the "dong bang" toan bo
            // ConnectionMonitor. Sua: chi giu _lock cho phan bookkeeping RE
            // (them timestamp, tinh he so bien thien) — viec danh gia
            // beacon (co DNS resolve cham) duoc goi SAU KHI da nha _lock.
            // TryReverseResolve cung duoc bound them timeout rieng (xem ben
            // duoi) de gioi han thoi gian cho toi da, khong chi dua vao
            // viec bo _lock.
            lock (_lock)
            {
                if (!_observations.TryGetValue(key, out var list))
                {
                    list = new List<long>();
                    _observations[key] = list;
                }
                if (list.Count == 0 || now - list[^1] > 1000) // tranh dem trung 1 ket noi qua nhieu vong poll lien tiep
                {
                    list.Add(now);
                    if (list.Count > MaxSamplesTracked) list.RemoveAt(0);
                }

                if (list.Count >= MinSamplesForRegularity)
                {
                    cv = ComputeIntervalCoefficientOfVariation(list);
                    shouldEvaluate = cv < LowVariationThreshold;
                }
            }

            if (shouldEvaluate)
            {
                EvaluateBeaconCandidate(key, cv, now);
            }
        }
    }

    private void EvaluateBeaconCandidate((int Pid, string RemoteAddress) conn, double cv, long now)
    {
        string? processPath = TryGetProcessPath(conn.Pid);
        string? hostname = TryReverseResolve(conn.RemoteAddress);
        double? entropy = hostname is not null ? ComputeShannonEntropy(hostname.Split('.')[0]) : null;

        // [TINH NANG THEO YEU CAU NGUOI DUNG] "neu dai IP nay bat duoc chu
        // the thi nhin no tot hon (vi du Google Singapore dang ping)" —
        // truoc day Summary CHI co IP tho ngay ca khi da resolve duoc
        // hostname (hostname chi xuat hien o nhanh entropy cao/DGA rieng).
        // Them nhan dang provider quen thuoc tu hostname resolve duoc de
        // nguoi dung phan biet nhanh "co ve la dich vu lon binh thuong"
        // voi "khong nhan ra, dang chu y hon".
        string? provider = IdentifyKnownProvider(hostname);
        string target = hostname is not null
            ? (provider is not null ? $"{conn.RemoteAddress} ({provider} — {hostname})" : $"{conn.RemoteAddress} ({hostname})")
            : conn.RemoteAddress;

        var reasonParts = new List<string>
        {
            $"Khoang cach ket noi toi {target} deu dan bat thuong (he so bien thien={cv:0.00})",
        };
        int severity = 40; // chi nang muc nghi ngo, KHONG tu dong block (dung theo tai lieu)
        if (entropy.HasValue && entropy.Value > 3.5)
        {
            reasonParts.Add($"Ten mien '{hostname}' co entropy cao ({entropy.Value:0.00}) — dac diem cua DGA");
            severity = 55;
        }

        var suspicion = new BeaconSuspicion
        {
            ProcessPath = processPath ?? $"(pid {conn.Pid})",
            Pid = conn.Pid,
            RemoteAddress = conn.RemoteAddress,
            ResolvedHostname = hostname,
            IntervalCoefficientOfVariation = cv,
            HostnameEntropy = entropy,
            Reason = string.Join("; ", reasonParts),
            DetectedAtUnixMs = now,
        };

        lock (_lock)
        {
            _recentSuspicions.Add(suspicion);
            if (_recentSuspicions.Count > 500) _recentSuspicions.RemoveAt(0);
        }

        _eventBus.Publish(new CorrelationEvent
        {
            EntityKey = $"pid:{conn.Pid}",
            SourceEngine = "firewall",
            Severity = severity,
            Summary = suspicion.Reason,
            TimestampUnixMs = now,
        });
    }

    private static double ComputeIntervalCoefficientOfVariation(List<long> timestamps)
    {
        if (timestamps.Count < 2) return 1.0;
        var intervals = new List<double>();
        for (int i = 1; i < timestamps.Count; i++) intervals.Add(timestamps[i] - timestamps[i - 1]);
        double mean = intervals.Average();
        if (mean <= 0) return 1.0;
        double variance = intervals.Sum(x => Math.Pow(x - mean, 2)) / intervals.Count;
        double stddev = Math.Sqrt(variance);
        return stddev / mean;
    }

    private static double ComputeShannonEntropy(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0;
        var freq = new Dictionary<char, int>();
        foreach (var c in s) freq[c] = freq.GetValueOrDefault(c) + 1;
        double entropy = 0;
        foreach (var count in freq.Values)
        {
            double p = (double)count / s.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private static bool IsPrivateOrLoopback(string address)
    {
        if (!IPAddress.TryParse(address, out var ip)) return true;
        if (IPAddress.IsLoopback(ip)) return true;
        var bytes = ip.GetAddressBytes();
        if (ip.AddressFamily != AddressFamily.InterNetwork) return true; // chi xu ly IPv4 cho don gian
        return bytes[0] == 10 ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168) ||
               bytes[0] == 127;
    }

    private static string? TryGetProcessPath(int pid)
    {
        try { using var p = System.Diagnostics.Process.GetProcessById(pid); return p.MainModule?.FileName; }
        catch { return null; }
    }

    private static string? TryReverseResolve(string address)
    {
        try
        {
            // [SUA LOI HIEU NANG] Dns.GetHostEntry dong bo KHONG co tham so
            // timeout nao — neu DNS server khong phan hoi (mang cham/bi
            // chan), goi nay co the treo GAN NHU VO HAN. Dung ban async +
            // gioi han thoi gian cho ro rang (2s) thay vi phu thuoc hoan
            // toan vao timeout mac dinh cua he thong (co the rat lau).
            var task = Dns.GetHostEntryAsync(address);
            if (!task.Wait(TimeSpan.FromSeconds(2))) return null;
            return task.Result.HostName;
        }
        catch
        {
            return null; // phan lon IP khong co PTR record — binh thuong, khong phai loi
        }
    }

    // [QUYET DINH TRIEN KHAI] Tap con nho cac hau to PTR quen thuoc cua vai
    // nha cung cap lon (Google/AWS/Microsoft/Cloudflare/Akamai...) — CHI de
    // hien thi than thien hon trong UI ("co ve la dich vu lon binh thuong"),
    // KHONG dung de tu dong allow/whitelist (mot beacon C2 hoan toan co the
    // dat tren ha tang cloud that). Danh sach khong day du, thieu thi tra
    // ve null va UI chi hien IP/hostname tho nhu truoc.
    private static string? IdentifyKnownProvider(string? hostname)
    {
        if (hostname is null) return null;
        var h = hostname.ToLowerInvariant();
        if (h.EndsWith(".1e100.net") || h.EndsWith(".googleusercontent.com") || h.EndsWith(".google.com")) return "Google";
        if (h.EndsWith(".amazonaws.com")) return "Amazon AWS";
        if (h.EndsWith(".akamai.net") || h.EndsWith(".akamaiedge.net") || h.EndsWith(".akamaitechnologies.com") || h.EndsWith(".akadns.net")) return "Akamai CDN";
        if (h.EndsWith(".cloudflare.com") || h.EndsWith(".cloudflare.net")) return "Cloudflare";
        if (h.EndsWith(".azure.com") || h.EndsWith(".microsoft.com") || h.EndsWith(".windows.net") || h.EndsWith(".msedge.net")) return "Microsoft Azure";
        if (h.EndsWith(".fbcdn.net") || h.EndsWith(".facebook.com")) return "Meta/Facebook";
        if (h.EndsWith(".apple.com")) return "Apple";
        if (h.EndsWith(".fastly.net")) return "Fastly CDN";
        return null;
    }
}

// Wrapper GetExtendedTcpTable — API user-mode chuan cua iphlpapi.dll, liet
// ke ket noi TCP dang mo kem PID chinh xac (khong can quyen dac biet).
internal static class TcpTableReader
{
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);

    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    public readonly record struct TcpConnection(int Pid, string RemoteAddress, int RemotePort);

    public static List<TcpConnection> GetActiveConnectionsWithPid()
    {
        var results = new List<TcpConnection>();
        int bufSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufSize, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (bufSize <= 0) return results;

        IntPtr buffer = Marshal.AllocHGlobal(bufSize);
        try
        {
            uint ret = GetExtendedTcpTable(buffer, ref bufSize, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0) return results;

            int rowCount = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, 4);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(IntPtr.Add(rowPtr, i * rowSize));
                if (row.remoteAddr == 0) continue; // chua thiet lap ket noi that
                var remoteIp = new IPAddress(BitConverter.GetBytes(row.remoteAddr));
                int remotePort = ((int)row.remotePort >> 8 & 0xFF) | ((int)row.remotePort << 8 & 0xFF00);
                results.Add(new TcpConnection((int)row.owningPid, remoteIp.ToString(), remotePort));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return results;
    }
}
