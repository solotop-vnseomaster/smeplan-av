using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Antivirus.Service.Audit;

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

    // [SUA LOI NGHIEM TRONG] FirewallRuleStore.FindBestMatch TRUOC DAY khong
    // co MOT call site san xuat nao — chi cac test goi no. Nguoi dung tao
    // rule "Block", thay no trong danh sach, va tin la may dang duoc bao ve;
    // trong khi khong mot dong code nao doc rule do de ra quyet dinh. Do la
    // truong hop nang nhat trong bao cao: khong phai thieu bao ve, ma la
    // BAO CAO SAI ve bao ve.
    //
    // Chan ket noi THAT SU o tang mang can WFP callout (drivers/wfp-firewall)
    // va nam ngoai pham vi mot ban sua loi. Nhung im lang thi khong chap
    // nhan duoc. ConnectionMonitor gio DOI CHIEU moi ket noi dang hoat dong
    // voi rule, va khi mot rule Block khop mot ket noi DANG MO, no phat su
    // kien + ghi audit ro rang rang rule KHONG duoc thuc thi. Xem them co
    // RulesAreEnforced ben duoi va /api/firewall/status.
    private readonly FirewallRuleStore _rules;
    private readonly AuditLogger _audit;
    private readonly EventBus _eventBus;
    private readonly ILogger<ConnectionMonitor> _logger;

    // Rule firewall trong ban nay CHUA duoc thuc thi o tang mang. Moi noi
    // hien thi trang thai firewall PHAI doc co nay va noi ro voi nguoi dung,
    // thay vi de ho suy dien rang tao rule la da duoc bao ve.
    public const bool RulesAreEnforced = false;

    private readonly HashSet<string> _reportedUnenforced = new();

    // (pid, remoteAddress) -> danh sach timestamp cac lan quan sat ket noi.
    private readonly Dictionary<(int Pid, string Remote), List<long>> _observations = new();

    // Tap (pid, remote) nhin thay o vong poll NGAY TRUOC. Dung de phan biet
    // "mot ket noi moi vua mo" (tin hieu beacon that) voi "mot ket noi cu van
    // dang song" (khong phai tin hieu gi ca) — xem PollConnections.
    // Chi duoc doc/ghi trong PollConnections, chay tuan tu tren mot luong duy
    // nhat cua BackgroundService, nen khong can khoa rieng.
    private HashSet<(int Pid, string Remote)> _previousPollKeys = new();
    private readonly List<BeaconSuspicion> _recentSuspicions = new();
    private readonly object _lock = new();

    public ConnectionMonitor(EventBus eventBus, FirewallRuleStore rules, AuditLogger audit,
        ILogger<ConnectionMonitor> logger)
    {
        _eventBus = eventBus;
        _rules = rules;
        _audit = audit;
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

    // [SUA LOI CAO] Xem ghi chu tai `_previousPollKeys` ben duoi.
    private void PollConnections()
    {
        var connections = TcpTableReader.GetActiveConnectionsWithPid();
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var currentPollKeys = new HashSet<(int Pid, string Remote)>();

        foreach (var conn in connections)
        {
            if (IsPrivateOrLoopback(conn.RemoteAddress)) continue; // chi quan tam ket noi ra internet that

            var key = (conn.Pid, conn.RemoteAddress);
            currentPollKeys.Add(key);
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
                // [SUA LOI CAO — FALSE POSITIVE HE THONG] TRUOC DAY dieu
                // kien la `now - list[^1] > 1000`, tuc mot cua so chong
                // trung 1 GIAY, trong khi vong poll chay moi 10 GIAY (xem
                // ExecuteAsync). Cua so chong trung NHO HON chu ky poll thi
                // khong chong duoc gi ca: MOT ket noi TCP song lau (tab
                // trinh duyet, Windows Update, chinh update client cua san
                // pham nay, mot phien SSH) duoc dem lai o MOI vong poll, deu
                // dan chinh xac 10 giay mot lan. Do la day timestamp co he
                // so bien thien ~0 — tuc la dinh nghia cua "beacon C2 rat
                // deu" ma LowVariationThreshold dung de bat. Ket qua: MOI
                // ket noi ra internet song qua ~MinSamplesForRegularity vong
                // poll deu bi bao la beacon C2. Va vi diem rui ro bao hoa o
                // 10 false positive, diem rui ro tong hop tut vinh vien.
                //
                // Sua: beacon la mot chuoi ket noi LAP LAI, khong phai mot
                // ket noi ben bi. Chi ghi nhan mot quan sat khi cap
                // (pid, remote) KHONG co mat o vong poll ngay truoc — tuc la
                // mot ket noi MOI vua duoc mo — thay vi moi lan nhin thay no.
                bool isNewConnection = !_previousPollKeys.Contains(key);
                if (isNewConnection)
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

            CheckAgainstFirewallRules(conn.Pid, conn.RemoteAddress, conn.RemotePort);
        }

        _previousPollKeys = currentPollKeys;
    }

    // Doi chieu mot ket noi dang mo voi cac rule firewall nguoi dung da dat.
    // Xem ghi chu tai _rules: day KHONG phai thuc thi, day la phat hien +
    // bao cao trung thuc rang rule khong duoc thuc thi.
    private void CheckAgainstFirewallRules(int pid, string remoteAddress, int remotePort)
    {
        string? processPath = TryGetProcessPath(pid);
        if (string.IsNullOrEmpty(processPath)) return;

        string sha256;
        try { sha256 = ComputeFileSha256(processPath); }
        catch { return; }
        if (sha256.Length == 0) return;

        FirewallRule? match;
        try
        {
            match = _rules.FindBestMatch(sha256, FirewallDirection.Outbound, FirewallProtocol.Tcp, remotePort);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Khong tra cuu duoc rule firewall cho {Path}", processPath);
            return;
        }

        if (match is null || match.Action != FirewallAction.Block) return;

        // Chi bao MOT LAN cho moi (rule, tien trinh, dich) de khong lam ngap
        // audit log moi 10 giay.
        string dedupeKey = $"{match.Id}|{sha256}|{remoteAddress}:{remotePort}";
        lock (_lock)
        {
            if (!_reportedUnenforced.Add(dedupeKey)) return;
        }

        string message =
            $"Rule firewall #{match.Id} (Block) KHOP mot ket noi DANG MO tu {processPath} toi {remoteAddress}:{remotePort} — " +
            "rule KHONG duoc thuc thi o tang mang trong ban nay, ket noi VAN DANG CHAY";
        _logger.LogWarning("{Message}", message);
        _audit.Log("firewall", message, new { ruleId = match.Id, processPath, remoteAddress, remotePort, enforced = false });
        _eventBus.Publish(new CorrelationEvent
        {
            EntityKey = $"pid:{pid}",
            SourceEngine = "firewall",
            Severity = 50, // rule Block khop nhung khong duoc thuc thi — dang chu y, khong phai phat hien malware
            Summary = message,
            TimestampUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        });
    }

    private static string ComputeFileSha256(string path)
    {
        using var stream = File.OpenRead(path);
        using var sha = System.Security.Cryptography.SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
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

    // [SUA LOI CAO] TRUOC DAY moi dia chi KHONG phai AddressFamily.InterNetwork
    // deu tra ve `true` ("coi nhu mang noi bo") va bi `continue` bo qua o
    // PollConnections. Tren Windows hien dai IPv6 duoc bat mac dinh va thuong
    // duoc uu tien hon IPv4, nen day khong phai mot gioi han nho: ma doc
    // beacon qua IPv6 la VO HINH TOAN DIEN voi tang phat hien nay, va cach
    // vong qua no chi la mot dia chi AAAA. Xu ly IPv6 dung nghia thay vi coi
    // ca ho dia chi la noi bo.
    private static bool IsPrivateOrLoopback(string address)
    {
        // Dia chi IPv6 tu bang TCP co the kem scope id ("fe80::1%12").
        int scopeSeparator = address.IndexOf('%');
        if (scopeSeparator >= 0) address = address[..scopeSeparator];

        if (!IPAddress.TryParse(address, out var ip)) return true;
        if (IPAddress.IsLoopback(ip)) return true;

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast) return true;
            // fc00::/7 — Unique Local Address, tuong duong dai IPv4 rieng.
            var v6 = ip.GetAddressBytes();
            if ((v6[0] & 0xFE) == 0xFC) return true;
            // ::ffff:a.b.c.d — IPv4 anh xa vao IPv6: danh gia theo luat IPv4.
            if (ip.IsIPv4MappedToIPv6) return IsPrivateOrLoopback(ip.MapToIPv4().ToString());
            return false; // IPv6 dinh tuyen duoc toan cau -> PHAI duoc theo doi
        }

        if (ip.AddressFamily != AddressFamily.InterNetwork) return true;

        var bytes = ip.GetAddressBytes();
        return bytes[0] == 10 ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168) ||
               bytes[0] == 127 ||
               (bytes[0] == 169 && bytes[1] == 254); // link-local IPv4
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
    private const int AF_INET6 = 23;
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

    // MIB_TCP6ROW_OWNER_PID — doi ung IPv6 cua MIB_TCPROW_OWNER_PID.
    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] remoteAddr;
        public uint remoteScopeId;
        public uint remotePort;
        public uint state;
        public uint owningPid;
    }

    public readonly record struct TcpConnection(int Pid, string RemoteAddress, int RemotePort);

    // Cong luu tru theo network byte order trong ca hai bang MIB.
    private static int NetworkToHostPort(uint port) =>
        ((int)port >> 8 & 0xFF) | ((int)port << 8 & 0xFF00);

    // [SUA LOI CAO] TRUOC DAY ham nay CHI truy van bang TCP cua AF_INET.
    // Tren Windows hien dai IPv6 duoc bat mac dinh va thuong duoc uu tien hon
    // IPv4 khi ca hai kha dung, nen mot ket noi ra ngoai qua IPv6 khong bao
    // gio xuat hien trong bang nay: no vo hinh voi ca phat hien beacon C2 lan
    // voi viec doi chieu rule tuong lua. Truy van CA hai ho dia chi.
    public static List<TcpConnection> GetActiveConnectionsWithPid()
    {
        var results = new List<TcpConnection>();
        ReadTable(results, AF_INET);
        ReadTable(results, AF_INET6);
        return results;
    }

    private static void ReadTable(List<TcpConnection> results, int addressFamily)
    {
        int bufSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufSize, false, addressFamily, TCP_TABLE_OWNER_PID_ALL, 0);
        if (bufSize <= 0) return;

        IntPtr buffer = Marshal.AllocHGlobal(bufSize);
        try
        {
            uint ret = GetExtendedTcpTable(buffer, ref bufSize, false, addressFamily, TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0) return;

            int rowCount = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, 4);

            if (addressFamily == AF_INET)
            {
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                for (int i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(IntPtr.Add(rowPtr, i * rowSize));
                    if (row.remoteAddr == 0) continue; // chua thiet lap ket noi that
                    var remoteIp = new IPAddress(BitConverter.GetBytes(row.remoteAddr));
                    results.Add(new TcpConnection((int)row.owningPid, remoteIp.ToString(), NetworkToHostPort(row.remotePort)));
                }
            }
            else
            {
                int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
                for (int i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(IntPtr.Add(rowPtr, i * rowSize));
                    if (row.remoteAddr is null || row.remoteAddr.All(b => b == 0)) continue;
                    var remoteIp = new IPAddress(row.remoteAddr, row.remoteScopeId);
                    results.Add(new TcpConnection((int)row.owningPid, remoteIp.ToString(), NetworkToHostPort(row.remotePort)));
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
