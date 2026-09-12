using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Antivirus.Service.Extensions.Network;

public sealed record DiscoveredDevice(string IpAddress, string? Name, string Source);

// "tai lieu moi.txt": "lang nghe mDNS/SSDP... tren cong chuan (5353 cho
// mDNS, 1900 cho SSDP) de thu thap them thiet bi chua co trong bang ARP".
// CHI lang nghe THU DONG cac goi thiet bi TU quang ba — khong tu gui goi
// truy van chu dong, dung dung tinh than "tranh bi hieu nham la chinh app
// dang quet/tan cong mang" ma tai lieu nhan manh.
public sealed class DiscoveryListener : IDisposable
{
    private readonly ConcurrentQueue<DiscoveredDevice> _queue = new();
    private UdpClient? _mdnsClient;
    private UdpClient? _ssdpClient;
    private CancellationTokenSource? _cts;

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _mdnsClient = StartListener(5353, IPAddress.Parse("224.0.0.251"), "mdns", _cts.Token);
        _ssdpClient = StartListener(1900, IPAddress.Parse("239.255.255.250"), "ssdp", _cts.Token);
    }

    private UdpClient? StartListener(int port, IPAddress multicastGroup, string source, CancellationToken ct)
    {
        try
        {
            var client = new UdpClient();
            client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            client.Client.Bind(new IPEndPoint(IPAddress.Any, port));
            client.JoinMulticastGroup(multicastGroup);

            _ = Task.Run(async () =>
            {
                while (!ct.IsCancellationRequested)
                {
                    try
                    {
                        var result = await client.ReceiveAsync(ct);
                        var device = ParsePacket(result.Buffer, result.RemoteEndPoint.Address.ToString(), source);
                        if (device is not null) _queue.Enqueue(device);
                    }
                    catch (OperationCanceledException) { break; }
                    catch (ObjectDisposedException) { break; }
                    catch { /* goi loi/khong parse duoc — bo qua, khong lam chet vong lang nghe */ }
                }
            }, ct);

            return client;
        }
        catch
        {
            // Co the port da bi chiem boi dich vu khac tren may (vi du
            // chinh Windows cung co the dang dung 1900 cho SSDP discovery
            // cua no) — chi mat nguon phat hien nay, khong nghiem trong.
            return null;
        }
    }

    private static DiscoveredDevice? ParsePacket(byte[] buffer, string sourceIp, string source)
    {
        if (source == "ssdp")
        {
            var text = Encoding.ASCII.GetString(buffer);
            string? server = ExtractHeader(text, "SERVER:");
            return new DiscoveredDevice(sourceIp, SanitizeUntrustedDeviceString(server), "ssdp");
        }

        // mDNS la dinh dang DNS nhi phan — khong parse day du cau truc goi
        // tin, chi tim heuristic: chuoi ASCII in duoc dang ten host ket
        // thuc bang ".local" thuong xuat hien ro rang (dang nhan van ban)
        // trong cac ban ghi PTR/SRV cua goi announce.
        var ascii = Encoding.ASCII.GetString(buffer);
        int idx = ascii.IndexOf(".local", StringComparison.OrdinalIgnoreCase);
        string? name = null;
        if (idx > 0)
        {
            int start = idx;
            while (start > 0 && IsPrintableHostChar(ascii[start - 1])) start--;
            if (idx + 6 <= ascii.Length) name = ascii[start..(idx + 6)];
        }
        return new DiscoveredDevice(sourceIp, SanitizeUntrustedDeviceString(name), "mdns");
    }

    private static bool IsPrintableHostChar(char c) => char.IsLetterOrDigit(c) || c == '-' || c == '.';

    // [SUA LOI TRUNG BINH] Ca "name" (mDNS) lan "server" (header SSDP
    // SERVER:) den tu goi tin UDP QUANG BA THU DONG cua BAT KY thiet bi nao
    // tren LAN (khong xac thuc, khong kiem soat duoc) — gia tri nay duoc
    // luu trong NetworkDeviceInfo.DiscoveredName va lo ra qua API cho UI
    // hien thi. IsPrintableHostChar da gioi han "name" (mDNS) o mot tap ky
    // tu an toan, nhung "server" (SSDP, doc thang tu header van ban, KHONG
    // qua bo loc nao) thi chua — mot thiet bi gia mao co the nhet ky tu HTML/
    // script vao header SERVER: cua phan hoi SSDP. Loc bo ky tu dieu khien
    // (co the gia mao them dong/header) VA ky tu co the dien giai thanh
    // HTML boi mot sink UI (< > & " ' `), gioi han do dai — ap dung cho CA
    // HAI nguon (mDNS lan SSDP) de phong thu theo chieu sau, du mDNS hien
    // da duoc gioi han rieng boi IsPrintableHostChar.
    private const int MaxDeviceStringLength = 128;

    private static string? SanitizeUntrustedDeviceString(string? raw)
    {
        if (string.IsNullOrEmpty(raw)) return null;

        var sb = new StringBuilder(Math.Min(raw.Length, MaxDeviceStringLength));
        foreach (var c in raw)
        {
            if (sb.Length >= MaxDeviceStringLength) break;
            if (char.IsControl(c)) continue;
            if (c is '<' or '>' or '&' or '"' or '\'' or '`') continue;
            sb.Append(c);
        }

        var result = sb.ToString().Trim();
        return result.Length == 0 ? null : result;
    }

    private static string? ExtractHeader(string text, string headerPrefix)
    {
        foreach (var line in text.Split("\r\n"))
        {
            if (line.StartsWith(headerPrefix, StringComparison.OrdinalIgnoreCase))
                return line[headerPrefix.Length..].Trim();
        }
        return null;
    }

    public List<DiscoveredDevice> DrainDiscovered()
    {
        var result = new List<DiscoveredDevice>();
        while (_queue.TryDequeue(out var device)) result.Add(device);
        return result;
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _mdnsClient?.Dispose();
        _ssdpClient?.Dispose();
    }
}
