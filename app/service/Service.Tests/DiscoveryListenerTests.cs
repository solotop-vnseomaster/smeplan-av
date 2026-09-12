using System.Reflection;
using System.Text;
using Antivirus.Service.Extensions.Network;
using Xunit;

namespace Antivirus.Service.Tests;

// [test-coverage][SUA LOI TRUNG BINH] ParsePacket xu ly du lieu tu goi tin
// UDP quang ba THU DONG cua bat ky thiet bi nao tren LAN (khong xac thuc) —
// truoc day KHONG co test nao, ke ca cho logic sanitize vua them de chan
// header SSDP SERVER: mang ky tu HTML/script lo ra qua API cho UI. ParsePacket
// la private static nen dung reflection de goi truc tiep, tranh phai mo
// UdpClient/multicast group that (khong on dinh, phu thuoc moi truong mang).
public class DiscoveryListenerTests
{
    private static object? ParsePacket(byte[] buffer, string sourceIp, string source)
    {
        var method = typeof(DiscoveryListener).GetMethod("ParsePacket", BindingFlags.NonPublic | BindingFlags.Static)!;
        return method.Invoke(null, new object[] { buffer, sourceIp, source });
    }

    private static (string IpAddress, string? Name, string Source) Unwrap(object? device)
    {
        Assert.NotNull(device);
        var type = device!.GetType();
        return (
            (string)type.GetProperty("IpAddress")!.GetValue(device)!,
            (string?)type.GetProperty("Name")!.GetValue(device),
            (string)type.GetProperty("Source")!.GetValue(device)!
        );
    }

    [Fact]
    public void Ssdp_NormalServerHeader_ParsedAsIs()
    {
        var packet = "HTTP/1.1 200 OK\r\nSERVER: Linux/3.0 UPnP/1.0 MyRouter/1.0\r\n\r\n";
        var buffer = Encoding.ASCII.GetBytes(packet);

        var (ip, name, source) = Unwrap(ParsePacket(buffer, "192.168.1.10", "ssdp"));

        Assert.Equal("192.168.1.10", ip);
        Assert.Equal("ssdp", source);
        Assert.Equal("Linux/3.0 UPnP/1.0 MyRouter/1.0", name);
    }

    // [test-coverage][SUA LOI TRUNG BINH] Kich ban chinh: thiet bi gia mao
    // gui header SERVER: chua ky tu HTML/script — phai bi loc bo truoc khi
    // ra khoi service.
    [Fact]
    public void Ssdp_ServerHeaderWithHtmlPayload_StripsUnsafeCharacters()
    {
        var packet = "HTTP/1.1 200 OK\r\nSERVER: <script>alert(1)</script>\r\n\r\n";
        var buffer = Encoding.ASCII.GetBytes(packet);

        var (_, name, _) = Unwrap(ParsePacket(buffer, "192.168.1.20", "ssdp"));

        Assert.NotNull(name);
        Assert.DoesNotContain('<', name);
        Assert.DoesNotContain('>', name);
    }

    // [SUA TEST VO NGHIA] TRUOC DAY test nay dung "\r\n" lam "ky tu dieu
    // khien" can bi loai bo. Nhung \r\n chinh la DAU PHAN CACH header cua
    // SSDP — bo phan tich tach header theo no, nen `name` khong bao gio
    // chua \r hay \n DU CO hay KHONG CO logic loc nao ca. Hai assertion
    // vi vay luon dung mot cach rong tuech: xoa sach ham loc di test van
    // xanh. Test khoa mot bao ve ma no khong he kiem tra.
    //
    // Sua: dung ky tu dieu khien THAT (NUL, BEL, ESC, backspace) NAM BEN
    // TRONG gia tri header — day moi la thu ke tan cong nhet vao de pha
    // giao dien/log, va la thu bo loc phai thuc su loai bo.
    [Fact]
    public void Ssdp_ServerHeaderWithControlCharacters_StripsThem()
    {
        var packet = "HTTP/1.1 200 OK\r\nSERVER: Evil\u0000Router\u0007\u001b[31m\u0008\r\n\r\n";
        var buffer = Encoding.ASCII.GetBytes(packet);

        var (_, name, _) = Unwrap(ParsePacket(buffer, "192.168.1.30", "ssdp"));

        Assert.NotNull(name);
        foreach (char c in name!)
        {
            Assert.False(char.IsControl(c),
                $"Ten thiet bi con chua ky tu dieu khien U+{(int)c:X4} — gia tri nay di thang ra UI va log");
        }
    }

    // Rang buoc may kiem duoc so 8 trong review: moi buffer UDP => Name la
    // null hoac Length <= 128, khong chua < > & " ' ` va khong ky tu dieu
    // khien; ParsePacket khong bao gio nem.
    [Theory]
    [InlineData("HTTP/1.1 200 OK\r\nSERVER: " + "A very long name that keeps going and going and going and going and going and going and going and going and going and going" + "\r\n\r\n")]
    [InlineData("HTTP/1.1 200 OK\r\nSERVER: <script>alert(1)</script>\r\n\r\n")]
    [InlineData("HTTP/1.1 200 OK\r\nSERVER: name&with\"quotes\'and`ticks\r\n\r\n")]
    [InlineData("")]
    [InlineData("\0\0\0\0")]
    public void ParsePacket_AnyInput_NameIsNullOrSafeAndBounded(string packet)
    {
        var buffer = Encoding.ASCII.GetBytes(packet);

        var result = ParsePacket(buffer, "192.168.1.99", "ssdp");
        if (result is null) return;

        var (_, name, _) = Unwrap(result);
        if (name is null) return;

        Assert.True(name.Length <= 128, $"Ten dai {name.Length} ky tu — khong duoc vuot 128");
        foreach (char c in name)
        {
            Assert.False(char.IsControl(c));
            Assert.DoesNotContain(c, "<>&\"'`");
        }
    }

    [Fact]
    public void Ssdp_NoServerHeader_ReturnsNullName()
    {
        var packet = "HTTP/1.1 200 OK\r\n\r\n";
        var buffer = Encoding.ASCII.GetBytes(packet);

        var (_, name, _) = Unwrap(ParsePacket(buffer, "192.168.1.40", "ssdp"));

        Assert.Null(name);
    }

    [Fact]
    public void Mdns_HostnameWithLocalSuffix_Extracted()
    {
        var buffer = Encoding.ASCII.GetBytes("\x00\x00\x0Cliving-room-tv.local\x00\x00");

        var (_, name, source) = Unwrap(ParsePacket(buffer, "192.168.1.50", "mdns"));

        Assert.Equal("mdns", source);
        Assert.Equal("living-room-tv.local", name);
    }

    [Fact]
    public void Mdns_NoLocalSuffix_ReturnsNullName()
    {
        var buffer = Encoding.ASCII.GetBytes("random binary noise without the suffix");

        var (_, name, _) = Unwrap(ParsePacket(buffer, "192.168.1.60", "mdns"));

        Assert.Null(name);
    }
}
