namespace Antivirus.Service.Extensions.Network;

// [QUYET DINH TRIEN KHAI] Bang IEEE OUI day du co hang chuc nghin dong,
// khong phu hop nhung/dong goi cung app trong pham vi phien nay. Dung MOT
// TAP CON nho cac hang pho bien trong thiet bi gia dinh (TV, dien thoai,
// router, IoT, may in...) — du de nhan dien phan lon thiet bi thuc te
// trong mot mang gia dinh dien hinh; thiet bi khong khop tra ve
// "Khong xac dinh" thay vi bao loi hay bo qua.
public static class OuiLookup
{
    private static readonly Dictionary<string, string> Prefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["00:1A:11"] = "Google",
        ["F4:F5:D8"] = "Google",
        ["3C:5A:B4"] = "Google",
        ["AC:DE:48"] = "Apple",
        ["F0:18:98"] = "Apple",
        ["A4:83:E7"] = "Apple",
        ["00:17:C9"] = "Cisco",
        ["00:0C:29"] = "VMware",
        ["08:00:27"] = "Oracle VirtualBox",
        ["B8:27:EB"] = "Raspberry Pi Foundation",
        ["DC:A6:32"] = "Raspberry Pi Foundation",
        ["18:FE:34"] = "Espressif (thiet bi IoT)",
        ["24:6F:28"] = "Espressif (thiet bi IoT)",
        ["A0:20:A6"] = "Samsung",
        ["8C:79:F5"] = "Samsung",
        ["5C:0A:5B"] = "Samsung",
        ["70:5A:0F"] = "Samsung",
        ["9C:8E:99"] = "Xiaomi",
        ["78:11:DC"] = "Xiaomi",
        ["64:16:66"] = "Xiaomi",
        ["18:B4:30"] = "Nest Labs",
        ["44:65:0D"] = "Amazon",
        ["68:37:E9"] = "Amazon",
        ["FC:65:DE"] = "Amazon",
        ["B0:7F:B9"] = "Ubiquiti Networks",
        ["24:A4:3C"] = "TP-Link",
        ["50:C7:BF"] = "TP-Link",
        ["00:1D:7E"] = "Cisco-Linksys",
        ["94:10:3E"] = "Roku",
        ["B0:A7:37"] = "Roku",
        ["00:11:32"] = "Synology",
        ["00:04:20"] = "Sonos",
        ["5C:AA:FD"] = "Sonos",
        ["94:9F:3E"] = "HP",
        ["3C:D9:2B"] = "HP",
        ["A0:B3:CC"] = "HP",
    };

    public static string Lookup(string macAddress)
    {
        if (string.IsNullOrEmpty(macAddress) || macAddress.Length < 8) return "Khong xac dinh";
        var prefix = macAddress[..8];
        return Prefixes.TryGetValue(prefix, out var vendor) ? vendor : "Khong xac dinh";
    }
}
