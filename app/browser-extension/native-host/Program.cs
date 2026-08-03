using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace SmeplanAv.NativeHost;

// [MA NGUON THAM KHAO — "tai lieu moi.txt" muc "Tich hop canh bao phishing
// vao trinh duyet"] Chua duoc dang ky/test trong mot trinh duyet that trong
// phien nay (features.md EXT-PH-03), nhung day du giao thuc Native
// Messaging chinh thuc cua Chromium: moi message duoc dong khung boi 4
// byte little-endian ghi do dai, theo sau la noi dung JSON UTF-8 — khong
// mo cong mang cuc bo nao (extension chi goi duoc executable da dang ky
// dung ten qua manifest, tranh bi gia mao boi tien trinh khac nhu mo
// cong TCP se gap phai).
//
// [HAN CHE DA BIET] Native host can doc token API cua service tu
// DataDir\api-token.txt (xem ApiTokenProvider.cs) de goi
// /api/phishing/check-url, nhung file do chi cap quyen doc cho
// SYSTEM/Administrators/danh tinh chay service (AclProtection.cs), trong
// khi native host thuong chay duoi quyen NGUOI DUNG dang dang nhap (do
// trinh duyet khoi chay) — trien khai that can mot co che cap quyen doc
// rieng cho nhom Users (vi du mot named pipe co ACL rieng thay vi doc
// truc tiep file), CHUA giai quyet trong pham vi tham khao nay.
public static class Program
{
    private const string ApiBaseUrl = "http://127.0.0.1:5270";
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(5);
    private static readonly Dictionary<string, (bool Malicious, DateTime ExpiresAt)> DomainCache = new();

    public static async Task Main()
    {
        using var stdin = Console.OpenStandardInput();
        using var stdout = Console.OpenStandardOutput();
        using var http = new HttpClient { BaseAddress = new Uri(ApiBaseUrl), Timeout = TimeSpan.FromSeconds(2) };

        string? token = TryReadApiToken();

        while (true)
        {
            var request = await ReadMessageAsync(stdin);
            if (request is null) break; // stdin dong -> trinh duyet da dong extension/tab

            var response = await HandleRequestAsync(http, token, request.Value);
            await WriteMessageAsync(stdout, response);
        }
    }

    private static async Task<JsonElement> HandleRequestAsync(HttpClient http, string? token, JsonElement request)
    {
        try
        {
            if (!request.TryGetProperty("type", out var typeProp) || typeProp.GetString() != "check_url")
            {
                return JsonSerializer.SerializeToElement(new { error = "unsupported_type" });
            }
            string url = request.GetProperty("url").GetString() ?? "";
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                return JsonSerializer.SerializeToElement(new { malicious = false });
            }

            // EXT-PH-04: "domain da kiem tra sach gan day duoc cache tai
            // CHINH NATIVE HOST de giu do tre duoi vai chuc mili giay".
            if (DomainCache.TryGetValue(uri.Host, out var cached) && cached.ExpiresAt > DateTime.UtcNow)
            {
                return JsonSerializer.SerializeToElement(new { malicious = cached.Malicious, cached = true });
            }

            using var httpRequest = new HttpRequestMessage(HttpMethod.Post, "/api/phishing/check-url");
            if (token is not null) httpRequest.Headers.Add("X-Av-Token", token);
            httpRequest.Content = new StringContent(
                JsonSerializer.Serialize(new { url }), Encoding.UTF8, "application/json");

            using var httpResponse = await http.SendAsync(httpRequest);
            if (!httpResponse.IsSuccessStatusCode)
            {
                // "fail open" — khong co ket luan tu service thi khong tu
                // chan, day chi la MOT lop bo sung trong nhieu lop (WFP IP
                // reputation + DNS filtering van con o cac tang khac).
                return JsonSerializer.SerializeToElement(new { malicious = false, error = "service_unreachable" });
            }

            var body = await httpResponse.Content.ReadFromJsonAsync<CheckUrlResult>();
            bool malicious = body?.Malicious ?? false;
            DomainCache[uri.Host] = (malicious, DateTime.UtcNow + CacheTtl);

            return JsonSerializer.SerializeToElement(new { malicious, matchedOn = body?.MatchedValue });
        }
        catch
        {
            return JsonSerializer.SerializeToElement(new { malicious = false, error = "native_host_exception" });
        }
    }

    private static string? TryReadApiToken()
    {
        try
        {
            string path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "AntivirusApp", "data", "api-token.txt");
            return File.Exists(path) ? File.ReadAllText(path).Trim() : null;
        }
        catch { return null; }
    }

    private static async Task<JsonElement?> ReadMessageAsync(Stream stdin)
    {
        var lengthBuffer = new byte[4];
        int read = await ReadExactAsync(stdin, lengthBuffer, 4);
        if (read < 4) return null;

        int length = BitConverter.ToInt32(lengthBuffer, 0);
        if (length <= 0 || length > 10 * 1024 * 1024) return null; // gioi han an toan, khong tin do dai tuy y

        var payload = new byte[length];
        read = await ReadExactAsync(stdin, payload, length);
        if (read < length) return null;

        using var doc = JsonDocument.Parse(payload);
        return doc.RootElement.Clone();
    }

    private static async Task<int> ReadExactAsync(Stream stream, byte[] buffer, int count)
    {
        int totalRead = 0;
        while (totalRead < count)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(totalRead, count - totalRead));
            if (n == 0) break; // EOF
            totalRead += n;
        }
        return totalRead;
    }

    private static async Task WriteMessageAsync(Stream stdout, JsonElement message)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(message);
        await stdout.WriteAsync(BitConverter.GetBytes(payload.Length));
        await stdout.WriteAsync(payload);
        await stdout.FlushAsync();
    }

    private sealed class CheckUrlResult
    {
        public bool Malicious { get; set; }
        public string? MatchedOn { get; set; }
        public string? MatchedValue { get; set; }
    }
}
