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
        // [SUA LOI — xem ghi chu ACL o dau file] TRUOC DAY khi doc token that
        // bai (vi du ACL chi cho SYSTEM/service doc, native host chay quyen
        // NGUOI DUNG thuong khong co quyen), loi nay HOAN TOAN IM LANG — Main()
        // tiep tuc chay binh thuong voi token=null, va tinh nang chan phishing
        // AM THAM fail-open (moi request toi /api/phishing/check-url khong co
        // header X-Av-Token, rat co the bi service tu choi/bo qua ma KHONG AI
        // biet). Day khong phai fix kien truc day du (van CAN mot co che cap
        // quyen doc rieng cho nhom Users, vi du named pipe rieng — ngoai pham
        // vi file tham khao nay), nhung it nhat phai LOG RO RANG ra stderr
        // (Chrome Native Messaging KHONG doc/can thiep stderr cua native host,
        // day la kenh an toan de chan doan) de admin/nguoi phat trien co the
        // phat hien tinh trang fail-open nay thay vi no troi qua trong im lang.
        if (token is null)
        {
            await Console.Error.WriteLineAsync(
                $"[CANH BAO] SMEPlan AV native host: KHONG doc duoc api-token.txt — " +
                $"tinh nang chan phishing se chay o che do FAIL-OPEN (khong co token xac thuc, " +
                $"cac yeu cau /api/phishing/check-url co the bi service tu choi ma khong bao loi ro). " +
                $"Nguyen nhan pho bien: ACL cua api-token.txt chi cho SYSTEM/Administrators doc, " +
                $"trong khi native host nay dang chay duoi quyen nguoi dung thuong.");
        }

        while (true)
        {
            var (status, request) = await ReadMessageAsync(stdin);

            // stdin dong (hoac khung tin nhan hong khong the dong bo lai) ->
            // trinh duyet da dong extension/tab, hoac kenh da hong.
            if (status == ReadStatus.EndOfStream) break;

            if (status == ReadStatus.Malformed)
            {
                // [SUA LOI NGHIEM TRONG] TRUOC DAY JsonDocument.Parse nam
                // NGOAI moi try/catch, va vong lap nay khong bat gi ca — mot
                // tin nhan JSON hong lam JsonException bay len tan Main va
                // GIET native host. Chrome khong khoi dong lai native host
                // sau khi no chet: tinh nang chan phishing tat han cho toi
                // khi nguoi dung khoi dong lai trinh duyet, va KHONG co dau
                // hieu nao tren giao dien.
                // So byte cua tin nhan nay da duoc doc het (do dai hop le),
                // nen luong van dong bo — bo qua rieng tin nhan hong va doc
                // tiep la an toan. Van tra ve mot phan hoi de callback ben
                // extension khong treo; background.js coi truong `error` la
                // "khong co ket luan" va KHONG cache thanh sach.
                await Console.Error.WriteLineAsync(
                    "[CANH BAO] SMEPlan AV native host: nhan duoc tin nhan JSON hong — bo qua, tiep tuc chay.");
                await WriteMessageAsync(stdout,
                    JsonSerializer.SerializeToElement(new { malicious = false, error = "malformed_request" }));
                continue;
            }

            var response = await HandleRequestAsync(http, token, request);
            await WriteMessageAsync(stdout, response);
        }
    }

    private enum ReadStatus
    {
        Message,      // doc duoc mot tin nhan JSON hop le
        Malformed,    // khung hop le nhung noi dung khong phai JSON -> bo qua, doc tiep
        EndOfStream,  // stdin dong, hoac khung hong khong the dong bo lai -> dung han
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
        string path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "AntivirusApp", "data", "api-token.txt");
        try
        {
            if (!File.Exists(path))
            {
                Console.Error.WriteLine($"[CANH BAO] SMEPlan AV native host: khong tim thay {path} (service co the chua chay lan nao, hoac chua tao token).");
                return null;
            }
            // [SUA LOI] Truoc day tra ve chuoi rong khi file ton tai nhung
            // dai 0 byte (service dang ghi do, hoac lan khoi tao bi ngat
            // giua chung). Chuoi rong KHONG phai null, nen canh bao fail-open
            // o Main khong chay, va moi request gui di mot header
            // "X-Av-Token: " rong — service tu choi, khong ai biet vi sao.
            // Token rong khong khac gi khong co token: coi la null de di
            // dung nhanh canh bao da co.
            var raw = File.ReadAllText(path).Trim();
            if (raw.Length == 0)
            {
                Console.Error.WriteLine($"[CANH BAO] SMEPlan AV native host: {path} rong (0 byte) — coi nhu khong co token.");
                return null;
            }
            return raw;
        }
        catch (Exception ex)
        {
            // Phan biet ro voi truong hop "file khong ton tai" o tren — vao
            // day nghia la file CO TON TAI nhung KHONG DOC DUOC, truong hop
            // pho bien nhat la UnauthorizedAccessException do ACL cua file
            // chi cap quyen cho SYSTEM/Administrators (xem ghi chu dau file):
            // day chinh la trieu chung cua han che ACL da biet, ghi log ro
            // loai ngoai le de de chan doan hon la mot "token=null" chung
            // chung khong ro nguyen nhan.
            Console.Error.WriteLine($"[CANH BAO] SMEPlan AV native host: doc {path} that bai ({ex.GetType().Name}: {ex.Message}) — rat co the do ACL chi cho SYSTEM/Administrators doc trong khi native host chay quyen nguoi dung thuong.");
            return null;
        }
    }

    private static async Task<(ReadStatus Status, JsonElement Message)> ReadMessageAsync(Stream stdin)
    {
        var lengthBuffer = new byte[4];
        int read = await ReadExactAsync(stdin, lengthBuffer, 4);
        if (read < 4) return (ReadStatus.EndOfStream, default);

        int length = BitConverter.ToInt32(lengthBuffer, 0);
        // Do dai vo ly: luong da mat dong bo va KHONG the dong bo lai (khong
        // biet phai bo qua bao nhieu byte) -> dung han, khac voi truong hop
        // JSON hong ben duoi.
        if (length <= 0 || length > 10 * 1024 * 1024) return (ReadStatus.EndOfStream, default);

        var payload = new byte[length];
        read = await ReadExactAsync(stdin, payload, length);
        if (read < length) return (ReadStatus.EndOfStream, default);

        // Toan bo `length` byte da duoc tieu thu, nen du parse that bai thi
        // luong VAN dong bo — bao "Malformed" de vong lap bo qua rieng tin
        // nhan nay thay vi giet ca tien trinh.
        try
        {
            using var doc = JsonDocument.Parse(payload);
            return (ReadStatus.Message, doc.RootElement.Clone());
        }
        catch (JsonException)
        {
            return (ReadStatus.Malformed, default);
        }
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
