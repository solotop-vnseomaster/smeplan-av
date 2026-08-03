using System.Text.Json;

namespace Antivirus.Service.Update;

// Trien khai HTTPS/JSON that theo apis/03-api.md (nhom giao tiep duy nhat
// duoc mo ta dang request/response qua mang trong toan bo spec). Khong co
// server that de tro toi trong moi truong nay nen lop nay khong duoc dang
// ky mac dinh (xem Program.cs dung LocalFolderUpdatePackageSource thay the)
// — nhung day la client HTTPS/JSON day du, san sang tro toi mot update
// server thuc te qua cau hinh BaseUrl.
public sealed class HttpUpdatePackageSource : IUpdatePackageSource
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly HttpClient _http;

    public HttpUpdatePackageSource(HttpClient http)
    {
        _http = http;
    }

    public async Task<VersionCheckResponse> CheckLatestVersionAsync(CancellationToken ct)
    {
        using var resp = await _http.GetAsync("/api/csdl/version", ct);
        resp.EnsureSuccessStatusCode();
        var json = await resp.Content.ReadAsStringAsync(ct);
        return JsonSerializer.Deserialize<VersionCheckResponse>(json, JsonOptions)
               ?? throw new InvalidOperationException("Response rong tu update server");
    }

    public async Task<byte[]?> DownloadPackageAsync(string packageName, CancellationToken ct)
    {
        using var resp = await _http.GetAsync($"/api/csdl/package/{Uri.EscapeDataString(packageName)}", ct);
        if (!resp.IsSuccessStatusCode) return null;
        return await resp.Content.ReadAsByteArrayAsync(ct);
    }
}
