using System.Text.Json;

namespace Antivirus.Service.Update;

// [QUYET DINH TRIEN KHAI] Nguon goi cuc bo — dung khi khong co update
// server that (moi truong nay), va lam test double cho TEST-10 (kiem tra
// ca luong incremental delta lan fallback full download). Doc goi da ky
// tu mot thu muc tren dia thay vi qua HTTPS — hanh vi CLIENT (so sanh
// version, ap delta tuan tu, fallback full khi tut qua xa, verify chu ky,
// swap nguyen tu) giong het du dung nguon nao.
public sealed class LocalFolderUpdatePackageSource : IUpdatePackageSource
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly string _folder;

    public LocalFolderUpdatePackageSource(string folder)
    {
        _folder = folder;
        Directory.CreateDirectory(folder);
    }

    public Task<VersionCheckResponse> CheckLatestVersionAsync(CancellationToken ct)
    {
        var manifestPath = Path.Combine(_folder, "manifest.json");
        if (!File.Exists(manifestPath))
        {
            return Task.FromResult(new VersionCheckResponse { LatestVersion = 0, Checksum = "" });
        }
        var json = File.ReadAllText(manifestPath);
        var manifest = JsonSerializer.Deserialize<VersionCheckResponse>(json, JsonOptions)
                       ?? new VersionCheckResponse();
        return Task.FromResult(manifest);
    }

    public Task<byte[]?> DownloadPackageAsync(string packageName, CancellationToken ct)
    {
        var path = Path.Combine(_folder, packageName);
        if (!File.Exists(path)) return Task.FromResult<byte[]?>(null);
        return Task.FromResult<byte[]?>(File.ReadAllBytes(path));
    }
}
