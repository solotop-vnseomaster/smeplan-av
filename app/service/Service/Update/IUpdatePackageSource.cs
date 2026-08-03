namespace Antivirus.Service.Update;

// Truu tuong hoa nguon lay goi CSDL — API-01/02 (apis/03-api.md): "kiem tra
// phien ban CSDL moi nhat" va "tai goi CSDL (delta hoac full)".
public interface IUpdatePackageSource
{
    Task<VersionCheckResponse> CheckLatestVersionAsync(CancellationToken ct);

    // packageName vi du "v100_to_v101.delta" hoac "full_v101.full"
    Task<byte[]?> DownloadPackageAsync(string packageName, CancellationToken ct);
}
