namespace Antivirus.Service.Update;

// [QUYET DINH TRIEN KHAI] Hop dong JSON toi gian tu dinh nghia cho phia
// client, vi apis/03-api.md ghi TODO [UNKNOWN] cho request/response cu the
// va khong co dac ta ve viec phai dung server that (xem features.md, muc
// "Quyet dinh trien khai rang buoc"). Hanh vi CLIENT (chu ky kiem tra,
// thu tu ap delta, nguong fallback full, verify chu ky, swap nguyen tu) la
// phan duy nhat co dac ta va da duoc trien khai dung.
public sealed class VersionCheckResponse
{
    public int LatestVersion { get; set; }
    public string Checksum { get; set; } = "";
}

public sealed class UpdateStatus
{
    public int CurrentVersion { get; set; }
    public DateTimeOffset? LastCheckedAt { get; set; }
    public string? LastResult { get; set; }
    public bool CheckInProgress { get; set; }
}
