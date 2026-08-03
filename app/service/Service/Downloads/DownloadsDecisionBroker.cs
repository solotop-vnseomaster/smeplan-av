using System.Collections.Concurrent;

namespace Antivirus.Service.Downloads;

public enum SuspiciousDownloadAction { Delete, Quarantine, Ignore }

public sealed class SuspiciousDownloadItem
{
    public required string ItemId { get; init; }
    public required string FilePath { get; init; }
    public required string Sha256Hex { get; init; }
    public required string Reason { get; init; }
    public long DetectedAtUnixMs { get; init; }
}

// flows/11: verdict Suspicious o Downloads -> "hien thi canh bao kem ba lua
// chon Xoa/Cach ly/Bo qua de nguoi dung tu quyet" (khong tu dong hanh dong).
public sealed class DownloadsDecisionBroker
{
    private readonly ConcurrentDictionary<string, SuspiciousDownloadItem> _pending = new();

    public event Action<SuspiciousDownloadItem>? ItemAdded;

    public string Add(string filePath, string sha256Hex, string reason)
    {
        var id = Guid.NewGuid().ToString("N");
        var item = new SuspiciousDownloadItem
        {
            ItemId = id,
            FilePath = filePath,
            Sha256Hex = sha256Hex,
            Reason = reason,
            DetectedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        };
        _pending[id] = item;
        ItemAdded?.Invoke(item);
        return id;
    }

    public SuspiciousDownloadItem? Get(string id) => _pending.GetValueOrDefault(id);
    public bool Remove(string id) => _pending.TryRemove(id, out _);
    public IReadOnlyCollection<SuspiciousDownloadItem> ListPending() => _pending.Values.ToList();
}
