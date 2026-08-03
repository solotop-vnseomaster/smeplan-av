using System.Collections.Concurrent;

namespace Antivirus.Service.Trust;

public enum UserPermissionChoice { AllowAlways, AllowOnce, Block }

public sealed class PendingPermissionRequest
{
    public required string RequestId { get; init; }
    public required string ProcessPath { get; init; }
    public required string Sha256Hex { get; init; }
    public string? PublisherName { get; init; }
    public string? PublisherThumbprint { get; init; }
    public long CreatedAtUnixMs { get; init; }
}

// sections/09-giao-dien-tuy-bien-quyen.md: hop thoai xin quyen luon do
// service SYSTEM khoi tao — lop nay giu hang doi cac yeu cau dang cho UI
// tra loi, ho tro timeout toi da 30s (business-rules/05 BIZ-04).
public sealed class PermissionRequestBroker
{
    private readonly ConcurrentDictionary<string, (PendingPermissionRequest Request, TaskCompletionSource<UserPermissionChoice> Tcs)> _pending = new();

    public event Action<PendingPermissionRequest>? RequestCreated;

    public async Task<UserPermissionChoice?> RequestDecisionAsync(
        string processPath, string sha256Hex, string? publisherName, string? publisherThumbprint,
        TimeSpan timeout, CancellationToken ct)
    {
        var requestId = Guid.NewGuid().ToString("N");
        var request = new PendingPermissionRequest
        {
            RequestId = requestId,
            ProcessPath = processPath,
            Sha256Hex = sha256Hex,
            PublisherName = publisherName,
            PublisherThumbprint = publisherThumbprint,
            CreatedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        };
        var tcs = new TaskCompletionSource<UserPermissionChoice>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[requestId] = (request, tcs);

        try
        {
            RequestCreated?.Invoke(request);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            await using var reg = cts.Token.Register(() => tcs.TrySetCanceled());
            return await tcs.Task;
        }
        catch (TaskCanceledException)
        {
            return null; // het timeout -> deny-and-log o tang goi (BIZ-04/NFR-AVAIL-03)
        }
        finally
        {
            _pending.TryRemove(requestId, out _);
        }
    }

    public bool Respond(string requestId, UserPermissionChoice choice)
    {
        if (_pending.TryGetValue(requestId, out var entry))
        {
            return entry.Tcs.TrySetResult(choice);
        }
        return false;
    }

    public IReadOnlyCollection<PendingPermissionRequest> ListPending() =>
        _pending.Values.Select(v => v.Request).ToList();
}
