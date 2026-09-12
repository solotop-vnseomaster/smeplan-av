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

    // [SUA LOI CHAN MAY LAM VIEC] Hai co de ProcessTrustEngine biet co NEN hoi
    // nguoi dung hay khong.
    //
    // TRUOC DAY moi tien trinh la deu sinh mot yeu cau xin quyen, bat ke co ai
    // dang nhin man hinh hay khong. Tren may dang lam viec, dieu do tao ra mot
    // con mua hop thoai: moi lan build lai sinh mot loat tien trinh moi, nguoi
    // dung bam khong kip, hop thoai chong len nhau, va moi yeu cau con giu mot
    // cho cho 30 giay.
    //
    // Giai phap khong phai la bo hoi, ma la chi hoi khi viec hoi CO NGHIA:
    //   1. Giao dien phai dang mo (no poll endpoint nay, xem MarkUiPolled).
    //   2. Khong duoc co qua nhieu yeu cau dang cho cung luc — neu hang doi da
    //      day thi nguoi dung ro rang khong theo kip, hoi them chi lam te hon.

    // Giao dien poll GET /api/permission-requests moi ~1,5 giay. Coi la "dang
    // mo" neu co lan poll trong 10 giay gan day — rong rai hon nhip poll nhieu
    // lan de mot lan tre mang/GC khong bi hieu nham thanh da dong giao dien.
    private static readonly TimeSpan UiPresenceWindow = TimeSpan.FromSeconds(10);

    // Nhieu hon con so nay thi nguoi dung khong the theo kip.
    private const int MaxConcurrentPending = 3;

    private long _lastUiPollTicks;

    public void MarkUiPolled() => Interlocked.Exchange(ref _lastUiPollTicks, DateTime.UtcNow.Ticks);

    public bool IsUiListening =>
        DateTime.UtcNow - new DateTime(Interlocked.Read(ref _lastUiPollTicks), DateTimeKind.Utc) < UiPresenceWindow;

    // Chi nen hoi khi giao dien dang mo VA hang doi chua qua tai.
    public bool CanPromptUser => IsUiListening && _pending.Count < MaxConcurrentPending;

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
