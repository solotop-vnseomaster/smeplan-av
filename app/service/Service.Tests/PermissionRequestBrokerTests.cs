using Antivirus.Service.Trust;
using Xunit;

namespace Antivirus.Service.Tests;

// [test-coverage] PermissionRequestBroker chua co test rieng (chi duoc dung
// gian tiep qua ProcessTrustEngineTests) — nhanh Respond() tra ve false khi
// id khong ton tai/da het han truoc day chua tung duoc kiem chung truc tiep.
public class PermissionRequestBrokerTests
{
    [Fact]
    public void Respond_UnknownRequestId_ReturnsFalse()
    {
        var broker = new PermissionRequestBroker();

        var result = broker.Respond("khong-ton-tai", UserPermissionChoice.AllowOnce);

        Assert.False(result);
    }

    [Fact]
    public async Task Respond_ValidPendingRequest_ReturnsTrue_AndResolvesDecision()
    {
        var broker = new PermissionRequestBroker();
        var evalTask = broker.RequestDecisionAsync("C:\\app.exe", "hash123", "Some Publisher", "thumb123",
            TimeSpan.FromSeconds(5), CancellationToken.None);

        PendingPermissionRequest? request = null;
        for (int i = 0; i < 50 && request is null; i++)
        {
            request = broker.ListPending().FirstOrDefault();
            if (request is null) await Task.Delay(20);
        }
        Assert.NotNull(request);

        var responded = broker.Respond(request!.RequestId, UserPermissionChoice.AllowAlways);
        Assert.True(responded);

        var choice = await evalTask;
        Assert.Equal(UserPermissionChoice.AllowAlways, choice);
    }

    // [test-coverage] Sau khi mot request DA HET HAN (timeout, khong ai
    // phan hoi kip), no bi remove khoi _pending trong finally cua
    // RequestDecisionAsync — Respond() goi SAU do (vi du UI cham tre gui
    // response qua muon) phai tra ve false, KHONG duoc nem ngoai le hay am
    // tham "thanh cong" tren mot request khong con ton tai.
    [Fact]
    public async Task Respond_AfterRequestAlreadyTimedOut_ReturnsFalse()
    {
        var broker = new PermissionRequestBroker();
        var evalTask = broker.RequestDecisionAsync("C:\\app.exe", "hash123", null, null,
            TimeSpan.FromMilliseconds(100), CancellationToken.None);

        var choice = await evalTask;
        Assert.Null(choice); // het timeout -> null (BIZ-04)

        var respondedTooLate = broker.Respond("bat-ky-id-nao-tu-request-da-het-han", UserPermissionChoice.AllowOnce);
        Assert.False(respondedTooLate);
    }

    [Fact]
    public async Task Respond_SameRequestTwice_SecondCallReturnsFalse()
    {
        var broker = new PermissionRequestBroker();
        var evalTask = broker.RequestDecisionAsync("C:\\app.exe", "hash123", null, null,
            TimeSpan.FromSeconds(5), CancellationToken.None);

        PendingPermissionRequest? request = null;
        for (int i = 0; i < 50 && request is null; i++)
        {
            request = broker.ListPending().FirstOrDefault();
            if (request is null) await Task.Delay(20);
        }
        Assert.NotNull(request);

        Assert.True(broker.Respond(request!.RequestId, UserPermissionChoice.Block));
        var choice = await evalTask;
        Assert.Equal(UserPermissionChoice.Block, choice);

        // Sau khi da resolve, request bi remove khoi _pending (finally) —
        // goi Respond lan thu hai voi CUNG id phai tra ve false.
        Assert.False(broker.Respond(request.RequestId, UserPermissionChoice.AllowOnce));
    }

    [Fact]
    public async Task RequestCreated_EventFires_WithMatchingRequestData()
    {
        var broker = new PermissionRequestBroker();
        PendingPermissionRequest? fired = null;
        broker.RequestCreated += req => fired = req;

        var evalTask = broker.RequestDecisionAsync("C:\\evil.exe", "deadbeef", "Evil Corp", "thumbXYZ",
            TimeSpan.FromMilliseconds(200), CancellationToken.None);

        await evalTask;

        Assert.NotNull(fired);
        Assert.Equal("C:\\evil.exe", fired!.ProcessPath);
        Assert.Equal("deadbeef", fired.Sha256Hex);
        Assert.Equal("Evil Corp", fired.PublisherName);
        Assert.Equal("thumbXYZ", fired.PublisherThumbprint);
    }

    [Fact]
    public void ListPending_NoRequests_ReturnsEmpty()
    {
        var broker = new PermissionRequestBroker();

        Assert.Empty(broker.ListPending());
    }
}
