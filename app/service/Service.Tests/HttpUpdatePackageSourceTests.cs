using System.Net;
using System.Text;
using Antivirus.Service.Update;
using Xunit;

namespace Antivirus.Service.Tests;

// [test-coverage] HttpUpdatePackageSource khong duoc dang ky mac dinh
// (Program.cs dung LocalFolderUpdatePackageSource) nhung la client HTTPS/JSON
// day du san sang tro toi update server that — truoc day KHONG co test nao
// cho cac nhanh loi HTTP (500/404/response rong), dung mot HttpMessageHandler
// gia (khong goi mang that) de kiem soat response.
public class HttpUpdatePackageSourceTests
{
    private sealed class FakeHttpMessageHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly string? _content;

        public FakeHttpMessageHandler(HttpStatusCode statusCode, string? content)
        {
            _statusCode = statusCode;
            _content = content;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var response = new HttpResponseMessage(_statusCode);
            if (_content is not null)
            {
                response.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(_content));
            }
            return Task.FromResult(response);
        }
    }

    private static HttpUpdatePackageSource CreateSource(HttpStatusCode statusCode, string? content)
    {
        var handler = new FakeHttpMessageHandler(statusCode, content);
        var client = new HttpClient(handler) { BaseAddress = new Uri("https://update.example.test") };
        return new HttpUpdatePackageSource(client);
    }

    [Fact]
    public async Task CheckLatestVersionAsync_Success_ParsesResponse()
    {
        var source = CreateSource(HttpStatusCode.OK, """{"LatestVersion":42,"Checksum":"abc123"}""");

        var result = await source.CheckLatestVersionAsync(CancellationToken.None);

        Assert.Equal(42, result.LatestVersion);
        Assert.Equal("abc123", result.Checksum);
    }

    // [test-coverage] Nhanh loi 500 chua tung duoc test — EnsureSuccessStatusCode
    // phai nem HttpRequestException, KHONG duoc am tham tra ve gia tri mac
    // dinh/null lam service tuong nham la "khong co ban cap nhat moi".
    [Fact]
    public async Task CheckLatestVersionAsync_ServerError_ThrowsHttpRequestException()
    {
        var source = CreateSource(HttpStatusCode.InternalServerError, "Internal Server Error");

        await Assert.ThrowsAsync<HttpRequestException>(
            () => source.CheckLatestVersionAsync(CancellationToken.None));
    }

    [Fact]
    public async Task CheckLatestVersionAsync_NotFound_ThrowsHttpRequestException()
    {
        var source = CreateSource(HttpStatusCode.NotFound, null);

        await Assert.ThrowsAsync<HttpRequestException>(
            () => source.CheckLatestVersionAsync(CancellationToken.None));
    }

    // [test-coverage] Response 200 nhung body rong/"null" -> Deserialize tra
    // ve null -> PHAI nem InvalidOperationException ro rang, khong duoc tra
    // ve mot VersionCheckResponse null cho caller roi NullReferenceException
    // o noi khac kho debug hon.
    [Fact]
    public async Task CheckLatestVersionAsync_EmptyJsonNull_ThrowsInvalidOperationException()
    {
        var source = CreateSource(HttpStatusCode.OK, "null");

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => source.CheckLatestVersionAsync(CancellationToken.None));
    }

    [Fact]
    public async Task DownloadPackageAsync_Success_ReturnsBytes()
    {
        var source = CreateSource(HttpStatusCode.OK, "package-bytes-content");

        var result = await source.DownloadPackageAsync("csdl-v42.bin", CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal("package-bytes-content", Encoding.UTF8.GetString(result!));
    }

    // [test-coverage] Khac voi CheckLatestVersionAsync (nem ngoai le),
    // DownloadPackageAsync CHU DINH tra ve null khi khong thanh cong (khong
    // nem) — truoc day chua co test nao xac nhan ca hai nhanh loi pho bien
    // (404 khong co goi, 500 loi server) deu di dung duong "tra ve null"
    // nay thay vi vo tinh throw.
    [Fact]
    public async Task DownloadPackageAsync_NotFound_ReturnsNull()
    {
        var source = CreateSource(HttpStatusCode.NotFound, null);

        var result = await source.DownloadPackageAsync("khong-ton-tai.bin", CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task DownloadPackageAsync_ServerError_ReturnsNull()
    {
        var source = CreateSource(HttpStatusCode.InternalServerError, "error");

        var result = await source.DownloadPackageAsync("csdl-v42.bin", CancellationToken.None);

        Assert.Null(result);
    }
}
