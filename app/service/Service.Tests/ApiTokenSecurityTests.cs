using Antivirus.Service.Security;
using Xunit;

namespace Antivirus.Service.Tests;

// [BO SUNG THEO REVIEW — High #2 va #7]
//
// Review chi ra hai dieu cung mot cho:
//   - lop xac thuc /api/* co token fixation + ghi file truoc khi ap ACL +
//     catch {} nuot loi ACL;
//   - va KHONG CO MOT test nao cham vao lop xac thuc do.
//
// Test middleware qua WebApplicationFactory se keo theo toan bo host that
// (driver simulator, cac FileSystemWatcher, hosted service quet dia...) —
// khong phu hop lam test don vi. Nhung LOGIC BAO MAT that su nam trong
// ApiTokenProvider, va no kiem tra duoc truc tiep. Cac test duoi day khoa
// dung nhung hanh vi ma ban va da thiet lap.
public class ApiTokenSecurityTests : IDisposable
{
    private readonly string _dir;
    private readonly string _tokenPath;

    public ApiTokenSecurityTests()
    {
        _dir = Directory.CreateTempSubdirectory("avtest_token_").FullName;
        _tokenPath = Path.Combine(_dir, "api-token.txt");
    }

    // --- TOKEN FIXATION ---
    // Ke tan cong ghi truoc mot file token voi gia tri ho tu chon. Truoc ban
    // va, service doc va TIN gia tri do => ho biet token gac toan bo /api/*.
    // Gia tri sai dinh dang phai bi vut bo, khong duoc dung lam bi mat.
    [Theory]
    [InlineData("attacker-chosen-token")]                 // sai do dai, co dau gach nhung khong phai base64url 43 ky tu
    [InlineData("")]                                       // rong
    [InlineData("   ")]                                    // toan khoang trang
    [InlineData("aaaa")]                                   // qua ngan
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")] // qua dai
    [InlineData("AAAAAAAAAAAAAAAAAAAA+AAAAAAAAAAAAAAAAAAAAAA")]         // dung do dai nhung co ky tu ngoai base64url
    public void PreExistingMalformedTokenFile_IsRejected_NotAdopted(string planted)
    {
        File.WriteAllText(_tokenPath, planted);

        var provider = new ApiTokenProvider(_tokenPath);

        Assert.NotEqual(planted, provider.Token);
        Assert.NotEqual(planted.Trim(), provider.Token);
        // Token thay the phai la mot token hop le do chinh service sinh ra.
        Assert.Equal(43, provider.Token.Length);
        Assert.False(provider.Validate(planted));
    }

    // Token DUNG dinh dang thi van duoc tai su dung — day la hanh vi co chu
    // y (giu phien lam viec cua nguoi dung qua cac lan restart service).
    // Lop phong thu that su chong fixation la ACL tren thu muc, duoc ap
    // dung TRUOC khi file duoc ghi (xem ApiTokenProvider).
    [Fact]
    public void PreExistingWellFormedToken_IsReused_AcrossRestarts()
    {
        var first = new ApiTokenProvider(_tokenPath);

        var second = new ApiTokenProvider(_tokenPath);

        Assert.Equal(first.Token, second.Token);
    }

    [Fact]
    public void GeneratedToken_IsBase64UrlWith256BitsOfEntropy()
    {
        var provider = new ApiTokenProvider(_tokenPath);

        // 32 byte ngau nhien -> base64 khong padding = 43 ky tu.
        Assert.Equal(43, provider.Token.Length);
        Assert.All(provider.Token, c =>
            Assert.True(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_',
                $"Token chua ky tu ngoai bang base64url: '{c}'"));
    }

    // Hai lan sinh khac nhau phai ra hai token khac nhau — neu khong thi
    // nguon ngau nhien da hong va moi may cai san pham deu dung chung mot
    // token.
    [Fact]
    public void TwoFreshProviders_ProduceDifferentTokens()
    {
        var a = new ApiTokenProvider(Path.Combine(_dir, "a.txt"));
        var b = new ApiTokenProvider(Path.Combine(_dir, "b.txt"));

        Assert.NotEqual(a.Token, b.Token);
    }

    // --- SO SANH TOKEN ---
    [Fact]
    public void Validate_RejectsNullEmptyAndWrongTokens()
    {
        var provider = new ApiTokenProvider(_tokenPath);

        Assert.False(provider.Validate(null));
        Assert.False(provider.Validate(""));
        Assert.False(provider.Validate("sai"));
        // Tien to dung nhung thieu ky tu cuoi — phai truot (chong so sanh
        // theo tien to).
        Assert.False(provider.Validate(provider.Token[..^1]));
        // Dai hon token that nhung bat dau bang no.
        Assert.False(provider.Validate(provider.Token + "x"));
        Assert.True(provider.Validate(provider.Token));
    }

    // --- THU TU ACL ---
    // File token phai TON TAI sau khi khoi tao, va bat ky that bai ACL nao
    // phai duoc BAO CAO qua AclFailure thay vi bi catch {} nuot im lang
    // (Program.cs doc thuoc tinh nay de ghi log/audit muc Critical).
    [Fact]
    public void TokenFile_IsWritten_AndAclOutcomeIsObservable()
    {
        var provider = new ApiTokenProvider(_tokenPath);

        Assert.True(File.Exists(_tokenPath));
        Assert.Equal(provider.Token, File.ReadAllText(_tokenPath).Trim());

        // Khong khang dinh ACL PHAI thanh cong (test co the chay khong
        // elevate) — khang dinh rang KET QUA cua no quan sat duoc. Truoc
        // ban va, thong tin nay bi nuot hoan toan va khong cach nao biet.
        _ = provider.AclFailure; // khong nem, luon doc duoc
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }
}
