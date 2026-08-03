using Antivirus.Service.Security;
using Xunit;

namespace Antivirus.Service.Tests;

// [SUA LOI NGHIEM TRONG - Program.cs] ApiTokenProvider la co che xac thuc
// GAC TOAN BO /api/* — truoc khi co no, bat ky tien trinh local nao (ke ca
// malware dang bi danh gia) co the goi thang /api/rules de tu whitelist
// chinh no. Class nay TRUOC DAY khong co test nao ca, du la thanh phan bao
// mat quan trong nhat cua toan bo API loopback. Test o day khoa lai hanh vi
// dung cua Validate() va viec token duoc giu on dinh qua cac lan restart.
public class ApiTokenProviderTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _tokenPath;

    public ApiTokenProviderTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("avtest_apitoken_").FullName;
        _tokenPath = Path.Combine(_tempDir, "api-token.txt");
    }

    [Fact]
    public void Validate_CorrectToken_ReturnsTrue()
    {
        var provider = new ApiTokenProvider(_tokenPath);

        Assert.True(provider.Validate(provider.Token));
    }

    [Fact]
    public void Validate_WrongToken_ReturnsFalse()
    {
        var provider = new ApiTokenProvider(_tokenPath);

        Assert.False(provider.Validate("chuoi-token-sai-hoan-toan"));
    }

    // Day chinh la loai dau vao se xuat hien khi header X-Av-Token bi thieu
    // hoan toan (context.Request.Headers["X-Av-Token"].FirstOrDefault() tra
    // ve null trong middleware o Program.cs).
    [Fact]
    public void Validate_NullCandidate_ReturnsFalse()
    {
        var provider = new ApiTokenProvider(_tokenPath);

        Assert.False(provider.Validate(null));
    }

    [Fact]
    public void Validate_EmptyStringCandidate_ReturnsFalse()
    {
        var provider = new ApiTokenProvider(_tokenPath);

        Assert.False(provider.Validate(""));
    }

    // Token phai la CHUOI KHAC RONG that su duoc sinh ngau nhien — khong
    // duoc de lot truong hop token rong (neu the thi Validate("") se vo
    // tinh tra True, tuong duong voi khong co xac thuc nao ca).
    [Fact]
    public void GeneratedToken_IsNonEmpty()
    {
        var provider = new ApiTokenProvider(_tokenPath);

        Assert.False(string.IsNullOrEmpty(provider.Token));
    }

    // [UX FIX da ghi trong ApiTokenProvider.cs] Token phai ON DINH qua cac
    // lan restart service (khoi tao lai ApiTokenProvider tren CUNG file) —
    // khac voi thiet ke ban dau sinh token moi moi lan, gay 401 kho hieu
    // cho URL/tab nguoi dung da mo tu truoc.
    [Fact]
    public void SecondInstance_SamePath_ReusesExistingToken()
    {
        var first = new ApiTokenProvider(_tokenPath);
        var firstToken = first.Token;

        var second = new ApiTokenProvider(_tokenPath);

        Assert.Equal(firstToken, second.Token);
        Assert.True(second.Validate(firstToken));
    }

    // File token phai THUC SU duoc ghi xuong dia (de UI Shell/nguoi dung co
    // the doc duoc de mo URL kem token — xem MainWindow.xaml.cs).
    [Fact]
    public void Constructor_WritesTokenFileToDisk()
    {
        var provider = new ApiTokenProvider(_tokenPath);

        Assert.True(File.Exists(_tokenPath));
        Assert.Equal(provider.Token, File.ReadAllText(_tokenPath).Trim());
    }

    // Regression cho bug da sua: neu file token ton tai nhung RONG (vi du
    // bi ghi do dang truoc khi crash), truoc day co the sinh ra Token rong
    // roi Validate("") se sai lech. Xac nhan truong hop nay van sinh token
    // moi hop le thay vi giu chuoi rong.
    [Fact]
    public void ExistingEmptyTokenFile_GeneratesNewNonEmptyToken()
    {
        File.WriteAllText(_tokenPath, "");

        var provider = new ApiTokenProvider(_tokenPath);

        Assert.False(string.IsNullOrEmpty(provider.Token));
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }
}
