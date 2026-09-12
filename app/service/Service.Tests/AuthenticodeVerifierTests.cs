using Antivirus.Service.Trust;
using Xunit;

namespace Antivirus.Service.Tests;

// [test-coverage] AuthenticodeVerifier (WinVerifyTrust P/Invoke +
// IsMicrosoftPublisher) truoc day KHONG co test nao — day la chot chan
// chinh cho ERR-02 (chong gia mao Unicode/homoglyph publisher name) va la
// mot trong 3 tieu chi "trusted-by-default" cua ProcessTrustEngine (SEC-01).
// IsMicrosoftPublisher la ham pure (khong P/Invoke), de test truc tiep;
// Verify/VerifyAsync goi WinVerifyTrust that nen dung file he thong that co
// san tren moi may Windows (giong pattern da dung o ProcessTrustEngineTests/
// QuarantineManagerTests) thay vi mock.
public class AuthenticodeVerifierTests
{
    // ---------- IsMicrosoftPublisher: so khop CHINH XAC, chong ERR-02 ----------

    [Theory]
    [InlineData("Microsoft Corporation")]
    [InlineData("Microsoft Windows")]
    [InlineData("Microsoft Windows Publisher")]
    public void IsMicrosoftPublisher_ExactKnownNames_ReturnsTrue(string name)
    {
        Assert.True(AuthenticodeVerifier.IsMicrosoftPublisher(name));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void IsMicrosoftPublisher_NullOrEmpty_ReturnsFalse(string? name)
    {
        Assert.False(AuthenticodeVerifier.IsMicrosoftPublisher(name));
    }

    // [KIEM THU HOI QUY - ERR-02] So khop CHUA CHUOI CON (Contains) se bi
    // gia mao bang cach nhet ten Microsoft that vao publisher name gia dai
    // hon — ham PHAI dung so khop CHINH XAC (Equals), khong duoc "chua".
    [Theory]
    [InlineData("Microsoft Corporation Fake")]
    [InlineData("Not Microsoft Corporation")]
    [InlineData("Microsoft Corporation ")]
    [InlineData(" Microsoft Corporation")]
    [InlineData("microsoft corporation")] // khac hoa/thuong -> Ordinal khong khop
    public void IsMicrosoftPublisher_SubstringOrCaseVariant_ReturnsFalse(string name)
    {
        Assert.False(AuthenticodeVerifier.IsMicrosoftPublisher(name));
    }

    // [KIEM THU HOI QUY - ERR-02 homoglyph] Ky tu Cyrillic "С" (U+0421)
    // nhin giong het Latin "C" nhung la ky tu KHAC — so khop Ordinal phai tu
    // choi, khong duoc coi la khop "Microsoft Corporation".
    [Fact]
    public void IsMicrosoftPublisher_CyrillicHomoglyph_ReturnsFalse()
    {
        string homoglyph = "Microsoft \u0421orporation"; // "C" dau tien la Cyrillic Es (U+0421)
        Assert.False(AuthenticodeVerifier.IsMicrosoftPublisher(homoglyph));
    }

    [Fact]
    public void IsMicrosoftPublisher_UnrelatedPublisher_ReturnsFalse()
    {
        Assert.False(AuthenticodeVerifier.IsMicrosoftPublisher("Evil Corp Ltd"));
    }

    // ---------- Verify/VerifyAsync: WinVerifyTrust that qua P/Invoke ----------

    [Fact]
    public void Verify_UnsignedFile_ChainInvalid_NoPublisher()
    {
        var path = Path.Combine(Path.GetTempPath(), $"avtest_unsigned_{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(path, new byte[] { 0x4D, 0x5A, 0x00, 0x00 }); // "MZ" toi gian, khong phai PE hop le
        try
        {
            var result = AuthenticodeVerifier.Verify(path);

            Assert.False(result.ChainValid);
            Assert.Null(result.PublisherName);
            Assert.Null(result.PublisherThumbprint);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    [Fact]
    public void Verify_NonExistentFile_DoesNotThrow_ReturnsInvalid()
    {
        var path = Path.Combine(Path.GetTempPath(), $"avtest_khong_ton_tai_{Guid.NewGuid():N}.exe");

        var result = AuthenticodeVerifier.Verify(path);

        Assert.False(result.ChainValid);
        Assert.Null(result.PublisherThumbprint);
    }

    // [test-coverage] File he thong Windows THAT, ky so hop le boi Microsoft
    // -> ChainValid=true va IsMicrosoftPublisher(PublisherName) phai true —
    // day la duong "happy path" ma 3-tieu-chi trusted-by-default cua
    // ProcessTrustEngine dua vao, truoc day chua tung duoc kiem chung.
    [Fact]
    public void Verify_GenuineSignedSystemFile_ChainValid_MicrosoftPublisher()
    {
        var candidates = new[]
        {
            @"C:\Windows\System32\svchost.exe",
            @"C:\Windows\explorer.exe",
        };
        var path = candidates.FirstOrDefault(File.Exists);
        if (path is null) return; // moi truong khong co san file ung vien — bo qua

        var result = AuthenticodeVerifier.Verify(path);

        Assert.True(result.ChainValid, $"{path} duoc ky ky so boi Microsoft, ky vong chain hop le");
        Assert.True(AuthenticodeVerifier.IsMicrosoftPublisher(result.PublisherName),
            $"Publisher thuc te: {result.PublisherName}");
        Assert.False(string.IsNullOrEmpty(result.PublisherThumbprint));
    }

    [Fact]
    public async Task VerifyAsync_CompletesWithinTimeout_ForGenuineSignedFile()
    {
        var candidates = new[]
        {
            @"C:\Windows\System32\svchost.exe",
            @"C:\Windows\explorer.exe",
        };
        var path = candidates.FirstOrDefault(File.Exists);
        if (path is null) return;

        var result = await AuthenticodeVerifier.VerifyAsync(path, TimeSpan.FromSeconds(5), CancellationToken.None);

        Assert.True(result.ChainValid);
    }
}
