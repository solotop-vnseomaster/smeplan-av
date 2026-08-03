using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Antivirus.Service.Update;
using Xunit;

namespace Antivirus.Service.Tests;

// [ERR-UPD-01 / test-coverage] TryVerifyAndExtract xu ly du lieu tu MOT
// GOI CAP NHAT TAI VE TU MANG (khong hoan toan tin cay cho toi khi verify
// xong chu ky) — day la be mat parse nhi phan kinh dien de gap loi
// length<4/sigLen am/tran neu thieu kiem tra bien, truoc day chua co test
// truc tiep nao cho cac truong hop dau vao di dang nay (chi duoc test
// gian tiep qua UpdateClientServiceTests voi goi HOP LE hoac ky SAI chu
// ky, khong test cau truc byte bi hong).
public class UpdatePackageVerifierTests
{
    private readonly X509Certificate2 _trustedCert;

    public UpdatePackageVerifierTests()
    {
        _trustedCert = CreateSelfSignedCert("CN=Test Trusted Verifier");
    }

    private static X509Certificate2 CreateSelfSignedCert(string subject)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var pfx = cert.Export(X509ContentType.Pfx, "test");
        return X509CertificateLoader.LoadPkcs12(pfx, "test", X509KeyStorageFlags.Exportable);
    }

    [Fact]
    public void ValidPackage_RoundTrips_ExtractsOriginalPayload()
    {
        var payload = Encoding.UTF8.GetBytes("hello-signature-payload");
        var signed = UpdatePackageVerifier.Sign(payload, _trustedCert);

        bool ok = UpdatePackageVerifier.TryVerifyAndExtract(signed, _trustedCert, out var extracted);

        Assert.True(ok);
        Assert.Equal(payload, extracted);
    }

    [Fact]
    public void EmptyArray_ReturnsFalse_DoesNotThrow()
    {
        bool ok = UpdatePackageVerifier.TryVerifyAndExtract(Array.Empty<byte>(), _trustedCert, out var payload);

        Assert.False(ok);
        Assert.Empty(payload);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void ShorterThanHeaderLength_ReturnsFalse_DoesNotThrow(int length)
    {
        var junk = new byte[length];
        bool ok = UpdatePackageVerifier.TryVerifyAndExtract(junk, _trustedCert, out _);

        Assert.False(ok);
    }

    [Fact]
    public void ExactlyFourBytes_ZeroSigLen_ReturnsFalse()
    {
        // 4 byte header, sigLen=0 -> khong the co chu ky rong, phai bi tu choi.
        var junk = new byte[4]; // BitConverter.ToInt32 tren all-zero = 0
        bool ok = UpdatePackageVerifier.TryVerifyAndExtract(junk, _trustedCert, out _);

        Assert.False(ok);
    }

    [Fact]
    public void NegativeSigLen_ReturnsFalse_DoesNotThrow()
    {
        // -1 dang little-endian int32 = 0xFF 0xFF 0xFF 0xFF.
        var junk = new byte[8];
        BitConverter.GetBytes(-1).CopyTo(junk, 0);

        bool ok = UpdatePackageVerifier.TryVerifyAndExtract(junk, _trustedCert, out var payload);

        Assert.False(ok);
        Assert.Empty(payload);
    }

    [Fact]
    public void IntMaxSigLen_ReturnsFalse_DoesNotThrow()
    {
        // sigLen = int.MaxValue nhung buffer chi vai byte -> phai bi tu
        // choi boi kiem tra "sigLen > signedPackage.Length - 4", KHONG
        // duoc phep gay OverflowException/IndexOutOfRange khi slice mang.
        var junk = new byte[10];
        BitConverter.GetBytes(int.MaxValue).CopyTo(junk, 0);

        bool ok = UpdatePackageVerifier.TryVerifyAndExtract(junk, _trustedCert, out var payload);

        Assert.False(ok);
        Assert.Empty(payload);
    }

    [Fact]
    public void SigLenLargerThanRemainingBuffer_ReturnsFalse()
    {
        // sigLen hop le ve mat "khong am, khong qua int.MaxValue" nhung VAN
        // lon hon phan con lai cua buffer thuc te.
        var junk = new byte[20];
        BitConverter.GetBytes(100).CopyTo(junk, 0); // tuyen bo 100 byte chu ky nhung buffer chi co 16 byte con lai

        bool ok = UpdatePackageVerifier.TryVerifyAndExtract(junk, _trustedCert, out var payload);

        Assert.False(ok);
        Assert.Empty(payload);
    }

    [Fact]
    public void SignedByDifferentCertificate_ReturnsFalse()
    {
        var attackerCert = CreateSelfSignedCert("CN=Attacker");
        var payload = Encoding.UTF8.GetBytes("payload-ky-boi-cert-khac");
        var signed = UpdatePackageVerifier.Sign(payload, attackerCert);

        bool ok = UpdatePackageVerifier.TryVerifyAndExtract(signed, _trustedCert, out var extracted);

        Assert.False(ok);
        Assert.Empty(extracted);
    }

    [Fact]
    public void TamperedPayload_AfterValidSigning_ReturnsFalse()
    {
        var payload = Encoding.UTF8.GetBytes("payload-goc-chua-bi-sua");
        var signed = UpdatePackageVerifier.Sign(payload, _trustedCert);

        // Sua 1 byte trong phan noi dung (sau header+chu ky) — chu ky van
        // con nguyen ve cau truc nhung KHONG con khop voi noi dung da bi sua.
        signed[signed.Length - 1] ^= 0xFF;

        bool ok = UpdatePackageVerifier.TryVerifyAndExtract(signed, _trustedCert, out var extracted);

        Assert.False(ok);
        Assert.Empty(extracted);
    }
}
