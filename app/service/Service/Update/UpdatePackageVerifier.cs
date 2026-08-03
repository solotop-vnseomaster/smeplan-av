using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Antivirus.Service.Update;

// security/09-bao-mat.md muc 1/3: "moi goi tai ve (full hoac delta) phai
// duoc xac minh chu ky so bang WinVerifyTrust ... ky bang chinh certificate
// cua cong ty, truoc khi duoc ap dung vao CSDL cuc bo" (API-03/SEC-04).
//
// [QUYET DINH TRIEN KHAI] Khong co EV Code Signing Certificate that trong
// moi truong nay (xem ops/README-known-limitations.md); dung mot certificate
// tu ky ("cua cong ty" theo dung tinh than spec — khong phai certificate
// cua ben thu ba) de ky/xac minh goi CSDL, thay cho WinVerifyTrust tren
// Authenticode (dung cho FILE THUC THI o AuthenticodeVerifier.cs) vi goi
// CSDL la mot blob du lieu, khong phai PE — RSA-SHA256 detached signature
// la co che tuong duong ve mat bao mat cho truong hop nay.
public sealed class UpdatePackageVerifier
{
    // Dinh dang goi: [4 byte little-endian: do dai chu ky][chu ky RSA-SHA256][noi dung goi]
    public static byte[] Sign(byte[] payload, X509Certificate2 signingCert)
    {
        using var rsa = signingCert.GetRSAPrivateKey() ?? throw new InvalidOperationException("Certificate khong co private key");
        byte[] signature = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);
        writer.Write(signature.Length);
        writer.Write(signature);
        writer.Write(payload);
        return ms.ToArray();
    }

    public static bool TryVerifyAndExtract(byte[] signedPackage, X509Certificate2 trustedCert, out byte[] payload)
    {
        payload = Array.Empty<byte>();
        if (signedPackage.Length < 4) return false;

        int sigLen = BitConverter.ToInt32(signedPackage, 0);
        if (sigLen <= 0 || sigLen > signedPackage.Length - 4) return false;

        byte[] signature = signedPackage[4..(4 + sigLen)];
        byte[] data = signedPackage[(4 + sigLen)..];

        using var rsa = trustedCert.GetRSAPublicKey();
        if (rsa is null) return false;

        bool valid = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (!valid) return false;

        payload = data;
        return true;
    }
}
