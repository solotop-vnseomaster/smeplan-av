using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Antivirus.Service.Data;

namespace Antivirus.Service.Update;

// [HAN CHE DA BIET] security/09-bao-mat.md yeu cau ky goi CSDL "bang chinh
// certificate cua cong ty" — trong san xuat day la mot certificate cong ty
// that (khong nhat thiet phai la EV Code Signing Cert, vi day la ky goi du
// lieu chu khong phai ky driver/installer). Moi truong phat trien nay chua
// co certificate cong ty that nen tu tao MOT LAN mot self-signed certificate
// va tai su dung on dinh giua cac lan chay (khong tao moi moi lan), luu tai
// DataPaths de vua ky (cong cu build goi test) vua verify (service) dung
// cung mot certificate — dung de kiem thu TEST-10, KHONG dung cho phat hanh
// that (thay the bang certificate cong ty that khi trien khai san xuat).
public static class CompanyCertificateProvider
{
    private static readonly string PfxPath = Path.Combine(DataPaths.DataDir, "dev-update-signing-cert.pfx");
    private const string PfxPassword = "dev-only-not-for-production";

    public static X509Certificate2 GetOrCreate()
    {
        if (File.Exists(PfxPath))
        {
            return X509CertificateLoader.LoadPkcs12FromFile(PfxPath, PfxPassword,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
        }

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=AntivirusApp Dev Update Signing (KHONG DUNG CHO PHAT HANH)",
            rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        var pfxBytes = cert.Export(X509ContentType.Pfx, PfxPassword);
        File.WriteAllBytes(PfxPath, pfxBytes);

        return X509CertificateLoader.LoadPkcs12(pfxBytes, PfxPassword,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
    }
}
