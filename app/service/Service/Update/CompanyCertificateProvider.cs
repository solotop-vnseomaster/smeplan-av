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

    // CHI dung trong moi truong Development — tu tao/tai su dung MOT
    // self-signed certificate cho TEST-10 (ky VA verify cung mot cert cuc
    // bo). KHONG BAO GIO goi truc tiep ham nay tu Program.cs nua, dung
    // GetOrCreateForEnvironment ben duoi de duoc gate dung moi truong.
    public static X509Certificate2 GetOrCreateDevCertificate()
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

    // [SUA LOI NGHIEM TRONG] TRUOC DAY GetOrCreate() (cert dev, password
    // hardcode ngay trong source) duoc Program.cs dang ky KHONG DIEU KIEN
    // lam certificate tin cay de ky/xac thuc goi update CSDL — neu build
    // nay chay nguyen trang production, bat ky ai doc duoc source hoac file
    // PFX (khong duoc AclProtection bao ve) co the tu ky mot goi CSDL gia
    // va service se verify PASS, pha vo hoan toan co che chong gia mao
    // supply-chain. Sua: gate theo IHostEnvironment — Development dung
    // dung cert dev nhu cu; moi truong khac BAT BUOC phai cau hinh
    // certificate cong ty that qua config (duong dan PFX + ten bien moi
    // truong chua password, KHONG hardcode password); thieu cau hinh se
    // lam service KHONG KHOI DONG duoc (fail-closed) thay vi am tham dung
    // cert dev khong an toan cho production.
    public static X509Certificate2 GetOrCreateForEnvironment(IHostEnvironment env, IConfiguration config)
    {
        if (env.IsDevelopment())
        {
            return GetOrCreateDevCertificate();
        }

        var certPath = config["UpdateSigning:CertPath"];
        var certPasswordEnvVar = config["UpdateSigning:CertPasswordEnvVar"];
        if (string.IsNullOrEmpty(certPath) || string.IsNullOrEmpty(certPasswordEnvVar))
        {
            throw new InvalidOperationException(
                "Thieu cau hinh UpdateSigning:CertPath / UpdateSigning:CertPasswordEnvVar cho moi " +
                "truong khong phai Development — KHONG the dung certificate dev (khong an toan) cho " +
                "san xuat. Cau hinh certificate cong ty that (duong dan PFX + ten bien moi truong chua " +
                "mat khau) truoc khi trien khai.");
        }
        var certPassword = Environment.GetEnvironmentVariable(certPasswordEnvVar);
        if (string.IsNullOrEmpty(certPassword))
        {
            throw new InvalidOperationException(
                $"Bien moi truong '{certPasswordEnvVar}' (mat khau PFX certificate cong ty) chua duoc thiet lap.");
        }
        return X509CertificateLoader.LoadPkcs12FromFile(certPath, certPassword,
            X509KeyStorageFlags.MachineKeySet);
    }
}
