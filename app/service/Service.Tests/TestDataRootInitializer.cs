using System.Runtime.CompilerServices;
using Antivirus.Service.Data;

namespace Antivirus.Service.Tests;

// [SUA LOI — TEST DONG VAO DU LIEU SAN XUAT]
//
// Nhieu test goi vao DataPaths (truc tiep hoac gian tiep qua
// CompanyCertificateProvider, AclProtection, cac store...). TRUOC DAY
// DataPaths.RootDir tro CO DINH vao %ProgramData%\AntivirusApp — thu muc du
// lieu THAT cua san pham tren chinh may dang chay test.
//
// Hai hau qua, ca hai deu da quan sat duoc:
//
//  1. CompanyCertificateProviderTests tao va ghi mot file PFX chua KHOA RIENG
//     vao thu muc do, roi noi long quyen de doc lai duoc. Tuc la chay bo test
//     LAM YEU may chay no.
//
//  2. Sau khi san pham duoc cai dat that va AclProtection khoa thu muc do lai
//     cho SYSTEM + Administrators (dung nhu thiet ke), cac test do do ngay
//     voi UnauthorizedAccessException. Chung tung "xanh" chi vi may con o
//     trang thai KHONG an toan.
//
// ModuleInitializer chay khi module cua assembly test duoc nap — truoc moi
// test class, va quan trong hon la truoc lan dau tien DataPaths.RootDir duoc
// doc (no la static readonly, chi khoi tao mot lan).
internal static class TestDataRootInitializer
{
    [ModuleInitializer]
    internal static void RedirectDataRootToTempDirectory()
    {
        // Moi lan chay test dung mot thu muc rieng: cac lan chay khong the
        // anh huong lan nhau, va khong lan nao dong vao du lieu that.
        var root = Path.Combine(
            Path.GetTempPath(),
            "SmePlanAvTests",
            $"run_{Environment.ProcessId}_{DateTime.UtcNow:yyyyMMddHHmmssfff}");

        Directory.CreateDirectory(root);
        Environment.SetEnvironmentVariable(DataPaths.RootDirOverrideEnvVar, root);
    }
}
