using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Antivirus.Service.Update;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Antivirus.Service.Tests;

// [test-coverage] CompanyCertificateProvider.GetOrCreateForEnvironment la
// cong fail-closed cho production (chan cert dev/hardcode-password lot vao
// moi truong khong phai Development khi ky/xac thuc goi update CSDL — xem
// ghi chu "[SUA LOI NGHIEM TRONG]" trong file goc). Truoc day KHONG co test
// nao xac nhan hanh vi nay THAT SU hoat dong — neu dieu kien gate bi dao
// nguoc trong tuong lai (vi du != thanh ==, hoac quen && mot dieu kien),
// khong gi bat duoc, va cert dev khong an toan co the am tham chay production.
public class CompanyCertificateProviderTests : IDisposable
{
    private sealed class FakeHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;
        public string ApplicationName { get; set; } = "Antivirus.Service.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private readonly List<string> _envVarsToClear = new();

    public void Dispose()
    {
        foreach (var name in _envVarsToClear)
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    private static IConfiguration EmptyConfig() => new ConfigurationBuilder().Build();

    private static IConfiguration ConfigWith(string? certPath, string? certPasswordEnvVar)
    {
        var dict = new Dictionary<string, string?>();
        if (certPath is not null) dict["UpdateSigning:CertPath"] = certPath;
        if (certPasswordEnvVar is not null) dict["UpdateSigning:CertPasswordEnvVar"] = certPasswordEnvVar;
        return new ConfigurationBuilder().AddInMemoryCollection(dict).Build();
    }

    [Fact]
    public void Development_ReturnsDevCertificate_WithoutRequiringConfig()
    {
        var env = new FakeHostEnvironment { EnvironmentName = Environments.Development };

        var cert = CompanyCertificateProvider.GetOrCreateForEnvironment(env, EmptyConfig());

        Assert.NotNull(cert);
        Assert.True(cert.HasPrivateKey);
    }

    // [test-coverage] Day CHINH XAC la kich ban gate can bao ve: production
    // (hoac bat ky moi truong nao khac Development) MA THIEU cau hinh
    // certificate cong ty THAT phai lam service KHONG KHOI DONG duoc
    // (fail-closed), khong duoc am tham roi ve dung cert dev.
    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("SomeOtherEnv")]
    public void NonDevelopment_MissingConfig_ThrowsInvalidOperationException(string environmentName)
    {
        var env = new FakeHostEnvironment { EnvironmentName = environmentName };

        Assert.Throws<InvalidOperationException>(() =>
            CompanyCertificateProvider.GetOrCreateForEnvironment(env, EmptyConfig()));
    }

    [Fact]
    public void NonDevelopment_CertPathConfiguredButPasswordEnvVarMissingFromConfig_Throws()
    {
        var env = new FakeHostEnvironment { EnvironmentName = Environments.Production };
        var config = ConfigWith(certPath: @"C:\some\cert.pfx", certPasswordEnvVar: null);

        Assert.Throws<InvalidOperationException>(() =>
            CompanyCertificateProvider.GetOrCreateForEnvironment(env, config));
    }

    [Fact]
    public void NonDevelopment_ConfiguredButEnvironmentVariableNotSet_Throws()
    {
        var env = new FakeHostEnvironment { EnvironmentName = Environments.Production };
        const string envVarName = "AVTEST_CERT_PW_NOT_SET_1234";
        Environment.SetEnvironmentVariable(envVarName, null); // dam bao chua duoc set
        var config = ConfigWith(certPath: @"C:\some\cert.pfx", certPasswordEnvVar: envVarName);

        Assert.Throws<InvalidOperationException>(() =>
            CompanyCertificateProvider.GetOrCreateForEnvironment(env, config));
    }

    // [test-coverage] Duong "happy path" that su cho production: cau hinh
    // day du (duong dan PFX hop le + bien moi truong chua mat khau dung) ->
    // phai load duoc certificate that, KHONG roi ve nhanh dev.
    [Fact]
    public void NonDevelopment_FullyConfigured_LoadsCertificateFromConfiguredPath()
    {
        var tempDir = Directory.CreateTempSubdirectory("avtest_companycert_").FullName;
        var pfxPath = Path.Combine(tempDir, "company-signing.pfx");
        const string password = "s3cr3t-test-only";
        const string envVarName = "AVTEST_CERT_PW_SET_5678";

        using (var rsa = RSA.Create(2048))
        {
            var req = new CertificateRequest("CN=AVTest Company Signing", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
            File.WriteAllBytes(pfxPath, cert.Export(X509ContentType.Pfx, password));
        }

        Environment.SetEnvironmentVariable(envVarName, password);
        _envVarsToClear.Add(envVarName);

        var env = new FakeHostEnvironment { EnvironmentName = Environments.Production };
        var config = ConfigWith(certPath: pfxPath, certPasswordEnvVar: envVarName);

        var loaded = CompanyCertificateProvider.GetOrCreateForEnvironment(env, config);

        Assert.NotNull(loaded);
        Assert.Contains("AVTest Company Signing", loaded.Subject);

        try { Directory.Delete(tempDir, recursive: true); } catch { }
    }
}
