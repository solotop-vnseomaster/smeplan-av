using Antivirus.Service.Settings;
using Xunit;

namespace Antivirus.Service.Tests;

// [test-coverage] AppSettingsStore anh huong truc tiep den privacy cua
// nguoi dung (CloudIntelEnabled: co gui hash file ra ngoai hay khong) —
// truoc day KHONG co test nao, ke ca nhanh phuc hoi khi file JSON bi hong.
public class AppSettingsStoreTests : IDisposable
{
    private readonly string _path;

    public AppSettingsStoreTests()
    {
        _path = Path.Combine(Path.GetTempPath(), $"avtest_settings_{Guid.NewGuid():N}.json");
    }

    public void Dispose()
    {
        try { File.Delete(_path); } catch { }
    }

    [Fact]
    public void FileDoesNotExist_UsesDefaults()
    {
        var store = new AppSettingsStore(_path);

        Assert.True(store.Current.FullScanCacheEnabled);
        Assert.True(store.Current.CloudIntelEnabled);
    }

    [Fact]
    public void ValidJson_LoadsPersistedValues()
    {
        File.WriteAllText(_path, """{"FullScanCacheEnabled":false,"CloudIntelEnabled":false}""");

        var store = new AppSettingsStore(_path);

        Assert.False(store.Current.FullScanCacheEnabled);
        Assert.False(store.Current.CloudIntelEnabled);
    }

    // [test-coverage] Nhanh phuc hoi khi JSON hong (vi du ghi dang do mat
    // dien/crash giua luc ghi, hoac bi chinh sua tay sai dinh dang) — truoc
    // day chua duoc kiem chung: PHAI roi ve mac dinh AN TOAN, KHONG duoc nem
    // ngoai le lam service khong khoi dong duoc.
    [Theory]
    [InlineData("{ khong phai json hop le")]
    [InlineData("{\"FullScanCacheEnabled\": \"khong-phai-bool\"}")]
    [InlineData("")]
    [InlineData("null")]
    [InlineData("[1,2,3]")]
    public void CorruptOrUnexpectedJson_FallsBackToDefaults_DoesNotThrow(string corruptContent)
    {
        File.WriteAllText(_path, corruptContent);

        var store = new AppSettingsStore(_path);

        Assert.True(store.Current.FullScanCacheEnabled);
        Assert.True(store.Current.CloudIntelEnabled);
    }

    [Fact]
    public void Update_PersistsChanges_ReloadedByNewInstance()
    {
        var store = new AppSettingsStore(_path);

        store.Update(s => s.CloudIntelEnabled = false);

        Assert.False(store.Current.CloudIntelEnabled);

        var reloaded = new AppSettingsStore(_path);
        Assert.False(reloaded.Current.CloudIntelEnabled);
        Assert.True(reloaded.Current.FullScanCacheEnabled);
    }
}
