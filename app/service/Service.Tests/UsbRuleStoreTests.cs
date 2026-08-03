using Antivirus.Service.Extensions.Usb;
using Xunit;

namespace Antivirus.Service.Tests;

// "tai lieu moi.txt" muc "Chinh sach allow/block theo VID/PID thiet bi":
// thu tu uu tien tra rule phai la exact (VID+PID+Serial) truoc, roi den
// VID+PID-only, roi moi ve mac dinh (ask + auto_scan=1).
public class UsbRuleStoreTests : IDisposable
{
    private readonly string _dbPath;
    private readonly UsbRuleStore _store;

    public UsbRuleStoreTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"avtest_usb_{Guid.NewGuid():N}.db");
        _store = new UsbRuleStore(_dbPath);
    }

    [Fact]
    public void ExactSerialMatch_WinsOverModelOnlyRule()
    {
        _store.Add(new UsbDeviceRule { VendorId = "0951", ProductId = "1666", SerialNumber = null, Action = UsbAction.Block, AutoScan = true });
        _store.Add(new UsbDeviceRule { VendorId = "0951", ProductId = "1666", SerialNumber = "AB123", Action = UsbAction.Allow, AutoScan = false });

        var policy = _store.ResolvePolicy("0951", "1666", "AB123");

        Assert.Equal(UsbAction.Allow, policy.Action);
        Assert.False(policy.AutoScan);
    }

    [Fact]
    public void NoSerialRule_FallsBackToModelOnlyRule()
    {
        _store.Add(new UsbDeviceRule { VendorId = "0951", ProductId = "1666", SerialNumber = null, Action = UsbAction.Block, AutoScan = true });

        var policy = _store.ResolvePolicy("0951", "1666", "SOME_OTHER_SERIAL");

        Assert.Equal(UsbAction.Block, policy.Action);
    }

    [Fact]
    public void NoRuleAtAll_DefaultsToAskWithAutoScan()
    {
        var policy = _store.ResolvePolicy("FFFF", "0001", "XYZ");

        Assert.Equal(UsbAction.Ask, policy.Action);
        Assert.True(policy.AutoScan);
    }

    [Fact]
    public void ParsePnpDeviceId_UsbStorFormat_ExtractsVenProdAndSerial()
    {
        var (vid, pid, serial) = UsbMonitorService.ParsePnpDeviceId(
            @"USBSTOR\DISK&VEN_KINGSTON&PROD_DATATRAVELER&REV_1.00\112233445566&0");

        Assert.Equal("KINGSTON", vid);
        Assert.Equal("DATATRAVELER", pid);
        Assert.Equal("112233445566", serial);
    }

    [Fact]
    public void ParsePnpDeviceId_UsbVidPidFormat_ExtractsVidPidAndSerial()
    {
        var (vid, pid, serial) = UsbMonitorService.ParsePnpDeviceId(@"USB\VID_0951&PID_1666\112233445566");

        Assert.Equal("0951", vid);
        Assert.Equal("1666", pid);
        Assert.Equal("112233445566", serial);
    }

    public void Dispose()
    {
        try { File.Delete(_dbPath); } catch { }
    }
}
