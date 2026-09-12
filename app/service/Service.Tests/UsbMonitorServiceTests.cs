using Antivirus.Service.Extensions.Usb;
using Xunit;

namespace Antivirus.Service.Tests;

// [test-coverage] ParsePnpDeviceId la ham pure quyet dinh VendorId/ProductId/
// Serial dung de tra cuu UsbRuleStore (allow/block chinh sach USB) — truoc
// day KHONG co test nao du la ham de test nhat (khong P/Invoke/WMI).
public class UsbMonitorServiceTests
{
    [Fact]
    public void UsbFormat_VidPid_ParsedCorrectly()
    {
        var (vid, pid, serial) = UsbMonitorService.ParsePnpDeviceId(@"USB\VID_0951&PID_1666\112233445566");

        Assert.Equal("0951", vid);
        Assert.Equal("1666", pid);
        Assert.Equal("112233445566", serial);
    }

    [Fact]
    public void UsbStorFormat_VenProd_ParsedCorrectly()
    {
        var (vid, pid, serial) = UsbMonitorService.ParsePnpDeviceId(
            @"USBSTOR\DISK&VEN_KINGSTON&PROD_DATATRAVELER&REV_1.00\112233445566&0");

        Assert.Equal("KINGSTON", vid);
        Assert.Equal("DATATRAVELER", pid);
        Assert.Equal("112233445566", serial);
    }

    [Fact]
    public void LowercaseInput_StillParsedCorrectly_CaseInsensitive()
    {
        var (vid, pid, _) = UsbMonitorService.ParsePnpDeviceId(@"usb\vid_0951&pid_1666\112233445566");

        Assert.Equal("0951", vid);
        Assert.Equal("1666", pid);
    }

    [Fact]
    public void MissingVidPidTags_ReturnsNullForThoseFields()
    {
        var (vid, pid, serial) = UsbMonitorService.ParsePnpDeviceId(@"SOME\UNKNOWN&FORMAT\ABC123");

        Assert.Null(vid);
        Assert.Null(pid);
        Assert.Equal("ABC123", serial);
    }

    [Fact]
    public void TooFewSegments_SerialIsNull()
    {
        var (_, _, serial) = UsbMonitorService.ParsePnpDeviceId(@"USB\VID_0951&PID_1666");

        Assert.Null(serial);
    }

    [Fact]
    public void EmptyString_DoesNotThrow_ReturnsAllNull()
    {
        var (vid, pid, serial) = UsbMonitorService.ParsePnpDeviceId("");

        Assert.Null(vid);
        Assert.Null(pid);
        Assert.Null(serial);
    }

    // [KIEM THU HOI QUY] Tag o CUOI CHUOI (khong co ky tu & hoac \ theo sau)
    // van phai duoc trich xuat day du — xac nhan dieu kien dung "end < length"
    // trong ExtractTag khong bi cat mat ky tu cuoi.
    [Fact]
    public void TagAtEndOfString_ExtractedFully()
    {
        var (vid, pid, _) = UsbMonitorService.ParsePnpDeviceId(@"USB\VID_0951&PID_1666");

        Assert.Equal("0951", vid);
        Assert.Equal("1666", pid);
    }

    [Fact]
    public void SerialWithAmpersandSuffix_TruncatedAtAmpersand()
    {
        var (_, _, serial) = UsbMonitorService.ParsePnpDeviceId(
            @"USBSTOR\DISK&VEN_SANDISK&PROD_CRUZER&REV_1.00\4C530001234567890123&0");

        Assert.Equal("4C530001234567890123", serial);
    }
}
