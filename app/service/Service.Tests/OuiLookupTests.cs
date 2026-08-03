using Antivirus.Service.Extensions.Network;
using Xunit;

namespace Antivirus.Service.Tests;

// "tai lieu moi.txt" muc "Giam sat thiet bi trong mang gia dinh": tra OUI
// de xac dinh hang san xuat tu 3 octet dau cua MAC.
public class OuiLookupTests
{
    [Theory]
    [InlineData("B8:27:EB:11:22:33", "Raspberry Pi Foundation")]
    [InlineData("b8:27:eb:aa:bb:cc", "Raspberry Pi Foundation")]
    [InlineData("A0:20:A6:00:11:22", "Samsung")]
    public void KnownPrefix_ReturnsExpectedVendor(string mac, string expectedVendor)
    {
        Assert.Equal(expectedVendor, OuiLookup.Lookup(mac));
    }

    [Fact]
    public void UnknownPrefix_ReturnsKhongXacDinh()
    {
        Assert.Equal("Khong xac dinh", OuiLookup.Lookup("00:00:00:11:22:33"));
    }

    [Fact]
    public void EmptyOrShortInput_DoesNotThrow_ReturnsKhongXacDinh()
    {
        Assert.Equal("Khong xac dinh", OuiLookup.Lookup(""));
        Assert.Equal("Khong xac dinh", OuiLookup.Lookup("AB:CD"));
    }
}
