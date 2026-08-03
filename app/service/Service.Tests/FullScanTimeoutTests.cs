using Antivirus.Service.FullScan;
using Xunit;

namespace Antivirus.Service.Tests;

// [TINH NANG THEO YEU CAU NGUOI DUNG] "cai timeout co the tuy bien theo
// tieu chuan nao de giam thoi gian cho ma khong lam lot luoi khong" —
// timeout theo kich thuoc file thay vi phang 20s cho moi file.
public class FullScanTimeoutTests
{
    [Theory]
    [InlineData(0, 5)]
    [InlineData(1024, 5)] // 1KB
    [InlineData(9L * 1024 * 1024, 5)] // 9MB — duoi nguong 10MB
    [InlineData(10L * 1024 * 1024, 10)] // dung nguong 10MB
    [InlineData(150L * 1024 * 1024, 10)] // giua 10-200MB
    [InlineData(200L * 1024 * 1024, 20)] // dung nguong 200MB
    [InlineData(2L * 1024 * 1024 * 1024, 20)] // 2GB — file rat lon
    public void GetTimeoutForFileSize_ReturnsExpectedTierBySize(long sizeBytes, int expectedSeconds)
    {
        var timeout = FullScanService.GetTimeoutForFileSize(sizeBytes);
        Assert.Equal(expectedSeconds, timeout.TotalSeconds);
    }
}
