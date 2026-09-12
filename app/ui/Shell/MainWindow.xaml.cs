using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Web.WebView2.Core;

namespace Antivirus.Shell;

// Shell native (.NET/WPF) cho tang UI, dung WebView2 de hien thi dashboard
// HTML/CSS/JS (xem app/service/Service/wwwroot). Theo dung nguyen tac
// modules/02-kien-truc.md: UI CHI hien thi/nhan thao tac, khong tu xu ly
// logic phat hien — toan bo logic nam trong Antivirus.Service (loopback
// 127.0.0.1:5270). Shell nay KHONG tu khoi dong service (dung kien truc:
// "service nen ... song doc lap voi UI", service se do Windows Service
// Control Manager khoi dong luc boot trong ban trien khai that).
public partial class MainWindow : Window
{
    // Duong dan file token phai khop chinh xac voi ApiTokenProvider.cs
    // (DataPaths.DataDir/api-token.txt) — xem ghi chu bao mat o do.
    private static readonly string TokenFilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "AntivirusApp", "data", "api-token.txt");

    // [SUA LOI CHAN PHAT HANH] Thu muc du lieu cua WebView2.
    //
    // TRUOC DAY khong cho nao cau hinh UserDataFolder, nen WebView2 dung mac
    // dinh cua no: mot thu muc "<duong-dan-exe>.WebView2" NGAY CANH file exe.
    // Khi chay tu thu muc phat trien thi khong sao. Khi cai that bang MSI,
    // exe nam o C:\Program Files\SmePlanAv\Shell\ — thu muc ma ngay ca tien
    // trinh elevated cung KHONG nen ghi vao, va WebView2 tu choi thang:
    //
    //   "We couldn't create the data directory
    //    Microsoft Edge can't read and write to its data directory:
    //    C:\Program Files\SmePlanAv\Shell\AntivirusApp.exe.WebView2\EBWebView"
    //
    // Ket qua: cua so mo len den thui, khong mot pixel giao dien nao. Loi nay
    // KHONG the lo ra khi chay tu bin/ luc phat trien — no chi xuat hien sau
    // khi da cai dat that, tuc la o dung noi ma nguoi dung gap dau tien.
    //
    // Sua: dat tuong minh vao %LOCALAPPDATA% — thu muc du lieu theo NGUOI
    // DUNG, luon ghi duoc, va la vi tri Microsoft khuyen dung cho
    // UserDataFolder cua ung dung cai vao Program Files.
    private static readonly string WebViewUserDataFolder = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SmePlanAv", "WebView2");

    public MainWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) => { TryEnableDarkTitleBar(); await InitializeBrowserAsync(); };
        Browser.NavigationCompleted += Browser_NavigationCompleted;
    }

    // Phai tao CoreWebView2Environment voi UserDataFolder rieng TRUOC khi
    // dung Browser.Source — dat Source trong khi CoreWebView2 chua khoi tao
    // se khien no tu khoi tao bang moi truong MAC DINH (canh exe), dung cai
    // ta muon tranh.
    private async Task InitializeBrowserAsync()
    {
        try
        {
            Directory.CreateDirectory(WebViewUserDataFolder);
            var env = await CoreWebView2Environment.CreateAsync(
                browserExecutableFolder: null,
                userDataFolder: WebViewUserDataFolder);
            await Browser.EnsureCoreWebView2Async(env);
        }
        catch (Exception ex)
        {
            // Khong khoi tao duoc WebView2 thi giao dien khong the hien thi.
            // Noi ro ly do thay vi de lai mot cua so den khong giai thich gi —
            // day dung la kieu that bai im lang ma ban review chi ra nhieu lan.
            MessageBox.Show(
                "Khong khoi tao duoc WebView2 (thanh phan hien thi giao dien).\n\n" +
                $"Thu muc du lieu: {WebViewUserDataFolder}\n" +
                $"Chi tiet: {ex.GetType().Name}: {ex.Message}\n\n" +
                "Kiem tra da cai WebView2 Runtime chua (Microsoft Edge WebView2 Runtime).",
                "SmePlanAv — loi khoi tao giao dien",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        await NavigateWithTokenAsync();
    }

    // [SUA LOI NGHIEM TRONG] Service gio yeu cau token xac thuc cho moi
    // API — Shell doc token TRUC TIEP TU FILE tren dia (khong qua HTTP,
    // tranh "ga-va-trung": neu co mot endpoint HTTP tra token thi endpoint
    // do cung phai khong xac thuc, vo hieu hoa muc dich cua token).
    private async Task NavigateWithTokenAsync()
    {
        string? token = null;
        for (int attempt = 0; attempt < 20 && token is null; attempt++)
        {
            try
            {
                if (File.Exists(TokenFilePath))
                {
                    token = (await File.ReadAllTextAsync(TokenFilePath)).Trim();
                }
            }
            catch
            {
                // File dang duoc service ghi do, thu lai.
            }
            if (token is null) await Task.Delay(300);
        }

        var url = token is null
            ? "http://127.0.0.1:5270/" // service co the chua khoi dong — hien retry overlay
            : $"http://127.0.0.1:5270/?token={Uri.EscapeDataString(token)}";

        Browser.Source = new Uri(url);
    }

    private void Browser_NavigationCompleted(object? sender, CoreWebView2NavigationCompletedEventArgs e)
    {
        RetryOverlay.Visibility = e.IsSuccess ? Visibility.Collapsed : Visibility.Visible;
    }

    private async void RetryButton_Click(object sender, RoutedEventArgs e)
    {
        RetryOverlay.Visibility = Visibility.Collapsed;
        // Neu lan khoi tao dau that bai, CoreWebView2 van chua san sang —
        // di lai duong khoi tao day du thay vi chi doi dieu huong.
        if (Browser.CoreWebView2 is null) { await InitializeBrowserAsync(); return; }
        await NavigateWithTokenAsync();
    }

    // Diem nhan "cong nghe tuong lai": thanh tieu de toi mau (Windows 11
    // DWM immersive dark mode) thay vi thanh tieu de sang mac dinh.
    private void TryEnableDarkTitleBar()
    {
        try
        {
            var hwnd = new WindowInteropHelper(this).Handle;
            int useDark = 1;
            DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref useDark, sizeof(int));
        }
        catch
        {
            // Windows cu hon khong ho tro thuoc tinh nay — bo qua, khong anh huong chuc nang.
        }
    }

    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}
