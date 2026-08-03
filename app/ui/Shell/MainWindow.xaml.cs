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

    public MainWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) => { TryEnableDarkTitleBar(); await NavigateWithTokenAsync(); };
        Browser.NavigationCompleted += Browser_NavigationCompleted;
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
