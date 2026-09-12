using System.Runtime.InteropServices;

namespace Antivirus.Service.Downloads;

// flows/11-luong-xu-ly.md: "lay duong dan that qua SHGetKnownFolderPath" —
// .NET khong co hang so san cho thu muc Downloads nen phai goi Win32 API.
public static class KnownFolders
{
    private static readonly Guid FOLDERID_Downloads = new("374DE290-123F-4565-9164-39C4925E467B");

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHGetKnownFolderPath(
        [MarshalAs(UnmanagedType.LPStruct)] Guid rfid, uint dwFlags, IntPtr hToken, out IntPtr pszPath);

    // [SUA LOI NGHIEM TRONG] GetDownloadsPath() goi SHGetKnownFolderPath voi
    // hToken = IntPtr.Zero, nghia la "nguoi dung cua tien trinh hien tai".
    // Service chay duoi LocalSystem, nen ket qua la
    // C:\Windows\System32\config\systemprofile\Downloads — mot thu muc
    // khong ai tai file ve. Fallback cung dung SpecialFolder.UserProfile nen
    // cung sai y het. Module quet file tai ve vi vay khong quet gi ca trong
    // khi van bao "da khoi dong tren <duong dan>".
    // Ham nay duoc GIU LAI cho cac ngu canh chay duoi tai khoan nguoi dung
    // that (vi du cong cu dong lenh), con service PHAI dung
    // GetAllUserDownloadsPaths().
    //
    // Thu muc Downloads cua MOI nguoi dung that tren may. Rong nghia la may
    // khong co profile nguoi dung nao — phia goi phai bao ro dieu do, KHONG
    // duoc am tham lui ve thu muc cua SYSTEM.
    public static IReadOnlyList<string> GetAllUserDownloadsPaths() =>
        Antivirus.Service.Common.UserProfiles.GetDownloadsFolders();

    public static string GetDownloadsPath()
    {
        int hr = SHGetKnownFolderPath(FOLDERID_Downloads, 0, IntPtr.Zero, out IntPtr pathPtr);
        if (hr != 0 || pathPtr == IntPtr.Zero)
        {
            // Fallback hop ly neu API loi vi ly do nao do.
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        }
        try
        {
            return Marshal.PtrToStringUni(pathPtr) ?? "";
        }
        finally
        {
            Marshal.FreeCoTaskMem(pathPtr);
        }
    }
}
