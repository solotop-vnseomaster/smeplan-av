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
