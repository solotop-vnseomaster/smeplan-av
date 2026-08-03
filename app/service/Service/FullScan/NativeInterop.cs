using System.Runtime.InteropServices;

namespace Antivirus.Service.FullScan;

// P/Invoke dung chung cho Full/Deep Scan — khop cac API duoc neu cu the
// trong flows/11 va nfr/06: FSCTL_ENUM_USN_DATA, GetVolumeInformation,
// IOCTL_STORAGE_QUERY_PROPERTY/StorageDeviceSeekPenaltyProperty,
// GetLastInputInfo, SetPriorityClass/PROCESS_MODE_BACKGROUND_BEGIN.
internal static class NativeInterop
{
    public const uint GENERIC_READ = 0x80000000;
    public const uint FILE_SHARE_READ = 0x1;
    public const uint FILE_SHARE_WRITE = 0x2;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeviceIoControl(
        IntPtr hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize,
        IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    public const uint FSCTL_ENUM_USN_DATA = 0x000900b3;

    [StructLayout(LayoutKind.Sequential)]
    public struct MFT_ENUM_DATA_V0
    {
        public ulong StartFileReferenceNumber;
        public long LowUsn;
        public long HighUsn;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetVolumeInformationW(
        string lpRootPathName, IntPtr lpVolumeNameBuffer, uint nVolumeNameSize,
        out uint lpVolumeSerialNumber, out uint lpMaximumComponentLength,
        out uint lpFileSystemFlags, System.Text.StringBuilder lpFileSystemNameBuffer, uint nFileSystemNameSize);

    // --- Storage seek-penalty (HDD vs SSD) ---
    public const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x2D1400;
    public const int StorageDeviceSeekPenaltyProperty = 7;
    public const int PropertyStandardQuery = 0;

    [StructLayout(LayoutKind.Sequential)]
    public struct STORAGE_PROPERTY_QUERY
    {
        public int PropertyId;
        public int QueryType;
        public byte AdditionalParameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DEVICE_SEEK_PENALTY_DESCRIPTOR
    {
        public uint Version;
        public uint Size;
        [MarshalAs(UnmanagedType.U1)] public bool IncursSeekPenalty;
    }

    // --- Idle detection ---
    [StructLayout(LayoutKind.Sequential)]
    public struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    [DllImport("kernel32.dll")]
    public static extern uint GetTickCount();

    // --- Process priority (giam canh tranh tai nguyen voi nguoi dung, NFR-PERF-04) ---
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetPriorityClass(IntPtr hProcess, uint dwPriorityClass);

    public const uint PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000;
    public const uint PROCESS_MODE_BACKGROUND_END = 0x00200000;
    public const uint NORMAL_PRIORITY_CLASS = 0x00000020;
}
