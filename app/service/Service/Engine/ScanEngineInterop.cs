using System.Runtime.InteropServices;

namespace Antivirus.Service.Engine;

// P/Invoke sang scan_engine.dll (C++), khop dung include/scan_engine.h.
// Giao tiep service C# <-> scan engine C++ qua P/Invoke, dung nhu mo ta
// trong sections/02-lua-chon-ngon-ngu-stack.md.
internal static class ScanEngineInterop
{
    private const string DllName = "scan_engine.dll";

    public enum NativeScanVerdict : int { Clean = 0, Malicious = 1, Suspicious = 2, ScanError = 3 }
    public enum NativeDetectionStage : int { None = 0, HashSignature = 1, Yara = 2, Heuristic = 3, ZipBombGuard = 4, IoError = 5 }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NativeScanResult
    {
        public NativeScanVerdict Verdict;
        public NativeDetectionStage Stage;
        public uint ThreatId;
        public byte Severity;
        public uint HeuristicScore;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 65)] public byte[] Sha256Hex;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)] public byte[] Reason;
    }

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int Engine_Initialize(
        [MarshalAs(UnmanagedType.LPWStr)] string? signatureDbPath,
        [MarshalAs(UnmanagedType.LPWStr)] string? yaraRulesDir,
        double bloomFalsePositiveRate);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void Engine_Shutdown();

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void Engine_UnmapSignatureDb();

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int Engine_LoadSignatureDb(
        [MarshalAs(UnmanagedType.LPWStr)] string signatureDbPath);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int Engine_ScanFile(
        [MarshalAs(UnmanagedType.LPWStr)] string filePath, out NativeScanResult result);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int Engine_ScanBuffer(
        byte[] data, UIntPtr length,
        [MarshalAs(UnmanagedType.LPStr)] string? virtualName, out NativeScanResult result);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int Engine_BuildSignatureDb(
        [MarshalAs(UnmanagedType.LPWStr)] string csvPath,
        [MarshalAs(UnmanagedType.LPWStr)] string outDbPath);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int Engine_Sha256File(
        [MarshalAs(UnmanagedType.LPWStr)] string filePath,
        [MarshalAs(UnmanagedType.LPArray, SizeConst = 65)] byte[] outHex65);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int Engine_Sha256Buffer(
        byte[] data, UIntPtr length,
        [MarshalAs(UnmanagedType.LPArray, SizeConst = 65)] byte[] outHex65);
}
