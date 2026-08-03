using System.Net;
using System.Runtime.InteropServices;

namespace Antivirus.Service.Extensions.Network;

public sealed record ArpEntry(string IpAddress, string MacAddress);

// "tai lieu moi.txt": "doc bang ARP hien co cua may (GetIpNetTable, khong
// can tu gui goi ARP request tran lan)".
internal static class ArpTableReader
{
    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_IPNETROW
    {
        public int dwIndex;
        public int dwPhysAddrLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] bPhysAddr;
        public int dwAddr;
        public int dwType;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

    private const int MIB_IPNET_TYPE_INVALID = 2;

    public static List<ArpEntry> GetArpTable()
    {
        var result = new List<ArpEntry>();
        int size = 0;
        GetIpNetTable(IntPtr.Zero, ref size, false);
        if (size == 0) return result;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            int ret = GetIpNetTable(buffer, ref size, false);
            if (ret != 0) return result; // 0 = NO_ERROR

            int numEntries = Marshal.ReadInt32(buffer);
            IntPtr rowsStart = IntPtr.Add(buffer, sizeof(int));
            int rowSize = Marshal.SizeOf<MIB_IPNETROW>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_IPNETROW>(IntPtr.Add(rowsStart, i * rowSize));
                if (row.dwType == MIB_IPNET_TYPE_INVALID) continue;
                if (row.dwPhysAddrLen != 6 || row.bPhysAddr is null) continue; // khong phai MAC Ethernet 6 byte

                var ip = new IPAddress(BitConverter.GetBytes(row.dwAddr)).ToString();
                var mac = string.Join(":", row.bPhysAddr.Take(6).Select(b => b.ToString("X2")));
                if (mac == "00:00:00:00:00:00") continue;
                if (IsMulticastOrBroadcast(row.bPhysAddr)) continue; // xem ghi chu duoi ham nay
                result.Add(new ArpEntry(ip, mac));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return result;
    }

    // Bit thap nhat cua byte dau tien (I/G bit theo chuan Ethernet) = 1
    // nghia la dia chi multicast/broadcast (vi du 01:00:5E:xx:xx:xx cho
    // IPv4 multicast, FF:FF:FF:FF:FF:FF cho broadcast) — day KHONG PHAI
    // mot thiet bi vat ly trong mang, chi la dia chi nhom/quang ba xuat
    // hien binh thuong trong bang ARP. Loc bo tranh HomeNetworkMonitorService
    // bao "thiet bi moi" gia cho nhung dia chi nay.
    private static bool IsMulticastOrBroadcast(byte[] mac) => mac.Length > 0 && (mac[0] & 0x01) != 0;
}
